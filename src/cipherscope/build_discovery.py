"""Discover how a native target was built so an equivalent instrumented build can be made.

Only CMake projects are supported in this version. Discovery reads the
project's own build metadata (`CMakeCache.txt`, `compile_commands.json`,
`OpenFHEConfig.cmake`) and never searches outside the target's build tree.
Nothing here modifies the user's source or build directory.
"""

from __future__ import annotations

import json
import re
import subprocess
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

# Cache entries forwarded into the shadow configuration so it reproduces the
# original build's semantics (compiler, standard, flags, package locations).
_FORWARDED_EXACT = {
    "CMAKE_BUILD_TYPE", "CMAKE_C_COMPILER", "CMAKE_CXX_COMPILER", "CMAKE_CXX_STANDARD",
    "CMAKE_CXX_EXTENSIONS", "CMAKE_CXX_STANDARD_REQUIRED", "CMAKE_PREFIX_PATH", "CMAKE_MODULE_PATH",
    "CMAKE_CXX_FLAGS", "CMAKE_CXX_FLAGS_DEBUG", "CMAKE_CXX_FLAGS_RELEASE", "CMAKE_CXX_FLAGS_RELWITHDEBINFO",
    "CMAKE_CXX_FLAGS_MINSIZEREL", "CMAKE_C_FLAGS", "CMAKE_EXE_LINKER_FLAGS", "CMAKE_SHARED_LINKER_FLAGS",
    "CMAKE_INSTALL_PREFIX", "CMAKE_POSITION_INDEPENDENT_CODE", "CMAKE_INTERPROCEDURAL_OPTIMIZATION",
    "BUILD_SHARED_LIBS", "OpenMP_CXX_FLAGS",
}
_FORWARDED_SUFFIXES = ("_DIR", "_ROOT", "_INCLUDE_DIR", "_LIBRARY", "_LIBRARIES", "_INCLUDE_DIRS")
_NOT_FORWARDED_PREFIXES = ("CMAKE_CACHEFILE_DIR", "CMAKE_CACHE_", "CMAKE_HOME_DIRECTORY", "CMAKE_GENERATOR",
                           "CMAKE_MAKE_PROGRAM", "CMAKE_COMMAND", "CMAKE_CPACK", "CMAKE_CTEST", "CMAKE_EDIT",
                           "CMAKE_EXPORT_COMPILE_COMMANDS", "CMAKE_PROJECT_", "CMAKE_NUMBER_OF", "CMAKE_ROOT",
                           "CMAKE_CXX_COMPILER_LAUNCHER", "CMAKE_C_COMPILER_LAUNCHER")
_CACHE_LINE = re.compile(r"^(?P<name>[^:=#/\s][^:=]*):(?P<type>[A-Z]+)=(?P<value>.*)$")


class BuildDiscoveryError(RuntimeError):
    """The target's build cannot be reproduced safely."""


@dataclass(frozen=True)
class OpenFHEInstall:
    config_path: Path
    include_dir: Path
    lib_dir: Path
    cxx_flags: tuple[str, ...]
    version: str | None

    @property
    def include_flags(self) -> list[str]:
        return [f"-I{self.include_dir}", f"-I{self.include_dir / 'core'}", f"-I{self.include_dir / 'pke'}",
                f"-I{self.include_dir / 'binfhe'}", f"-I{self.include_dir / 'cereal'}"]

    @property
    def link_flags(self) -> list[str]:
        return [f"-L{self.lib_dir}", "-lOPENFHEpke", "-lOPENFHEcore", "-lOPENFHEbinfhe", f"-Wl,-rpath,{self.lib_dir}", "-fopenmp"]


@dataclass(frozen=True)
class CMakeBuild:
    source_root: Path
    build_root: Path
    cache_path: Path
    compile_commands_path: Path | None
    compiler: Path
    compiler_version: str
    generator: str
    build_type: str | None
    cache: dict[str, tuple[str, str]] = field(default_factory=dict, compare=False, hash=False)

    @property
    def forwarded_definitions(self) -> list[str]:
        definitions: list[str] = []
        for name, (kind, value) in sorted(self.cache.items()):
            if kind in {"INTERNAL", "STATIC"}:
                continue
            if name.startswith(_NOT_FORWARDED_PREFIXES):
                continue
            forward = name in _FORWARDED_EXACT or name.endswith(_FORWARDED_SUFFIXES) or not name.startswith("CMAKE_")
            if not forward:
                continue
            if kind == "UNINITIALIZED":
                # A `-DNAME=value` the user gave at configure time (e.g. OpenFHE_DIR).
                definitions.append(f"-D{name}={value}")
            else:
                definitions.append(f"-D{name}:{kind}={value}")
        return definitions


@dataclass(frozen=True)
class NativeTarget:
    binary: Path
    cmake_target: str
    relative_path: Path  # binary relative to build_root
    build: CMakeBuild
    openfhe: OpenFHEInstall | None


def parse_cmake_cache(path: Path) -> dict[str, tuple[str, str]]:
    entries: dict[str, tuple[str, str]] = {}
    for line in path.read_text(encoding="utf-8", errors="replace").splitlines():
        match = _CACHE_LINE.match(line.strip())
        if match:
            entries[match.group("name")] = (match.group("type"), match.group("value"))
    return entries


def compiler_version(compiler: Path) -> str:
    try:
        completed = subprocess.run([str(compiler), "-dumpfullversion"], capture_output=True, text=True, check=False, timeout=30)
    except (OSError, subprocess.TimeoutExpired) as error:
        raise BuildDiscoveryError(f"cannot run {compiler}: {error}") from error
    text = completed.stdout.strip() or completed.stderr.strip()
    if completed.returncode != 0 or not text:
        raise BuildDiscoveryError(f"{compiler} did not report a version")
    return text.splitlines()[0]


def is_gcc(compiler: Path) -> bool:
    try:
        completed = subprocess.run([str(compiler), "--version"], capture_output=True, text=True, check=False, timeout=30)
    except (OSError, subprocess.TimeoutExpired):
        return False
    first = (completed.stdout or "").splitlines()[:1]
    return bool(first) and ("GCC" in first[0] or "g++" in first[0]) and "clang" not in first[0].lower()


def find_cmake_cache(start: Path, build_dir: Path | None = None) -> Path | None:
    """The nearest CMakeCache.txt at or above the target, never outside its tree."""

    candidates = [build_dir] if build_dir is not None else []
    current = start.resolve()
    if current.is_file():
        current = current.parent
    for _ in range(8):
        candidates.append(current)
        if current.parent == current:
            break
        current = current.parent
    for candidate in candidates:
        if candidate is None:
            continue
        cache = Path(candidate) / "CMakeCache.txt"
        if cache.is_file():
            return cache
    return None


def discover_openfhe(cache: dict[str, tuple[str, str]]) -> OpenFHEInstall | None:
    """Read OpenFHEConfig.cmake, which OpenFHE installs beside its libraries."""

    config_dir = cache.get("OpenFHE_DIR", (None, None))[1]
    if not config_dir:
        return None
    config = Path(config_dir) / "OpenFHEConfig.cmake"
    if not config.is_file():
        return None
    text = config.read_text(encoding="utf-8", errors="replace")

    def setting(name: str) -> str | None:
        match = re.search(rf'^\s*set\({name}\s+"([^"]*)"\)', text, re.MULTILINE)
        return match.group(1) if match else None

    include = setting("OpenFHE_INCLUDE")
    libdir = setting("OpenFHE_LIBDIR")
    if include is None or libdir is None:
        return None
    flags = tuple(part for part in (setting("OpenFHE_CXX_FLAGS") or "").split() if part and part != "-Werror")
    version_match = re.search(r"-DOPENFHE_VERSION=([0-9.]+)", text)
    return OpenFHEInstall(config, Path(include), Path(libdir), flags, version_match.group(1) if version_match else None)


def discover_cmake_build(binary: Path, build_dir: Path | None = None) -> CMakeBuild:
    cache_path = find_cmake_cache(binary, build_dir)
    if cache_path is None:
        raise BuildDiscoveryError(
            f"no CMakeCache.txt found at or above {binary}; pass --build-dir, or profile a "
            "CipherScope-instrumented binary"
        )
    cache = parse_cmake_cache(cache_path)
    source = cache.get("CMAKE_HOME_DIRECTORY", (None, None))[1]
    compiler = cache.get("CMAKE_CXX_COMPILER", (None, None))[1]
    if not source or not compiler:
        raise BuildDiscoveryError(f"{cache_path} lacks CMAKE_HOME_DIRECTORY or CMAKE_CXX_COMPILER")
    compiler_path = Path(compiler)
    if not compiler_path.is_file():
        raise BuildDiscoveryError(f"configured compiler {compiler} does not exist")
    if not is_gcc(compiler_path):
        raise BuildDiscoveryError(f"configured compiler {compiler} is not GCC; the CipherScope frontend is GCC-only")
    build_root = cache_path.parent
    compile_commands = build_root / "compile_commands.json"
    return CMakeBuild(
        source_root=Path(source),
        build_root=build_root,
        cache_path=cache_path,
        compile_commands_path=compile_commands if compile_commands.is_file() else None,
        compiler=compiler_path,
        compiler_version=compiler_version(compiler_path),
        generator=cache.get("CMAKE_GENERATOR", ("", "Unix Makefiles"))[1] or "Unix Makefiles",
        build_type=cache.get("CMAKE_BUILD_TYPE", ("", ""))[1] or None,
        cache=cache,
    )


def cmake_targets(build: CMakeBuild) -> list[str]:
    """Executable/library targets known to the original build (from CMakeFiles/*.dir)."""

    names: set[str] = set()
    for directory in build.build_root.rglob("CMakeFiles/*.dir"):
        if directory.is_dir() and not directory.name.startswith("cmake"):
            names.add(directory.name[: -len(".dir")])
    return sorted(names)


def resolve_target(binary: Path, build: CMakeBuild, cmake_target: str | None = None) -> NativeTarget:
    resolved = binary.resolve()
    try:
        relative = resolved.relative_to(build.build_root.resolve())
    except ValueError as error:
        raise BuildDiscoveryError(f"{binary} is not inside the build directory {build.build_root}") from error
    known = cmake_targets(build)
    name = cmake_target or resolved.name
    if known and name not in known:
        raise BuildDiscoveryError(
            f"no CMake target named {name!r} in {build.build_root}; pass --cmake-target one of: {', '.join(known)}"
        )
    return NativeTarget(resolved, name, relative, build, discover_openfhe(build.cache))


def translation_units_for(build: CMakeBuild, compile_commands: Path | None = None) -> int | None:
    """Number of C++ compile commands in the build (all targets)."""

    path = compile_commands or build.compile_commands_path
    if path is None or not path.is_file():
        return None
    try:
        entries = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        return None
    count = 0
    for entry in entries:
        file = str(entry.get("file", ""))
        if file.endswith((".cpp", ".cc", ".cxx", ".C")):
            count += 1
    return count


def describe(build: CMakeBuild, target: NativeTarget | None = None) -> dict[str, Any]:
    document: dict[str, Any] = {
        "source_root": str(build.source_root),
        "build_root": str(build.build_root),
        "generator": build.generator,
        "build_type": build.build_type,
        "compiler": str(build.compiler),
        "compiler_version": build.compiler_version,
        "compile_commands": str(build.compile_commands_path) if build.compile_commands_path else None,
    }
    if target is not None:
        document.update({
            "binary": str(target.binary),
            "cmake_target": target.cmake_target,
            "openfhe": None if target.openfhe is None else {
                "config": str(target.openfhe.config_path),
                "include": str(target.openfhe.include_dir),
                "lib": str(target.openfhe.lib_dir),
                "version": target.openfhe.version,
            },
        })
    return document


__all__ = [
    "BuildDiscoveryError", "CMakeBuild", "NativeTarget", "OpenFHEInstall", "cmake_targets", "compiler_version",
    "describe", "discover_cmake_build", "discover_openfhe", "find_cmake_cache", "is_gcc", "parse_cmake_cache",
    "resolve_target", "translation_units_for",
]
