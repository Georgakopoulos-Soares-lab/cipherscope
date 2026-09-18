"""`cipherscope profile` for native (C++/GCC/OpenFHE) targets.

    resolve target
      -> already instrumented (ELF .cipherscope.marker)?  run it
      -> else discover the CMake build, create or reuse an isolated shadow build
         compiled through the CipherScope GCC plugin, run the shadow binary
    -> native spool -> cipherscope.native_trace.normalize -> canonical trace
    -> build_analysis_bundle (the same pipeline the Python frontend uses)

The user's source tree, build tree, and original binary are never modified.
Everything CipherScope creates lives under `<source>/.cipherscope/` (or
$CIPHERSCOPE_CACHE) and the requested output directory.
"""

from __future__ import annotations

import hashlib
import json
import os
import shutil
import struct
import subprocess
import sys
import tempfile
import time
from collections.abc import Mapping, Sequence
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from . import native_trace
from .build_discovery import (
    BuildDiscoveryError,
    CMakeBuild,
    NativeTarget,
    OpenFHEInstall,
    describe,
    discover_cmake_build,
    resolve_target,
    translation_units_for,
)
from .exporters import write_bundle
from .pipeline import build_analysis_bundle
from .validation import ValidationError

REPOSITORY_ROOT = Path(__file__).resolve().parents[2]
NATIVE_SOURCE = REPOSITORY_ROOT / "native"
MANIFEST_JSON = NATIVE_SOURCE / "openfhe" / "openfhe-1.5.operations.json"
PLUGIN_BASENAME = "libcipherscope_gcc"
RUNTIME_BASENAME = "libcipherscope_openfhe"
MARKER_SECTION = ".cipherscope.marker"


class NativeProfileError(RuntimeError):
    pass


# ---------------------------------------------------------------------------
# ELF marker
# ---------------------------------------------------------------------------
def read_marker(binary: Path) -> dict[str, str] | None:
    """Parse the .cipherscope.marker section of an ELF64 file, if present."""

    try:
        data = binary.read_bytes()
    except OSError:
        return None
    if len(data) < 64 or data[:4] != b"\x7fELF" or data[4] != 2:  # ELF64 only
        return None
    little = data[5] == 1
    order = "<" if little else ">"
    shoff, = struct.unpack_from(order + "Q", data, 0x28)
    shentsize, shnum, shstrndx = struct.unpack_from(order + "HHH", data, 0x3A)
    if shoff == 0 or shnum == 0 or shoff + shnum * shentsize > len(data):
        return None

    def section(index: int) -> tuple[int, int, int]:
        base = shoff + index * shentsize
        name, _type, _flags, _addr, offset, size = struct.unpack_from(order + "IIQQQQ", data, base)
        return name, offset, size

    _, str_off, str_size = section(shstrndx)
    strings = data[str_off : str_off + str_size]
    for index in range(shnum):
        name_off, offset, size = section(index)
        end = strings.find(b"\0", name_off)
        name = strings[name_off:end].decode("ascii", "replace")
        if name == MARKER_SECTION:
            payload = data[offset : offset + size]
            fields: dict[str, str] = {}
            for entry in payload.split(b"\0"):
                for pair in entry.decode("utf-8", "replace").split(";"):
                    key, sep, value = pair.partition("=")
                    if sep:
                        fields[key.strip()] = value.strip()
            return fields or None
    return None


# ---------------------------------------------------------------------------
# Native toolchain (plugin + runtime), built with the target's own compiler
# ---------------------------------------------------------------------------
@dataclass(frozen=True)
class NativeToolchain:
    directory: Path
    plugin: Path
    runtime: Path
    manifest_txt: Path
    launcher: Path
    fingerprint: str


def _sha256_text(*parts: str) -> str:
    digest = hashlib.sha256()
    for part in parts:
        digest.update(part.encode("utf-8"))
        digest.update(b"\0")
    return digest.hexdigest()[:16]


def _source_fingerprint() -> str:
    digest = hashlib.sha256()
    for path in sorted(NATIVE_SOURCE.rglob("*")):
        if path.is_file() and path.suffix in {".cpp", ".h", ".json", ".py"}:
            digest.update(str(path.relative_to(NATIVE_SOURCE)).encode())
            digest.update(path.read_bytes())
    return digest.hexdigest()[:16]


def _run(command: Sequence[str], *, cwd: Path | None = None, env: Mapping[str, str] | None = None, log: Path | None = None) -> None:
    completed = subprocess.run(list(command), cwd=cwd, env=dict(env) if env else None, capture_output=True, text=True)
    if log is not None:
        with log.open("a", encoding="utf-8") as stream:
            stream.write("$ " + " ".join(command) + "\n" + completed.stdout + completed.stderr + "\n")
    if completed.returncode != 0:
        tail = (completed.stderr or completed.stdout).strip().splitlines()[-25:]
        raise NativeProfileError(f"command failed ({completed.returncode}): {' '.join(command[:3])} ...\n" + "\n".join(tail))


def ensure_toolchain(compiler: Path, compiler_version: str, openfhe: OpenFHEInstall, cache_root: Path) -> NativeToolchain:
    """Build (or reuse) the GCC plugin and runtime library for this compiler and OpenFHE install."""

    fingerprint = _sha256_text(str(compiler), compiler_version, str(openfhe.include_dir), str(openfhe.lib_dir),
                               openfhe.version or "", _source_fingerprint())
    directory = cache_root / "native" / fingerprint
    plugin = directory / f"{PLUGIN_BASENAME}.so"
    runtime = directory / f"{RUNTIME_BASENAME}.so"
    manifest_txt = directory / "manifest.txt"
    launcher = directory / "cipherscope-cxx-launcher"
    stamp = directory / "toolchain.json"
    if stamp.is_file() and plugin.is_file() and runtime.is_file() and launcher.is_file():
        return NativeToolchain(directory, plugin, runtime, manifest_txt, launcher, fingerprint)

    directory.mkdir(parents=True, exist_ok=True)
    log = directory / "build.log"
    log.write_text("", encoding="utf-8")
    sys.path.insert(0, str(NATIVE_SOURCE / "openfhe"))
    from manifest_to_plugin import render  # type: ignore[import-not-found]

    manifest_txt.write_text(render(json.loads(MANIFEST_JSON.read_text(encoding="utf-8"))), encoding="utf-8")

    plugin_include = subprocess.run([str(compiler), "-print-file-name=plugin"], capture_output=True, text=True, check=True).stdout.strip()
    if not (Path(plugin_include) / "include" / "gcc-plugin.h").is_file():
        raise NativeProfileError(f"{compiler} has no plugin headers ({plugin_include}/include/gcc-plugin.h); install the gcc plugin development package")
    _run([str(compiler), "-shared", "-fPIC", "-fno-rtti", "-std=c++17", "-O2", "-w", f"-I{plugin_include}/include",
          str(NATIVE_SOURCE / "gcc" / "plugin.cpp"), "-o", str(plugin)], log=log)
    flags = ["-std=c++17", "-O2", "-fPIC", "-w", f"-I{NATIVE_SOURCE / 'include'}", *openfhe.include_flags,
             *[f for f in openfhe.cxx_flags if f.startswith(("-D", "-f", "-m"))]]
    _run([str(compiler), "-shared", *flags, str(NATIVE_SOURCE / "runtime" / "runtime.cpp"),
          str(NATIVE_SOURCE / "runtime" / "adapter.cpp"), "-o", str(runtime), *openfhe.link_flags], log=log)
    launcher.write_text(
        "#!/bin/sh\n"
        "# CipherScope compiler launcher: runs the real compiler with the semantic\n"
        "# instrumentation plugin. CMake invokes it as: launcher <compiler> <args...>\n"
        "compiler=\"$1\"; shift\n"
        f"exec \"$compiler\" -fplugin={plugin} -fplugin-arg-{PLUGIN_BASENAME}-manifest={manifest_txt} "
        f"-fplugin-arg-{PLUGIN_BASENAME}-site-dir=\"${{CIPHERSCOPE_SITE_DIR:?CIPHERSCOPE_SITE_DIR is not set}}\" \"$@\"\n",
        encoding="utf-8",
    )
    launcher.chmod(0o755)
    stamp.write_text(json.dumps({
        "compiler": str(compiler), "compiler_version": compiler_version, "openfhe_version": openfhe.version,
        "openfhe_include": str(openfhe.include_dir), "openfhe_lib": str(openfhe.lib_dir), "fingerprint": fingerprint,
        "frontend_version": "0.1.0", "manifest": "openfhe-1.5-v1", "built_unix": int(time.time()),
    }, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    return NativeToolchain(directory, plugin, runtime, manifest_txt, launcher, fingerprint)


# ---------------------------------------------------------------------------
# Shadow build
# ---------------------------------------------------------------------------
@dataclass(frozen=True)
class InstrumentedTarget:
    binary: Path
    site_dir: Path
    shadow_root: Path
    build: CMakeBuild | None
    cmake_target: str | None
    expected_translation_units: int | None
    metadata: dict[str, Any]


def cache_root_for(build: CMakeBuild) -> Path:
    override = os.environ.get("CIPHERSCOPE_CACHE")
    return Path(override) if override else build.source_root / ".cipherscope"


def shadow_build(target: NativeTarget, toolchain: NativeToolchain, cache_root: Path, *, jobs: int | None = None,
                 rebuild: bool = False, log_stream=None) -> InstrumentedTarget:
    build = target.build
    definitions = build.forwarded_definitions
    fingerprint = _sha256_text(str(build.source_root), str(build.compiler), build.compiler_version, build.generator,
                               json.dumps(definitions, sort_keys=True), toolchain.fingerprint, target.cmake_target)
    shadow_root = cache_root / "builds" / fingerprint
    shadow_build_dir = shadow_root / "build"
    site_dir = shadow_root / "sites"
    metadata_path = shadow_root / "metadata.json"
    binary = shadow_build_dir / target.relative_path

    if not rebuild and metadata_path.is_file() and binary.is_file() and read_marker(binary):
        metadata = json.loads(metadata_path.read_text(encoding="utf-8"))
        return InstrumentedTarget(binary, site_dir, shadow_root, build, target.cmake_target,
                                  metadata.get("expected_translation_units"), metadata)

    if rebuild and shadow_root.exists():
        shutil.rmtree(shadow_root)
    shadow_root.mkdir(parents=True, exist_ok=True)
    site_dir.mkdir(exist_ok=True)
    for stale in site_dir.glob("*.sites.jsonl"):
        stale.unlink()
    log = shadow_root / "shadow-build.log"
    log.write_text("", encoding="utf-8")

    original_linker = build.cache.get("CMAKE_EXE_LINKER_FLAGS", ("STRING", ""))[1]
    linker_flags = f"{original_linker} -Wl,--no-as-needed -L{toolchain.directory} -l{RUNTIME_BASENAME[3:]} -Wl,-rpath,{toolchain.directory}".strip()
    configure = [
        "cmake", "-S", str(build.source_root), "-B", str(shadow_build_dir), "-G", build.generator,
        *[d for d in definitions if not d.startswith("-DCMAKE_EXE_LINKER_FLAGS")],
        f"-DCMAKE_EXE_LINKER_FLAGS:STRING={linker_flags}",
        f"-DCMAKE_CXX_COMPILER_LAUNCHER:STRING={toolchain.launcher}",
        "-DCMAKE_EXPORT_COMPILE_COMMANDS:BOOL=ON",
    ]
    env = dict(os.environ, CIPHERSCOPE_SITE_DIR=str(site_dir))
    if log_stream:
        print(f"Configuring instrumented shadow build in {shadow_build_dir} ...", file=log_stream)
    _run(configure, env=env, log=log)
    if log_stream:
        print(f"Building CMake target {target.cmake_target} through the CipherScope GCC plugin ...", file=log_stream)
    command = ["cmake", "--build", str(shadow_build_dir), "--target", target.cmake_target]
    if jobs:
        command += ["--parallel", str(jobs)]
    _run(command, env=env, log=log)
    if not binary.is_file():
        raise NativeProfileError(f"shadow build finished but {binary} was not produced (is {target.cmake_target} the right --cmake-target?)")
    marker = read_marker(binary)
    if not marker:
        raise NativeProfileError(f"shadow binary {binary} carries no CipherScope marker; the plugin did not instrument it")

    units = translation_units_for(build, shadow_build_dir / "compile_commands.json")
    metadata = {
        "fingerprint": fingerprint,
        "original_binary": str(target.binary),
        "instrumented_binary": str(binary),
        "cmake_target": target.cmake_target,
        "build": describe(build, target),
        "forwarded_definitions": definitions,
        "toolchain": str(toolchain.directory),
        "marker": marker,
        "expected_translation_units": units,
        "created_unix": int(time.time()),
    }
    metadata_path.write_text(json.dumps(metadata, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    return InstrumentedTarget(binary, site_dir, shadow_root, build, target.cmake_target, units, metadata)


# ---------------------------------------------------------------------------
# Profile
# ---------------------------------------------------------------------------
def _run_id() -> str:
    return "run_" + hashlib.sha256(f"{time.time_ns()}{os.getpid()}".encode()).hexdigest()[:24]


def profile_native(
    target: Path,
    arguments: Sequence[str],
    *,
    output: Path,
    build_dir: Path | None = None,
    cmake_target: str | None = None,
    site_dir: Path | None = None,
    strict: bool = True,
    max_events: int | None = None,
    max_trace_bytes: int | None = None,
    allow_testing_security: bool = False,
    jobs: int | None = None,
    rebuild: bool = False,
    stream=None,
) -> int:
    """Profile a native binary; returns the target's exit status (or 2 on profiler failure)."""

    stream = stream or sys.stderr
    if output.exists():
        print(f"cipherscope: output path already exists: {output}", file=sys.stderr)
        return 2
    target = target.resolve()
    if not target.is_file():
        print(f"cipherscope: target does not exist: {target}", file=sys.stderr)
        return 2

    print("CipherScope", file=stream)
    print(f"Target:        {target}", file=stream)
    print("Frontend:      GCC/OpenFHE", file=stream)
    marker = read_marker(target)
    instrumented: InstrumentedTarget
    try:
        if marker:
            print(f"Instrumented:  yes (marker {marker.get('frontend')} {marker.get('frontend_version')}, manifest {marker.get('manifest')})", file=stream)
            sites = site_dir or (target.parent.parent / "sites" if (target.parent.parent / "sites").is_dir() else target.parent / "sites")
            metadata_path = target.parent.parent / "metadata.json"
            metadata = json.loads(metadata_path.read_text(encoding="utf-8")) if metadata_path.is_file() else {}
            instrumented = InstrumentedTarget(target, sites, target.parent, None, None, metadata.get("expected_translation_units"), metadata)
        else:
            build = discover_cmake_build(target, build_dir)
            native_target = resolve_target(target, build, cmake_target)
            print(f"Compiler:      GCC {build.compiler_version} ({build.compiler})", file=stream)
            print(f"Build:         CMake ({build.generator}), source {build.source_root}", file=stream)
            if native_target.openfhe is None:
                raise BuildDiscoveryError("the build's CMakeCache.txt has no OpenFHE_DIR; the target does not appear to use OpenFHE via CMake")
            print(f"OpenFHE:       {native_target.openfhe.version or 'unknown version'} at {native_target.openfhe.lib_dir}", file=stream)
            cache_root = cache_root_for(build)
            print("Preparing CipherScope GCC plugin and runtime ...", file=stream)
            toolchain = ensure_toolchain(build.compiler, build.compiler_version, native_target.openfhe, cache_root)
            instrumented = shadow_build(native_target, toolchain, cache_root, jobs=jobs, rebuild=rebuild, log_stream=stream)
            print(f"Shadow target: {instrumented.binary}", file=stream)
    except (BuildDiscoveryError, NativeProfileError, OSError, subprocess.SubprocessError) as error:
        print(f"\ncipherscope: cannot establish complete semantic tracing for this target.\n\nReason:\n  {error}\n\nCoverage: UNSUPPORTED\nNo analysis-quality bundle was produced.", file=sys.stderr)
        return 2

    run_id = _run_id()
    with tempfile.TemporaryDirectory(prefix="cipherscope-native-") as temporary:
        spool = Path(temporary) / "spool.jsonl"
        env = dict(os.environ, CIPHERSCOPE_NATIVE_SPOOL=str(spool))
        if max_events:
            env["CIPHERSCOPE_MAX_EVENTS"] = str(max_events)
        if max_trace_bytes:
            env["CIPHERSCOPE_MAX_TRACE_BYTES"] = str(max_trace_bytes)
        print("Running target ...", file=stream)
        started = time.time()
        try:
            completed = subprocess.run([str(instrumented.binary), *arguments], env=env, check=False)
            exit_status = completed.returncode
        except KeyboardInterrupt:
            exit_status = 130
        print(f"Target exited with {exit_status} after {time.time() - started:.1f}s", file=stream)
        if not spool.is_file():
            print("cipherscope: the target wrote no spool; is the runtime library linked (see shadow-build.log)?", file=sys.stderr)
            return exit_status or 2

        runtime_metadata: dict[str, Any] = {
            "target": str(target),
            "instrumented_binary": str(instrumented.binary),
            "shadow_build": str(instrumented.shadow_root),
        }
        if instrumented.build is not None:
            runtime_metadata.update({
                "compiler_path": str(instrumented.build.compiler),
                "compiler_version": instrumented.build.compiler_version,
                "cmake_generator": instrumented.build.generator,
                "cmake_build_type": instrumented.build.build_type,
                "source_root": str(instrumented.build.source_root),
                "cmake_target": instrumented.cmake_target,
            })
        try:
            trace = native_trace.normalize(
                spool, instrumented.site_dir, MANIFEST_JSON,
                run_id=run_id, name=target.stem, exit_status=exit_status, strict=strict,
                expected_translation_units=instrumented.expected_translation_units,
                instrumented_binary_verified=read_marker(instrumented.binary) is not None,
                runtime_metadata=runtime_metadata, testing_security_acknowledged=allow_testing_security,
            )
            artifacts = build_analysis_bundle(trace)
            destination = write_bundle(output, manifest=artifacts["manifest"], trace=artifacts["trace"],
                                       graph=artifacts["graph"], recommendations=artifacts["recommendations"])
            native_dir = destination / "native"
            native_dir.mkdir()
            shutil.copy2(spool, native_dir / "spool.jsonl")
            if instrumented.site_dir.is_dir():
                shutil.copytree(instrumented.site_dir, native_dir / "sites")
            (native_dir / "build-metadata.json").write_text(json.dumps(instrumented.metadata, indent=2, sort_keys=True) + "\n", encoding="utf-8")
        except (native_trace.NativeTraceError, ValidationError, OSError, ValueError) as error:
            print(f"cipherscope: trace normalization failed: {error}", file=sys.stderr)
            return 2

    coverage = trace["run"]["coverage"]
    from .coverage import classify_run

    assessment = classify_run(trace)
    print(f"Trace validation ....... ok ({len(trace['events'])} events)", file=stream)
    print(f"Coverage ............... {assessment.coverage_class}" + (f" ({'; '.join(assessment.reasons)})" if assessment.reasons else ""), file=stream)
    print(f"Semantic calls:        {coverage['traced_semantic_calls']}", file=stream)
    print(f"Ciphertext versions:   {len(trace['ciphertexts'])}", file=stream)
    print(f"Findings:              {len(artifacts['recommendations']['findings'])}", file=stream)
    print(f"Bundle:                {destination}", file=stream)
    return exit_status


__all__ = ["InstrumentedTarget", "NativeProfileError", "NativeToolchain", "ensure_toolchain", "profile_native", "read_marker", "shadow_build"]
