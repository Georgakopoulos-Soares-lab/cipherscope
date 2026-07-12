"""Write immutable source-build provenance from inside the primary image."""

from __future__ import annotations

import hashlib
import json
import platform
import subprocess
from pathlib import Path


def command_version(*command: str) -> str:
    completed = subprocess.run(
        command,
        check=True,
        capture_output=True,
        text=True,
    )
    return completed.stdout.splitlines()[0]


def sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


package = Path("/opt/python311/lib/python3.11/site-packages/openfhe")
native_modules = {
    path.name: sha256(path)
    for path in sorted(package.glob("*.so"))
}
manifest = {
    "schema_version": "1.0.0",
    "base_image": {
        "name": "ubuntu:24.04",
        "digest": "sha256:4fbb8e6a8395de5a7550b33509421a2bafbc0aab6c06ba2cef9ebffbc7092d90",
        "architecture": platform.machine(),
    },
    "python": {
        "version": platform.python_version(),
        "source": "https://www.python.org/ftp/python/3.11.15/Python-3.11.15.tar.xz",
        "source_sha256": "272179ddd9a2e41a0fc8e42e33dfbdca0b3711aa5abf372d3f2d51543d09b625",
        "configure_flags": [
            "--prefix=/opt/python311",
            "--enable-shared",
            "--with-ensurepip=install",
        ],
    },
    "openfhe_native": {
        "repository": "https://github.com/openfheorg/openfhe-development.git",
        "tag": "v1.5.1",
        "commit": "1306d14f8c26bb6150d3e6ad54f28dfe1007689e",
        "cmake_flags": {
            "CMAKE_BUILD_TYPE": "Release",
            "CMAKE_INSTALL_PREFIX": "/opt/openfhe",
            "BUILD_UNITTESTS": "OFF",
            "BUILD_EXAMPLES": "OFF",
            "BUILD_BENCHMARKS": "OFF",
        },
    },
    "openfhe_python": {
        "repository": "https://github.com/openfheorg/openfhe-python.git",
        "tag": "v1.5.1.0",
        "commit": "4f13e2c3a7e35f73f4816904dabd3a3db47b6e51",
        "cmake_flags": {
            "CMAKE_BUILD_TYPE": "Release",
            "CMAKE_PREFIX_PATH": "/opt/openfhe",
            "OPENFHE_REQUIRED_VERSION": "1.5.1",
            "Python_EXECUTABLE": "/opt/python311/bin/python3.11",
            "PYTHON_EXECUTABLE_PATH": "/opt/python311/bin/python3.11",
        },
        "native_module_hashes": native_modules,
    },
    "toolchain": {
        "cc": command_version("cc", "--version"),
        "cxx": command_version("c++", "--version"),
        "cmake": command_version("cmake", "--version"),
    },
}

output = Path("/opt/cipherscope-openfhe-build-manifest.json")
output.write_text(
    json.dumps(manifest, indent=2, sort_keys=True, allow_nan=False) + "\n",
    encoding="utf-8",
)
output.chmod(0o444)
