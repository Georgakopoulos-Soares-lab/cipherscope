#!/usr/bin/env python3
"""Native (C++) tracing overhead: plain vs instrumented builds of the same kernel.

Arms, all from tests/cpp/fixtures/scaling_kernel.cpp built by the project's
own CMake configuration:

  plain        the user's binary, no CipherScope anywhere
  hooks        the CipherScope shadow build run WITHOUT a spool: every
               cs_event_* call executes (registry, clocks, state reads) but
               nothing is written -- the cost of instrumentation itself
  full         the shadow build with CIPHERSCOPE_NATIVE_SPOOL set -- what
               `cipherscope profile` measures

Each (size, arm, repetition) is one fresh process; wall time is measured
outside the process, the kernel's own loop time is read from its stdout, and
peak RSS comes from wait4(). Appends rows to evaluation/raw/native_overhead.csv.

    source ls6_env.sh
    PYTHONPATH=src python3 evaluation/native_overhead/run_native_overhead.py \\
        --openfhe-dir "$BUILD_ROOT/opt/openfhe/lib/OpenFHE" --sizes 100 1000 10000 100000 --repeat 3
"""

from __future__ import annotations

import argparse
import csv
import json
import os
import platform
import shutil
import subprocess
import sys
import tempfile
import time
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / "src"))

from cipherscope.build_discovery import discover_cmake_build, discover_openfhe, resolve_target  # noqa: E402
from cipherscope.native_profile import cache_root_for, ensure_toolchain, shadow_build  # noqa: E402

COLUMNS = ("size", "arm", "repetition", "events", "wall_ms", "loop_ms", "peak_rss_mb", "spool_bytes",
           "compiler_version", "openfhe_version", "python_version", "machine", "lane", "allocator")

# glibc trims the heap after every freed ~500 KB ciphertext buffer and re-faults
# it on the next allocation; a handful of long-lived allocations (such as the
# runtime's registry) suppresses that and makes an instrumented binary *faster*
# than the plain one. The `notrim` setting pins the allocator so both arms are
# measured under the same heap policy; `default` records what users see.
ALLOCATORS = {
    "default": {},
    "notrim": {"MALLOC_TRIM_THRESHOLD_": "2147483647", "MALLOC_TOP_PAD_": "268435456"},
}


def run_once(binary: Path, size: int, env: dict[str, str], stdout_path: Path) -> tuple[float, float, float]:
    """Run one process; return (external wall ms, kernel loop ms, peak RSS MB)."""

    fd = os.open(stdout_path, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o644)
    try:
        started = time.perf_counter()
        pid = os.posix_spawn(str(binary), [str(binary), str(size)], env,
                             file_actions=[(os.POSIX_SPAWN_DUP2, fd, 1), (os.POSIX_SPAWN_OPEN, 2, os.devnull, os.O_WRONLY, 0o644)])
        _, status, usage = os.wait4(pid, 0)
        wall_ms = (time.perf_counter() - started) * 1000
    finally:
        os.close(fd)
    if status != 0:
        raise RuntimeError(f"{binary} {size} exited with status {status}")
    loop_ms = json.loads(stdout_path.read_text(encoding="utf-8").strip().splitlines()[-1])["loop_ms"]
    return wall_ms, loop_ms, usage.ru_maxrss * 1024 / 1e6


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--openfhe-dir", type=Path, required=True)
    parser.add_argument("--compiler", type=Path, default=Path(shutil.which(os.environ.get("CXX", "g++")) or "g++"))
    parser.add_argument("--sizes", type=int, nargs="+", default=[100, 1000, 10000, 100000])
    parser.add_argument("--repeat", type=int, default=3)
    parser.add_argument("--arms", nargs="+", default=["plain", "hooks", "full"])
    parser.add_argument("--allocator", choices=sorted(ALLOCATORS), default="default")
    parser.add_argument("--output", type=Path, default=ROOT / "evaluation" / "raw" / "native_overhead.csv")
    parser.add_argument("--work", type=Path, default=None)
    args = parser.parse_args()

    work = args.work or Path(tempfile.mkdtemp(prefix="cipherscope-native-overhead-"))
    project = work / "project"
    if project.exists():
        shutil.rmtree(project)
    shutil.copytree(ROOT / "tests" / "cpp" / "fixtures", project, ignore=shutil.ignore_patterns("build", ".cipherscope"))
    build = project / "build"
    subprocess.run(["cmake", "-S", str(project), "-B", str(build), f"-DOpenFHE_DIR={args.openfhe_dir}",
                    f"-DCMAKE_CXX_COMPILER={args.compiler}"], check=True, capture_output=True)
    subprocess.run(["cmake", "--build", str(build), "--target", "scaling_kernel", "--parallel", "8"], check=True, capture_output=True)
    plain = build / "scaling_kernel"

    env = dict(os.environ, OMP_NUM_THREADS=os.environ.get("OMP_NUM_THREADS", "1"), CIPHERSCOPE_CACHE=str(work / "cache"),
               **ALLOCATORS[args.allocator])
    os.environ["CIPHERSCOPE_CACHE"] = env["CIPHERSCOPE_CACHE"]
    discovered = discover_cmake_build(plain)
    openfhe = discover_openfhe(discovered.cache)
    target = resolve_target(plain, discovered)
    toolchain = ensure_toolchain(discovered.compiler, discovered.compiler_version, openfhe, cache_root_for(discovered))
    instrumented = shadow_build(target, toolchain, cache_root_for(discovered)).binary
    lane = os.environ.get("CIPHERSCOPE_OPENFHE_LANE", "developer")

    args.output.parent.mkdir(parents=True, exist_ok=True)
    write_header = not args.output.exists() or args.output.stat().st_size == 0
    with args.output.open("a", encoding="utf-8", newline="") as stream:
        writer = csv.DictWriter(stream, fieldnames=COLUMNS)
        if write_header:
            writer.writeheader()
        for size in args.sizes:
            for repetition in range(args.repeat):
                for arm in args.arms:
                    run_env = dict(env)
                    run_env.pop("CIPHERSCOPE_NATIVE_SPOOL", None)
                    binary = plain if arm == "plain" else instrumented
                    spool = work / f"spool-{size}-{arm}-{repetition}.jsonl"
                    if arm == "full":
                        run_env["CIPHERSCOPE_NATIVE_SPOOL"] = str(spool)
                    try:
                        wall_ms, loop_ms, peak = run_once(binary, size, run_env, work / "stdout.txt")
                    except RuntimeError as error:
                        print(f"{arm} size={size}: {error}", file=sys.stderr)
                        return 1
                    row = {
                        "size": size, "arm": arm, "repetition": repetition,
                        "events": size + 4 if arm != "plain" else 0,  # loop ops + Encrypt x2 + KeyGen + EvalRotateKeyGen (+2 MakeCKKS)
                        "wall_ms": round(wall_ms, 3), "loop_ms": round(loop_ms, 3),
                        "peak_rss_mb": round(peak, 1),
                        "spool_bytes": spool.stat().st_size if arm == "full" and spool.exists() else "",
                        "compiler_version": discovered.compiler_version, "openfhe_version": openfhe.version,
                        "python_version": platform.python_version(), "machine": platform.machine(), "lane": lane,
                        "allocator": f"glibc-{args.allocator}",
                    }
                    writer.writerow(row)
                    stream.flush()
                    print(json.dumps(row, sort_keys=True))
                    if spool.exists():
                        spool.unlink()
    return 0


if __name__ == "__main__":
    sys.exit(main())
