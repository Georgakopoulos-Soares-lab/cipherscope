#!/usr/bin/env python3
"""D-03: before/after transformations for the TP-ACTIONABLE external-corpus findings.

For each transformation below the pinned python-log-reg-examples clone is
patched (a one-line config change taken from the finding's evidence), the
program is run untraced in fresh processes before and after the patch (wall,
CPU, peak RSS via wait4 rusage, plus a program-specific correctness value
parsed from its own output), each variant is also run once through
CipherScope to confirm the rule fires before and is silent after, the patch
is saved next to this script as a unified diff, and the clone is restored.
The medians are written into the transformation columns of
evaluation/adjudication/findings.csv, which is what
evaluation/tables/before_after.csv is generated from.

A transformation that OpenFHE refuses to run (insufficient depth) is
recorded as transformation_status=refused with the error, and a depth
finding's verdict is revised to FALSE-POSITIVE with that evidence. A
security-level patch is a fix, not an optimization: when it runs and the rule
clears it is recorded as validated_fix (or fix_changes_result when the
program's own output moves beyond its run-to-run spread), and the timing
columns are its cost.

The bootstrapped log_reg programs train for 100 epochs (about an hour per
run); their transformations carry `scale_edits` that cut both arms to the
same few epochs. The scale edit is applied identically before and after and
is not part of the saved patch.

    source ls6_env.sh
    OMP_NUM_THREADS=1 python3 evaluation/adjudication/transformations/run_transformations.py --repeat 3
    # one transformation, in its own clone, so several can run side by side:
    LOG_REG_EXAMPLES=/path/to/clone-copy python3 .../run_transformations.py --only sol_log_reg.mult_depth.33_to_31
"""

from __future__ import annotations

import argparse
import csv
import fcntl
import json
import os
import re
import resource
import shutil
import statistics
import subprocess
import sys
import time
from pathlib import Path

HERE = Path(__file__).resolve().parent
ROOT = HERE.parent.parent.parent
FINDINGS = ROOT / "evaluation" / "adjudication" / "findings.csv"
CORPUS = Path(os.environ.get("LOG_REG_EXAMPLES", "/work/10899/kimopro/ls6/python-log-reg-examples"))
DEPTH_RULE = "parameters.depth_headroom_observed.v1"


def _lin_reg_correctness(stdout: str) -> float | None:
    """|final encrypted MSE - final plaintext MSE| from the program's own epoch log."""
    plain = re.findall(r"^epoch: 4 ----> MSE: ([0-9.]+)$", stdout, re.M)
    enc = re.findall(r"^epoch: 4 ----> MSE: \[([0-9.]+)\]$", stdout, re.M)
    if not plain or not enc:
        return None
    return abs(float(enc[-1]) - float(plain[-1]))


def _inference_predictions(stdout: str) -> list[float]:
    return [float(v) for v in re.findall(r"^Prediction: ([-0-9.e]+),", stdout, re.M)]


def _final_loss(output: str) -> list[float]:
    """The last logged training loss (the programs log it to stderr)."""
    losses = re.findall(r"Iteration: \d+ Loss: ([-0-9.e]+)", output)
    return [float(losses[-1])] if losses else []


LOG_REG_CONFIG = "efficient_regression/config.yml"
LOG_REG_EPOCHS = 4
LOG_REG_SCALE = [(LOG_REG_CONFIG, r"^(  epochs: )100$", rf"\g<1>{LOG_REG_EPOCHS}")]
LOG_REG_SECURITY = [
    (LOG_REG_CONFIG, r"^(  ring_dimensionality: )32768 #131072 ", r"\g<1>131072 "),
    (LOG_REG_CONFIG, r"^(  security_level: )HEStd_NotSet #HEStd_128_classic$", r"\g<1>HEStd_128_classic"),
]
LOG_REG_SECURITY_WHY = (
    "config.yml carries '# TODO: swap out the values below' with HEStd_128_classic and ring 131072 commented beside "
    "HEStd_NotSet and 32768. At depth 33 with 59-bit scaling primes the modulus exceeds the 128-bit bound for 32768 "
    "(and 65536), so the patch takes both commented values; the timing columns are the cost of enforcing the standard."
)


TRANSFORMATIONS = [
    {
        "finding_id": "sol_lin_reg:keys.unused_in_observed_run.v1:301225c3",
        "rule": "keys.unused_in_observed_run.v1",
        "workload": "sol_lin_reg",
        "script": "sol_lin_reg.py",
        "transformation_id": "sol_lin_reg.rotation_keys.by_samples_to_by_features",
        "edits": [("sol_lin_reg.py", r"^(        num_data_points=-1 if config\[\"crypto_params\"\]\[\"run_bootstrap\"\] else )len\(X\),", r"\g<1>16,")],
        "correctness_metric": "abs(final encrypted MSE - final plaintext MSE), from the program's own epoch-4 log lines",
        "correctness": _lin_reg_correctness,
        "why": "The BSGS rotation-key set is sized by the sample count (1280 -> 89 keys) but the only EvalRotate site spans the feature count: the trace shows used indices -1..-4. Sizing the key set for 16 yields 6 keys (-1,-2,-3,-4,-8,-12) that still cover every used index (second reviewer's evidence).",
    },
    {
        "finding_id": "sol_encrypted_inference:configuration.testing_only_security.v1:db918a94",
        "rule": "configuration.testing_only_security.v1",
        "workload": "sol_encrypted_inference",
        "script": "sol_encrypted_inference.py",
        "transformation_id": "sol_encrypted_inference.security_level.not_set_to_128_classic",
        "edits": [("efficient_regression/inference_config.yml", r"^(  security_level: )HEStd_NotSet ", r"\g<1>HEStd_128_classic ")],
        "correctness_metric": "max abs difference of the 11 printed predictions vs the unpatched run",
        "correctness": _inference_predictions,
        "why": "inference_config.yml carries '# TODO: swap out the values below' with HEStd_128_classic commented beside HEStd_NotSet. At depth 9 with 59-bit scaling the modulus (~591 bits) fits the 128-bit bound for the ring dimension the config already fixes (32768), so enforcing the standard level should cost nothing; this run measures that.",
    },
    {
        "finding_id": "sol_lin_reg:parameters.depth_headroom_observed.v1:2183a0f6",
        "rule": DEPTH_RULE,
        "workload": "sol_lin_reg",
        "script": "sol_lin_reg.py",
        "transformation_id": "sol_lin_reg.mult_depth.12_to_7",
        "edits": [("naive_regression/config.yml", r"^(  mult_depth: )12 ", r"\g<1>7 ")],
        "correctness_metric": "abs(final encrypted MSE - final plaintext MSE), from the program's own epoch-4 log lines",
        "correctness": _lin_reg_correctness,
        "why": "CipherScope observed 6 levels consumed per epoch (each epoch re-encrypts the weights) against 12 configured. Depth 6 is refused by OpenFHE (FLEXIBLEAUTO defers the last rescale, so one more level than the observed consumption is needed); depth 7 is the smallest that runs.",
    },
    {
        "finding_id": "sol_encrypted_inference:parameters.depth_headroom_observed.v1:57bb233a",
        "rule": DEPTH_RULE,
        "workload": "sol_encrypted_inference",
        "script": "sol_encrypted_inference.py",
        "transformation_id": "sol_encrypted_inference.mult_depth.9_to_8",
        "edits": [("efficient_regression/inference_config.yml", r"^(  mult_depth: )9 ", r"\g<1>8 ")],
        "correctness_metric": "max abs difference of the 11 printed predictions vs the unpatched run",
        "correctness": _inference_predictions,
        "why": "CipherScope observed 8 of 9 configured levels consumed (one hadamard multiplication plus a degree-59 EvalLogistic). The finding's recommendation is to test depth 8.",
    },
    {
        "finding_id": "sol_log_reg:parameters.depth_headroom_observed.v1:7e0cebab",
        "rule": DEPTH_RULE,
        "workload": "sol_log_reg",
        "script": "sol_log_reg.py",
        "transformation_id": "sol_log_reg.mult_depth.33_to_31",
        "edits": [(LOG_REG_CONFIG, r"^(  levels_before_bootstrap_64bit: )16$", r"\g<1>14")],
        "scale_edits": LOG_REG_SCALE,
        "relative": True,
        "correctness_metric": f"abs difference of the final logged training loss vs the unpatched run (both arms {LOG_REG_EPOCHS} epochs)",
        "correctness": _final_loss,
        "why": "The second reviewer found depth 31 completes with matching losses and depth 30 aborts, so levels_before_bootstrap_64bit 16 -> 14 (total depth 33 -> 31) is the largest real reduction; the rule had reported 4 levels of headroom, 2 of them real.",
    },
    {
        "finding_id": "sol_log_reg:configuration.testing_only_security.v1:d27c000b",
        "rule": "configuration.testing_only_security.v1",
        "workload": "sol_log_reg",
        "script": "sol_log_reg.py",
        "transformation_id": "sol_log_reg.security_level.not_set_to_128_classic",
        "edits": LOG_REG_SECURITY,
        "scale_edits": LOG_REG_SCALE,
        "relative": True,
        "correctness_metric": f"abs difference of the final logged training loss vs the unpatched run (both arms {LOG_REG_EPOCHS} epochs)",
        "correctness": _final_loss,
        "why": LOG_REG_SECURITY_WHY,
    },
    {
        "finding_id": "sol_nag_log_reg:configuration.testing_only_security.v1:538b9f7d",
        "rule": "configuration.testing_only_security.v1",
        "workload": "sol_nag_log_reg",
        "script": "sol_nag_log_reg.py",
        "transformation_id": "sol_nag_log_reg.security_level.not_set_to_128_classic",
        "edits": LOG_REG_SECURITY,
        "scale_edits": LOG_REG_SCALE,
        "relative": True,
        "correctness_metric": f"abs difference of the final logged training loss vs the unpatched run (both arms {LOG_REG_EPOCHS} epochs)",
        "correctness": _final_loss,
        "why": LOG_REG_SECURITY_WHY,
    },
]
for _t in TRANSFORMATIONS:
    _t.setdefault("scale_edits", [])
    _t.setdefault("relative", _t["workload"] == "sol_encrypted_inference")


def _apply(edits) -> None:
    for relative, pattern, replacement in edits:
        path = CORPUS / relative
        text = path.read_text(encoding="utf-8")
        new = re.sub(pattern, replacement, text, count=1, flags=re.M)
        if new == text:
            raise RuntimeError(f"pattern {pattern!r} did not match in {path}")
        path.write_text(new, encoding="utf-8")


def _restore(edits) -> None:
    subprocess.run(["git", "-C", str(CORPUS), "checkout", "--", *sorted({e[0] for e in edits})], check=True)


def _output(run: dict) -> str:
    return run["stdout"] + "\n" + run["stderr"]


_WRAPPER = r"""
import json, os, resource, subprocess, sys, time
start = time.perf_counter_ns()
completed = subprocess.run([sys.executable, sys.argv[1]], capture_output=True, text=True)
wall_ms = (time.perf_counter_ns() - start) / 1e6
usage = resource.getrusage(resource.RUSAGE_CHILDREN)
print(json.dumps({"returncode": completed.returncode, "stdout": completed.stdout, "stderr": completed.stderr[-2000:],
                  "wall_ms": wall_ms, "cpu_ms": (usage.ru_utime + usage.ru_stime) * 1000.0,
                  "peak_rss_mb": usage.ru_maxrss / 1024.0}))
"""


def _run_untraced(script: str) -> dict:
    # A fresh wrapper process per measurement so RUSAGE_CHILDREN.ru_maxrss is
    # this run's peak, not the maximum over every earlier child.
    completed = subprocess.run([sys.executable, "-c", _WRAPPER, script], cwd=CORPUS, capture_output=True, text=True,
                               env={**os.environ, "PYTHONPATH": f"{os.environ.get('PYTHONPATH', '')}:{CORPUS}"})
    if completed.returncode != 0:
        raise RuntimeError(f"measurement wrapper failed: {completed.stderr[-1000:]}")
    return json.loads(completed.stdout.splitlines()[-1])


def _run_traced(script: str, bundle: Path, rule: str) -> str:
    if bundle.exists():
        shutil.rmtree(bundle)
    completed = subprocess.run(
        [sys.executable, "-m", "cipherscope.cli", "run", "--output", str(bundle), str(ROOT / "examples" / "profile_unmodified.py"), "--", script],
        cwd=CORPUS, capture_output=True, text=True,
        env={**os.environ, "PYTHONPATH": f"{ROOT / 'src'}:{CORPUS}"},
    )
    if completed.returncode != 0 or not (bundle / "recommendations.json").exists():
        return f"failed: {completed.stderr[-500:]}"
    rec = json.loads((bundle / "recommendations.json").read_text(encoding="utf-8"))
    return rec["analyzer_status"].get(rule, "missing")


def main(argv=None) -> int:
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--repeat", type=int, default=3)
    parser.add_argument("--bundles", type=Path, default=ROOT / "cipherscope-results" / "corpus_patches")
    parser.add_argument("--only", action="append", default=[], help="transformation_id to run (repeatable); default all")
    args = parser.parse_args(argv)
    selected = [t for t in TRANSFORMATIONS if not args.only or t["transformation_id"] in args.only]
    if args.only and len(selected) != len(set(args.only)):
        raise SystemExit(f"unknown transformation in {args.only}")

    if subprocess.run(["git", "-C", str(CORPUS), "status", "--porcelain"], capture_output=True, text=True).stdout.strip():
        raise SystemExit(f"{CORPUS} has local modifications; refusing to patch a dirty clone")
    corpus_commit = subprocess.run(["git", "-C", str(CORPUS), "rev-parse", "--short", "HEAD"], capture_output=True, text=True).stdout.strip()

    results = {}
    threads = os.environ.get("OMP_NUM_THREADS", "unset")
    for t in selected:
        print(f"=== {t['transformation_id']}", flush=True)
        record = {"transformation": t, "before": [], "after": [], "corpus_commit": corpus_commit, "threads": threads}
        # The saved patch is taken on the pristine clone, so it never contains the scale edit.
        _apply(t["edits"])
        record["diff"] = subprocess.run(["git", "-C", str(CORPUS), "diff"], capture_output=True, text=True).stdout
        _restore(t["edits"])
        (HERE / f"{t['transformation_id']}.diff").write_text(record["diff"], encoding="utf-8")
        _apply(t["scale_edits"])
        try:
            _measure(t, record, args)
        finally:
            _restore(t["edits"] + t["scale_edits"])
        results[t["finding_id"]] = record
    _fold(results)
    return 0


def _measure(t: dict, record: dict, args) -> None:
    record["before_status"] = _run_traced(t["script"], args.bundles / f"{t['transformation_id']}_before", t["rule"])
    print(f"  traced before: {t['rule']} -> {record['before_status']}", flush=True)
    for i in range(args.repeat):
        run = _run_untraced(t["script"])
        if run["returncode"] != 0:
            raise RuntimeError(f"unpatched {t['script']} failed:\n{run['stderr']}")
        record["before"].append(run)
        print(f"  before #{i}: wall {run['wall_ms']:.0f} ms, rss {run['peak_rss_mb']:.0f} MB", flush=True)

    _apply(t["edits"])
    first = _run_untraced(t["script"])
    if first["returncode"] != 0:
        record["after_error"] = first["stderr"].strip().splitlines()[-1] if first["stderr"].strip() else "non-zero exit"
        print(f"  after: program refused to run -> {record['after_error']}", flush=True)
    else:
        record["after"].append(first)
        print(f"  after #0: wall {first['wall_ms']:.0f} ms, rss {first['peak_rss_mb']:.0f} MB", flush=True)
        for i in range(1, args.repeat):
            run = _run_untraced(t["script"])
            if run["returncode"] != 0:
                raise RuntimeError(f"patched {t['script']} failed on repetition {i}:\n{run['stderr']}")
            record["after"].append(run)
            print(f"  after #{i}: wall {run['wall_ms']:.0f} ms, rss {run['peak_rss_mb']:.0f} MB", flush=True)
        record["after_status"] = _run_traced(t["script"], args.bundles / f"{t['transformation_id']}_after", t["rule"])
        print(f"  traced after: {t['rule']} -> {record['after_status']}", flush=True)


def _fold(results: dict) -> None:
    """Fold the outcome into findings.csv (locked: several runners may finish together)."""
    with FINDINGS.open(encoding="utf-8") as lock:
        fcntl.flock(lock, fcntl.LOCK_EX)
        _fold_locked(results)


def _fold_locked(results: dict) -> None:
    with FINDINGS.open(newline="", encoding="utf-8") as handle:
        reader = csv.DictReader(handle)
        fieldnames, rows = reader.fieldnames, list(reader)
    for row in rows:
        record = results.get(row["finding_id"])
        if record is None:
            continue
        t = record["transformation"]
        before = record["before"]
        med = lambda runs, key: statistics.median(r[key] for r in runs)  # noqa: E731
        row["transformation_id"] = t["transformation_id"]
        row["before_wall_ms"] = f"{med(before, 'wall_ms'):.1f}"
        row["before_rss_mb"] = f"{med(before, 'peak_rss_mb'):.1f}"
        corr = t["correctness"]
        if t["relative"]:
            reference = corr(_output(before[0]))
            row["correctness_before"] = f"{max(abs(a - b) for a, b in zip(corr(_output(before[-1])), reference)):.3e}" if len(before) > 1 else "0"
            correctness_after = (
                f"{max(abs(a - b) for a, b in zip(corr(_output(record['after'][0])), reference)):.3e}" if record["after"] else ""
            )
        else:
            row["correctness_before"] = f"{corr(before[0]['stdout']):.3e}"
            correctness_after = f"{corr(record['after'][0]['stdout']):.3e}" if record["after"] else ""
        row["correctness_after"] = correctness_after
        note = f"D-03 ({record['corpus_commit']}): {t['why']} Patch: transformations/{t['transformation_id']}.diff. Correctness metric: {t['correctness_metric']}."
        if t["scale_edits"]:
            note += f" Both arms run at {LOG_REG_EPOCHS} of the program's 100 epochs (scale edit, not part of the patch); OMP_NUM_THREADS={record['threads']}."
        if record["after"]:
            after = record["after"]
            row["after_wall_ms"] = f"{med(after, 'wall_ms'):.1f}"
            row["after_rss_mb"] = f"{med(after, 'peak_rss_mb'):.1f}"
            speedup = med(before, "wall_ms") / med(after, "wall_ms")
            row["speedup"] = f"{speedup:.3f}"
            if t["rule"].startswith("configuration."):
                # Same answer = the after deviation stays within 10x the unpatched runs' own spread.
                noise = max(float(row["correctness_before"] or 0), 1e-9)
                changed = bool(correctness_after) and float(correctness_after) > 10 * noise
                if record.get("after_status") != "clean":
                    row["transformation_status"] = "fix_not_confirmed"
                else:
                    row["transformation_status"] = "fix_changes_result" if changed else "validated_fix"
            else:
                row["transformation_status"] = "validated_improvement" if speedup > 1.02 else ("regression" if speedup < 0.98 else "no_improvement")
            note += f" Medians of {len(before)} before / {len(after)} after untraced runs. Traced: {t['rule']} {record['before_status']} before, {record.get('after_status')} after."
        else:
            row["after_wall_ms"] = row["after_rss_mb"] = row["speedup"] = ""
            row["transformation_status"] = "refused"
            note += f" RESULT: OpenFHE refuses the patched program ({record['after_error']}); the one unconsumed level is an internal transient of the library that the observed ciphertext levels do not show. Verdict revised to FALSE-POSITIVE: the rule claimed headroom that does not exist (see the second reviewer's finding on deferred rescales; the analyzer now reserves that level)."
            row["adjudication"] = "FALSE-POSITIVE" if t["rule"] == DEPTH_RULE else row["adjudication"]
            row["evidence_summary"] = row["evidence_summary"].split(" D-03 UPDATE:")[0] + " D-03 UPDATE: the recommended smaller depth was tested and OpenFHE's SetLevel() check rejects it (see notes); the reported headroom was not real."
        # Idempotent: a rerun replaces the previous D-03 record instead of appending to it.
        previous = row["notes"].split(" D-03 (")[0] if " D-03 (" in row["notes"] else ("" if row["notes"].startswith("D-03 (") else row["notes"])
        row["notes"] = (previous + " " if previous else "") + note
    with FINDINGS.open("w", newline="", encoding="utf-8") as handle:
        writer = csv.DictWriter(handle, fieldnames=fieldnames)
        writer.writeheader()
        writer.writerows(rows)
    print(f"updated {len(results)} rows in {FINDINGS}")


if __name__ == "__main__":
    raise SystemExit(main())
