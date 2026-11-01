#!/usr/bin/env python3
"""F-02: misconfiguration / silent-correctness hunt over every real program CipherScope has traced.

The subjects are real code nobody wrote for this evaluation: the four
python-log-reg-examples workloads (Python frontend, strict COMPLETE runs) and
the six unmodified upstream OpenFHE C++ examples (C++ frontend). Each archived
trace is re-analyzed with the current analyzers, so the record reflects
today's rules rather than whatever version produced the bundle, and every
security/correctness rule's status is written out -- clean and
not-applicable included, so a reader can see what the hunt could and could
not look at.

Positives are joined to an adjudication: external-corpus findings take the
verdict already in evaluation/adjudication/findings.csv; upstream C++
examples are adjudicated here from their own source comments (ADJUDICATIONS).
A positive with no adjudication is written as `pending`, never assumed.

    PYTHONPATH=src python3 evaluation/bug_hunt/run_bug_hunt.py \
        --bundle sol_lin_reg=$SCRATCH/cipherscope-ls6/external-v2/sol_lin_reg ... \
        --output evaluation/raw/bug_hunt.csv

With no --bundle arguments the LS6 archive layout under $SCRATCH is used.
"""

from __future__ import annotations

import argparse
import csv
import json
import os
import sys
from pathlib import Path

HERE = Path(__file__).resolve().parent
ROOT = HERE.parent.parent
sys.path.insert(0, str(ROOT / "src"))

from cipherscope.coverage import classify_run  # noqa: E402
from cipherscope.pipeline import build_analysis_bundle  # noqa: E402
from cipherscope.tables import SECURITY_RULES  # noqa: E402

COLUMNS = (
    "subject",
    "frontend",
    "program_source",
    "coverage_class",
    "rule_id",
    "status",
    "finding_summary",
    "adjudication",
    "adjudication_evidence",
)

EXTERNAL = ("sol_encrypted_inference", "sol_lin_reg", "sol_log_reg", "sol_nag_log_reg")
UPSTREAM = (
    "advanced-real-numbers",
    "function-evaluation",
    "polynomial-evaluation",
    "simple-ckks-bootstrapping",
    "simple-real-numbers",
    "simple-real-numbers-serial",
)

# Upstream C++ positives, adjudicated against the example's own source.
ADJUDICATIONS = {
    ("function-evaluation", "configuration.testing_only_security.v1"): (
        "TP-NONACTIONABLE",
        "function-evaluation.cpp:57-62 sets HEStd_NotSet with SetRingDim(1 << 10) under the comment 'We set a smaller "
        "ring dimension to improve performance for this example. In production environments, the security level should "
        "be set to HEStd_128_classic ...'. The run genuinely has no enforced security level; the example documents it "
        "as a demo shortcut, so no change is due in an upstream example.",
    ),
    ("simple-ckks-bootstrapping", "configuration.testing_only_security.v1"): (
        "TP-NONACTIONABLE",
        "simple-ckks-bootstrapping.cpp:74-83 sets HEStd_NotSet with SetRingDim(1 << 12) under the comment 'we use the "
        "\"NotSet\" option, so the example can run more quickly ... should be used only in non-production environments'. "
        "Correct finding, documented demo shortcut.",
    ),
}


# Why a rule cannot look at an unmodified program (the analyzers' own preconditions).
NOT_APPLICABLE_BECAUSE = {
    "configuration.testing_only_security.v1": "the program declared no security level through its parameters",
    "precision.tolerance_violated.v1": "needs a precision checkpoint with a declared tolerance; unmodified programs carry none",
    "precision.checkpoint_drop.v1": "needs two or more precision checkpoints; unmodified programs carry none",
}


def _default_bundles() -> dict[str, tuple[str, Path]]:
    archive = Path(os.environ.get("RESULTS_ROOT", Path(os.environ.get("SCRATCH", "/nonexistent")) / "cipherscope-ls6"))
    bundles = {name: ("python-log-reg-examples@5a34dc68", archive / "external-v2" / name) for name in EXTERNAL}
    bundles.update({name: ("openfhe-development v1.5.1 src/pke/examples", archive / "cpp-upstream-v3" / name) for name in UPSTREAM})
    return bundles


def _findings_verdicts() -> dict[tuple[str, str], tuple[str, str]]:
    path = ROOT / "evaluation" / "adjudication" / "findings.csv"
    with path.open(newline="", encoding="utf-8") as handle:
        return {(row["workload_id"], row["rule_id"]): (row["adjudication"] or "pending", row["evidence_summary"]) for row in csv.DictReader(handle)}


def hunt(bundles: dict[str, tuple[str, Path]]) -> list[dict[str, str]]:
    verdicts = _findings_verdicts()
    rows: list[dict[str, str]] = []
    for subject, (source, bundle) in sorted(bundles.items()):
        trace = json.loads((bundle / "trace.json").read_text(encoding="utf-8"))
        frontend = str(trace.get("run", {}).get("producer", {}).get("frontend") or "unknown")
        coverage_class = classify_run(trace).coverage_class
        recommendations = build_analysis_bundle(trace)["recommendations"]
        status_by_rule = recommendations["analyzer_status"]
        for rule in SECURITY_RULES:
            status = status_by_rule.get(rule, "missing")
            summary = ""
            if status == "positive":
                summary = " | ".join(str(f.get("recommendation") or "") for f in recommendations["findings"] if f.get("rule_id") == rule)
            elif status == "not_applicable":
                summary = NOT_APPLICABLE_BECAUSE.get(rule, "")
            adjudication, evidence = "", ""
            if status == "positive":
                adjudication, evidence = verdicts.get((subject, rule)) or ADJUDICATIONS.get((subject, rule)) or ("pending", "")
            rows.append(
                {
                    "subject": subject,
                    "frontend": frontend,
                    "program_source": source,
                    "coverage_class": coverage_class,
                    "rule_id": rule,
                    "status": status,
                    "finding_summary": summary,
                    "adjudication": adjudication,
                    "adjudication_evidence": evidence,
                }
            )
    return rows


def main(argv=None) -> int:
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--bundle", action="append", default=[], help="subject=path (repeatable); default: the LS6 archive")
    parser.add_argument("--output", type=Path, default=ROOT / "evaluation" / "raw" / "bug_hunt.csv")
    args = parser.parse_args(argv)
    defaults = _default_bundles()
    bundles = defaults
    if args.bundle:
        bundles = {}
        for item in args.bundle:
            name, _, path = item.partition("=")
            bundles[name] = (defaults.get(name, ("unknown", Path()))[0], Path(path))
    rows = hunt(bundles)
    args.output.parent.mkdir(parents=True, exist_ok=True)
    with args.output.open("w", newline="", encoding="utf-8") as handle:
        writer = csv.DictWriter(handle, fieldnames=COLUMNS, lineterminator="\n")
        writer.writeheader()
        writer.writerows(rows)
    positives = [r for r in rows if r["status"] == "positive"]
    print(f"{len(rows)} rule results over {len(bundles)} programs; {len(positives)} positive: "
          + ", ".join(f"{r['subject']}:{r['rule_id']}={r['adjudication']}" for r in positives))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
