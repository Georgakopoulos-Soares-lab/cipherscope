#!/usr/bin/env python3
"""Compare real-binding evidence across lanes and report every disagreement.

A lane is a `feasibility.json` plus, optionally, the directory that
`evaluation/parity/run_lane.sh` wrote (seeded results, ablation rows, example
bundles, scaling rows). Artifacts that must not depend on the platform are
compared exactly; hardware-dependent measurements are placed side by side and
never asserted. The exit status is nonzero when any disagreement is outside
the allowed list, so three green gates on three platforms become one checked
claim instead of three anecdotes.

    python3 evaluation/parity/compare_lanes.py \\
        --lane developer artifact/feasibility/developer/feasibility.json \\
            --seeded developer=evaluation/raw/seeded/case_results.json \\
            --ablation developer=evaluation/raw/semantic_ablation.csv \\
        --lane primary-source-py311 artifact/feasibility/primary-source-py311/feasibility.json \\
            "$RESULTS_ROOT/primary-source-py311" \\
        --lane ls6-native-py311 artifact/feasibility/ls6-native-py311/feasibility.json \\
            "$RESULTS_ROOT/ls6-native-py311" \\
        --output evaluation/parity/parity_report.md
"""

from __future__ import annotations

import argparse
import csv
import json
import sys
from collections.abc import Iterable, Mapping, Sequence
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

# The one check that legitimately differs: it reads /proc/self/status.
ALLOWED_CHECK_DIFFERENCES = {"RES-02": {"Darwin": "skip", "Linux": "pass"}}
# Observed numeric errors and the tolerance each is judged against. Keys are
# (check id, observed field); a field naming its own tolerance uses that.
NUMERIC_FIELDS = {
    ("NUM-01", "max_direct_vs_traced_error"): "tolerance",
    ("NUM-01", "max_expected_error"): "tolerance",
    ("NUM-02", "max_direct_vs_traced_error"): "tolerance",
    ("NUM-02", "max_expected_error"): "tolerance",
    ("BOOT-02", "direct_vs_traced_max_error"): "tolerance",
    ("BOOT-02", "source_max_error"): "tolerance",
    ("ROT-01", "positive_direct_error"): "basic_max_abs_tolerance",
    ("ROT-01", "negative_direct_error"): "basic_max_abs_tolerance",
    ("ROT-01", "positive_expected_error"): "basic_max_abs_tolerance",
    ("ROT-01", "negative_expected_error"): "basic_max_abs_tolerance",
    ("MUT-01", "max_error"): "basic_max_abs_tolerance",
    ("PROXY-05", "max_abs_error"): "basic_max_abs_tolerance",
}
# Diagnoses examples/README.md promises; checked on every lane that ran them.
EXAMPLE_EXPECTATIONS = {
    "repeated_rotations": {"rotation.hoist_same_input.v1": "positive", "keys.unused_in_observed_run.v1": "positive"},
    "bootstrap_then_idle": {"bootstrap.restored_levels_underused.v1": {"clean", "not_applicable"}},
    "vector_variance": {"parameters.depth_headroom_observed.v1": "positive"},
    "squared_distance": {"parameters.depth_headroom_observed.v1": "positive"},
    "public_constant_mult": {"provenance.public_value_ciphertext_mult.v1": "positive"},
    "repeated_public_constant": {"encoding.repeated_public_constant.v1": "positive"},
    "serial_reduction_region": {"multiplication.serial_reduction_review.v1": "positive"},
    "annotate_packing": {"packing.low_utilization_annotated.v1": "positive"},
    "precision_checkpoints": {"precision.checkpoint_drop.v1": "positive"},
}


@dataclass
class Lane:
    name: str
    feasibility: dict[str, Any]
    seeded: dict[str, Any] | None = None
    ablation: list[dict[str, str]] | None = None
    examples: dict[str, dict[str, Any]] = field(default_factory=dict)
    coverage: list[dict[str, str]] | None = None
    scaling: list[dict[str, str]] | None = None

    @property
    def platform(self) -> str:
        return str(self.feasibility["environment"]["platform"])

    @property
    def hashes(self) -> dict[str, str]:
        return dict(self.feasibility["environment"]["native_module_hashes"])


@dataclass
class Report:
    sections: list[tuple[str, list[str]]] = field(default_factory=list)
    disagreements: list[str] = field(default_factory=list)
    allowed: list[str] = field(default_factory=list)

    def section(self, title: str, lines: Iterable[str]) -> None:
        self.sections.append((title, list(lines)))

    def disagree(self, message: str) -> None:
        self.disagreements.append(message)


def _read_json(path: Path) -> Any:
    return json.loads(path.read_text(encoding="utf-8"))


def _read_csv(path: Path) -> list[dict[str, str]]:
    with path.open(encoding="utf-8", newline="") as stream:
        return list(csv.DictReader(stream))


def load_lane(name: str, feasibility: Path, results: Path | None) -> Lane:
    lane = Lane(name=name, feasibility=_read_json(feasibility))
    if results is None:
        return lane
    seeded = results / "seeded" / "case_results.json"
    if seeded.is_file():
        lane.seeded = _read_json(seeded)
    ablation = results / "semantic_ablation.csv"
    if ablation.is_file():
        lane.ablation = _read_csv(ablation)
    examples = results / "examples"
    if examples.is_dir():
        for bundle in sorted(p for p in examples.iterdir() if p.is_dir()):
            recommendations = bundle / "recommendations.json"
            if recommendations.is_file():
                lane.examples[bundle.name] = _read_json(recommendations)
        coverage = examples / "coverage_report.csv"
        if coverage.is_file():
            lane.coverage = _read_csv(coverage)
    scaling = results / "scaling.csv"
    if scaling.is_file():
        lane.scaling = _read_csv(scaling)
    return lane


def _table(header: Sequence[str], rows: Iterable[Sequence[Any]]) -> list[str]:
    lines = ["| " + " | ".join(header) + " |", "|" + "---|" * len(header)]
    for row in rows:
        lines.append("| " + " | ".join("" if cell is None else str(cell) for cell in row) + " |")
    return lines


def compare_pins(lanes: Sequence[Lane], report: Report) -> None:
    pins = {lane.name: lane.feasibility["pins"] for lane in lanes}
    reference = pins[lanes[0].name]
    rows = []
    for key in sorted(reference):
        values = [pins[lane.name].get(key) for lane in lanes]
        rows.append([key, *values])
        if len(set(map(str, values))) != 1:
            report.disagree(f"pins.{key} differs: " + ", ".join(f"{lane.name}={pins[lane.name].get(key)}" for lane in lanes))
    report.section("Pins", _table(["pin", *(lane.name for lane in lanes)], rows))


def compare_checks(lanes: Sequence[Lane], report: Report) -> None:
    statuses = {lane.name: {check["id"]: check["status"] for check in lane.feasibility["checks"]} for lane in lanes}
    ids = sorted({check_id for lane_status in statuses.values() for check_id in lane_status})
    rows = []
    for check_id in ids:
        values = [statuses[lane.name].get(check_id, "absent") for lane in lanes]
        note = ""
        if len(set(values)) != 1:
            allowed = ALLOWED_CHECK_DIFFERENCES.get(check_id)
            if allowed and all(statuses[lane.name].get(check_id) == allowed.get(lane.platform) for lane in lanes):
                note = "allowed (platform-specific check)"
                report.allowed.append(f"{check_id}: " + ", ".join(f"{lane.name}={statuses[lane.name].get(check_id)}" for lane in lanes))
            else:
                note = "DISAGREES"
                report.disagree(f"check {check_id}: " + ", ".join(f"{lane.name}={statuses[lane.name].get(check_id, 'absent')}" for lane in lanes))
        rows.append([check_id, *values, note])
    report.section("Gate check status per lane", _table(["check", *(lane.name for lane in lanes), "note"], rows))


def compare_numerics(lanes: Sequence[Lane], golden: Mapping[str, Any], report: Report) -> None:
    observed = {lane.name: {check["id"]: check.get("observed") or {} for check in lane.feasibility["checks"]} for lane in lanes}
    rows = []
    for (check_id, field_name), tolerance_key in sorted(NUMERIC_FIELDS.items()):
        values = []
        for lane in lanes:
            block = observed[lane.name].get(check_id, {})
            value = block.get(field_name)
            tolerance = block.get(tolerance_key) if tolerance_key in block else golden.get(tolerance_key)
            values.append(value)
            if value is None:
                continue
            if tolerance is not None and abs(float(value)) > float(tolerance):
                report.disagree(f"{check_id}.{field_name} on {lane.name} = {value} exceeds tolerance {tolerance}")
        rows.append([f"{check_id}.{field_name}", *(f"{v:.3e}" if isinstance(v, (int, float)) else v for v in values), tolerance_key])
    report.section(
        "Observed numerical error per lane (each must be within its tolerance; the values themselves are build noise)",
        _table(["observation", *(lane.name for lane in lanes), "tolerance"], rows),
    )


def _seeded_signature(document: Mapping[str, Any]) -> dict[str, tuple[Any, ...]]:
    signature: dict[str, tuple[Any, ...]] = {}
    for case in document["cases"]:
        for rule in case["rules"]:
            signature[f"{case['case_id']} / {rule['rule_id']}"] = (rule["expected"], rule["observed"], rule["outcome"])
        signature[f"{case['case_id']} / coverage"] = (case["coverage_class"], case["exit_code"], tuple(sorted(case.get("unexpected_positives") or [])))
    return signature


def compare_seeded(lanes: Sequence[Lane], report: Report, *, allow_missing_cases: bool = False) -> None:
    present = [lane for lane in lanes if lane.seeded is not None]
    if len(present) < 2:
        report.section("Seeded benchmark", ["fewer than two lanes provided case_results.json; nothing to compare"])
        return
    signatures = {lane.name: _seeded_signature(lane.seeded) for lane in present}
    keys = sorted({key for signature in signatures.values() for key in signature})
    differing = []
    for key in keys:
        values = [signatures[lane.name].get(key) for lane in present]
        missing_from = [lane.name for lane in present if key not in signatures[lane.name]]
        if missing_from and allow_missing_cases and len(missing_from) < len(present):
            # A lane whose archived seeded result predates a corpus extension
            # did not run this case; that is listed, never silently ignored.
            report.allowed.append(f"seeded {key}: not run on {', '.join(missing_from)} (result predates the case)")
            continue
        if len({json.dumps(v, sort_keys=True) for v in values}) != 1:
            differing.append([key, *values])
            report.disagree(f"seeded {key}: " + ", ".join(f"{lane.name}={signatures[lane.name].get(key)}" for lane in present))
    lines = [
        f"{len(keys)} (case, rule) expectations compared across {', '.join(lane.name for lane in present)}; "
        + ", ".join(f"{lane.name}: all_matched={lane.seeded['all_matched']}, cases={len(lane.seeded['cases'])}" for lane in present),
    ]
    lines += ["", "No per-case disagreement." if not differing else "Disagreements:"] + (_table(["expectation", *(lane.name for lane in present)], differing) if differing else [])
    report.section("Seeded benchmark (must be identical on every platform)", lines)


def compare_ablation(lanes: Sequence[Lane], report: Report) -> None:
    present = [lane for lane in lanes if lane.ablation is not None]
    if len(present) < 2:
        report.section("Semantic ablation", ["fewer than two lanes provided semantic_ablation.csv; nothing to compare"])
        return
    columns = ("bundle", "name", "mode", "rule_id", "analysis_status", "findings", "signature")
    rowsets = {lane.name: {tuple(row.get(c, "") for c in columns) for row in lane.ablation} for lane in present}
    reference = rowsets[present[0].name]
    lines = [", ".join(f"{lane.name}: {len(rowsets[lane.name])} rows" for lane in present)]
    for lane in present[1:]:
        missing = sorted(reference - rowsets[lane.name])
        extra = sorted(rowsets[lane.name] - reference)
        if missing or extra:
            report.disagree(f"ablation rows differ between {present[0].name} and {lane.name}: {len(missing)} missing, {len(extra)} extra")
            lines += [f"", f"Rows in {present[0].name} but not {lane.name} ({len(missing)}):"] + [f"- {' | '.join(r)}" for r in missing[:20]]
            lines += [f"", f"Rows in {lane.name} but not {present[0].name} ({len(extra)}):"] + [f"- {' | '.join(r)}" for r in extra[:20]]
    if len(lines) == 1:
        lines.append("Row sets are identical.")
    report.section("Semantic ablation (must be identical on every platform)", lines)


def _example_signature(recommendations: Mapping[str, Any]) -> dict[str, Any]:
    return {
        "analysis_status": recommendations["analysis_status"],
        "analyzer_status": dict(sorted(recommendations["analyzer_status"].items())),
        "findings": sorted((f["rule_id"], f.get("severity")) for f in recommendations["findings"]),
    }


def compare_examples(lanes: Sequence[Lane], report: Report) -> None:
    present = [lane for lane in lanes if lane.examples]
    if not present:
        report.section("Example gallery", ["no lane provided example bundles"])
        return
    names = sorted({name for lane in present for name in lane.examples})
    rows = []
    for name in names:
        signatures = {lane.name: _example_signature(lane.examples[name]) for lane in present if name in lane.examples}
        identical = len({json.dumps(s, sort_keys=True) for s in signatures.values()}) == 1
        if not identical:
            report.disagree(f"example {name}: diagnoses differ between " + ", ".join(signatures))
        if len(signatures) < len(present):
            report.disagree(f"example {name}: missing on " + ", ".join(lane.name for lane in present if name not in lane.examples))
        first = next(iter(signatures.values()))
        positives = [rule for rule, status in first["analyzer_status"].items() if status == "positive"]
        expectation_note = ""
        for rule, expected in EXAMPLE_EXPECTATIONS.get(name, {}).items():
            for lane_name, signature in signatures.items():
                status = signature["analyzer_status"].get(rule)
                ok = status in expected if isinstance(expected, set) else status == expected
                if not ok:
                    report.disagree(f"example {name} on {lane_name}: {rule} is {status}, README expects {expected}")
                    expectation_note = "README expectation violated"
        rows.append([name, len(signatures), "identical" if identical else "DIFFER", ", ".join(positives) or "—", expectation_note])
    lines = _table(["example", "lanes", "diagnoses", "positive rules", "note"], rows)
    for lane in present:
        if lane.coverage is not None:
            classes = {}
            for row in lane.coverage:
                classes[row["coverage_class"]] = classes.get(row["coverage_class"], 0) + 1
            lines.append(f"\n{lane.name} coverage classes: {classes}")
            for row in lane.coverage:
                if row["coverage_class"] != "COMPLETE":
                    report.disagree(f"example {row['name']} on {lane.name} is {row['coverage_class']}: {row.get('reasons')}")
    report.section("Example gallery (diagnoses must be identical; README expectations must hold)", lines)


def compare_scaling(lanes: Sequence[Lane], archived: Path | None, report: Report) -> None:
    rows_by_source: dict[str, list[dict[str, str]]] = {lane.name: lane.scaling for lane in lanes if lane.scaling}
    if archived is not None and archived.is_file():
        rows_by_source[f"archived {archived}"] = _read_csv(archived)
    if not rows_by_source:
        report.section("Scaling", ["no scaling rows available"])
        return
    table = []
    for source, rows in rows_by_source.items():
        groups: dict[tuple[str, int, str], list[dict[str, str]]] = {}
        for row in rows:
            groups.setdefault((row["machine"], int(row["size"]), row["arm"]), []).append(row)
        for (machine, size, arm), records in sorted(groups.items()):
            baseline = groups.get((machine, size, "baseline"), [])
            wall = sum(float(r["run_wall_ms"]) for r in records) / len(records)
            base_wall = sum(float(r["run_wall_ms"]) for r in baseline) / len(baseline) if baseline else None
            events = [int(r["events"]) for r in records if r.get("events")]
            trace_bytes = [int(r["trace_bytes"]) for r in records if r.get("trace_bytes")]
            per_event = (sum(trace_bytes) / sum(events)) if events and trace_bytes and sum(events) else None
            peak = max(float(r["peak_rss_mb"]) for r in records)
            table.append([
                source, machine, size, arm, f"{wall:.0f}",
                f"{wall / base_wall:.3f}" if base_wall and arm != "baseline" else "—",
                f"{peak:.0f}", f"{per_event:.0f}" if per_event else "—",
            ])
    report.section(
        "Scaling, side by side (absolute times and memory are hardware-dependent and are not asserted; ratios and bytes per event are the comparable columns)",
        _table(["source", "machine", "events", "arm", "wall ms", "wall / baseline", "peak RSS MB", "trace bytes / event"], table),
    )


def build_report(lanes: Sequence[Lane], golden: Mapping[str, Any], archived_scaling: Path | None, *, allow_missing_cases: bool = False) -> Report:
    report = Report()
    header = _table(
        ["lane", "status", "pass / skip / total", "platform", "machine", "python", "native module sha256"],
        [
            [
                lane.name, lane.feasibility["status"],
                f"{lane.feasibility['summary']['pass']} / {lane.feasibility['summary']['skip']} / {lane.feasibility['summary']['total']}",
                f"{lane.platform} {lane.feasibility['environment']['os_release'].get('ID', '')} {lane.feasibility['environment']['os_release'].get('VERSION_ID', '')}".strip(),
                lane.feasibility["environment"]["machine"], lane.feasibility["environment"]["python"],
                ", ".join(f"`{h[:12]}…`" for h in lane.hashes.values()) or "—",
            ]
            for lane in lanes
        ],
    )
    report.section("Lanes", header)
    compare_pins(lanes, report)
    compare_checks(lanes, report)
    compare_numerics(lanes, golden, report)
    compare_seeded(lanes, report, allow_missing_cases=allow_missing_cases)
    compare_ablation(lanes, report)
    compare_examples(lanes, report)
    compare_scaling(lanes, archived_scaling, report)
    return report


def render(report: Report, lanes: Sequence[Lane]) -> str:
    verdict = "**No disagreement outside the allowed list.**" if not report.disagreements else f"**{len(report.disagreements)} disagreement(s).**"
    lines = [
        "# Lane parity report",
        "",
        "Generated by `evaluation/parity/compare_lanes.py`; do not edit. Lanes: " + ", ".join(f"`{lane.name}`" for lane in lanes) + ".",
        "",
        verdict,
        "",
    ]
    if report.disagreements:
        lines += ["## Disagreements", ""] + [f"- {d}" for d in report.disagreements] + [""]
    if report.allowed:
        lines += ["## Allowed differences", ""] + [f"- {a}" for a in report.allowed] + [""]
    for title, body in report.sections:
        lines += [f"## {title}", ""] + body + [""]
    return "\n".join(lines).rstrip() + "\n"


def _parse_overrides(values: Sequence[str] | None) -> dict[str, Path]:
    result: dict[str, Path] = {}
    for item in values or ():
        name, _, path = item.partition("=")
        if not path:
            raise SystemExit(f"expected NAME=PATH, got {item!r}")
        result[name] = Path(path)
    return result


def main(argv: Sequence[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--lane", nargs="+", action="append", metavar=("NAME FEASIBILITY", "RESULTS_ROOT"), required=True,
                        help="lane name, its feasibility.json, and optionally the run_lane.sh output root")
    parser.add_argument("--seeded", action="append", metavar="NAME=PATH", help="case_results.json for a lane without a results root")
    parser.add_argument("--ablation", action="append", metavar="NAME=PATH", help="semantic_ablation.csv for a lane without a results root")
    parser.add_argument("--golden", type=Path, default=Path("tests/integration_openfhe/golden_core.json"))
    parser.add_argument("--archived-scaling", type=Path, default=Path("evaluation/raw/scaling.csv"))
    parser.add_argument("--allow-missing-cases", action="store_true",
                        help="a seeded case absent from some lanes (their result predates it) is listed as allowed, not a disagreement")
    parser.add_argument("--output", type=Path, help="write the Markdown report here (default: stdout)")
    args = parser.parse_args(argv)

    seeded_overrides = _parse_overrides(args.seeded)
    ablation_overrides = _parse_overrides(args.ablation)
    lanes: list[Lane] = []
    for spec in args.lane:
        if len(spec) not in (2, 3):
            raise SystemExit(f"--lane takes NAME FEASIBILITY [RESULTS_ROOT], got {spec}")
        name, feasibility = spec[0], Path(spec[1])
        results = Path(spec[2]) if len(spec) == 3 else None
        lane = load_lane(name, feasibility, results)
        if name in seeded_overrides:
            lane.seeded = _read_json(seeded_overrides[name])
        if name in ablation_overrides:
            lane.ablation = _read_csv(ablation_overrides[name])
        lanes.append(lane)

    golden = _read_json(args.golden) if args.golden.is_file() else {}
    report = build_report(lanes, golden, args.archived_scaling, allow_missing_cases=args.allow_missing_cases)
    text = render(report, lanes)
    if args.output:
        args.output.parent.mkdir(parents=True, exist_ok=True)
        args.output.write_text(text, encoding="utf-8")
        print(f"wrote {args.output}: {len(report.disagreements)} disagreement(s), {len(report.allowed)} allowed difference(s)")
    else:
        sys.stdout.write(text)
    return 1 if report.disagreements else 0


if __name__ == "__main__":
    sys.exit(main())
