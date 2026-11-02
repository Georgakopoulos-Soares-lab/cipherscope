#!/usr/bin/env python3
"""Regenerate every measurement figure in the manuscript from the generated tables.

Reads only evaluation/tables/*.csv (which themselves regenerate byte-identically
from checksummed raw records), writes PDFs next to this script. No number is
typed by hand here; if a figure disagrees with a table, the table wins.

    python3 paper/figures/make_figures.py
"""

from __future__ import annotations

import csv
from pathlib import Path

import matplotlib

matplotlib.use("Agg")
import matplotlib.pyplot as plt

HERE = Path(__file__).resolve().parent
TABLES = HERE.parents[1] / "evaluation" / "tables"

plt.rcParams.update(
    {
        "font.size": 8,
        "axes.titlesize": 8,
        "axes.labelsize": 8,
        "legend.fontsize": 7,
        "xtick.labelsize": 7,
        "ytick.labelsize": 7,
        "figure.dpi": 150,
        "pdf.fonttype": 42,
    }
)


def rows(name: str) -> list[dict[str, str]]:
    with (TABLES / name).open() as fh:
        return list(csv.DictReader(fh))


def overhead_figure() -> None:
    """Fixed absolute cost, falling relative cost: both series per workload."""

    data = [r for r in rows("overhead.csv") if r["workload_id"] != "ALL"]
    data.sort(key=lambda r: float(r["wall_baseline_median_ms"]))
    # Wrap on word boundaries so neighbouring tick labels cannot collide.
    names = [r["workload_id"].replace("sol_", "").replace("_", " ") for r in data]
    baseline_s = [float(r["wall_baseline_median_ms"]) / 1000 for r in data]
    absolute_s = [float(r["wall_overhead_abs_ms"]) / 1000 for r in data]
    relative_pct = [100 * float(r["wall_overhead_ratio"]) for r in data]

    fig, ax_abs = plt.subplots(figsize=(7.0, 2.7))
    x = range(len(data))
    ax_abs.bar(x, absolute_s, width=0.6, color="#4878a8", label="absolute overhead (s)")
    ax_abs.set_ylabel("absolute overhead (s)")
    ax_abs.set_ylim(0, max(absolute_s) * 1.12)
    ax_abs.set_xticks(list(x))
    # Rotated: horizontal labels of this length collide at the right-hand end.
    ax_abs.set_xticklabels(names, fontsize=6, rotation=30, ha="right",
                           rotation_mode="anchor")
    ax_abs.tick_params(axis="x", length=0, pad=1)

    ax_rel = ax_abs.twinx()
    ax_rel.plot(x, relative_pct, "o-", color="#b05030", markersize=3.5,
                linewidth=1.2, label="relative overhead (%)")
    ax_rel.set_ylabel("relative overhead (%)")
    ax_rel.set_yscale("log")

    for i, b in enumerate(baseline_s):
        ax_abs.annotate(
            f"{b:.1f}s" if b < 10 else f"{b:.0f}s",
            (i, absolute_s[i]), textcoords="offset points", xytext=(0, 3),
            ha="center", fontsize=5.5, color="#555555",
        )

    handles = ax_abs.get_legend_handles_labels()[0] + ax_rel.get_legend_handles_labels()[0]
    labels = ax_abs.get_legend_handles_labels()[1] + ax_rel.get_legend_handles_labels()[1]
    # Legend above the axes: inside, it sits under the relative-overhead line.
    # No title here -- the caption already states the annotation and repetitions.
    ax_abs.legend(handles, labels, loc="lower center", bbox_to_anchor=(0.5, 1.01),
                  ncol=2, frameon=False, fontsize=6.5, columnspacing=1.5)
    for spine in ("top",):
        ax_abs.spines[spine].set_visible(False)
        ax_rel.spines[spine].set_visible(False)
    fig.tight_layout()
    fig.savefig(HERE / "overhead.pdf", bbox_inches="tight")
    plt.close(fig)


def ablation_figure() -> None:
    """Which trace view each rule needs: detected/positives per view, per rule."""

    data = rows("semantic_ablation.csv")
    order = {"TIMING_ONLY": 0, "STATE": 1, "FULL": 2}
    data.sort(key=lambda r: (order[r["minimum_mode"]], r["rule_id"]))
    names = [r["rule_id"].rsplit(".v1", 1)[0] for r in data]
    views = ["detected_timing_only", "detected_state", "detected_full"]
    # Short headers: the caption says these are progressively richer views.
    view_labels = ["timing\nonly", "+ state", "+ identity\n(full)"]

    fig, ax = plt.subplots(figsize=(3.4, 3.1))
    matrix = [
        [float(r[v]) / float(r["full_positives"]) if float(r["full_positives"]) else 0 for v in views]
        for r in data
    ]
    ax.imshow(matrix, cmap="Blues", vmin=0, vmax=1, aspect="auto")
    ax.set_xticks(range(3))
    ax.set_xticklabels(view_labels, fontsize=6.5)
    ax.set_yticks(range(len(names)))
    ax.set_yticklabels(names, fontsize=6)
    ax.tick_params(length=0)
    for spine in ax.spines.values():
        spine.set_visible(False)
    # Cell text carries the counts, so a colorbar would be redundant.
    for i, r in enumerate(data):
        for j, v in enumerate(views):
            det, pos = int(r[v]), int(r["full_positives"])
            ax.text(
                j, i, f"{det}/{pos}",
                ha="center", va="center", fontsize=5.5,
                color="white" if matrix[i][j] > 0.6 else "#222222",
            )
    # Separate the three view columns visually.
    for j in (0.5, 1.5):
        ax.axvline(j, color="white", linewidth=1.2)
    fig.tight_layout()
    fig.savefig(HERE / "ablation.pdf", bbox_inches="tight")
    plt.close(fig)


def impact_figure() -> None:
    """Measured outcome of every attempted transformation, including the refusal."""

    from decimal import Decimal, ROUND_HALF_UP

    data = [r for r in rows("before_after.csv") if r["transformation_id"]]
    bars = []
    for r in data:
        label = (
            r["transformation_id"]
            .replace("sol_", "")
            .replace("_", " ")
            .replace("security level not set to 128 classic", "security: enable 128-bit")
            .replace("mult depth", "depth")
            .replace("rotation keys by samples to by features", "rotation keys by feature")
        )
        if r["transformation_status"] == "refused":
            bars.append((label, None, r["transformation_status"]))
        else:
            sp = float(Decimal(r["speedup"]).quantize(Decimal("0.01"), ROUND_HALF_UP))
            bars.append((label, sp, r["transformation_status"]))
    bars.sort(key=lambda b: -(b[1] or 0))

    fig, ax = plt.subplots(figsize=(3.4, 2.3))
    y = range(len(bars))
    palette = {
        "validated_improvement": "#4878a8",
        "validated_fix": "#6aa84f",
        "fix_changes_result": "#c08030",
        "refused": "#b0b0b0",
    }
    values = [b[1] if b[1] is not None else 0 for b in bars]
    ax.barh(y, values, color=[palette.get(b[2], "#c0c0c0") for b in bars], height=0.62)
    ax.set_yticks(list(y))
    ax.set_yticklabels([b[0] for b in bars], fontsize=5.5)
    ax.axvline(1.0, color="#666666", linewidth=0.7, linestyle="--", zorder=0)
    # Headroom so the value labels stay inside the axes.
    ax.set_xlim(0, max(values) * 1.28)
    for i, b in enumerate(bars):
        if b[1] is None:
            ax.text(0.06, i, "refused by OpenFHE", va="center", fontsize=5.5, color="#555555")
        else:
            inside = b[1] > max(values) * 0.55
            ax.text(
                b[1] - 0.08 if inside else b[1] + 0.08, i, f"{b[1]:.2f}x",
                va="center", ha="right" if inside else "left", fontsize=5.5,
                color="white" if inside else "#222222",
            )
    ax.set_xlabel("wall-time speedup (dashed: no change)", fontsize=6.5)
    ax.invert_yaxis()
    for spine in ("top", "right"):
        ax.spines[spine].set_visible(False)
    handles = [plt.Rectangle((0, 0), 1, 1, color=palette[k]) for k in
               ("validated_improvement", "validated_fix", "fix_changes_result")]
    ax.legend(
        handles,
        ["speedup", "fix, output unchanged", "fix, output changed"],
        loc="upper center", bbox_to_anchor=(0.5, -0.30), ncol=3, frameon=False,
        fontsize=5, columnspacing=0.9, handlelength=1.0, handletextpad=0.4,
    )
    fig.tight_layout()
    fig.savefig(HERE / "impact.pdf", bbox_inches="tight")
    plt.close(fig)


if __name__ == "__main__":
    overhead_figure()
    ablation_figure()
    impact_figure()
    print("wrote", ", ".join(p.name for p in sorted(HERE.glob("*.pdf"))))
