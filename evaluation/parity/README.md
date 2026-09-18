# Lane parity

Three real-binding lanes ran the same gate and the same evaluation programs
on three platforms; this directory holds the tooling that proves the
platform-independent results agree.

| File | Role |
|---|---|
| `run_lane.sh <lane> <out> [examples seeded scaling]` | Runs the 16 example programs, the 27-case seeded benchmark plus ablation, and the 10²–10⁵ scaling sweep for one lane, into `<out>`. Same commands for every lane. |
| `run_external.sh <out> [programs…]` | Traces the pinned `python-log-reg-examples` corpus through `examples/profile_unmodified.py`, strict first, permissive only to inventory unsupported operations. |
| `compare_lanes.py` | Compares `feasibility.json` files and `run_lane.sh` outputs; exits nonzero on any disagreement outside the allowed list. Tested by `tests/test_parity.py`. |
| `parity_report.md` | Generated output (do not edit). |

What must be identical across platforms: pins, every gate check's status
(except `RES-02`, which reads `/proc` and is skipped on macOS), each seeded
(case, rule) outcome, the ablation row set, each example's diagnoses and the
`examples/README.md` expectations, and the coverage class of every bundle.
What is only placed side by side: wall time, RSS, and analysis time, which
depend on hardware; the comparable columns there are the traced/baseline
ratio and trace bytes per event.

Regenerate (LS6; the container lane needs `run_in_primary`, and long jobs
should be started with `setsid -f` so they outlive the shell):

```bash
source ls6_env.sh
setsid -f bash -c 'run_in_primary bash evaluation/parity/run_lane.sh primary-source-py311 /results/primary-source-py311' > "$RESULTS_ROOT/logs/primary.log" 2>&1
CIPHERSCOPE_OPENFHE_LANE=ls6-native-py311 bash evaluation/parity/run_lane.sh ls6-native-py311 "$RESULTS_ROOT/ls6-native-py311"
python3 evaluation/parity/compare_lanes.py \
  --lane developer artifact/feasibility/developer/feasibility.json \
      --seeded developer=evaluation/raw/seeded/case_results.json \
      --ablation developer=evaluation/raw/semantic_ablation.csv \
  --lane primary-source-py311 artifact/feasibility/primary-source-py311/feasibility.json "$RESULTS_ROOT/primary-source-py311" \
  --lane ls6-native-py311 artifact/feasibility/ls6-native-py311/feasibility.json "$RESULTS_ROOT/ls6-native-py311" \
  --output evaluation/parity/parity_report.md
```

`evaluation/raw/scaling.csv` carries the developer lane's arm64 rows and the
primary lane's x86_64 rows; the native lane's sweep stays in its results
directory because both LS6 lanes report `machine = x86_64` and the table
generator groups by machine. Single repetitions on a shared VM: the two LS6
sweeps' baseline arms ran under different concurrent load, which is why the
container lane's traced/baseline ratios fall below 1 while the native lane's
sit at 1.08–1.11; the arm64 sweep gives 1.22 at 10⁵. Bytes per event
(2 139–2 193) and peak RSS at 10⁵ (2.98–3.17 GB) agree across all three.
