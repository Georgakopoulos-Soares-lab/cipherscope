# Evidence ledger, refreshed against the working tree

**Read before writing any results or contribution claim.** This replaces the
audit in `references/project-evidence.md`, which examined the archive at commit
`2c1d027` — before the C++ frontend merge, before RQ3/RQ4/RQ6 were completed,
and before BFV/BGV support. Every number in that file is stale.

**Audited:** 2026-11-01, working tree at `8e55b53` **plus 78 uncommitted
changes**. That matters: nothing below is reproducible from a clean clone until
those changes are committed. Re-run the commands rather than trusting this file
once they are.

Every numerical sentence below carries `[population, source path, status]`. An
unresolved item is marked `[VERIFY]` rather than resolved favourably.

## 1. What the system is now

CipherScope is pre-alpha, source-attributed **runtime semantic observability
and diagnosis for CKKS, BFV and BGV programs using OpenFHE**, through either of
two frontends: a Python proxy around a live context, or a GCC plugin that
instruments an unmodified C++ program at compile time. Both emit the same
canonical trace; validation, the ciphertext graph, every analyzer and every
exporter are shared.

Two corrections to the older description. It is no longer Python-only, and it
is no longer CKKS-only. But "already-written program" still means different
things per frontend: the **Python** path requires the program to call `trace()`
or `attach()` and route calls through `session.context`, whereas the **C++**
path genuinely requires no source change. Do not blur the two in the paper.

## 2. Scheme support, stated precisely

| | CKKS | BGV | BFV |
|---|---|---|---|
| Identified from a live context with no declared parameters | yes | yes | yes |
| Depth coordinate | ciphertext levels | ciphertext levels | recorded multiplications |
| Depth finding confidence | `measured` | `measured` | `inferred` |
| Slot capacity | N/2 | N | N |
| Precision rules | apply | `not_applicable` (exact) | `not_applicable` (exact) |
| Bootstrap rule | applies | `not_applicable` | `not_applicable` |

Two facts behind that table, both measured on the pinned build and both worth
stating in the paper because they are not obvious:

- **BFV has no level ladder.** `GetLevel()` is 0 for every BFV ciphertext in a
  run. The noise scale degree is not a substitute: it accumulates along a
  multiplication chain but `EvalAdd(deg 1, deg 2)` returns degree 1, so an
  addition against a shallower operand erases the evidence of upstream
  multiplications. BFV depth is therefore counted from recorded operations, and
  the finding says so in its `depth_evidence` field.
- **OpenFHE 1.5.1.0 has no bootstrapping for either integer scheme.**
  `EvalBootstrapSetup` raises "Not supported" from `base-fhe.h` for BFV and BGV
  even after `Enable(FHE)` succeeds. The bootstrap rule's `not_applicable` on
  those schemes is a measured fact, not a design choice.

Source: `src/cipherscope/graph.py` (`depth_coordinate`, `LEVELED_SCHEMES`),
`src/cipherscope/compatibility.py` (`_detect_live_scheme`),
`src/cipherscope/analyzers/_shared.py` (`EXACT_SCHEMES`).

## 3. Evidence lanes

Eight archived lanes, `artifact/feasibility/*/feasibility.json`, cross-checked
against `docs/evidence.md` by `tests/test_evidence.py`.

| Lane | Status | pass/skip/total | Authoritative |
|---|---|---|---|
| `primary-source-py311` | `pass` | 40 / 0 / 40 | **yes** |
| `ls6-native-py311` | `native_pass` | 40 / 0 / 40 | no |
| `emulated-docker-py311` | `emulated_pass` | **42 / 0 / 42** | no |
| `developer` | `incomplete` | 41 / 1 / 42 | no |
| `provisional-wheel-py312` | `provisional_pass` | 33 / 0 / 33 | no |
| `cpp-gcc152-openfhe151` | `native_pass` | 21 / 0 / 21 | no |
| `cpp-gcc133-openfhe151` | `native_pass` | 21 / 0 / 21 | no |
| `cpp-gcc133-openfhe151-emulated` | `emulated_pass` | 21 / 0 / 21 | no |

**The authoritative lane is at 40 checks; the gate is at 42.** `API-09` (live
scheme identification and per-scheme depth coordinate) and `ROT-04`
(fast-rotation equivalence under BV key switching) exist only on the developer
and emulated lanes. `evaluation/parity/parity_report.md` lists this as an
allowed difference. **Do not write "42/42 on the primary lane"** until the LS6
lanes are rerun.

The two emulated lanes were built and run under x86_64 emulation on arm64
hardware. They are real Linux x86_64 runs of the pinned recipe, and the
emulated Python lane is the only one that has executed all 42 checks — but
their native module hashes to `91b0253f…` where the primary lane hashes to
`a3a6e18a…`, so they are a different binary and never authoritative. Quote
cluster numerics in the paper, not emulated ones.

## 4. Results, with denominators

| Claim | Number | Population | Source |
|---|---|---|---|
| Seeded recall | **31/31 = 1.0000** | 61 cases, 12 rules, 3 schemes | `evaluation/tables/recall.csv` |
| Seeded false positives | **0 on 44 negatives** | 6 of which are `not_applicable` expectations | same |
| Coverage | **20/20 COMPLETE** | 16 examples + 4 external workloads, strict mode | `evaluation/tables/coverage.csv` |
| Real-workload precision | **6/8 = 0.7500** | 12 findings; 4 NOT-IN-SCOPE excluded | `evaluation/tables/precision.csv` |
| Impact | 6/6 actionable findings patched and measured | best 4.03× (depth 12→7) | `evaluation/tables/before_after.csv` |
| Overhead | +0.7–1.8% on 100–180 s workloads | 12 workloads, matched baseline/traced | `evaluation/tables/overhead.csv` |

Seeded cases by scheme: 28 CKKS, 17 BFV, 16 BGV.

**The precision denominator deserves a sentence of its own.** It is 8, not 12,
because `depth.critical_path` contributes 4 findings all adjudicated
NOT-IN-SCOPE and so carries no denominator at all. And of the 2 false
positives, only one is still live: `sol_nag_log_reg` is the documented
opaque-bootstrap limitation, whereas `sol_encrypted_inference` was a deferred
rescale that the analyzer now reserves, so the current rule reports that run
clean. The table deliberately keeps the verdict as adjudicated. Quote 0.75 and
explain it; do not quote 7/8.

## 5. What is not established

- **The integer-scheme corpus is 2 of 5, not 4 of 4.** The upstream OpenFHE
  Python examples at the pinned wrapper commit were run on 2026-11-01:
  `simple-integers.py` (BFV) and `simple-integers-bgvrns.py` (BGV) trace
  `COMPLETE` and both report a measured rotation-hoisting finding. The other
  three fail because `MultipartyKeyGen` (threshold FHE) and `ReKeyGen` (proxy
  re-encryption) are outside the operation manifest. See
  `evaluation/corpus/integer_schemes.md`. This is real third-party evidence,
  but it is four workloads smaller than the CKKS corpus and has **no
  adjudicated verdicts**, so precision and impact stay CKKS-only.
- **Threshold FHE and proxy re-encryption are unsupported.** Named in
  `coverage.unsupported_operations` rather than silently forwarded, which is
  the designed behaviour, but it is a real boundary to state.
- **No manuscript exists.** `paper/` holds claims, this ledger, and two
  matrices. There is no `.tex`, no `.bib` and no figure anywhere in the tree.
- **HEProfiler is only partly verified.** `[VERIFY]` Layer, language, scheme
  coverage and the per-library-subclass design are confirmed; the per-call,
  lineage, rotation-key, bootstrap-epoch and before/after cells are not. The
  ePrint PDF returns 403 to automated fetch and the journal version is
  paywalled, so this needs a manual read.
- **Bootstrap seeded cases need ~7 GB of RAM.** `bootstrap.limitation.underused_real`
  peaks at 6.98 GB resident and is SIGKILLed below roughly an 8 GB limit,
  surfacing as `unreadable bundle: ... trace.json`. That is a memory failure,
  not a tracing failure.

## 6. Reproducing the numbers above

```bash
make test                                   # 312 tests; 42 skips without the binding, 1 with it
make verify-checksums                       # 8 raw records, every line ": OK"
make reproduce-small                        # 61 seeded cases, ablation, every table (~7 GB RAM)
PYTHONPATH=src python -m unittest tests.test_evidence   # table vs the 8 archived lanes
```

Tables regenerate byte-identically from the checksummed raw records; that
property is asserted by `tests/test_tables.py`.
