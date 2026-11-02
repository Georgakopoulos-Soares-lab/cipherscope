# Manuscript working notes — read this first when resuming

**State as of 2026-11-01.** `paper/manuscript.md` is a complete first draft
(abstract through conclusion), written under the protocol in the user's
`cipherscope-paper-writing` skill (at
`~/Downloads/cipherscope-fable-skill-complete/cipherscope-paper-writing/SKILL.md`)
and the three guides in `references/` (five-papers, voice-edits,
project-evidence — note project-evidence.md audits an old snapshot; the
refreshed audit is `paper/evidence_ledger.md`).

All numbers were verified against the working tree at commit `8e55b53` plus
~80 uncommitted changes. **If the tree has been committed or LS6 lanes rerun
since, re-verify before editing results text** — the checker below does it
mechanically.

## How to re-verify every number (run before any results edit)

```bash
PYTHONPATH=src python3 -m unittest tests.test_evidence tests.test_artifact tests.test_tables
make verify-checksums          # 8 raw records ": OK"
# the ad-hoc ledger checker used during drafting asserts: lane counts/status,
# 61 seeded cases (28/17/16 by scheme), recall 31/31, 0 FP/44, precision
# 0.75 with denominator 8, coverage 20/20. Reconstruct from
# paper/evidence_ledger.md section 4 if needed.
```

## Claim ledger (claim → source → status)

| Claim in draft | Source | Status |
|---|---|---|
| CKKS traced-vs-direct max err 2.2e-13 (primary), 3.4e-13 worst lane | `evaluation/parity/parity_report.md` numerics table | measured |
| BFV/BGV bit-identical | seeded `check_exact` + C++ NUM-01 | measured |
| Lanes 40/40, 40/40, 42/42, 41/42, 33/33, C++ 21/21 ×3 | `artifact/feasibility/*/feasibility.json` | archived |
| Parity 0 disagreements, 3 allowed | `evaluation/parity/parity_report.md` (regenerated with emulated lane) | generated |
| Seeded 31/31, 0 FP on 44, 61 cases (28/17/16) | `evaluation/tables/recall.csv`, `ground_truth.json` | measured |
| Ablation: 1 rule TIMING_ONLY, 5 STATE, 6 FULL | `evaluation/tables/semantic_ablation.csv` | measured (projection, labeled) |
| Coverage 20/20 CKKS; 2/5 integer corpus; C++ 6/6 | `evaluation/tables/coverage.csv`, `evaluation/corpus/integer_schemes.md` | measured |
| Precision 6/8=0.75, 4 NOT-IN-SCOPE, 2 FP causes | `evaluation/tables/precision.csv`, `evaluation/adjudication/findings.csv` | adjudicated (AI reviewers — disclosed in 5.4) |
| Impact 4.03× / 1.21× / 1.09×; security fix free on inference; one refused | `evaluation/tables/before_after.csv`, rq_matrix RQ4 | measured |
| Designed impact suite 10/10; security fix ~4× slower on toy | `evaluation/tables/impact.csv` | measured |
| Overhead fixed 0.4–2.3 s; 0.7–1.8% at 100–180 s; 1.5–2.6× sub-second | `evaluation/tables/overhead.csv` (do NOT quote ALL-row pooled 1.50) | measured, 3 reps |
| Scaling 2.2 KB/event, ~190 ms/1k analyze, 3.2 GB at 1e5 | `evaluation/tables/scaling.csv` | single runs — say "observation" |
| Bootstrap case 6.98 GB RSS, OOM <8 GB | `evaluation/seeded/README.md` known limits | measured |
| BFV noise degree non-cumulative (EvalAdd deg1,deg2→1) | seeded README + `bfv.positive.mixed_add_depth` | measured |
| GetModulusCKKS / NORESCALE detection | API-09; `compatibility._detect_live_scheme` | gate-checked |
| EvalBootstrapSetup "Not supported" on BFV/BGV | bootstrap.py comment; probed this session | measured |
| RQ6: 5 HEStd TPs / 5 clean / 0 FP on 10 programs | `evaluation/tables/security_cases.csv` | adjudicated |
| HEProfiler characterization | abstract + search only | **partially verified — [VERIFY]** |

## Open items (no \verify markers remain in the PDF)

1. **HEProfiler — RESOLVED 2026-11-01.** Full JCE PDF read via
   d-nb.info/1374663646/34 (the ePrint PDF 403s and Springer paywalls).
   Verified: compares PALISADE, SEAL, HElib, HEAAN (NOT OpenFHE); CKKS only;
   C++ only; user writes benchmarks against the framework; focuses on core
   operations; no per-call source attribution, no lineage, no rotation-key
   accounting, no before/after. prior_art_matrix.csv row now fully verified;
   Related Work rewritten with these facts.
2. **LS6 lanes at 40 vs gate 42** — user excluded LS6 runs. Stated honestly
   in prose (§6.1 + Limitations) and in the parity report's allowed
   differences, so no marker is needed. Rerun before submission, then update
   §6.1 and docs/evidence.md.
3. **AI adjudication** — fully disclosed in §5 (Adjudication protocol) and
   §7. A human pass is a decision, not a verification.

## Venue restructure (2026-11-01, later same session) — .tex IS NOW CANONICAL

`manuscript.md` is SUPERSEDED (header says so); edit only `manuscript.tex`.
Restructured to the dominant flow of the user's 10-paper reference corpus:
Intro -> Background and Motivation (schemes / OpenFHE+application boundary /
motivating example with Figure 1) -> Threat Model and Scope (new; privacy
venue) -> The CipherScope Framework (trace+versioning, frontends, coverage,
scheme model, rules) -> Experimental Setup (new: RQs, lanes, corpora,
adjudication protocol, reproducibility) -> Results and Discussion (RQ1,2,3
recall, 3 precision, 4, 5, 6 in order) -> Limitations -> Related Work ->
Conclusion and Future Work. Authors: Provatas, Georgakopoulos-Soares,
Benhamou (UT Austin); re-add [review,anonymous] class options for
double-blind. Teaser moved from acmart teaserfigure to figure* in the
motivating example (fig:overview). Ubiquitous terms fixed throughout:
"observation boundary" (concept) vs "coverage class" (measurement); "rule"
not analyzer; "gate check"; "evidence lane"; "seeded case" / "corpus
workload" / "gallery example". Four related-work entries added from the
corpus (safetycentric2025, hecate2022, fheagent2025, crossplatform2025 —
all with TODO author fields).

## LaTeX build (added 2026-11-01, same session)

- `paper/manuscript.tex` — acmart [sigconf,review,anonymous,nonacm]; 8 pp.
  Build: `cd paper && tectonic manuscript.tex`. Retarget the class when the
  venue is fixed (comment at top of the .tex); body is class-agnostic.
- Figures: `python3 paper/figures/make_figures.py` regenerates
  overhead/ablation/impact PDFs from evaluation/tables/*.csv (table wins on
  any disagreement — the 4.03x in the text is the table's 4.0250 half-up).
  Teaser: `tectonic paper/figures/teaser.tex -o paper/figures` (TikZ
  standalone; style name `out` collides with /tikz/out — stays `finding`).
- `paper/references.bib` exists; entries marked TODO need checking against
  publisher pages (HEIR/CryptOracle/Rotom/HERTA author lists, page numbers).
- KEEP manuscript.md and manuscript.tex IN SYNC — both were edited together
  for: the security-fix outcomes (free / 3.5–4x slower *and changed results*,
  status fix_changes_result in before_after.csv) and the abstract/contrib-4
  rewording (three perf findings 1.09–4.03x; three security fixes are trades,
  not speedups). Any future results edit goes to BOTH files.
- \verify{} macro is defined but UNUSED (all items resolved or stated in
  prose). Re-use it if a new open item appears.
- Typography: `\setlength{\emergencystretch}{3em}` + microtype took overfull
  boxes 46 -> 0. hyphenat[htt] did NOT work under acmart/XeTeX (fontspec) and
  was removed. Zero overfull, zero undefined refs as of the last build.
- Figure design rules learned: no colorbar on the ablation heatmap (cell text
  carries the counts); impact bar labels must sit inside the axes (xlim
  headroom + inside/outside placement); overhead x-labels must be rotated 30
  deg or they collide at the right-hand end; its legend goes ABOVE the axes
  or the relative-overhead line runs through it.

## Visual/structural pass (2026-11-01, third revision)

- Results condensed: Table 1 now carries every headline number with its
  population; subsection prose explains what each result does and does not
  establish rather than restating figures. §4.1 "Design principles" added
  (observe where decisions are made / explicit ciphertext identity / trace
  as contract / abstention over inference).
- WATCH OUT: when rewriting the results block wholesale, the three figure
  environments live inside it. A previous pass deleted them and produced 4
  dangling \ref's. Re-check `grep -c includegraphics` (should be 4: teaser,
  ablation, impact, overhead) after any big results edit.
- A python .replace() that does not match fails SILENTLY. The HEProfiler
  paragraph update missed once for this reason and shipped a red [VERIFY]
  into a rendered PDF. Verify every scripted edit landed.

## Still to do on the manuscript

- [x] References/.bib — created (TODO notes inside entries remain). Primary cites needed: HEProfiler
  (ePrint 2024/1059 / JCE 15:14), Scalene (OSDI 23), Coz (SOSP 15), EVA
  (PLDI 20), HEIR (arXiv 2508.11095), CryptOracle (arXiv 2510.03565), Rotom
  (USENIX Sec 26), HERTA (arXiv 2606.22519), OpenFHE, CKKS/BFV/BGV scheme
  papers. DOIs/links are in `references/five-papers.md` and
  `paper/prior_art_matrix.csv`.
- [x] Figures: teaser (TikZ), overhead (figure*), ablation heatmap, impact
  bars — all regenerable (make_figures.py + teaser.tex).
- [x] LaTeX conversion done (acmart, anonymous). Venue retarget pending.
- [ ] Prose pass per skill §6 (done once lightly at draft time; do a full
  read-aloud pass after technical review).
- [ ] Reviewer pass: strongest objections anticipated are (a) AI
  adjudication, (b) emulated-lane evidence, (c) BFV headroom semantics,
  (d) corpus size (4 CKKS + 2/5 integer workloads). §5.4/§5.1/§3.4/§5.3
  address them in place; check they survive edits.
- [ ] Numbers freeze: after LS6 rerun, update §5.1 counts (40→42) and the
  abstract's lane sentence if changed.

## Session facts a resumer needs

- Everything is **uncommitted** (~80 files incl. this draft). Committing is
  the first safe step of any resumption.
- The emulated Docker image `cipherscope-openfhe-py311:emulated` (518 MB) and
  a buildx container exist locally; the emulated gate reruns with the
  command in docs/evidence.md.
- Integer corpus staging lives under gitignored
  `cipherscope-results/bfv-corpus/` and `bfv-runs/`; the permanent record is
  `evaluation/corpus/integer_schemes.md`. The safety classifier blocked
  running tools over paths outside the repo; staging inside the repo works.
- Suite green: 312 tests (42 skips fake / 1 skip real binding); seeded
  61/61; emulated gate 42/42; checksums 8/8.
