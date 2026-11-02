# Paper claims (frozen draft)

This file fixes what the paper will claim before more experiments run. Every
engineering task must serve one of the research questions below; a proposed
analyzer or feature with no RQ row in `rq_matrix.csv` is deferred. Edit this
file deliberately: changing a claim after results exist is a scope change, not
a wording change.

## Thesis

CipherScope is a source-aware runtime observability and diagnosis system for
OpenFHE programs: it reconstructs immutable ciphertext versions, scheme state
transitions, and provenance from an already-written program while it runs, and
uses that execution model to identify, and then validate, performance and
correctness pathologies that ordinary profilers cannot express.

Default framing: "runtime semantic observability and diagnosis for OpenFHE
programs". Do not lead with "the first FHE profiler".

## Contributions

1. **A source-attributed runtime model of FHE execution.** A proxy around the
   OpenFHE context records every covered call once, attributes it to the calling
   Python line, and reconstructs immutable ciphertext versions, level and scale
   transitions, rotation-key use, and lineage into a validated graph. The
   coverage boundary is explicit and measured, not assumed.
   The model is scheme-parametric: CKKS, BFV and BGV are identified from a live
   context with no declared parameters, and depth is read from whichever
   coordinate the scheme actually moves — the level ladder for CKKS and BGV,
   and the recorded multiplication count for BFV, whose level never changes and
   whose noise scale degree is not cumulative. Every depth finding names the
   coordinate it used.
2. **Conservative diagnoses over that model.** Twelve rules (repeated compatible
   rotations, rotation keys unused in the observed run, observed depth headroom,
   bootstrap underuse, annotated packing utilization, public-value provenance,
   repeated public encodings, serial associative products, precision checkpoint
   drops, declared-tolerance violations, testing-only security configuration,
   depth critical path) that fire only on observed evidence and explicit user
   assertions, never on inferred contents.
3. **An evidence methodology for FHE tooling.** Coverage classes that keep
   incomplete traces out of quality claims; human adjudication of every real
   finding under a fixed rubric for precision; a seeded known-answer benchmark
   with hard negatives for recall; and a data contract under which every paper
   table regenerates from raw records.
4. **Validated impact on real workloads**: measured before/after results for
   every actionable true positive on the independently authored external
   corpus (`before_after.csv`), with refused and result-changing
   transformations retained, plus a designed before/after pair for every
   prescriptive rule (`impact.csv`).

## Research questions

- **RQ1 Fidelity.** Does tracing preserve OpenFHE numerical behavior and
  reconstruct executed source, state, and provenance correctly, on every
  supported scheme?
- **RQ2 Coverage.** What fraction of real OpenFHE-Python workloads and semantic
  calls are completely observable?
- **RQ3 Finding quality.** How precise are findings on real workloads, and what
  is seeded recall per rule?
- **RQ4 Impact.** How often do validated findings produce performance, resource,
  depth, or precision improvements?
- **RQ5 Cost.** What runtime, memory, trace-size, and analysis overhead does
  CipherScope add?
- **RQ6 Security and correctness.** Does the tool expose real misconfigurations
  or silent correctness failures, and what are their impacts?

`rq_matrix.csv` maps each RQ to its experiment, raw input, generated table, and
current status.

## Non-claims

- Not a cryptographic parameter-security proof. CipherScope does not estimate
  bit security and will not; a future rule may report that standard security
  enforcement was disabled (`HEStd_NotSet`), which is a configuration
  observation, not a security verdict.
- Not a compiler or an optimizer. It recommends measured experiments; it does
  not rewrite programs or predict speedups.
- Not complete outside the coverage boundary. Calls through the original
  context object, module-level free functions, `GetCryptoContext()`, and work
  inside native calls are not observed (ciphertext operator overloads are,
  since GAP-01). Runs are labeled
  `COMPLETE`, `PARTIAL-PERMISSIVE`, or `UNSUPPORTED`, and only `COMPLETE` runs
  enter quality tables.
- **Traces are not safe to publish.** A trace records argument and result
  representations, exception messages, absolute source paths, and, in shadow
  mode, the plaintext values compared at each checkpoint. It does not record
  ciphertext coefficients or keys, but no privacy or leakage guarantee is
  claimed.
- Recall on real workloads is undefined and is never reported; recall comes
  only from the seeded benchmark, and precision only from adjudicated real
  findings.
- Not every rule applies to every scheme, and the paper must not imply it
  does. The two precision rules and the bootstrap rule are CKKS-only by
  construction: BFV and BGV are exact, so a checkpoint has no approximation
  error to lose, and the restored-level analysis is defined for CKKS
  bootstrapping. On those schemes the rules report `not_applicable` with a
  reason, which the seeded corpus asserts rather than assumes. A wrong result
  on an exact scheme is a correctness fault — a plaintext-modulus overflow,
  say — and diagnosing it would be a new rule with its own evidence, not an
  extension of the precision rules.
- Scheme support is claimed only for CKKS, BFV and BGV on the pinned OpenFHE
  1.5.1.0 build. The BFV/BGV evidence is the seeded corpus, the `API-08`,
  `API-09` and `ROT-04` gate checks, the C++ `SCHEME-01`/`PARITY-01` checks,
  and **2 of 5 upstream OpenFHE Python examples traced `COMPLETE`**
  (`evaluation/corpus/integer_schemes.md`). Report that as two of five, not as
  two workloads: the other three exercise threshold FHE (`MultipartyKeyGen`)
  and proxy re-encryption (`ReKeyGen`), neither of which is in the operation
  manifest, and strict mode refuses them by design. The integer-scheme corpus
  is far smaller than the CKKS one and carries no adjudicated verdicts, so the
  precision and impact tables remain CKKS-only.
- Two rules have documented limits: bootstrap underuse is visible only for an
  input deeper than the level OpenFHE returns every bootstrap output at
  (`depth - levelsAvailableAfterBootstrap`), and observed depth headroom is an
  upper bound, because levels a library call consumes internally (inside an
  iterative `EvalBootstrap`) are not observed. Both are reported as
  limitations, not hidden.
- The two false positives in the real-workload precision have **different
  causes, and only one is still live**. `sol_nag_log_reg` is the limitation
  above: depths 32 and 31 both abort inside a two-iteration `EvalBootstrap`,
  whose internal level use no ciphertext state exposes. `sol_encrypted_inference`
  was a deferred FLEXIBLEAUTO rescale that the level field had not yet shown,
  and the analyzer now reserves that level
  (`parameters.deferred_rescale_levels`) and reports the run clean. The
  precision table deliberately keeps the verdict as adjudicated rather than
  retroactively crediting the fix, so the reported 6/8 understates the current
  rule by one finding. Quote it as measured and say why, rather than quoting
  7/8.

## Rule for new analyzers

A new rule is accepted only with (1) a one-line mapping to an RQ, (2) a seeded
positive and hard negative in `evaluation/seeded/`, and (3) a planned row in the
adjudication export. Otherwise it waits.
