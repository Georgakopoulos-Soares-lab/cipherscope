# Paper claims (frozen draft)

This file fixes what the paper will claim before more experiments run. Every
engineering task must serve one of the research questions below; a proposed
analyzer or feature with no RQ row in `rq_matrix.csv` is deferred. Edit this
file deliberately: changing a claim after results exist is a scope change, not
a wording change.

## Thesis

CipherScope is a source-aware runtime observability and diagnosis system for
OpenFHE programs: it reconstructs immutable ciphertext versions, CKKS state
transitions, and provenance from an already-written Python program while it
runs, and uses that execution model to identify, and then validate, performance
and correctness pathologies that ordinary profilers cannot express.

Default framing: "runtime semantic observability and diagnosis for OpenFHE
programs". Do not lead with "the first FHE profiler".

## Contributions

1. **A source-attributed runtime model of FHE execution.** A proxy around the
   OpenFHE context records every covered call once, attributes it to the calling
   Python line, and reconstructs immutable ciphertext versions, level and scale
   transitions, rotation-key use, and lineage into a validated graph. The
   coverage boundary is explicit and measured, not assumed.
2. **Conservative diagnoses over that model.** Ten rules (repeated compatible
   rotations, rotation keys unused in the observed run, observed depth headroom,
   bootstrap underuse, annotated packing utilization, public-value provenance,
   repeated public encodings, serial associative products, precision checkpoints,
   depth critical path) that fire only on observed evidence and explicit user
   assertions, never on inferred contents.
3. **An evidence methodology for FHE tooling.** Coverage classes that keep
   incomplete traces out of quality claims; human adjudication of every real
   finding under a fixed rubric for precision; a seeded known-answer benchmark
   with hard negatives for recall; and a data contract under which every paper
   table regenerates from raw records.
4. **Validated impact on real workloads** *(pending D-03/D-04)*: measured
   before/after results for every actionable true positive, including a
   rotation-hoisting case study on an independently authored program, with
   non-improving transformations retained.

## Research questions

- **RQ1 Fidelity.** Does tracing preserve OpenFHE numerical behavior and
  reconstruct executed source, state, and provenance correctly?
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
  context object, module-level free functions, `GetCryptoContext()`, operator
  overloads, and work inside native calls are not observed. Runs are labeled
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
- Two rules have documented real-binding limits: bootstrap underuse cannot be
  observed through `GetLevel()` on OpenFHE Python 1.5.1.0, and the precision
  rule has no minimum threshold and can fire on decryption noise. Both are
  reported as limitations, not hidden.

## Rule for new analyzers

A new rule is accepted only with (1) a one-line mapping to an RQ, (2) a seeded
positive and hard negative in `evaluation/seeded/`, and (3) a planned row in the
adjudication export. Otherwise it waits.
