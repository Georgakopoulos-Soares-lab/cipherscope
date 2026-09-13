# Architecture

CipherScope separates observation from offline interpretation so that a native
call is invoked exactly once and analysis failures cannot rewrite execution
history.

```text
user call -> traced context -> recorder -> validated trace
                                      |-> ciphertext graph
                                      |-> analyzers
                                      `-> bundle exporters
```

The session owns one run ID, its attached contexts, and its coverage counters.
`TracedCryptoContext` defines methods for each supported OpenFHE call. It reads
metadata before timing, calls the backend method once, stops clocks in `finally`,
and records success or failure. Strict mode rejects methods it cannot classify.
The recorder keeps the name of every rejected or forwarded method under
`coverage.unsupported_operations`.

`coverage.py` turns those counters, plus a static scan of the target source, into
one of three classes: `COMPLETE`, `PARTIAL-PERMISSIVE`, or `UNSUPPORTED`. The
scan looks for calls on a raw context that is also traced, `GetCryptoContext()`,
`_context`, and module-level `Eval*` free functions. It cannot prove absence of a
bypass; it only lowers the class when it finds one.

`adjudication.py` exports findings from `COMPLETE` real runs into a CSV whose
verdict columns are always empty on export and never overwritten afterwards.
Finding IDs hash the rule and source location, not timing or event numbers, so a
re-run keeps the same IDs. Precision is computed only over rows with a rubric
verdict and written evidence; recall is never computed from real workloads.

`seeded.py` measures recall instead on `evaluation/seeded/`: known-answer
OpenFHE programs with a declared outcome per rule. Each case runs in its own
process through `cipherscope run`, must classify as `COMPLETE` on a real
backend, and is compared with `ground_truth.json` on analyzer status, source
lines, and evidence values. Rules not named by a case are reported but not
counted, so each case tests one thing.

Every run's `runtime` block carries a build fingerprint from `fingerprint.py`:
the evidence lane, the loaded OpenFHE wrapper's native-module hashes, and the
CipherScope commit, so a bundle can be matched to a row in `docs/evidence.md`.
`tables.py` reads `evaluation/schema/results.schema.json` as the data contract,
validates every raw record against it, and regenerates all paper tables
deterministically; `evaluation/generate_paper_tables.py` is its only entry
point.

The registry uses Python object identity for lookup. Recorded ciphertext IDs are
names such as `ct_0001:v0`. Events also record argument and result
representations. A first-seen operand becomes a preexisting root. Encryption
creates a ciphertext with no ciphertext parent, and decryption consumes
that ciphertext. An in-place method creates the next `:vN` version for the same
Python object. The first ciphertext operand is treated as the changed value,
including when a scalar or plaintext appears first in the Python arguments.

Graph construction happens only after trace validation. Its nodes represent
runtime events, ciphertext versions, source sites, and rotation-key requirements;
edges represent calls, consumption, production, lineage, and observed key use.
Critical-path calculations distinguish
ciphertext-ciphertext nonlinear depth from observed level transitions. Bootstrap
starts a new epoch without erasing historical lineage or the global maximum.

Analyzers use validated documents and return `not_applicable` when required data
is missing. The repeated-rotation rule requires the same recorded input version,
distinct indices, compatible context/key/scaling metadata, HYBRID key
switching, and no earlier compatible fast-rotation precompute. It recommends a
measured experiment and does not predict speedup.

Two rules depend on what the program declares rather than on the context: the
configuration rule reads the security level from `trace(..., parameters=)`
because the live context cannot report it, and the tolerance rule reads the
contract each `checkpoint(..., tolerance=)` recorded at decryption time.

The key-usage rule compares successful traced `EvalRotateKeyGen` requests with
covered `EvalRotate` indices. It declines analysis for truncated or permissive
traces and says "unused in this observed run," never globally unnecessary.

The recorder serializes each event once and keeps the lines in memory only up to
a buffer; beyond it they are appended to a temporary JSONL spool, as are
ciphertext states once their version is superseded or their object is
collected. `max_events` and `max_trace_bytes` stop recording at a hard limit:
later calls run natively and are only counted, so every reference in a
truncated trace still resolves. `ablation.py` projects a finished trace onto
timing-only and identity-free views to measure which observability each rule
depends on.

Exporters write JSON, CSV, Perfetto-compatible JSON, and a static HTML summary.
Files are staged and then moved into one run directory.

## What the tests prove

The fake backend establishes instrumentation mechanics, deterministic contracts,
and failure handling—not OpenFHE correctness or cryptographic security. The real
feasibility gate must verify proxy boundaries, pybind object identity, available
getters, alias/mutation behavior, and traced-versus-untraced numerical equivalence
against OpenFHE Python 1.5.1.0.
