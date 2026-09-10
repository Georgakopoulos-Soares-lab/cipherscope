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

The key-usage rule compares successful traced `EvalRotateKeyGen` requests with
covered `EvalRotate` indices. It declines analysis for truncated or permissive
traces and says "unused in this observed run," never globally unnecessary.

Exporters write JSON, CSV, Perfetto-compatible JSON, and a static HTML summary.
Files are staged and then moved into one run directory.

## What the tests prove

The fake backend establishes instrumentation mechanics, deterministic contracts,
and failure handling—not OpenFHE correctness or cryptographic security. The real
feasibility gate must verify proxy boundaries, pybind object identity, available
getters, alias/mutation behavior, and traced-versus-untraced numerical equivalence
against OpenFHE Python 1.5.1.0.
