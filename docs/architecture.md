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

The session owns one run ID, lifecycle, context attachment, and coverage counters.
`TracedCryptoContext` has explicit adapters for the supported operation registry.
It snapshots metadata before timing, invokes the bound backend method once, stops
clocks in `finally`, and records success or failure. An unclassified call fails
closed in strict mode.

The registry uses Python identity as its lookup key. Serialized IDs are monotonic
names such as `ct_0001:v0`. Events also record argument and result
representations. A first-seen operand becomes a preexisting root. Encryption
creates a ciphertext with no ciphertext parent, and decryption consumes
ciphertext lineage. Declared
in-place methods extend the same logical object through immutable `:vN` state
nodes. Mutation selection follows the first ciphertext operand, including reverse
scalar/plaintext overloads, rather than assuming the first Python argument is the
mutated object.

Graph construction happens only after trace validation. Its nodes represent
runtime events, ciphertext versions, source sites, and rotation-key requirements;
edges represent calls, consumption, production, lineage, and observed key use.
Critical-path calculations distinguish
ciphertext-ciphertext nonlinear depth from observed level transitions. Bootstrap
starts a new epoch without erasing historical lineage or the global maximum.

Analyzers consume validated documents and decline to emit findings when required
evidence is missing. The repeated-rotation rule requires the same immutable input
version, distinct indices, compatible context/key/scaling metadata, HYBRID key
switching, and no earlier compatible fast-rotation precompute. It recommends a
measured experiment and does not predict speedup.

The key-usage rule compares successful traced `EvalRotateKeyGen` requests with
covered `EvalRotate` indices. It declines analysis for truncated or permissive
traces and says "unused in this observed run," never globally unnecessary.

Exporters project one analysis model into JSON, CSV, Perfetto-compatible JSON,
and a static HTML summary. Files are staged and then published as one run
directory.

## Claim boundary

The fake backend establishes instrumentation mechanics, deterministic contracts,
and failure handling—not OpenFHE correctness or cryptographic security. The real
feasibility gate must verify proxy boundaries, pybind object identity, available
getters, alias/mutation behavior, and traced-versus-untraced numerical equivalence
against OpenFHE Python 1.5.1.0.
