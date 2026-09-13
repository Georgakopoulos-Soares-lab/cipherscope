# CipherScope synthetic fixture corpus

Every artifact in this directory was written specifically for CipherScope tests. The
catalog in `corpus.json` is authoritative: it gives each artifact a stable ID, records its
expected processing result, and declares synthetic provenance.

## Semantic JSON fixtures

`graphs/` and `traces/` contain compact positive and negative cases derived from the
CipherScope 1.0 research contract. Positive cases exercise minimal, empty, deep,
repeated-operation, bootstrap, disconnected-component, Unicode, and large-metadata
shapes. Large metadata cases confirm that validation does not impose a string-size limit.
Negative cases isolate a cycle, dangling reference, duplicate ID, non-monotonic sequence,
illegal failed-call output, or malformed JSON. Timing values are illustrative invariants,
not performance observations.

The `expected` record in the catalog is test intent, not a claim that a fixture has ever
been produced by OpenFHE. `outcome` is `accept`, `reject`, or `not_applicable`; `stage`
identifies the intended processing boundary; and `code` is a stable corpus-level
expectation code.

## Adding a fixture

1. Use wholly synthetic values and generated IDs.
2. Add one catalog entry with a unique stable ID and relative path.
3. Record that the fixture is synthetic and has no external source or asserted license.
4. Give invalid JSON cases one intended failure code whenever possible.
5. Update the fixed counts in `../test_fixture_catalog.py` intentionally.
