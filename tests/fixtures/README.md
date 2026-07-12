# CipherScope synthetic fixture corpus

Every artifact in this directory was written specifically for CipherScope tests. The
catalog in `corpus.json` is authoritative: it gives each artifact a stable ID, records its
expected processing result, and declares synthetic provenance. None of these files contains
a production trace, key material, plaintext values, credentials, or personal data.

## Semantic JSON fixtures

`graphs/` and `traces/` contain compact positive and negative cases derived from the
CipherScope 1.0 research contract. Positive cases exercise minimal, empty, deep,
repeated-operation, bootstrap, disconnected-component, Unicode, and bounded-metadata
shapes. Negative cases isolate a cycle, dangling reference, duplicate ID, non-monotonic
sequence, illegal failed-call output, malformed JSON, or metadata-limit violation where
practical. Timing values are illustrative invariants, not performance observations.

The `expected` record in the catalog is test intent, not a claim that a fixture has ever
been produced by OpenFHE. `outcome` is `accept`, `reject`, or `not_applicable`; `stage`
identifies the intended processing boundary; and `code` is a stable corpus-level
expectation code.

## Ancillary opaque stack text

`ancillary/stacks/` contains exactly 18 synthetic stack-text samples: two each for Python,
JavaScript, TypeScript, Java, Go, Rust, C#, Ruby, and native-style diagnostics. They exist
only to test escaping, path redaction, Unicode handling, and input/stack-size limits in
generic exporters or security helpers. **They are not supported CipherScope runtime inputs
and must not be parsed as semantic traces.** Their language labels describe surface syntax,
not provenance from a real runtime.

## Adding a fixture

1. Use wholly synthetic values and run-local IDs.
2. Add one catalog entry with a unique stable ID and relative path.
3. Keep the provenance object exactly explicit; do not infer a license or external origin.
4. Give invalid JSON cases one intended failure code whenever possible.
5. Update the fixed counts in `../test_fixture_catalog.py` intentionally.
