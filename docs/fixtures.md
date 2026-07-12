# Fixture corpus

The test corpus is synthetic and cataloged in `tests/fixtures/corpus.json`. Each
entry records a stable ID, expected validation stage/outcome, tags, and provenance.
No sample is copied from a production incident or claimed under an external
license; the catalog uses `NOASSERTION` until the repository owner chooses a
project license.

Semantic fixtures cover empty and minimal traces, branches, deep multiplication,
repeated rotations, bootstrap epochs, failure events, missing metadata, Unicode,
truncation, concurrent ordering, and adversarial limits. Invalid cases isolate
unknown schema majors, duplicate IDs, non-monotonic sequences, dangling
references, cycles, negative durations, and failed calls with outputs.

The corpus also contains two opaque exception-stack samples for each of Python,
JavaScript, TypeScript, Java, Go, Rust, C#, Ruby, and native code. They exercise
UTF-8 decoding, byte limits, path redaction, and HTML escaping. They are not input
to the semantic graph builder and do not imply that CipherScope profiles those
languages.

Large/deep stress input is generated with a fixed seed during tests rather than
stored as a large artifact. Golden expectations omit machine-specific timings and
thread identifiers.

