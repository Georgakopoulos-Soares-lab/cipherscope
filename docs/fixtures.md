# Fixture corpus

The test corpus is synthetic and cataloged in `tests/fixtures/corpus.json`. Each
entry records a stable ID, expected validation stage/outcome, tags, and provenance.
No sample is copied from a production incident or claimed under an external
license; the catalog uses `NOASSERTION` until the repository owner chooses a
project license.

Semantic fixtures cover empty and minimal traces, branches, deep multiplication,
repeated rotations, bootstrap epochs, failure events, missing metadata, Unicode,
truncation, concurrent ordering, and large metadata. Invalid cases isolate
unknown schema majors, duplicate IDs, non-monotonic sequences, dangling
references, cycles, negative durations, and failed calls with outputs.

Large/deep stress input is generated with a fixed seed during tests rather than
stored as a large artifact. Golden expectations omit machine-specific timings and
thread identifiers.
