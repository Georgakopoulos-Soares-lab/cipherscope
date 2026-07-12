# Security and privacy model

CipherScope traces are sensitive artifacts. Even without coefficients or keys,
source locations, control topology, rotation sets, timings, ciphertext lineage,
levels, and bootstrap placement may disclose model or protocol structure.

Default artifacts must not contain plaintext values, decrypted vectors,
ciphertext coefficients, key values, environment dumps, raw Python addresses,
object representations, or arbitrary exception messages. Error events retain
only the exception class. Source paths default to basename plus a content hash;
absolute paths and command arguments are not recorded.

Output directories are created with mode `0700` and files with `0600` where the
platform supports POSIX permissions. Writers refuse collisions and publish a
fully staged temporary directory using an atomic rename. HTML output escapes all
source and finding fields.

These controls reduce accidental disclosure; they do not make a trace public or
production-safe. Python cannot promise memory zeroization, process timing can be
sensitive, file permissions do not protect a compromised account, and no formal
side-channel analysis has been performed. The MVP bounds individual user metadata
strings and ancillary opaque text, but it does not yet enforce a total event or
trace-byte limit. Use synthetic/public development input, review every artifact
before sharing, and never treat CipherScope as a parameter security validator.
