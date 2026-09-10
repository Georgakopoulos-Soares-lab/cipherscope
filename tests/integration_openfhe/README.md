# Pinned OpenFHE integration gate

These tests are separate from the fake-backend unit suite. They run
only when the official `openfhe` Python distribution is installed and must target
exactly version `1.5.1.0` before their results support a compatibility claim.

The current scaffold checks the wrapper pin. The remaining feasibility suite must
add real CKKS construction, traced/untraced numerical equivalence, proxy-boundary,
metadata-getter, identity/alias, rotation, and bootstrap tests on the primary Linux
CPU environment. A skipped suite is not a passed feasibility gate.
