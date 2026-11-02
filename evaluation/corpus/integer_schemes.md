# Integer-scheme corpus: upstream OpenFHE Python examples

The CKKS evidence rests on an independently authored corpus
(`python-log-reg-examples`, 4 workloads). This is the BFV/BGV counterpart:
the OpenFHE project's own Python examples, which ship **inside the pinned
wrapper commit** `4f13e2c3a7e35f73f4816904dabd3a3db47b6e51` — the same commit
every lane already pins, so the corpus needs no separate pin.

Run on the `emulated-docker-py311` lane on 2026-11-01. Programs were staged
under the gitignored `cipherscope-results/` tree and traced through
`examples/profile_unmodified.py` in **strict** mode; nothing is vendored into
the repository.

## Result

| Program | Scheme | Preflight | Traced calls | Class | Findings |
|---|---|---|---|---|---|
| `simple-integers.py` | BFV | clean | 17 semantic (23 events) | `COMPLETE` | rotation hoisting, depth critical path |
| `simple-integers-bgvrns.py` | BGV | clean | 17 semantic (23 events) | `COMPLETE` | rotation hoisting, depth critical path |
| `threshold-fhe.py` | BGV | clean | — | failed | `MultipartyKeyGen` not in the manifest |
| `threshold-fhe-5p.py` | BFV | clean | — | failed | `MultipartyKeyGen` not in the manifest |
| `pre-buffer.py` | BFV | clean | — | failed | `ReKeyGen` not in the manifest |

**2 of 5 trace `COMPLETE`.** Report that fraction, not "2 workloads traced".

## What the two complete runs found

Both fire `rotation.hoist_same_input.v1` with `confidence: measured`: the
program rotates one recorded ciphertext version (`ct_0001:v0`) by four
distinct indices `[-2, -1, 1, 2]`. This is a real finding on code CipherScope's
authors did not write.

The BFV case is only assessable because of `ROT-04`. BFV defaults to **BV**
key switching, and the hoisting rule previously accepted HYBRID only, so
before that check was added the rule would have declined this program as
"not a validated key-switch technique". The BGV context defaults to HYBRID and
would have been assessed either way.

Note the depth finding differs by scheme on the same program: BGV reports
`confidence: inferred`, BFV `unknown`, because BFV has no level ladder for the
level-use half of the metric.

## The coverage boundary this exposed

Running the corpus found three gaps, in two classes.

**Fixed — read-only context getters that were simply missing.**
`GetPlaintextModulus`, `GetDigitSize` and `GetModulus` are configuration
getters that touch no ciphertext, and `snapshot_context` already reads them
internally, so rejecting a program for calling them was an omission rather
than a judgement. They are now in `allowed_nonsemantic_calls`. Before the fix
`GetPlaintextModulus` alone failed three of the five programs outright.

**Not fixed — two whole feature families are outside the manifest.**
`MultipartyKeyGen` (threshold FHE) and `ReKeyGen` (proxy re-encryption) are
genuine semantic operations, not getters. Supporting them means modelling
multiparty key generation and re-encryption keys, which is a feature decision
with its own evidence requirements, not a classification fix. Strict mode
refusing them is the designed behaviour: the operations are named in
`coverage.unsupported_operations` rather than silently forwarded.

The honest statement for the paper is that the manifest covers the core
PKE / leveled-SHE surface on all three schemes, and that threshold FHE and
proxy re-encryption are unsupported and reported as such.

## Reproducing

```bash
git init /tmp/ofhe-py && cd /tmp/ofhe-py
git remote add origin https://github.com/openfheorg/openfhe-python.git
git fetch --depth 1 origin 4f13e2c3a7e35f73f4816904dabd3a3db47b6e51
git checkout --detach FETCH_HEAD
# then, from the cipherscope checkout, for each examples/pke/<name>.py:
python -m cipherscope preflight <staged>.py
python -m cipherscope run --output <out> examples/profile_unmodified.py -- <staged>.py
python -m cipherscope coverage <out>...
```
