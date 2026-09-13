"""Hard negative: three rotations whose inputs are three different ciphertext versions.

Same three indices as rotation_same_version, but each rotation reads a fresh
value (the running sum), so no two rotations share an input version and there
is nothing to hoist. Every generated key is used.
Expected: rotation.hoist_same_input.v1 clean; keys.unused_in_observed_run.v1 clean.
"""

from _kernel import check_close, decode, make_context

import cipherscope

BATCH = 8
data = [1.0, 2.0, 3.0, 4.0, 5.0, 6.0, 7.0, 8.0]

context, keys = make_context(1, batch=BATCH)

with cipherscope.trace(context, name="rotation_different_versions") as session:
    cc = session.context
    cc.EvalRotateKeyGen(keys.secretKey, [1, 2, 3])
    ciph = cc.Encrypt(keys.publicKey, cc.MakeCKKSPackedPlaintext(data))
    total = cc.EvalRotate(ciph, 1)
    total = cc.EvalAdd(total, ciph)
    total = cc.EvalRotate(total, 2)
    total = cc.EvalAdd(total, ciph)
    total = cc.EvalRotate(total, 3)
    result = cc.Decrypt(total, keys.secretKey)


def rotate(values, k):
    return [values[(i + k) % BATCH] for i in range(BATCH)]


step = [a + b for a, b in zip(rotate(data, 1), data)]
step = [a + b for a, b in zip(rotate(step, 2), data)]
check_close(decode(result, BATCH), rotate(step, 3))
