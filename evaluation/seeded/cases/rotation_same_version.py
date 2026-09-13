"""Seeded positive: three distinct rotations of one ciphertext version.

Mutation of rotation_kernel_clean: rotate by 1, 2, 3 instead of once, and
generate an extra rotation key (5) that this run never uses.
Expected: rotation.hoist_same_input.v1 positive; keys.unused_in_observed_run.v1 positive.
"""

from _kernel import check_close, decode, make_context

import cipherscope

BATCH = 8
data = [1.0, 2.0, 3.0, 4.0, 5.0, 6.0, 7.0, 8.0]

context, keys = make_context(1, batch=BATCH)

with cipherscope.trace(context, name="rotation_same_version") as session:
    cc = session.context
    cc.EvalRotateKeyGen(keys.secretKey, [1, 2, 3, 5])
    ciph = cc.Encrypt(keys.publicKey, cc.MakeCKKSPackedPlaintext(data))
    rotated_1 = cc.EvalRotate(ciph, 1)
    rotated_2 = cc.EvalRotate(ciph, 2)
    rotated_3 = cc.EvalRotate(ciph, 3)
    combined = cc.EvalAdd(cc.EvalAdd(rotated_1, rotated_2), rotated_3)
    result = cc.Decrypt(combined, keys.secretKey)

expected = [
    data[(i + 1) % BATCH] + data[(i + 2) % BATCH] + data[(i + 3) % BATCH]
    for i in range(BATCH)
]
check_close(decode(result, BATCH), expected)
