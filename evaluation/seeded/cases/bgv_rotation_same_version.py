"""Seeded positive: three distinct rotations of one BGV ciphertext version.

Mutation of bgv_kernel_clean: rotate by 1, 2 and 3 instead of once, and
generate an extra rotation key (5) that this run never uses.
Expected: rotation.hoist_same_input.v1 positive; keys.unused_in_observed_run.v1 positive.
"""

from _kernel import check_exact, decode_integers, make_integer_context, rotate_left

import cipherscope

BATCH = 8
data = [1, 2, 3, 4, 5, 6, 7, 8]

context, keys = make_integer_context(1, scheme="BGV", batch=BATCH)

with cipherscope.trace(context, name="bgv_rotation_same_version") as session:
    cc = session.context
    cc.EvalRotateKeyGen(keys.secretKey, [1, 2, 3, 5])
    ciph = cc.Encrypt(keys.publicKey, cc.MakePackedPlaintext(data))
    rotated_1 = cc.EvalRotate(ciph, 1)
    rotated_2 = cc.EvalRotate(ciph, 2)
    rotated_3 = cc.EvalRotate(ciph, 3)
    combined = cc.EvalAdd(cc.EvalAdd(rotated_1, rotated_2), rotated_3)
    result = cc.Decrypt(combined, keys.secretKey)

expected = [
    sum(rotate_left(data, amount, BATCH)[i] for amount in (1, 2, 3))
    for i in range(BATCH)
]
check_exact(decode_integers(result, BATCH), expected)
