"""Hard negative: every BFV rotation reads a different ciphertext version.

Mutation of bfv_kernel_clean: three rotations again, but each one rotates the
running sum rather than the original ciphertext, so no shared precompute
exists. Every generated key is used.
Expected: rotation.hoist_same_input.v1 clean; keys.unused_in_observed_run.v1 clean.
"""

from _kernel import check_exact, decode_integers, make_integer_context, rotate_left

import cipherscope

BATCH = 8
data = [1, 2, 3, 4, 5, 6, 7, 8]

context, keys = make_integer_context(1, scheme="BFV", batch=BATCH)

with cipherscope.trace(context, name="bfv_rotation_different_versions") as session:
    cc = session.context
    cc.EvalRotateKeyGen(keys.secretKey, [1, 2, 3])
    ciph = cc.Encrypt(keys.publicKey, cc.MakePackedPlaintext(data))
    accumulator = ciph
    for amount in (1, 2, 3):
        accumulator = cc.EvalRotate(accumulator, amount)
    result = cc.Decrypt(accumulator, keys.secretKey)

expected = data
for amount in (1, 2, 3):
    expected = rotate_left(expected, amount, BATCH)
check_exact(decode_integers(result, BATCH), expected)
