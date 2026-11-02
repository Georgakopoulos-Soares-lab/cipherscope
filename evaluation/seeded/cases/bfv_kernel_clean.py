"""Clean kernel for the BFV seeded cases.

One rotation from one ciphertext version, every generated key used, and a
context whose configured depth the run actually spends.
Expected: rotation, keys and parameters all clean.
"""

from _kernel import check_exact, decode_integers, make_integer_context, rotate_left

import cipherscope

BATCH = 8
data = [1, 2, 3, 4, 5, 6, 7, 8]

context, keys = make_integer_context(1, scheme="BFV", batch=BATCH)

with cipherscope.trace(context, name="bfv_kernel_clean") as session:
    cc = session.context
    cc.EvalRotateKeyGen(keys.secretKey, [1])
    ciph = cc.Encrypt(keys.publicKey, cc.MakePackedPlaintext(data))
    rotated = cc.EvalRotate(ciph, 1)
    squared = cc.EvalMult(ciph, ciph)
    combined = cc.EvalAdd(squared, rotated)
    result = cc.Decrypt(combined, keys.secretKey)

shifted = rotate_left(data, 1, BATCH)
expected = [data[i] * data[i] + shifted[i] for i in range(BATCH)]
check_exact(decode_integers(result, BATCH), expected)
