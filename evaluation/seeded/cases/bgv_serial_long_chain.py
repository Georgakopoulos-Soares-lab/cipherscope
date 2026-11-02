"""Seeded positive: five BGV factors multiplied left to right in an associative region.

Mutation of bgv_serial_short_chain: two more factors, so the serial fold is four
multiplications deep where a balanced tree would need three.
Expected: multiplication.serial_reduction_review.v1 positive.
"""

from _kernel import check_exact, decode_integers, make_integer_context

import cipherscope

FACTORS = [2, 3, 1, 2, 1]

context, keys = make_integer_context(len(FACTORS), scheme="BGV", batch=4)

with cipherscope.trace(context, name="bgv_serial_long_chain") as session:
    cc = session.context
    ciphertexts = [
        cc.Encrypt(keys.publicKey, cc.MakePackedPlaintext([value] * 4)) for value in FACTORS
    ]
    with session.region("product", operator="multiply", associative=True, commutative=True):
        accumulator = ciphertexts[0]
        for factor in ciphertexts[1:]:
            accumulator = cc.EvalMult(accumulator, factor)
    result = cc.Decrypt(accumulator, keys.secretKey)

expected = 1
for value in FACTORS:
    expected *= value
check_exact(decode_integers(result, 1), [expected])
