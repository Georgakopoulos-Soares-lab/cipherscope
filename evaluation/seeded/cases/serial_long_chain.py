"""Seeded positive: five factors multiplied left to right inside an associative region.

Mutation of serial_short_chain: two more factors, so the serial fold is four
multiplications deep where a balanced tree would need three.
Expected: multiplication.serial_reduction_review.v1 positive.
"""

from _kernel import check_close, decode, make_context

import cipherscope

FACTORS = [1.10, 1.05, 0.95, 1.20, 0.90]

context, keys = make_context(len(FACTORS), batch=4)

with cipherscope.trace(context, name="serial_long_chain") as session:
    cc = session.context
    ciphertexts = [
        cc.Encrypt(keys.publicKey, cc.MakeCKKSPackedPlaintext([value] * 4)) for value in FACTORS
    ]
    with session.region("product", operator="multiply", associative=True, commutative=True):
        accumulator = ciphertexts[0]
        for factor in ciphertexts[1:]:
            accumulator = cc.EvalMult(accumulator, factor)
    result = cc.Decrypt(accumulator, keys.secretKey)

expected = 1.0
for value in FACTORS:
    expected *= value
check_close(decode(result, 1), [expected])
