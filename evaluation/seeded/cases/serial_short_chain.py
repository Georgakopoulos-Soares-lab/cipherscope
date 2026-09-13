"""Hard negative: three factors in an associative region, only two multiplications.

The region is declared associative, so the rule does assess it, but a two-step
fold is already as shallow as a balanced tree; there is nothing to reorder.
Expected: multiplication.serial_reduction_review.v1 clean.
"""

from _kernel import check_close, decode, make_context

import cipherscope

FACTORS = [1.10, 1.05, 0.95]

context, keys = make_context(len(FACTORS), batch=4)

with cipherscope.trace(context, name="serial_short_chain") as session:
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
