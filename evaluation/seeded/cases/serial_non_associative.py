"""Near miss: the same five-factor serial fold, but the region is not declared associative.

Without the user's associativity assertion CipherScope must not propose a
different evaluation order, however long the chain is.
Expected: multiplication.serial_reduction_review.v1 not_applicable.
"""

from _kernel import check_close, decode, make_context

import cipherscope

FACTORS = [1.10, 1.05, 0.95, 1.20, 0.90]

context, keys = make_context(len(FACTORS), batch=4)

with cipherscope.trace(context, name="serial_non_associative") as session:
    cc = session.context
    ciphertexts = [
        cc.Encrypt(keys.publicKey, cc.MakeCKKSPackedPlaintext([value] * 4)) for value in FACTORS
    ]
    with session.region("product", operator="multiply", associative=False):
        accumulator = ciphertexts[0]
        for factor in ciphertexts[1:]:
            accumulator = cc.EvalMult(accumulator, factor)
    result = cc.Decrypt(accumulator, keys.secretKey)

expected = 1.0
for value in FACTORS:
    expected *= value
check_close(decode(result, 1), [expected])
