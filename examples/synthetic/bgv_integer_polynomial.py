#!/usr/bin/env python3
"""Evaluate an integer polynomial on packed data under BGV.

Real OpenFHE program. It computes 3x^3 + 2x^2 + 5 by Horner's method on an
encrypted integer vector, using three of the six multiplicative levels the
context was configured for, so the depth critical path and the observed
depth-headroom rule both have something to measure.

BGV is included in the gallery because it spends levels exactly as CKKS does
(one per multiplication) while being an exact scheme: the result below is
checked for equality, not against a tolerance. Arithmetic is modulo the
plaintext modulus, and OpenFHE returns the signed representative, so the
expected values are reduced the same way.
"""

from openfhe import *

BATCH = 8
PLAINTEXT_MODULUS = 65537

parameters = CCParamsBGVRNS()
parameters.SetPlaintextModulus(PLAINTEXT_MODULUS)
parameters.SetMultiplicativeDepth(6)
parameters.SetBatchSize(BATCH)

cc = GenCryptoContext(parameters)
cc.Enable(PKESchemeFeature.PKE)
cc.Enable(PKESchemeFeature.KEYSWITCH)
cc.Enable(PKESchemeFeature.LEVELEDSHE)

keys = cc.KeyGen()
cc.EvalMultKeyGen(keys.secretKey)

data = [1, 2, 3, 4, 5, 6, 7, 8]
ciph = cc.Encrypt(keys.publicKey, cc.MakePackedPlaintext(data))

# Horner: ((3x + 2)x + 0)x + 5, three ciphertext-plaintext scalings and three
# ciphertext-ciphertext multiplications by x.
accumulator = cc.EvalMult(ciph, cc.MakePackedPlaintext([3] * BATCH))
accumulator = cc.EvalAdd(accumulator, cc.MakePackedPlaintext([2] * BATCH))
accumulator = cc.EvalMult(accumulator, ciph)
accumulator = cc.EvalMult(accumulator, ciph)
accumulator = cc.EvalAdd(accumulator, cc.MakePackedPlaintext([5] * BATCH))

result = cc.Decrypt(accumulator, keys.secretKey)
result.SetLength(BATCH)
observed = [int(value) for value in result.GetPackedValue()[:BATCH]]


def signed(value: int) -> int:
    reduced = value % PLAINTEXT_MODULUS
    return reduced if reduced < PLAINTEXT_MODULUS // 2 else reduced - PLAINTEXT_MODULUS


expected = [signed(3 * x**3 + 2 * x**2 + 5) for x in data]
print("BGV: 3x^3 + 2x^2 + 5 by Horner on packed integers")
print(f"observed: {observed}")
print(f"expected: {expected}")
