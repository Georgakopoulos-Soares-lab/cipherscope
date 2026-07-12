#!/usr/bin/env python3
"""Encrypted squared Euclidean distance between two packed CKKS vectors.

Real OpenFHE program. Computes ``sum_i (a_i - b_i)^2`` with one subtraction, one
square, and a slot-wise ``EvalSum`` reduction.
"""

from openfhe import *

BATCH = 8

parameters = CCParamsCKKSRNS()
parameters.SetMultiplicativeDepth(3)
parameters.SetScalingModSize(50)
parameters.SetBatchSize(BATCH)

cc = GenCryptoContext(parameters)
cc.Enable(PKESchemeFeature.PKE)
cc.Enable(PKESchemeFeature.KEYSWITCH)
cc.Enable(PKESchemeFeature.LEVELEDSHE)
cc.Enable(PKESchemeFeature.ADVANCEDSHE)

keys = cc.KeyGen()
cc.EvalMultKeyGen(keys.secretKey)
cc.EvalSumKeyGen(keys.secretKey)

a = [1.0, 2.0, 3.0, 4.0, 5.0, 6.0, 7.0, 8.0]
b = [1.5, 2.5, 2.0, 4.0, 6.0, 5.0, 7.0, 9.0]
ciph_a = cc.Encrypt(keys.publicKey, cc.MakeCKKSPackedPlaintext(a))
ciph_b = cc.Encrypt(keys.publicKey, cc.MakeCKKSPackedPlaintext(b))

difference = cc.EvalSub(ciph_a, ciph_b)
squared = cc.EvalSquare(difference)
distance = cc.EvalSum(squared, BATCH)

result = cc.Decrypt(distance, keys.secretKey)
result.SetLength(1)
expected = sum((x - y) ** 2 for x, y in zip(a, b))
print(
    f"Squared distance: {result.GetRealPackedValue()[0]:.4f} (expected {expected:.4f})"
)
