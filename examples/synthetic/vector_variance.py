#!/usr/bin/env python3
"""Encrypted mean and variance of a packed CKKS vector.

Real OpenFHE program. Uses ``EvalSum`` for the slot-wise total and one square on
both the values and their mean, so it exercises a small nonlinear depth path.
"""

from openfhe import *

BATCH = 8

parameters = CCParamsCKKSRNS()
parameters.SetMultiplicativeDepth(4)
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

data = [2.0, 4.0, 4.0, 4.0, 5.0, 5.0, 7.0, 9.0]
ciph = cc.Encrypt(keys.publicKey, cc.MakeCKKSPackedPlaintext(data))

inverse_n = [1.0 / BATCH] * BATCH
inverse_plaintext = cc.MakeCKKSPackedPlaintext(inverse_n)

# mean = (1/n) * sum(x); mean_of_squares = (1/n) * sum(x^2)
mean = cc.EvalMult(cc.EvalSum(ciph, BATCH), inverse_plaintext)
squares = cc.EvalSquare(ciph)
mean_of_squares = cc.EvalMult(cc.EvalSum(squares, BATCH), inverse_plaintext)

# variance = mean_of_squares - mean^2
variance = cc.EvalSub(mean_of_squares, cc.EvalSquare(mean))

mean_result = cc.Decrypt(mean, keys.secretKey)
variance_result = cc.Decrypt(variance, keys.secretKey)
mean_result.SetLength(1)
variance_result.SetLength(1)

expected_mean = sum(data) / BATCH
expected_var = sum((x - expected_mean) ** 2 for x in data) / BATCH
print(f"Mean: {mean_result.GetRealPackedValue()[0]:.4f} (expected {expected_mean:.4f})")
print(
    f"Variance: {variance_result.GetRealPackedValue()[0]:.4f} "
    f"(expected {expected_var:.4f})"
)
