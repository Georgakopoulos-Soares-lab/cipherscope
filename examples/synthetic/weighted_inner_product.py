#!/usr/bin/env python3
"""Encrypted weighted inner product of two packed CKKS vectors.

Real OpenFHE program. ``EvalInnerProduct`` multiplies element-wise and then sums
with log-step rotations, so it needs ADVANCEDSHE and summation keys.
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

features = [0.1, 0.2, 0.3, 0.4, 0.5, 0.6, 0.7, 0.8]
weights = [1.0, 0.0, 2.0, 0.0, 3.0, 0.0, 4.0, 0.0]
ciph_features = cc.Encrypt(keys.publicKey, cc.MakeCKKSPackedPlaintext(features))
ciph_weights = cc.Encrypt(keys.publicKey, cc.MakeCKKSPackedPlaintext(weights))

ciph_product = cc.EvalInnerProduct(ciph_features, ciph_weights, BATCH)

result = cc.Decrypt(ciph_product, keys.secretKey)
result.SetLength(1)
expected = sum(f * w for f, w in zip(features, weights))
print(
    f"Weighted inner product: {result.GetRealPackedValue()[0]:.4f} (expected {expected:.4f})"
)
