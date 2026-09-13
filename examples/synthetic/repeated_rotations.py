#!/usr/bin/env python3
"""Combine several distinct rotations of one encrypted vector.

Real OpenFHE program. It rotates the same recorded ciphertext version by indices
1, 2, and 3 and sums them, which is exactly the shape CipherScope's
repeated-rotation analyzer looks for. A fourth rotation key (index 5) is generated
but never used, so the observed-run key analyzer reports it as unused in this run.
"""

from openfhe import *

BATCH = 8

parameters = CCParamsCKKSRNS()
parameters.SetMultiplicativeDepth(1)
parameters.SetScalingModSize(50)
parameters.SetBatchSize(BATCH)

cc = GenCryptoContext(parameters)
cc.Enable(PKESchemeFeature.PKE)
cc.Enable(PKESchemeFeature.KEYSWITCH)
cc.Enable(PKESchemeFeature.LEVELEDSHE)

keys = cc.KeyGen()
# Generate keys for 1, 2, 3 (all used below) and 5 (never used this run).
cc.EvalRotateKeyGen(keys.secretKey, [1, 2, 3, 5])

data = [1.0, 2.0, 3.0, 4.0, 5.0, 6.0, 7.0, 8.0]
ciph = cc.Encrypt(keys.publicKey, cc.MakeCKKSPackedPlaintext(data))

rotated_1 = cc.EvalRotate(ciph, 1)
rotated_2 = cc.EvalRotate(ciph, 2)
rotated_3 = cc.EvalRotate(ciph, 3)
combined = cc.EvalAdd(cc.EvalAdd(rotated_1, rotated_2), rotated_3)

result = cc.Decrypt(combined, keys.secretKey)
result.SetLength(BATCH)
observed = [round(v, 4) for v in result.GetRealPackedValue()[:BATCH]]
expected = [
    round(data[(i + 1) % BATCH] + data[(i + 2) % BATCH] + data[(i + 3) % BATCH], 4)
    for i in range(BATCH)
]
print("Sum of rotations by 1, 2, 3 of one ciphertext")
print(f"observed: {observed}")
print(f"expected: {expected}")
