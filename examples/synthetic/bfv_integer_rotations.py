#!/usr/bin/env python3
"""Combine several distinct rotations of one encrypted integer vector (BFV).

Real OpenFHE program, the integer counterpart of repeated_rotations.py. It
rotates the same recorded ciphertext version by 1, 2 and 3 and sums them, which
is the shape the repeated-rotation analyzer looks for. A fourth rotation key
(index 5) is generated but never used, so the observed-run key analyzer reports
it as unused in this run.

Two things differ from the CKKS example and are the point of having this one.
BFV defaults to BV key switching rather than HYBRID, which the hoisting rule
accepts because ROT-04 shows a shared precompute reproduces a regular rotation
exactly under BV. And BFV rotation shifts left with zero fill instead of
wrapping the batch, so the expected values below are not a cyclic rotation.
"""

from openfhe import *

BATCH = 8

parameters = CCParamsBFVRNS()
parameters.SetPlaintextModulus(65537)
parameters.SetMultiplicativeDepth(1)
parameters.SetBatchSize(BATCH)

cc = GenCryptoContext(parameters)
cc.Enable(PKESchemeFeature.PKE)
cc.Enable(PKESchemeFeature.KEYSWITCH)
cc.Enable(PKESchemeFeature.LEVELEDSHE)

keys = cc.KeyGen()
# Generate keys for 1, 2, 3 (all used below) and 5 (never used this run).
cc.EvalRotateKeyGen(keys.secretKey, [1, 2, 3, 5])

data = [1, 2, 3, 4, 5, 6, 7, 8]
ciph = cc.Encrypt(keys.publicKey, cc.MakePackedPlaintext(data))

rotated_1 = cc.EvalRotate(ciph, 1)
rotated_2 = cc.EvalRotate(ciph, 2)
rotated_3 = cc.EvalRotate(ciph, 3)
combined = cc.EvalAdd(cc.EvalAdd(rotated_1, rotated_2), rotated_3)

result = cc.Decrypt(combined, keys.secretKey)
result.SetLength(BATCH)
observed = [int(value) for value in result.GetPackedValue()[:BATCH]]
expected = [
    sum(data[i + amount] if i + amount < BATCH else 0 for amount in (1, 2, 3))
    for i in range(BATCH)
]
print("BFV: sum of rotations by 1, 2, 3 of one ciphertext (shift with zero fill)")
print(f"observed: {observed}")
print(f"expected: {expected}")
