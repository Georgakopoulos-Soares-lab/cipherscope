#!/usr/bin/env python3
"""Encrypted 4x4 matrix-vector product using the diagonal (Halevi-Shoup) method.

Real OpenFHE program. Each generalized diagonal of the matrix is multiplied by a
rotation of the encrypted vector, and the partial products are accumulated. This
is a realistic use of several distinct rotations of one ciphertext.
"""

from openfhe import *

DIM = 4

parameters = CCParamsCKKSRNS()
parameters.SetMultiplicativeDepth(2)
parameters.SetScalingModSize(50)
parameters.SetBatchSize(DIM)

cc = GenCryptoContext(parameters)
cc.Enable(PKESchemeFeature.PKE)
cc.Enable(PKESchemeFeature.KEYSWITCH)
cc.Enable(PKESchemeFeature.LEVELEDSHE)

keys = cc.KeyGen()
cc.EvalMultKeyGen(keys.secretKey)
cc.EvalRotateKeyGen(keys.secretKey, [1, 2, 3])

matrix = [
    [1.0, 2.0, 0.0, 0.0],
    [0.0, 3.0, 1.0, 0.0],
    [0.0, 0.0, 2.0, 1.0],
    [1.0, 0.0, 0.0, 4.0],
]
vector = [1.0, 2.0, 3.0, 4.0]

# Generalized diagonals: diag_k[i] = matrix[i][(i + k) % DIM]
diagonals = [[matrix[i][(i + k) % DIM] for i in range(DIM)] for k in range(DIM)]

ciph_vector = cc.Encrypt(keys.publicKey, cc.MakeCKKSPackedPlaintext(vector))

accumulator = None
for k in range(DIM):
    rotated = ciph_vector if k == 0 else cc.EvalRotate(ciph_vector, k)
    diag_plaintext = cc.MakeCKKSPackedPlaintext(diagonals[k])
    term = cc.EvalMult(rotated, diag_plaintext)
    accumulator = term if accumulator is None else cc.EvalAdd(accumulator, term)

result = cc.Decrypt(accumulator, keys.secretKey)
result.SetLength(DIM)
expected = [sum(matrix[i][j] * vector[j] for j in range(DIM)) for i in range(DIM)]
observed = [round(v, 4) for v in result.GetRealPackedValue()[:DIM]]
print("Matrix-vector product (diagonal method)")
print(f"observed: {observed}")
print(f"expected: {[round(v, 4) for v in expected]}")
