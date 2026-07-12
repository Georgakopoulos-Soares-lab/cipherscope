#!/usr/bin/env python3
"""Evaluate a degree-4 polynomial on encrypted data with Horner's method.

Real OpenFHE program. Horner's rule is a serial chain of multiply-then-add
steps, which produces a clear nonlinear-depth critical path.
"""

from openfhe import *

# p(x) = 1 + 2x + 3x^2 + 4x^3 + 5x^4
COEFFS = [1.0, 2.0, 3.0, 4.0, 5.0]

parameters = CCParamsCKKSRNS()
parameters.SetMultiplicativeDepth(len(COEFFS))  # one level per Horner step
parameters.SetScalingModSize(50)
parameters.SetScalingTechnique(ScalingTechnique.FLEXIBLEAUTO)

cc = GenCryptoContext(parameters)
cc.Enable(PKESchemeFeature.PKE)
cc.Enable(PKESchemeFeature.KEYSWITCH)
cc.Enable(PKESchemeFeature.LEVELEDSHE)

keys = cc.KeyGen()
cc.EvalMultKeyGen(keys.secretKey)

data = [-1.0, -0.5, 0.0, 0.5, 1.0]
ciph = cc.Encrypt(keys.publicKey, cc.MakeCKKSPackedPlaintext(data))

# Horner: acc = (((c4*x + c3)*x + c2)*x + c1)*x + c0
acc = cc.EvalAdd(cc.EvalMult(ciph, COEFFS[-1]), COEFFS[-2])
for coeff in reversed(COEFFS[:-2]):
    acc = cc.EvalMult(acc, ciph)
    acc = cc.EvalAdd(acc, coeff)

result = cc.Decrypt(acc, keys.secretKey)
result.SetLength(len(data))


def horner(x: float) -> float:
    value = 0.0
    for coeff in reversed(COEFFS):
        value = value * x + coeff
    return value


expected = [horner(x) for x in data]
observed = [round(v, 4) for v in result.GetRealPackedValue()[: len(data)]]
print("Polynomial p(x) = 1 + 2x + 3x^2 + 4x^3 + 5x^4")
print(f"observed: {observed}")
print(f"expected: {[round(v, 4) for v in expected]}")
