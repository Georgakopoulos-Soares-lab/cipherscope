"""Python twin of tests/cpp/fixtures/many_and_series.cpp.

Vector-input composites (EvalAddMany, EvalMultMany, EvalLinearWSum), a
Chebyshev series and the EvalAtIndex / EvalAtIndexKeyGen aliases. Both
frontends must record the aliases under their canonical names (EvalRotate,
EvalRotateKeyGen) and the vector composites with every element as an input.
"""

from openfhe import *

parameters = CCParamsCKKSRNS()
parameters.SetMultiplicativeDepth(6)
parameters.SetScalingModSize(50)
parameters.SetBatchSize(8)
cc = GenCryptoContext(parameters)
cc.Enable(PKESchemeFeature.PKE)
cc.Enable(PKESchemeFeature.KEYSWITCH)
cc.Enable(PKESchemeFeature.LEVELEDSHE)
cc.Enable(PKESchemeFeature.ADVANCEDSHE)
keys = cc.KeyGen()
cc.EvalMultKeyGen(keys.secretKey)
cc.EvalAtIndexKeyGen(keys.secretKey, [1])   # alias of EvalRotateKeyGen

x = [1.0, 2.0, 3.0, 4.0, 5.0, 6.0, 7.0, 8.0]
y = [8.0, 7.0, 6.0, 5.0, 4.0, 3.0, 2.0, 1.0]
z = [1.0] * 8
a = cc.Encrypt(keys.publicKey, cc.MakeCKKSPackedPlaintext(x))
b = cc.Encrypt(keys.publicKey, cc.MakeCKKSPackedPlaintext(y))
c = cc.Encrypt(keys.publicKey, cc.MakeCKKSPackedPlaintext(z))

many = [a, b, c]
total_sum = cc.EvalAddMany(many)                        # a + b + c
product = cc.EvalMultMany(many)                         # a * b * c
weighted = cc.EvalLinearWSum(many, [0.5, 0.25, 0.25])   # 0.5a + 0.25b + 0.25c
series = cc.EvalChebyshevSeries(a, [0.5, 0.25, 0.125, 0.0625], -8.0, 8.0)  # degree 3
rotated = cc.EvalAtIndex(total_sum, 1)                  # alias of EvalRotate
total = cc.EvalAdd(rotated, product)

out = cc.Decrypt(total, keys.secretKey)
out.SetLength(8)
print(f"total[0] = {int(out.GetRealPackedValue()[0] + 0.5)} (expected 18)")
out = cc.Decrypt(weighted, keys.secretKey)
out.SetLength(8)
print(f"weighted[0] = {int(out.GetRealPackedValue()[0] * 4 + 0.5)}/4 (expected 11/4)")
