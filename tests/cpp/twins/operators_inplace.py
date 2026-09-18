"""Python twin of tests/cpp/fixtures/operators_inplace.cpp.

The C++ program uses operator overloads (a * b, a + b, c += d, -a); the Python
proxy cannot observe the binding's operators (a documented gap), so the twin
spells the same operations as context calls. The semantic trace must match.
"""

from openfhe import *

parameters = CCParamsCKKSRNS()
parameters.SetMultiplicativeDepth(3)
parameters.SetScalingModSize(50)
parameters.SetBatchSize(8)
cc = GenCryptoContext(parameters)
cc.Enable(PKESchemeFeature.PKE)
cc.Enable(PKESchemeFeature.KEYSWITCH)
cc.Enable(PKESchemeFeature.LEVELEDSHE)
keys = cc.KeyGen()
cc.EvalMultKeyGen(keys.secretKey)

x = [1.0, 2.0, 3.0, 4.0, 5.0, 6.0, 7.0, 8.0]
y = [8.0, 7.0, 6.0, 5.0, 4.0, 3.0, 2.0, 1.0]
w = [0.5] * 8
px = cc.MakeCKKSPackedPlaintext(x)
py = cc.MakeCKKSPackedPlaintext(y)
pw = cc.MakeCKKSPackedPlaintext(w)
a = cc.Encrypt(keys.publicKey, px)
b = cc.Encrypt(keys.publicKey, py)

c = cc.EvalMult(a, b)          # a * b
d = cc.EvalAdd(a, b)           # a + b
c = cc.EvalAdd(c, d)           # c += d
cc.EvalAddInPlace(d, a)        # in place
cc.RescaleInPlace(c)           # in place
e = cc.EvalNegate(a)           # -a
f = cc.EvalMult(a, pw)         # ct * pt

out = cc.Decrypt(c, keys.secretKey)
out.SetLength(8)
print(f"c[0] = {int(out.GetRealPackedValue()[0] + 0.5)} (expected 17)")
