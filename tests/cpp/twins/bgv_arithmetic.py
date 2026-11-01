"""Python twin of tests/cpp/fixtures/bgv_arithmetic.cpp (BGV integer arithmetic)."""

from openfhe import *

parameters = CCParamsBGVRNS()
parameters.SetPlaintextModulus(65537)
parameters.SetMultiplicativeDepth(2)
cc = GenCryptoContext(parameters)
cc.Enable(PKESchemeFeature.PKE)
cc.Enable(PKESchemeFeature.KEYSWITCH)
cc.Enable(PKESchemeFeature.LEVELEDSHE)
cc.Enable(PKESchemeFeature.ADVANCEDSHE)
keys = cc.KeyGen()
cc.EvalMultKeyGen(keys.secretKey)

x = [1, 2, 3, 4, 5, 6, 7, 8]
y = [8, 7, 6, 5, 4, 3, 2, 1]
z = [1] * 8
a = cc.Encrypt(keys.publicKey, cc.MakePackedPlaintext(x))
b = cc.Encrypt(keys.publicKey, cc.MakePackedPlaintext(y))
c = cc.Encrypt(keys.publicKey, cc.MakePackedPlaintext(z))

many = [a, b, c]
total_sum = cc.EvalAddMany(many)          # 10 everywhere
product = cc.EvalMult(a, b)               # 8, 14, 18, ...
negated = cc.EvalNegate(c)                # -1
result = cc.EvalSub(product, negated)     # product + 1
total = cc.EvalSub(result, total_sum)     # product + 1 - 10

out = cc.Decrypt(total, keys.secretKey)
out.SetLength(8)
print(f"total[1] = {out.GetPackedValue()[1]} (expected 5)")
