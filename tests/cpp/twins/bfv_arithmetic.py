"""Python twin of tests/cpp/fixtures/bfv_arithmetic.cpp (BFV integer arithmetic)."""

from openfhe import *

parameters = CCParamsBFVRNS()
parameters.SetPlaintextModulus(65537)
parameters.SetMultiplicativeDepth(2)
cc = GenCryptoContext(parameters)
cc.Enable(PKESchemeFeature.PKE)
cc.Enable(PKESchemeFeature.KEYSWITCH)
cc.Enable(PKESchemeFeature.LEVELEDSHE)
keys = cc.KeyGen()
cc.EvalMultKeyGen(keys.secretKey)
cc.EvalRotateKeyGen(keys.secretKey, [1])

x = [1, 2, 3, 4, 5, 6, 7, 8]
y = [8, 7, 6, 5, 4, 3, 2, 1]
px = cc.MakePackedPlaintext(x)
py = cc.MakePackedPlaintext(y)
a = cc.Encrypt(keys.publicKey, px)
b = cc.Encrypt(keys.publicKey, py)

total_sum = cc.EvalAdd(a, b)          # 9 everywhere
product = cc.EvalMult(a, b)           # 8, 14, 18, 20, 20, 18, 14, 8
rotated = cc.EvalRotate(product, 1)
total = cc.EvalAdd(total_sum, rotated)
result = cc.EvalSub(total, a)

out = cc.Decrypt(result, keys.secretKey)
out.SetLength(8)
print(f"result[0] = {out.GetPackedValue()[0]} (expected 22)")
