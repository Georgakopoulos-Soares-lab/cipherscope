"""Python twin of tests/cpp/fixtures/aliasing.cpp: handle copies and temporaries."""

from openfhe import *

parameters = CCParamsCKKSRNS()
parameters.SetMultiplicativeDepth(1)
parameters.SetScalingModSize(50)
parameters.SetBatchSize(8)
cc = GenCryptoContext(parameters)
cc.Enable(PKESchemeFeature.PKE)
cc.Enable(PKESchemeFeature.KEYSWITCH)
cc.Enable(PKESchemeFeature.LEVELEDSHE)
keys = cc.KeyGen()

x = [1.0, 2.0, 3.0, 4.0, 5.0, 6.0, 7.0, 8.0]
a = cc.Encrypt(keys.publicKey, cc.MakeCKKSPackedPlaintext(x))
b = a                                  # same object
total = cc.EvalAdd(a, b)               # one distinct input
kept = [total]
again = cc.EvalAdd(kept[0], a)
for _ in range(3):
    temporary = cc.EvalAdd(a, a)       # a new object each iteration
    del temporary
last = cc.EvalAdd(again, a)

out = cc.Decrypt(last, keys.secretKey)
out.SetLength(8)
print(f"last[0] = {int(out.GetRealPackedValue()[0] + 0.5)} (expected 4)")
