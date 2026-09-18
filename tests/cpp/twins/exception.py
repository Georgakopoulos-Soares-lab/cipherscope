"""Python twin of tests/cpp/fixtures/exception.cpp: a failing OpenFHE call."""

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
cc.EvalRotateKeyGen(keys.secretKey, [1])

x = [1.0, 2.0, 3.0, 4.0, 5.0, 6.0, 7.0, 8.0]
a = cc.Encrypt(keys.publicKey, cc.MakeCKKSPackedPlaintext(x))
caught = 0
try:
    bad = cc.EvalRotate(a, 4)          # no key for index 4: raises
except Exception:
    caught = 1
good = cc.EvalRotate(a, 1)
out = cc.Decrypt(good, keys.secretKey)
out.SetLength(8)
print(f"caught={caught} good[0]={int(out.GetRealPackedValue()[0] + 0.5)}")
raise SystemExit(0 if caught == 1 else 3)
