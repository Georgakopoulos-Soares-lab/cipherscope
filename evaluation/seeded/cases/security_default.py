"""Hard negative: the default 128-bit classic security level, declared.

Same computation as security_not_set with OpenFHE's default security level;
the rule must assess the declared level and stay clean.
Expected: configuration.testing_only_security.v1 clean.
"""

import openfhe

import cipherscope

parameters = openfhe.CCParamsCKKSRNS()
parameters.SetMultiplicativeDepth(1)
parameters.SetScalingModSize(50)
parameters.SetBatchSize(8)
context = openfhe.GenCryptoContext(parameters)
context.Enable(openfhe.PKESchemeFeature.PKE)
context.Enable(openfhe.PKESchemeFeature.LEVELEDSHE)
keys = context.KeyGen()

data = [1.0, 2.0, 3.0, 4.0, 5.0, 6.0, 7.0, 8.0]

with cipherscope.trace(context, name="security_default", parameters=parameters) as session:
    cc = session.context
    ciph = cc.Encrypt(keys.publicKey, cc.MakeCKKSPackedPlaintext(data))
    doubled = cc.EvalAdd(ciph, ciph)
    result = cc.Decrypt(doubled, keys.secretKey)

result.SetLength(8)
observed = [float(v) for v in result.GetRealPackedValue()[:8]]
if max(abs(a - 2 * b) for a, b in zip(observed, data)) > 1e-2:
    raise RuntimeError(f"numerical mismatch: {observed}")
