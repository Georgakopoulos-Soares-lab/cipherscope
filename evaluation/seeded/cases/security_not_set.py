"""Seeded positive: standard security-level enforcement disabled (HEStd_NotSet).

Mutation of security_default: the same computation, but the parameters set
HEStd_NotSet and a 64-slot ring, which OpenFHE accepts only because enforcement
is off. The parameters are declared to the session because the live context
cannot report its security level.
Expected: configuration.testing_only_security.v1 positive (warning).
"""

import openfhe

import cipherscope

parameters = openfhe.CCParamsCKKSRNS()
parameters.SetMultiplicativeDepth(1)
parameters.SetScalingModSize(40)
parameters.SetBatchSize(8)
parameters.SetSecurityLevel(openfhe.SecurityLevel.HEStd_NotSet)
parameters.SetRingDim(64)
context = openfhe.GenCryptoContext(parameters)
context.Enable(openfhe.PKESchemeFeature.PKE)
context.Enable(openfhe.PKESchemeFeature.LEVELEDSHE)
keys = context.KeyGen()

data = [1.0, 2.0, 3.0, 4.0, 5.0, 6.0, 7.0, 8.0]

with cipherscope.trace(context, name="security_not_set", parameters=parameters) as session:
    cc = session.context
    ciph = cc.Encrypt(keys.publicKey, cc.MakeCKKSPackedPlaintext(data))
    doubled = cc.EvalAdd(ciph, ciph)
    result = cc.Decrypt(doubled, keys.secretKey)

result.SetLength(8)
observed = [float(v) for v in result.GetRealPackedValue()[:8]]
if max(abs(a - 2 * b) for a, b in zip(observed, data)) > 1e-2:
    raise RuntimeError(f"numerical mismatch: {observed}")
