"""Seeded positive: BGV with standard security enforcement disabled (HEStd_NotSet).

Mutation of bgv_security_default: the same computation, but the parameters set
HEStd_NotSet and a 64-slot ring, which OpenFHE accepts only because enforcement
is off. The parameters are declared to the session because the live context
cannot report its security level.
Expected: configuration.testing_only_security.v1 positive (warning).
"""

import openfhe

import cipherscope

parameters = openfhe.CCParamsBGVRNS()
parameters.SetPlaintextModulus(65537)
parameters.SetMultiplicativeDepth(1)
parameters.SetBatchSize(8)
parameters.SetSecurityLevel(openfhe.SecurityLevel.HEStd_NotSet)
parameters.SetRingDim(64)
context = openfhe.GenCryptoContext(parameters)
context.Enable(openfhe.PKESchemeFeature.PKE)
context.Enable(openfhe.PKESchemeFeature.LEVELEDSHE)
keys = context.KeyGen()

data = [1, 2, 3, 4, 5, 6, 7, 8]

with cipherscope.trace(context, name="bgv_security_not_set", parameters=parameters) as session:
    cc = session.context
    ciph = cc.Encrypt(keys.publicKey, cc.MakePackedPlaintext(data))
    doubled = cc.EvalAdd(ciph, ciph)
    result = cc.Decrypt(doubled, keys.secretKey)

result.SetLength(8)
observed = [int(value) for value in result.GetPackedValue()[:8]]
if observed != [2 * value for value in data]:
    raise RuntimeError(f"exact mismatch: {observed}")
