"""Hard negative: BGV with the default standard security level left in place.

The same computation with enforcement on; the configuration rule has a
declared security level to assess and nothing to report.
Expected: configuration.testing_only_security.v1 clean.
"""

import openfhe

import cipherscope

parameters = openfhe.CCParamsBGVRNS()
parameters.SetPlaintextModulus(65537)
parameters.SetMultiplicativeDepth(1)
parameters.SetBatchSize(8)
context = openfhe.GenCryptoContext(parameters)
context.Enable(openfhe.PKESchemeFeature.PKE)
context.Enable(openfhe.PKESchemeFeature.LEVELEDSHE)
keys = context.KeyGen()

data = [1, 2, 3, 4, 5, 6, 7, 8]

with cipherscope.trace(context, name="bgv_security_default", parameters=parameters) as session:
    cc = session.context
    ciph = cc.Encrypt(keys.publicKey, cc.MakePackedPlaintext(data))
    doubled = cc.EvalAdd(ciph, ciph)
    result = cc.Decrypt(doubled, keys.secretKey)

result.SetLength(8)
observed = [int(value) for value in result.GetPackedValue()[:8]]
if observed != [2 * value for value in data]:
    raise RuntimeError(f"exact mismatch: {observed}")
