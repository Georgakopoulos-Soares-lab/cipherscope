"""Known limitation: an underused bootstrap that the real binding cannot expose.

Five squarings, one bootstrap, one more multiplication: the refreshed budget is
almost entirely wasted, which is the pathology the bootstrap rule describes. On
OpenFHE Python 1.5.1.0, however, GetLevel() returns the same value before and
after EvalBootstrap under every scaling technique that can bootstrap at all, so
the rule measures a zero level delta. This case pins that behavior: the rule
must stay silent rather than fabricate a restored-level count. The positive
outcome is covered only by the fake-model test in tests/golden/test_bootstrap.py.
Expected: bootstrap.restored_levels_underused.v1 clean.
"""

import openfhe
from _kernel import decode

import cipherscope

secret_key_dist = openfhe.SecretKeyDist.UNIFORM_TERNARY
level_budget = [3, 3]
slots = 8

parameters = openfhe.CCParamsCKKSRNS()
parameters.SetSecretKeyDist(secret_key_dist)
parameters.SetScalingModSize(50)
parameters.SetMultiplicativeDepth(
    6 + openfhe.FHECKKSRNS.GetBootstrapDepth(level_budget, secret_key_dist)
)
context = openfhe.GenCryptoContext(parameters)
for feature in ("PKE", "KEYSWITCH", "LEVELEDSHE", "ADVANCEDSHE", "FHE"):
    context.Enable(getattr(openfhe.PKESchemeFeature, feature))
context.EvalBootstrapSetup(level_budget, [0, 0], slots)
keys = context.KeyGen()
context.EvalMultKeyGen(keys.secretKey)
context.EvalBootstrapKeyGen(keys.secretKey, slots)

with cipherscope.trace(context, name="bootstrap_underused_real") as session:
    cc = session.context
    ciph = cc.Encrypt(keys.publicKey, cc.MakeCKKSPackedPlaintext([1.02] * slots, 1, 0, None, slots))
    for _ in range(5):
        ciph = cc.EvalMult(ciph, ciph)
    refreshed = cc.EvalBootstrap(ciph)
    final = cc.EvalMult(refreshed, refreshed)
    result = cc.Decrypt(final, keys.secretKey)

expected = 1.02 ** (2**6)
value = decode(result, 1)[0]
if abs(value - expected) > 0.1 * expected:
    raise RuntimeError(f"bootstrapped result {value:.4f} is not within 10% of {expected:.4f}")
