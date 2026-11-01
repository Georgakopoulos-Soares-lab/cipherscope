"""Hard negative: a bootstrap that restores nothing because it came too early.

Five squarings, one bootstrap, one more multiplication: the refreshed budget is
almost entirely wasted. But the bootstrap happens at level 5 of about 23, and
OpenFHE returns every bootstrapped ciphertext at the fixed level
depth - levelsAvailableAfterBootstrap, so the output is deeper than the input
and no levels were restored. The rule must stay silent rather than fabricate a
restored-level count; bootstrap_underused_deep.py is the real positive.
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
