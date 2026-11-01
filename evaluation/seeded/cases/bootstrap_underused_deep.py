"""Seeded positive: a bootstrap whose refreshed levels go unused.

The ciphertext is encrypted at the last level (depth - 1), so it has no
multiplicative budget left; EvalBootstrap brings it back to
depth - levelsAvailableAfterBootstrap, restoring ten levels. The program then
decrypts without using any of them. This is the same shape as OpenFHE's own
simple-ckks-bootstrapping example and the pathology the bootstrap rule
describes.

OpenFHE always returns the bootstrapped ciphertext at that fixed level, so
GetLevel() only shows a restoration when the input was deeper than it; the
companion case bootstrap_underused_real.py bootstraps a shallow ciphertext and
therefore stays clean. Both frontends observe the same transition (C++: the
upstream example, level 31 -> 21).
Expected: bootstrap.restored_levels_underused.v1 positive.
"""

import openfhe
from _kernel import decode

import cipherscope

secret_key_dist = openfhe.SecretKeyDist.UNIFORM_TERNARY
level_budget = [4, 4]
levels_after_bootstrap = 10

parameters = openfhe.CCParamsCKKSRNS()
parameters.SetSecretKeyDist(secret_key_dist)
parameters.SetSecurityLevel(openfhe.SecurityLevel.HEStd_NotSet)  # testing-only, as in the upstream example
parameters.SetRingDim(1 << 12)
parameters.SetScalingModSize(59)
parameters.SetFirstModSize(60)
parameters.SetScalingTechnique(openfhe.ScalingTechnique.FLEXIBLEAUTO)
depth = levels_after_bootstrap + openfhe.FHECKKSRNS.GetBootstrapDepth(level_budget, secret_key_dist)
parameters.SetMultiplicativeDepth(depth)
context = openfhe.GenCryptoContext(parameters)
for feature in ("PKE", "KEYSWITCH", "LEVELEDSHE", "ADVANCEDSHE", "FHE"):
    context.Enable(getattr(openfhe.PKESchemeFeature, feature))
slots = context.GetRingDimension() // 2
context.EvalBootstrapSetup(level_budget)
keys = context.KeyGen()
context.EvalMultKeyGen(keys.secretKey)
context.EvalBootstrapKeyGen(keys.secretKey, slots)

values = [0.25, 0.5, 0.75, 1.0]
with cipherscope.trace(context, name="bootstrap_underused_deep", parameters=parameters, allow_testing_security=True) as session:
    cc = session.context
    plaintext = cc.MakeCKKSPackedPlaintext(values, 1, depth - 1)
    plaintext.SetLength(len(values))
    ciph = cc.Encrypt(keys.publicKey, plaintext)          # level depth - 1: nothing left
    refreshed = cc.EvalBootstrap(ciph)                    # back to depth - 10
    result = cc.Decrypt(refreshed, keys.secretKey)        # none of the ten levels used

observed = decode(result, len(values))
for got, expected in zip(observed, values):
    if abs(got - expected) > 0.01:
        raise RuntimeError(f"bootstrapped value {got:.4f} is not within 0.01 of {expected:.4f}")
