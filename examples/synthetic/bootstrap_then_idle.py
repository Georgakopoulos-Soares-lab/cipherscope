#!/usr/bin/env python3
"""Bootstrap a nearly-exhausted ciphertext, then use very little of the refresh.

Real OpenFHE program. Five squarings exhaust the level budget, a bootstrap
restores it, and only a single multiplication follows. The restored capacity is
far larger than the suffix consumes, which is the pattern CipherScope's bootstrap
analyzer flags as an underused refresh.
"""

from openfhe import *

secret_key_dist = SecretKeyDist.UNIFORM_TERNARY

parameters = CCParamsCKKSRNS()
parameters.SetSecretKeyDist(secret_key_dist)
parameters.SetScalingModSize(50)

level_budget = [3, 3]
computation_depth = 6
depth = computation_depth + FHECKKSRNS.GetBootstrapDepth(level_budget, secret_key_dist)
parameters.SetMultiplicativeDepth(depth)

cc = GenCryptoContext(parameters)
cc.Enable(PKESchemeFeature.PKE)
cc.Enable(PKESchemeFeature.KEYSWITCH)
cc.Enable(PKESchemeFeature.LEVELEDSHE)
cc.Enable(PKESchemeFeature.ADVANCEDSHE)
cc.Enable(PKESchemeFeature.FHE)

num_slots = 8
cc.EvalBootstrapSetup(level_budget, [0, 0], num_slots)
keys = cc.KeyGen()
cc.EvalMultKeyGen(keys.secretKey)
cc.EvalBootstrapKeyGen(keys.secretKey, num_slots)

values = [1.02] * num_slots
plaintext = cc.MakeCKKSPackedPlaintext(values, 1, 0, None, num_slots)
ciph = cc.Encrypt(keys.publicKey, plaintext)

for _ in range(5):
    ciph = cc.EvalMult(ciph, ciph)
print(f"Level before bootstrapping: {ciph.GetLevel()}")

refreshed = cc.EvalBootstrap(ciph)
print(f"Level after bootstrapping: {refreshed.GetLevel()}")

# Only one cheap multiplication follows the refresh: most of the restored
# capacity goes unused in this run.
final = cc.EvalMult(refreshed, refreshed)

result = cc.Decrypt(final, keys.secretKey)
result.SetLength(1)
print(f"Final value: {result.GetRealPackedValue()[0]:.4f}")
