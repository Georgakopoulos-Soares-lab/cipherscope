from openfhe import *

# 1. Setup Context with Bootstrapping enabled
parameters = CCParamsCKKSRNS()
secret_key_dist = SecretKeyDist.UNIFORM_TERNARY
parameters.SetSecretKeyDist(secret_key_dist)
parameters.SetScalingModSize(50)

# depth = (levels for computation) + (levels consumed by bootstrapping)
# The bootstrap depth is not a free constant: it is derived from the level
# budget below, so the multiplicative depth must reserve it explicitly.
level_budget = [3, 3]
computation_depth = 6  # 5 squarings plus one post-refresh multiplication
depth = computation_depth + FHECKKSRNS.GetBootstrapDepth(level_budget, secret_key_dist)
parameters.SetMultiplicativeDepth(depth)

cc = GenCryptoContext(parameters)
cc.Enable(PKESchemeFeature.PKE)
cc.Enable(PKESchemeFeature.KEYSWITCH)
cc.Enable(PKESchemeFeature.LEVELEDSHE)
cc.Enable(PKESchemeFeature.ADVANCEDSHE)
cc.Enable(PKESchemeFeature.FHE) # Enables Bootstrapping

# 2. Key Generation (This takes significantly longer)
num_slots = 8 # Small for demo
# EvalBootstrapKeyGen cannot mint bootstrap keys until the linear-transform
# precomputation for this exact slot count and level budget exists.
cc.EvalBootstrapSetup(level_budget, [0, 0], num_slots)
keys = cc.KeyGen()
cc.EvalMultKeyGen(keys.secretKey)
cc.EvalBootstrapKeyGen(keys.secretKey, num_slots)

# 3. Initial computation
# The plaintext must be encoded into exactly num_slots slots so the ciphertext's
# slot count matches the bootstrap precomputation set up above; otherwise
# EvalBootstrap cannot find precomputations for the (default, full) slot count.
val = [1.1] * num_slots
plaintext = cc.MakeCKKSPackedPlaintext(val, 1, 0, None, num_slots)
ciph = cc.Encrypt(keys.publicKey, plaintext)

# Perform 5 multiplications (consuming 5 levels)
for i in range(5):
    ciph = cc.EvalMult(ciph, ciph)
    
print(f"Levels remaining before bootstrapping: {ciph.GetLevel()}")

# 4. Bootstrapping: Refresh the noise and modulus
ciph_refreshed = cc.EvalBootstrap(ciph)

print(f"Levels remaining after bootstrapping: {ciph_refreshed.GetLevel()}")

# Now we can continue multiplying even though we initially ran out of levels!
ciph_final = cc.EvalMult(ciph_refreshed, ciph_refreshed)

result = cc.Decrypt(ciph_final, keys.secretKey)
result.SetLength(1)
print(f"Final Result after bootstrapping: {result.GetRealPackedValue()[0]:.4f}")