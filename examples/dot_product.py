from openfhe import *

parameters = CCParamsCKKSRNS()
parameters.SetMultiplicativeDepth(2)
parameters.SetScalingModSize(50)
cc = GenCryptoContext(parameters)
cc.Enable(PKESchemeFeature.PKE)
cc.Enable(PKESchemeFeature.KEYSWITCH)
cc.Enable(PKESchemeFeature.LEVELEDSHE)
# EvalInnerProduct performs log-step rotations via EvalSum. Both the summation
# key generation below and the inner-product evaluation live in ADVANCEDSHE, so
# the feature must be enabled before EvalSumKeyGen or the call cannot run.
cc.Enable(PKESchemeFeature.ADVANCEDSHE)

keys = cc.KeyGen()
cc.EvalMultKeyGen(keys.secretKey)
# We must generate keys for EVERY rotation power (1, 2, 4...) for summing
cc.EvalSumKeyGen(keys.secretKey)

# 3. Encrypt two vectors
vec1 = [1.0, 2.0, 3.0, 4.0]
vec2 = [0.5, 0.5, 0.5, 0.5]
ciph1 = cc.Encrypt(keys.publicKey, cc.MakeCKKSPackedPlaintext(vec1))
ciph2 = cc.Encrypt(keys.publicKey, cc.MakeCKKSPackedPlaintext(vec2))

# 4. Complex Operation: Dot Product
# EvalInnerProduct multiplies elements and then performs log-step rotations to sum them
# The '4' specifies the number of elements to sum
ciph_dot = cc.EvalInnerProduct(ciph1, ciph2, 4)

# 5. Decryption
result = cc.Decrypt(ciph_dot, keys.secretKey)
result.SetLength(1) # The result is now conceptually a single scalar
print(f"Dot Product Result: {result.GetRealPackedValue()[0]:.4f}") 
# (1*0.5 + 2*0.5 + 3*0.5 + 4*0.5) = 5.0