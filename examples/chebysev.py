import math
from openfhe import *

# 1. Setup Context with higher depth for polynomial evaluation
parameters = CCParamsCKKSRNS()
parameters.SetMultiplicativeDepth(10) # Enough depth for high-degree polynomial
parameters.SetScalingModSize(50)
parameters.SetScalingTechnique(ScalingTechnique.FLEXIBLEAUTO) # Auto-rescaling

cc = GenCryptoContext(parameters)
cc.Enable(PKESchemeFeature.PKE)
cc.Enable(PKESchemeFeature.KEYSWITCH)
cc.Enable(PKESchemeFeature.LEVELEDSHE)
cc.Enable(PKESchemeFeature.ADVANCEDSHE) # Required for EvalChebyshev

# 2. Key Generation
keys = cc.KeyGen()
cc.EvalMultKeyGen(keys.secretKey)

# 3. Encryption
data = [-4.0, -2.0, 0.0, 2.0, 4.0]
ptxt = cc.MakeCKKSPackedPlaintext(data)
ciph = cc.Encrypt(keys.publicKey, ptxt)

# 4. Evaluate Sigmoid function using Chebyshev approximation
# We approximate 1/(1 + exp(-x)) over the interval [-5, 5] with degree 31
lower_bound = -5
upper_bound = 5
poly_degree = 31
sigmoid_fn = lambda x: 1 / (1 + math.exp(-x))

ciph_sigmoid = cc.EvalChebyshevFunction(sigmoid_fn, ciph, lower_bound, upper_bound, poly_degree)

# 5. Decryption
result = cc.Decrypt(ciph_sigmoid, keys.secretKey)
result.SetLength(len(data))
print("Sigmoid Approximation Results:")
print([round(x, 4) for x in result.GetRealPackedValue()])