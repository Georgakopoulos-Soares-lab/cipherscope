"""Python twin of tests/cpp/fixtures/checkpoints.cpp.

The C++ program opts into cipherscope/annotate.h; here the same assertions go
through the session API (annotate_plaintext, annotate, checkpoint). Launched by
profile_unmodified.py, so the nested trace() joins the active session and
enables shadow mode with the program's own secret key.
"""

from openfhe import *

import cipherscope

parameters = CCParamsCKKSRNS()
parameters.SetMultiplicativeDepth(6)
parameters.SetScalingModSize(50)
parameters.SetBatchSize(4)
cc = GenCryptoContext(parameters)
cc.Enable(PKESchemeFeature.PKE)
cc.Enable(PKESchemeFeature.KEYSWITCH)
cc.Enable(PKESchemeFeature.LEVELEDSHE)
keys = cc.KeyGen()
cc.EvalMultKeyGen(keys.secretKey)

data = [1.5, 2.0, 2.5, 3.0]
weights = [1.0, 1.0, 1.0, 1.0]
with cipherscope.trace(cc, secret_key=keys.secretKey, shadow_mode=True) as session:
    pw1 = cc.MakeCKKSPackedPlaintext(weights)
    session.annotate_plaintext(pw1, provenance="model_parameter", constant_id="layer0")
    pw2 = cc.MakeCKKSPackedPlaintext(weights)          # the same public constant encoded twice
    session.annotate_plaintext(pw2, provenance="model_parameter", constant_id="layer0")

    ciph = cc.Encrypt(keys.publicKey, cc.MakeCKKSPackedPlaintext(data))
    session.annotate(ciph, shape=[4], packing="row_major", meaningful_slots=4)
    session.checkpoint("fresh", ciphertext=ciph, expected=data)

    encrypted_weights = cc.Encrypt(keys.publicKey, pw1)
    session.annotate(encrypted_weights, provenance="model_parameter")
    scaled = cc.EvalMult(ciph, encrypted_weights)      # ct * ct on a public operand

    current = list(data)
    for _ in range(3):
        scaled = cc.EvalSquare(scaled)
        current = [value * value for value in current]
    session.checkpoint("after_three_squarings", ciphertext=scaled, expected=current, tolerance={"min_bits": 40.0})

    out = cc.Decrypt(scaled, keys.secretKey)
out.SetLength(4)
print(f"result[3] = {int(out.GetRealPackedValue()[3] + 0.5)} (expected {int(current[3])})")
