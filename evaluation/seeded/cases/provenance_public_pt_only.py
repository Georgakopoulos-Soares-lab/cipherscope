"""Hard negative: a public-constant ciphertext that never enters a ct-by-ct multiply.

The same public_constant annotation is present, but the annotated ciphertext is
only added to another ciphertext and multiplied by a plaintext. The rule looks
specifically for a ciphertext-ciphertext product with a public operand.
Expected: provenance.public_value_ciphertext_mult.v1 clean.
"""

from _kernel import check_close, decode, make_context

import cipherscope

public_bias = [0.25, 0.25, 0.25, 0.25]
private_input = [1.0, 2.0, 3.0, 4.0]
scale = [2.0, 2.0, 2.0, 2.0]

context, keys = make_context(2, batch=4)

with cipherscope.trace(context, name="provenance_public_pt_only") as session:
    cc = session.context
    ciph_bias = cc.Encrypt(keys.publicKey, cc.MakeCKKSPackedPlaintext(public_bias))
    ciph_input = cc.Encrypt(keys.publicKey, cc.MakeCKKSPackedPlaintext(private_input))
    session.annotate(ciph_bias, provenance="public_constant")
    shifted = cc.EvalAdd(ciph_input, ciph_bias)
    scaled = cc.EvalMult(shifted, cc.MakeCKKSPackedPlaintext(scale))
    result = cc.Decrypt(scaled, keys.secretKey)

check_close(decode(result, 4), [(x + b) * s for x, b, s in zip(private_input, public_bias, scale)])
