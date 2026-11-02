"""Hard negative: a public-constant BFV ciphertext that never enters a ct-by-ct multiply.

The same public_constant annotation is present, so the rule does assess this
run, but the annotated ciphertext is only added to another ciphertext and the
product is taken against a plaintext. The rule looks specifically for a
ciphertext-ciphertext product with a public operand.
Expected: provenance.public_value_ciphertext_mult.v1 clean.
"""

from _kernel import check_exact, decode_integers, make_integer_context

import cipherscope

public_bias = [1, 1, 1, 1]
private_input = [1, 2, 3, 4]
scale = [2, 2, 2, 2]

context, keys = make_integer_context(2, scheme="BFV", batch=4)

with cipherscope.trace(context, name="bfv_provenance_public_pt_only") as session:
    cc = session.context
    ciph_bias = cc.Encrypt(keys.publicKey, cc.MakePackedPlaintext(public_bias))
    ciph_input = cc.Encrypt(keys.publicKey, cc.MakePackedPlaintext(private_input))
    session.annotate(ciph_bias, provenance="public_constant")
    shifted = cc.EvalAdd(ciph_input, ciph_bias)
    scaled = cc.EvalMult(shifted, cc.MakePackedPlaintext(scale))
    result = cc.Decrypt(scaled, keys.secretKey)

check_exact(
    decode_integers(result, 4),
    [(x + b) * s for x, b, s in zip(private_input, public_bias, scale)],
)
