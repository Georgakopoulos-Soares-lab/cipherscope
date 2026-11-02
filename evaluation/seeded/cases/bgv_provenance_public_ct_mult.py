"""Seeded positive: a BGV ciphertext holding a public constant is multiplied ct-by-ct.

Mutation of bgv_provenance_public_pt_only: the public weights are encrypted and
then used as a ciphertext operand of EvalMult, although a plaintext would do.
Expected: provenance.public_value_ciphertext_mult.v1 positive.
"""

from _kernel import check_exact, decode_integers, make_integer_context

import cipherscope

public_weights = [2, 2, 2, 2]
private_input = [1, 2, 3, 4]

context, keys = make_integer_context(2, scheme="BGV", batch=4)

with cipherscope.trace(context, name="bgv_provenance_public_ct_mult") as session:
    cc = session.context
    ciph_weights = cc.Encrypt(keys.publicKey, cc.MakePackedPlaintext(public_weights))
    ciph_input = cc.Encrypt(keys.publicKey, cc.MakePackedPlaintext(private_input))
    session.annotate(ciph_weights, provenance="public_constant")
    product = cc.EvalMult(ciph_weights, ciph_input)
    result = cc.Decrypt(product, keys.secretKey)

check_exact(decode_integers(result, 4), [w * x for w, x in zip(public_weights, private_input)])
