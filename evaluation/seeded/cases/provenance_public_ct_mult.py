"""Seeded positive: a ciphertext holding a public constant is multiplied ct-by-ct.

Mutation of provenance_public_pt_only: the public weights are encrypted and then
used as a ciphertext operand of EvalMult, although a plaintext would do.
Expected: provenance.public_value_ciphertext_mult.v1 positive.
"""

from _kernel import check_close, decode, make_context

import cipherscope

public_weights = [0.5, 0.5, 0.5, 0.5]
private_input = [1.0, 2.0, 3.0, 4.0]

context, keys = make_context(2, batch=4)

with cipherscope.trace(context, name="provenance_public_ct_mult") as session:
    cc = session.context
    ciph_weights = cc.Encrypt(keys.publicKey, cc.MakeCKKSPackedPlaintext(public_weights))
    ciph_input = cc.Encrypt(keys.publicKey, cc.MakeCKKSPackedPlaintext(private_input))
    session.annotate(ciph_weights, provenance="public_constant")
    product = cc.EvalMult(ciph_weights, ciph_input)
    result = cc.Decrypt(product, keys.secretKey)

check_close(decode(result, 4), [w * x for w, x in zip(public_weights, private_input)])
