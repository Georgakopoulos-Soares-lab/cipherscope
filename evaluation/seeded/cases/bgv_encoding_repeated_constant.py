"""Seeded positive: one BGV public constant encoded twice under the same constant_id.

Mutation of bgv_encoding_distinct_constants: both encodings carry the same
constant_id, asserting that they are the same public value.
Expected: encoding.repeated_public_constant.v1 positive.
"""

from _kernel import check_exact, decode_integers, make_integer_context

import cipherscope

weights = [2, 3, 4, 5]
inputs_a = [1, 1, 1, 1]
inputs_b = [2, 2, 2, 2]

context, keys = make_integer_context(2, scheme="BGV", batch=4)

with cipherscope.trace(context, name="bgv_encoding_repeated_constant") as session:
    cc = session.context
    weights_1 = cc.MakePackedPlaintext(weights)
    session.annotate_plaintext(weights_1, provenance="model_parameter", constant_id="layer0")
    out_a = cc.EvalMult(cc.Encrypt(keys.publicKey, cc.MakePackedPlaintext(inputs_a)), weights_1)

    weights_2 = cc.MakePackedPlaintext(weights)
    session.annotate_plaintext(weights_2, provenance="model_parameter", constant_id="layer0")
    out_b = cc.EvalMult(cc.Encrypt(keys.publicKey, cc.MakePackedPlaintext(inputs_b)), weights_2)

    result_a = cc.Decrypt(out_a, keys.secretKey)
    result_b = cc.Decrypt(out_b, keys.secretKey)

check_exact(decode_integers(result_a, 4), [w * x for w, x in zip(weights, inputs_a)])
check_exact(decode_integers(result_b, 4), [w * x for w, x in zip(weights, inputs_b)])
