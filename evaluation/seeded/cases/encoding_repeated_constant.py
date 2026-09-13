"""Seeded positive: one public constant encoded twice under the same constant_id.

Mutation of encoding_distinct_constants: both encodings carry the same
constant_id, asserting that they are the same public value.
Expected: encoding.repeated_public_constant.v1 positive.
"""

from _kernel import check_close, decode, make_context

import cipherscope

weights = [0.1, 0.2, 0.3, 0.4]
inputs_a = [1.0, 1.0, 1.0, 1.0]
inputs_b = [2.0, 2.0, 2.0, 2.0]

context, keys = make_context(2, batch=4)

with cipherscope.trace(context, name="encoding_repeated_constant") as session:
    cc = session.context
    weights_1 = cc.MakeCKKSPackedPlaintext(weights)
    session.annotate_plaintext(weights_1, provenance="model_parameter", constant_id="layer0")
    out_a = cc.EvalMult(cc.Encrypt(keys.publicKey, cc.MakeCKKSPackedPlaintext(inputs_a)), weights_1)

    weights_2 = cc.MakeCKKSPackedPlaintext(weights)
    session.annotate_plaintext(weights_2, provenance="model_parameter", constant_id="layer0")
    out_b = cc.EvalMult(cc.Encrypt(keys.publicKey, cc.MakeCKKSPackedPlaintext(inputs_b)), weights_2)

    result_a = cc.Decrypt(out_a, keys.secretKey)
    result_b = cc.Decrypt(out_b, keys.secretKey)

check_close(decode(result_a, 4), [w * x for w, x in zip(weights, inputs_a)])
check_close(decode(result_b, 4), [w * x for w, x in zip(weights, inputs_b)])
