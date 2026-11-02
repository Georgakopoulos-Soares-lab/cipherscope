"""Hard negative: two genuinely different BGV public constants.

Each encoding carries its own constant_id, so there is no repeated encoding
of one value to hoist out of the run.
Expected: encoding.repeated_public_constant.v1 clean.
"""

from _kernel import check_exact, decode_integers, make_integer_context

import cipherscope

weights_a = [2, 3, 4, 5]
weights_b = [6, 7, 8, 9]
inputs = [1, 1, 1, 1]

context, keys = make_integer_context(2, scheme="BGV", batch=4)

with cipherscope.trace(context, name="bgv_encoding_distinct_constants") as session:
    cc = session.context
    first = cc.MakePackedPlaintext(weights_a)
    session.annotate_plaintext(first, provenance="model_parameter", constant_id="layer0")
    out_a = cc.EvalMult(cc.Encrypt(keys.publicKey, cc.MakePackedPlaintext(inputs)), first)

    second = cc.MakePackedPlaintext(weights_b)
    session.annotate_plaintext(second, provenance="model_parameter", constant_id="layer1")
    out_b = cc.EvalMult(cc.Encrypt(keys.publicKey, cc.MakePackedPlaintext(inputs)), second)

    result_a = cc.Decrypt(out_a, keys.secretKey)
    result_b = cc.Decrypt(out_b, keys.secretKey)

check_exact(decode_integers(result_a, 4), [w * x for w, x in zip(weights_a, inputs)])
check_exact(decode_integers(result_b, 4), [w * x for w, x in zip(weights_b, inputs)])
