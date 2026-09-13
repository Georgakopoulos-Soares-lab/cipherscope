"""Hard negative: two public constants, each encoded once under its own constant_id.

Same shape as encoding_repeated_constant, but the two encodings are declared
as different constants, so neither is redundant.
Expected: encoding.repeated_public_constant.v1 clean.
"""

from _kernel import check_close, decode, make_context

import cipherscope

weights_0 = [0.1, 0.2, 0.3, 0.4]
weights_1 = [0.4, 0.3, 0.2, 0.1]
inputs = [1.0, 2.0, 3.0, 4.0]

context, keys = make_context(2, batch=4)

with cipherscope.trace(context, name="encoding_distinct_constants") as session:
    cc = session.context
    ciph = cc.Encrypt(keys.publicKey, cc.MakeCKKSPackedPlaintext(inputs))
    plain_0 = cc.MakeCKKSPackedPlaintext(weights_0)
    session.annotate_plaintext(plain_0, provenance="model_parameter", constant_id="layer0")
    plain_1 = cc.MakeCKKSPackedPlaintext(weights_1)
    session.annotate_plaintext(plain_1, provenance="model_parameter", constant_id="layer1")
    out_0 = cc.EvalMult(ciph, plain_0)
    out_1 = cc.EvalMult(ciph, plain_1)
    result_0 = cc.Decrypt(out_0, keys.secretKey)
    result_1 = cc.Decrypt(out_1, keys.secretKey)

check_close(decode(result_0, 4), [w * x for w, x in zip(weights_0, inputs)])
check_close(decode(result_1, 4), [w * x for w, x in zip(weights_1, inputs)])
