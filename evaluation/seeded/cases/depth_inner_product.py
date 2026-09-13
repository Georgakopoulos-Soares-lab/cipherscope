"""Seeded value check: one EvalInnerProduct, an opaque composite operation.

The true ciphertext-only depth is 1 (one multiply inside the composite), but
CipherScope does not model the inside of EvalInnerProduct. The correct answer
is therefore to refuse: the nonlinear depth must be reported with confidence
"unknown", never as a fabricated number.
Expected: depth.critical_path.v1 reports nonlinear_ciphertext.confidence == "unknown".
"""

from _kernel import check_close, decode, make_context

import cipherscope

BATCH = 8
features = [0.1, 0.2, 0.3, 0.4, 0.5, 0.6, 0.7, 0.8]
weights = [1.0, 0.0, 2.0, 0.0, 3.0, 0.0, 4.0, 0.0]

context, keys = make_context(3, batch=BATCH, advanced=True)
context.EvalSumKeyGen(keys.secretKey)

with cipherscope.trace(context, name="depth_inner_product") as session:
    cc = session.context
    ciph_features = cc.Encrypt(keys.publicKey, cc.MakeCKKSPackedPlaintext(features))
    ciph_weights = cc.Encrypt(keys.publicKey, cc.MakeCKKSPackedPlaintext(weights))
    product = cc.EvalInnerProduct(ciph_features, ciph_weights, BATCH)
    result = cc.Decrypt(product, keys.secretKey)

check_close(decode(result, 1), [sum(f * w for f, w in zip(features, weights))])
