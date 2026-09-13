"""Hard negative for depth: additions and a rotation, no ciphertext multiplication.

Hand-derived nonlinear depth: there is no ciphertext-by-ciphertext product
anywhere, so the deepest ciphertext-only path is 0. The rule must not invent
depth from additions or rotations.
Expected: depth.critical_path.v1 reports nonlinear_ciphertext.max_depth == 0.
"""

from _kernel import check_close, decode, make_context

import cipherscope

BATCH = 8
left = [1.0, 2.0, 3.0, 4.0, 5.0, 6.0, 7.0, 8.0]
right = [8.0, 7.0, 6.0, 5.0, 4.0, 3.0, 2.0, 1.0]

context, keys = make_context(1, batch=BATCH)

with cipherscope.trace(context, name="depth_linear_only") as session:
    cc = session.context
    cc.EvalRotateKeyGen(keys.secretKey, [1])
    ciph_left = cc.Encrypt(keys.publicKey, cc.MakeCKKSPackedPlaintext(left))
    ciph_right = cc.Encrypt(keys.publicKey, cc.MakeCKKSPackedPlaintext(right))
    total = cc.EvalAdd(ciph_left, ciph_right)
    total = cc.EvalSub(total, ciph_right)
    shifted = cc.EvalRotate(total, 1)
    result = cc.Decrypt(shifted, keys.secretKey)

check_close(decode(result, BATCH), [left[(i + 1) % BATCH] for i in range(BATCH)])
