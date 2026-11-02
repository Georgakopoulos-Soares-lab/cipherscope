"""Seeded positive: BFV depth measured across an add that lowers the noise degree.

Regression guard for the BFV depth model. OpenFHE's noise scale degree
accumulates along a multiplication chain but an EvalAdd against a shallower
operand resets it downward, so it cannot stand in for a level ladder. This
program is the smallest one that shows it: one multiplication (the real depth),
a rotation that preserves the degree, then an add against a degree-1 operand
that drops it back to 1.

Depth must come from the recorded multiplications, giving 1 consumed of a
configured 4. A model that read the noise degree would report the run as
shallower than it is and overstate the headroom.
Expected: parameters.depth_headroom_observed.v1 positive, headroom 3.
"""

from _kernel import check_exact, decode_integers, make_integer_context, rotate_left

import cipherscope

BATCH = 8
left = [1, 2, 3, 4, 5, 6, 7, 8]
right = [8, 7, 6, 5, 4, 3, 2, 1]

context, keys = make_integer_context(4, scheme="BFV", batch=BATCH)

with cipherscope.trace(context, name="bfv_mixed_add_depth") as session:
    cc = session.context
    cc.EvalRotateKeyGen(keys.secretKey, [1])
    a = cc.Encrypt(keys.publicKey, cc.MakePackedPlaintext(left))
    b = cc.Encrypt(keys.publicKey, cc.MakePackedPlaintext(right))
    total = cc.EvalAdd(a, b)
    product = cc.EvalMult(a, b)
    rotated = cc.EvalRotate(product, 1)
    combined = cc.EvalAdd(total, rotated)
    result = cc.Decrypt(combined, keys.secretKey)

products = [left[i] * right[i] for i in range(BATCH)]
shifted = rotate_left(products, 1, BATCH)
expected = [left[i] + right[i] + shifted[i] for i in range(BATCH)]
check_exact(decode_integers(result, BATCH), expected)
