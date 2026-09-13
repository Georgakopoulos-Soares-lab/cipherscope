"""Seeded positive: precision measured before and after three squarings of values above 1.

Mutation of precision_no_drop: the computation between the two checkpoints
grows the magnitudes to the thousands, so the absolute error grows with them
and the second checkpoint has measurably fewer correct bits (about 14 fewer on
this build). Values below 1 would shrink the error instead and not reliably fire.
Expected: precision.checkpoint_drop.v1 positive.
"""

from _kernel import check_close, decode, make_context

import cipherscope

data = [1.5, 2.0, 2.5, 3.0]

context, keys = make_context(4, batch=4)

with cipherscope.trace(
    context, name="precision_drop", secret_key=keys.secretKey, shadow_mode=True
) as session:
    cc = session.context
    ciph = cc.Encrypt(keys.publicKey, cc.MakeCKKSPackedPlaintext(data))
    session.checkpoint("fresh", ciphertext=ciph, expected=data)
    current = list(data)
    for _ in range(3):
        ciph = cc.EvalSquare(ciph)
        current = [value * value for value in current]
    session.checkpoint("after_three_squarings", ciphertext=ciph, expected=current)
    result = cc.Decrypt(ciph, keys.secretKey)

check_close(decode(result, 4), current)
