"""Hard negative: precision that improves between two checkpoints.

The first checkpoint follows three squarings of values above 1 and has lost
roughly 14 absolute bits. The second checkpoint is a fresh encryption of the
exact same values, so it is about 14 bits more precise. A later checkpoint that
is better than an earlier one is not a drop, and the rule must stay silent.

Why not two checkpoints on one unchanged ciphertext: OpenFHE floods CKKS
decryption with fresh noise, so two decryptions of the same ciphertext differ at
the 1e-12 level and the rule, which has no minimum threshold, fires on that noise
about half the time. The 14-bit improvement here is far outside that noise.
Expected: precision.checkpoint_drop.v1 clean.
"""

from _kernel import check_close, decode, make_context

import cipherscope

data = [1.5, 2.0, 2.5, 3.0]

context, keys = make_context(4, batch=4)

with cipherscope.trace(
    context, name="precision_no_drop", secret_key=keys.secretKey, shadow_mode=True
) as session:
    cc = session.context
    ciph = cc.Encrypt(keys.publicKey, cc.MakeCKKSPackedPlaintext(data))
    current = list(data)
    for _ in range(3):
        ciph = cc.EvalSquare(ciph)
        current = [value * value for value in current]
    session.checkpoint("after_three_squarings", ciphertext=ciph, expected=current)
    fresh = cc.Encrypt(keys.publicKey, cc.MakeCKKSPackedPlaintext(current))
    session.checkpoint("fresh_reencryption", ciphertext=fresh, expected=current)
    result = cc.Decrypt(fresh, keys.secretKey)

check_close(decode(result, 4), current)
