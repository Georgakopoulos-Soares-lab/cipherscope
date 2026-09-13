"""Hard negative: the same computation under a tolerance it satisfies.

Three squarings of values above 1 lose about 14 bits, but the declared
absolute tolerance of 1e-3 is far looser than the ~1e-8 error, so both
checkpoints are within contract and the rule must stay clean.
Expected: precision.tolerance_violated.v1 clean.
"""

from _kernel import check_close, decode, make_context

import cipherscope

data = [1.5, 2.0, 2.5, 3.0]
TOLERANCE = {"absolute": 1e-3}

context, keys = make_context(4, batch=4)

with cipherscope.trace(
    context, name="precision_tolerance_within", secret_key=keys.secretKey, shadow_mode=True
) as session:
    cc = session.context
    ciph = cc.Encrypt(keys.publicKey, cc.MakeCKKSPackedPlaintext(data))
    session.checkpoint("fresh", ciphertext=ciph, expected=data, tolerance=TOLERANCE)
    current = list(data)
    for _ in range(3):
        ciph = cc.EvalSquare(ciph)
        current = [value * value for value in current]
    session.checkpoint(
        "after_three_squarings", ciphertext=ciph, expected=current, tolerance=TOLERANCE
    )
    result = cc.Decrypt(ciph, keys.secretKey)

check_close(decode(result, 4), current)
