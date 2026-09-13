"""Seeded positive: a declared absolute tolerance broken by three squarings.

Mutation of precision_tolerance_within: the same computation and checkpoints,
but the tolerance is 1e-11. The fresh encryption is within it (error ~1e-13);
after three squarings of values above 1 the error is ~1e-9, so the
second checkpoint is the first to violate the contract.
Expected: precision.tolerance_violated.v1 positive at "after_three_squarings".
"""

from _kernel import check_close, decode, make_context

import cipherscope

data = [1.5, 2.0, 2.5, 3.0]
TOLERANCE = {"absolute": 1e-11}

context, keys = make_context(4, batch=4)

with cipherscope.trace(
    context, name="precision_tolerance_violated", secret_key=keys.secretKey, shadow_mode=True
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
