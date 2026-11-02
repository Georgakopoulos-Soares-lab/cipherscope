"""Hard negative: a declared tolerance on an exact BGV run.

BGV reproduces its inputs exactly, so there is no approximation error for a
precision rule to measure. The checkpoint is recorded with its tolerance and
both precision rules must decline rather than report a clean measurement they
never made.
Expected: both precision rules not_applicable.
"""

from _kernel import check_exact, decode_integers, make_integer_context

import cipherscope

BATCH = 8
data = [1, 2, 3, 4, 5, 6, 7, 8]

context, keys = make_integer_context(2, scheme="BGV", batch=BATCH)

with cipherscope.trace(
    context,
    name="bgv_precision_exact",
    secret_key=keys.secretKey,
    shadow_mode=True,
) as session:
    cc = session.context
    ciph = cc.Encrypt(keys.publicKey, cc.MakePackedPlaintext(data))
    squared = cc.EvalMult(ciph, ciph)
    session.checkpoint(
        "squared",
        ciphertext=squared,
        expected=[value * value for value in data],
        tolerance={"absolute": 0.5},
    )
    quartic = cc.EvalMult(squared, squared)
    session.checkpoint(
        "quartic",
        ciphertext=quartic,
        expected=[value ** 4 for value in data],
        tolerance={"absolute": 0.5},
    )
    result = cc.Decrypt(quartic, keys.secretKey)

check_exact(decode_integers(result, BATCH), [value ** 4 for value in data])
