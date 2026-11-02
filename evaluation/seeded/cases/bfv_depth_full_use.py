"""Hard negative: a depth-2 BFV context that spends both levels.

The run consumes exactly the depth it was configured for, so there is no
headroom to report even though the depth model measures the run fully.
Expected: parameters.depth_headroom_observed.v1 clean.
"""

from _kernel import check_exact, decode_integers, make_integer_context

import cipherscope

BATCH = 8
data = [1, 2, 3, 4, 5, 6, 7, 8]

context, keys = make_integer_context(2, scheme="BFV", batch=BATCH)

with cipherscope.trace(context, name="bfv_depth_full_use") as session:
    cc = session.context
    ciph = cc.Encrypt(keys.publicKey, cc.MakePackedPlaintext(data))
    squared = cc.EvalMult(ciph, ciph)
    cubed = cc.EvalMult(squared, ciph)
    result = cc.Decrypt(cubed, keys.secretKey)

check_exact(decode_integers(result, BATCH), [value ** 3 for value in data])
