"""Seeded positive: a depth-4 BFV context that spends one multiplication.

Mutation of bfv_depth_full_use: the same single multiplication against a
context configured for four levels instead of the depth it needs.
Expected: parameters.depth_headroom_observed.v1 positive.
"""

from _kernel import check_exact, decode_integers, make_integer_context

import cipherscope

BATCH = 8
data = [1, 2, 3, 4, 5, 6, 7, 8]

context, keys = make_integer_context(4, scheme="BFV", batch=BATCH)

with cipherscope.trace(context, name="bfv_depth_headroom") as session:
    cc = session.context
    ciph = cc.Encrypt(keys.publicKey, cc.MakePackedPlaintext(data))
    squared = cc.EvalMult(ciph, ciph)
    result = cc.Decrypt(squared, keys.secretKey)

check_exact(decode_integers(result, BATCH), [value * value for value in data])
