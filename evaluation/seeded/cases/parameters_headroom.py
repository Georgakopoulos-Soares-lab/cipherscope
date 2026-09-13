"""Seeded positive: a depth-4 context that consumes only one level.

Mutation of parameters_full_use: the same single multiplication, but the
context is configured for four levels instead of one. FIXEDMANUAL with an
explicit Rescale makes each multiplication consume exactly one observable level.
Expected: parameters.depth_headroom_observed.v1 positive with headroom 3.
"""

from _kernel import check_close, decode, make_context

import cipherscope

BATCH = 8
data = [0.5, 1.0, 1.5, 2.0, 2.5, 3.0, 3.5, 4.0]

context, keys = make_context(4, technique="FIXEDMANUAL", batch=BATCH)

with cipherscope.trace(context, name="parameters_headroom") as session:
    cc = session.context
    ciph = cc.Encrypt(keys.publicKey, cc.MakeCKKSPackedPlaintext(data))
    squared = cc.Rescale(cc.EvalMult(ciph, ciph))
    result = cc.Decrypt(squared, keys.secretKey)

check_close(decode(result, BATCH), [value * value for value in data])
