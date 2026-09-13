"""Seeded positive: eight meaningful slots in a ciphertext with thousands available.

Mutation of packing_full_utilization: the same annotation shape, but only
eight of the available slots carry data.
Expected: packing.low_utilization_annotated.v1 positive.
"""

from _kernel import check_close, decode, make_context

import cipherscope

MEANINGFUL = 8
values = [float(i) for i in range(MEANINGFUL)]

context, keys = make_context(1, batch=MEANINGFUL)

with cipherscope.trace(context, name="packing_low_utilization") as session:
    cc = session.context
    ciph = cc.Encrypt(keys.publicKey, cc.MakeCKKSPackedPlaintext(values))
    session.annotate(ciph, shape=[MEANINGFUL], packing="row_major", meaningful_slots=MEANINGFUL)
    doubled = cc.EvalAdd(ciph, ciph)
    result = cc.Decrypt(doubled, keys.secretKey)

check_close(decode(result, MEANINGFUL), [2 * value for value in values])
