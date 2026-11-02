"""Seeded positive: eight meaningful BGV slots in a ciphertext with thousands available.

Mutation of bgv_packing_full_utilization: the same annotation shape, but only
eight of the available slots carry data. The integer schemes pack N slots, not
the N/2 that CKKS packs.
Expected: packing.low_utilization_annotated.v1 positive.
"""

from _kernel import check_exact, decode_integers, make_integer_context

import cipherscope

MEANINGFUL = 8
values = list(range(MEANINGFUL))

context, keys = make_integer_context(1, scheme="BGV", batch=MEANINGFUL)

with cipherscope.trace(context, name="bgv_packing_low_utilization") as session:
    cc = session.context
    ciph = cc.Encrypt(keys.publicKey, cc.MakePackedPlaintext(values))
    session.annotate(ciph, shape=[MEANINGFUL], packing="row_major", meaningful_slots=MEANINGFUL)
    doubled = cc.EvalAdd(ciph, ciph)
    result = cc.Decrypt(doubled, keys.secretKey)

check_exact(decode_integers(result, MEANINGFUL), [2 * value for value in values])
