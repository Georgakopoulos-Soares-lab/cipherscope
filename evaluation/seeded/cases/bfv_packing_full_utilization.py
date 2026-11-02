"""Hard negative: every available BFV slot carries meaningful data.

The annotation claims exactly ring_dimension meaningful slots, which is the
full capacity of an integer scheme, so utilization is 1.0 and nothing is
under-packed.
Expected: packing.low_utilization_annotated.v1 clean.
"""

from _kernel import check_exact, decode_integers, make_integer_context

import cipherscope

context, keys = make_integer_context(1, scheme="BFV", batch=None)
slots = context.GetRingDimension()
values = [i % 17 for i in range(slots)]

with cipherscope.trace(context, name="bfv_packing_full_utilization") as session:
    cc = session.context
    ciph = cc.Encrypt(keys.publicKey, cc.MakePackedPlaintext(values))
    session.annotate(ciph, shape=[slots], packing="row_major", meaningful_slots=slots)
    doubled = cc.EvalAdd(ciph, ciph)
    result = cc.Decrypt(doubled, keys.secretKey)

check_exact(decode_integers(result, 16), [2 * value for value in values[:16]])
