"""Hard negative: every available slot carries meaningful data.

The annotation claims exactly ring_dimension / 2 meaningful slots, which is the
full CKKS capacity, so utilization is 1.0 and nothing is under-packed.
Expected: packing.low_utilization_annotated.v1 clean.
"""

from _kernel import check_close, decode, make_context

import cipherscope

context, keys = make_context(1, batch=None)
slots = context.GetRingDimension() // 2
values = [float(i % 17) / 16.0 for i in range(slots)]

with cipherscope.trace(context, name="packing_full_utilization") as session:
    cc = session.context
    ciph = cc.Encrypt(keys.publicKey, cc.MakeCKKSPackedPlaintext(values))
    session.annotate(ciph, shape=[slots], packing="row_major", meaningful_slots=slots)
    doubled = cc.EvalAdd(ciph, ciph)
    result = cc.Decrypt(doubled, keys.secretKey)

check_close(decode(result, 16), [2 * value for value in values[:16]])
