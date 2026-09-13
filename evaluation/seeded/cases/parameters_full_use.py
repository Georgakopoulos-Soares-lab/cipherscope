"""Hard negative: a depth-3 context whose three levels are all consumed.

Three chained multiplications, each followed by an explicit Rescale under
FIXEDMANUAL, use exactly the configured depth, so there is no headroom to report.
Expected: parameters.depth_headroom_observed.v1 clean.
"""

from _kernel import check_close, decode, make_context

import cipherscope

BATCH = 8
data = [0.5, 0.6, 0.7, 0.8, 0.9, 1.0, 1.1, 1.2]

context, keys = make_context(3, technique="FIXEDMANUAL", batch=BATCH)

with cipherscope.trace(context, name="parameters_full_use") as session:
    cc = session.context
    ciph = cc.Encrypt(keys.publicKey, cc.MakeCKKSPackedPlaintext(data))
    power = ciph
    for _ in range(3):
        power = cc.Rescale(cc.EvalMult(power, ciph))
    result = cc.Decrypt(power, keys.secretKey)

check_close(decode(result, BATCH), [value**4 for value in data])
