"""Hard negative: the same ciphertext version rotated three times by one index.

Three EvalRotate calls share their input version, but the rule needs at least
two distinct indices before it can suggest a shared precompute.
Expected: rotation.hoist_same_input.v1 clean; keys.unused_in_observed_run.v1 clean.
"""

from _kernel import check_close, decode, make_context

import cipherscope

BATCH = 8
data = [1.0, 2.0, 3.0, 4.0, 5.0, 6.0, 7.0, 8.0]

context, keys = make_context(1, batch=BATCH)

with cipherscope.trace(context, name="rotation_single_index") as session:
    cc = session.context
    cc.EvalRotateKeyGen(keys.secretKey, [1])
    ciph = cc.Encrypt(keys.publicKey, cc.MakeCKKSPackedPlaintext(data))
    first = cc.EvalRotate(ciph, 1)
    second = cc.EvalRotate(ciph, 1)
    third = cc.EvalRotate(ciph, 1)
    combined = cc.EvalAdd(cc.EvalAdd(first, second), third)
    result = cc.Decrypt(combined, keys.secretKey)

expected = [3 * data[(i + 1) % BATCH] for i in range(BATCH)]
check_close(decode(result, BATCH), expected)
