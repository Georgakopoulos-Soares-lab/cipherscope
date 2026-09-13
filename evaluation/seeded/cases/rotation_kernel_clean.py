"""Clean kernel: one rotation of one ciphertext, one key, nothing wasted.

The rotation and key cases are mutations of this program.
Expected: rotation.hoist_same_input.v1 clean; keys.unused_in_observed_run.v1 clean.
"""

from _kernel import check_close, decode, make_context

import cipherscope

BATCH = 8
data = [1.0, 2.0, 3.0, 4.0, 5.0, 6.0, 7.0, 8.0]

context, keys = make_context(1, batch=BATCH)

with cipherscope.trace(context, name="rotation_kernel_clean") as session:
    cc = session.context
    cc.EvalRotateKeyGen(keys.secretKey, [1])
    ciph = cc.Encrypt(keys.publicKey, cc.MakeCKKSPackedPlaintext(data))
    rotated = cc.EvalRotate(ciph, 1)
    result = cc.Decrypt(rotated, keys.secretKey)

check_close(decode(result, BATCH), [data[(i + 1) % BATCH] for i in range(BATCH)])
