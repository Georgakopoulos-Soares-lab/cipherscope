"""Hard negative: two checkpoints on one unchanged ciphertext.

Decryption noise flooding makes the two decryptions differ at about 1e-12
(roughly half a bit either way). This is the case that exposed that jitter; with
the one-bit minimum the drop rule must stay clean.
Expected: precision.checkpoint_drop.v1 clean.
"""

from _kernel import check_close, decode, make_context

import cipherscope

data = [0.2, 0.4, 0.6, 0.8]

context, keys = make_context(2, batch=4)

with cipherscope.trace(
    context, name="precision_same_ciphertext", secret_key=keys.secretKey, shadow_mode=True
) as session:
    cc = session.context
    ciph = cc.Encrypt(keys.publicKey, cc.MakeCKKSPackedPlaintext(data))
    session.checkpoint("first", ciphertext=ciph, expected=data)
    session.checkpoint("second", ciphertext=ciph, expected=data)
    result = cc.Decrypt(ciph, keys.secretKey)

check_close(decode(result, 4), data)
