#!/usr/bin/env python3
"""Sliding-window sums over an encrypted integer vector under BGV.

Real OpenFHE program, no CipherScope import: run it directly, or profile it
unchanged through ``profile_unmodified.py``. It exercises the two rules that
need no developer annotation, on a scheme that spends levels exactly as CKKS
does while being exact:

* four rotations read the same recorded ciphertext version, which is the
  shape the repeated-rotation rule looks for;
* rotation keys are generated for five offsets and only four are used, so the
  observed-run key rule reports the fifth;
* the context is configured for six multiplicative levels and the program
  spends one, which the depth-headroom rule reports from the BGV level ladder
  (``depth_evidence: ciphertext_levels``, unlike BFV).

BGV rotation shifts left with zero fill rather than wrapping the batch, so the
expected window sums below are not cyclic.
"""

from openfhe import *

WINDOW = 4
LENGTH = 8
PLAINTEXT_MODULUS = 65537

parameters = CCParamsBGVRNS()
parameters.SetPlaintextModulus(PLAINTEXT_MODULUS)
parameters.SetMultiplicativeDepth(6)
parameters.SetBatchSize(LENGTH)

cc = GenCryptoContext(parameters)
cc.Enable(PKESchemeFeature.PKE)
cc.Enable(PKESchemeFeature.KEYSWITCH)
cc.Enable(PKESchemeFeature.LEVELEDSHE)

keys = cc.KeyGen()
cc.EvalMultKeyGen(keys.secretKey)
# Offsets 1..3 are used below; 7 is generated and never used this run.
cc.EvalRotateKeyGen(keys.secretKey, [1, 2, 3, 7])

data = [2, 4, 6, 8, 10, 12, 14, 16]
source = cc.Encrypt(keys.publicKey, cc.MakePackedPlaintext(data))

# Four reads of one ciphertext version: the identity, plus three rotations.
window = source
for offset in range(1, WINDOW):
    window = cc.EvalAdd(window, cc.EvalRotate(source, offset))

# One multiplication, against a context configured for six levels.
scaled = cc.EvalMult(window, cc.MakePackedPlaintext([2] * LENGTH))

decrypted = cc.Decrypt(scaled, keys.secretKey)
decrypted.SetLength(LENGTH)
observed = [int(value) for value in decrypted.GetPackedValue()[:LENGTH]]


def shifted(amount: int) -> list[int]:
    return [data[i + amount] if i + amount < LENGTH else 0 for i in range(LENGTH)]


expected = [
    2 * sum(shifted(offset)[i] for offset in range(WINDOW)) % PLAINTEXT_MODULUS
    for i in range(LENGTH)
]

print(f"BGV sliding window of {WINDOW} over {LENGTH} encrypted integers, doubled")
print(f"observed: {observed}")
print(f"expected: {expected}")
if observed != expected:
    raise SystemExit("exact mismatch: BGV must reproduce the window sums bit for bit")
