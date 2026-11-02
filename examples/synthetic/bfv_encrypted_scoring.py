#!/usr/bin/env python3
"""Score encrypted integer records against a public model under BFV.

Real OpenFHE program using CipherScope's session annotation API. It is the
integer counterpart of the CKKS annotation examples and exists to exercise
four analyzers at once on an exact scheme:

* the same public weight vector is encoded twice under one ``constant_id``,
  so the repeated-encoding rule can report it;
* the public bias is encrypted and then multiplied ciphertext-by-ciphertext
  although a plaintext operand would do, which the provenance rule reports;
* only a handful of the N integer slots carry data, declared through
  ``meaningful_slots``, which the packing rule reports;
* the per-record products are folded left to right inside a declared
  associative region, which the serial-reduction rule reports.

BFV packs N slots rather than the N/2 CKKS packs, and it is exact: the
printed score is checked for equality, not against a tolerance.
"""

from __future__ import annotations

import cipherscope
import openfhe

RECORDS = 8  # BFV requires a power-of-two batch size (or zero for full packing)
PLAINTEXT_MODULUS = 65537

parameters = openfhe.CCParamsBFVRNS()
parameters.SetPlaintextModulus(PLAINTEXT_MODULUS)
parameters.SetMultiplicativeDepth(4)
parameters.SetBatchSize(RECORDS)

context = openfhe.GenCryptoContext(parameters)
context.Enable(openfhe.PKESchemeFeature.PKE)
context.Enable(openfhe.PKESchemeFeature.KEYSWITCH)
context.Enable(openfhe.PKESchemeFeature.LEVELEDSHE)
keys = context.KeyGen()
context.EvalMultKeyGen(keys.secretKey)

features = [3, 1, 4, 1, 5, 9, 2, 6]
weights = [2, 2, 2, 2, 2, 2, 2, 2]
bias = [1, 1, 1, 1, 1, 1, 1, 1]
gates = [1, 2, 1, 1, 2, 1, 1, 2]

with cipherscope.trace(context, name="bfv_encrypted_scoring") as session:
    cc = session.context

    encrypted_features = cc.Encrypt(keys.publicKey, cc.MakePackedPlaintext(features))
    session.annotate(
        encrypted_features,
        shape=[RECORDS],
        packing="row_major",
        meaningful_slots=RECORDS,
    )

    # The same public weights, encoded once per use under one constant_id.
    weights_first = cc.MakePackedPlaintext(weights)
    session.annotate_plaintext(
        weights_first, provenance="model_parameter", constant_id="weights"
    )
    weighted = cc.EvalMult(encrypted_features, weights_first)

    weights_second = cc.MakePackedPlaintext(weights)
    session.annotate_plaintext(
        weights_second, provenance="model_parameter", constant_id="weights"
    )
    rescored = cc.EvalMult(encrypted_features, weights_second)

    # The bias is public, but it enters as a ciphertext operand of EvalMult.
    encrypted_bias = cc.Encrypt(keys.publicKey, cc.MakePackedPlaintext(bias))
    session.annotate(encrypted_bias, provenance="public_constant")
    biased = cc.EvalMult(weighted, encrypted_bias)

    # A left-to-right fold inside a region the developer declares associative.
    encrypted_gates = [
        cc.Encrypt(keys.publicKey, cc.MakePackedPlaintext(gates)) for _ in range(3)
    ]
    with session.region("gate_product", operator="multiply", associative=True, commutative=True):
        accumulator = biased
        for gate in encrypted_gates:
            accumulator = cc.EvalMult(accumulator, gate)

    combined = cc.EvalAdd(accumulator, rescored)
    decrypted = cc.Decrypt(combined, keys.secretKey)

decrypted.SetLength(RECORDS)
observed = [int(value) for value in decrypted.GetPackedValue()[:RECORDS]]


def reduce_modulus(value: int) -> int:
    remainder = value % PLAINTEXT_MODULUS
    return remainder if remainder < PLAINTEXT_MODULUS // 2 else remainder - PLAINTEXT_MODULUS


expected = [
    reduce_modulus(
        features[i] * weights[i] * bias[i] * gates[i] ** 3 + features[i] * weights[i]
    )
    for i in range(RECORDS)
]

print("BFV encrypted scoring over 8 records")
print(f"observed: {observed}")
print(f"expected: {expected}")
if observed != expected:
    raise SystemExit("exact mismatch: BFV must reproduce the score bit for bit")
