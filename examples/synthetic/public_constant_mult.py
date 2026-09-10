#!/usr/bin/env python3
"""Multiply an encrypted input by an operand asserted to be a public constant.

Real OpenFHE program using CipherScope's session annotation API. The model
weights are public, so multiplying them as a ciphertext-ciphertext product is a
candidate for a cheaper plaintext multiplication. The provenance analyzer surfaces
this as an advisory review item; it is not proof the change is correct.
"""

from __future__ import annotations

import cipherscope
import openfhe
from cipherscope.analyzers.provenance import analyze_provenance

parameters = openfhe.CCParamsCKKSRNS()
parameters.SetMultiplicativeDepth(2)
parameters.SetScalingModSize(50)

context = openfhe.GenCryptoContext(parameters)
context.Enable(openfhe.PKESchemeFeature.PKE)
context.Enable(openfhe.PKESchemeFeature.KEYSWITCH)
context.Enable(openfhe.PKESchemeFeature.LEVELEDSHE)
keys = context.KeyGen()
context.EvalMultKeyGen(keys.secretKey)

public_weights = [0.5, 0.5, 0.5, 0.5]
private_input = [1.0, 2.0, 3.0, 4.0]

with cipherscope.trace(context, name="public_constant_mult") as session:
    cc = session.context
    ciph_weights = cc.Encrypt(
        keys.publicKey, cc.MakeCKKSPackedPlaintext(public_weights)
    )
    ciph_input = cc.Encrypt(keys.publicKey, cc.MakeCKKSPackedPlaintext(private_input))
    # Assert that the weights ciphertext holds a public constant.
    session.annotate(ciph_weights, provenance="public_constant")
    product = cc.EvalMult(ciph_weights, ciph_input)
    decrypted = cc.Decrypt(product, keys.secretKey)

decrypted.SetLength(len(private_input))
observed = [round(v, 4) for v in decrypted.GetRealPackedValue()[: len(private_input)]]
print(f"product: {observed} (expected [0.5, 1.0, 1.5, 2.0])")

report = analyze_provenance(session.to_trace())
print(f"provenance analysis: {report['analysis_status']}")
for finding in report["findings"]:
    print(
        f"  public-operand ciphertext multiply at event {finding['evidence_event_ids']}"
    )
