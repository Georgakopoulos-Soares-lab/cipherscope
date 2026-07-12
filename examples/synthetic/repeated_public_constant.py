#!/usr/bin/env python3
"""Encode the same public constant twice under one explicit constant_id.

Real OpenFHE program using CipherScope's plaintext-provenance API. The same model
weights are encoded on two occasions; tagging both encodings with one run-local
``constant_id`` lets the encoding analyzer flag the redundant work. CipherScope
does not hash or compare plaintext values to detect this.
"""

from __future__ import annotations

import cipherscope
import openfhe
from cipherscope.analyzers.encoding import analyze_encoding

parameters = openfhe.CCParamsCKKSRNS()
parameters.SetMultiplicativeDepth(2)
parameters.SetScalingModSize(50)

context = openfhe.GenCryptoContext(parameters)
context.Enable(openfhe.PKESchemeFeature.PKE)
context.Enable(openfhe.PKESchemeFeature.KEYSWITCH)
context.Enable(openfhe.PKESchemeFeature.LEVELEDSHE)
keys = context.KeyGen()
context.EvalMultKeyGen(keys.secretKey)

weights = [0.1, 0.2, 0.3, 0.4]
inputs_a = [1.0, 1.0, 1.0, 1.0]
inputs_b = [2.0, 2.0, 2.0, 2.0]

with cipherscope.trace(context, name="repeated_public_constant") as session:
    cc = session.context

    # First use of the public weights.
    weights_plaintext_1 = cc.MakeCKKSPackedPlaintext(weights)
    session.annotate_plaintext(
        weights_plaintext_1, provenance="model_parameter", constant_id="layer0_weights"
    )
    ciph_a = cc.Encrypt(keys.publicKey, cc.MakeCKKSPackedPlaintext(inputs_a))
    out_a = cc.EvalMult(ciph_a, weights_plaintext_1)

    # Second, redundant encoding of the same public weights.
    weights_plaintext_2 = cc.MakeCKKSPackedPlaintext(weights)
    session.annotate_plaintext(
        weights_plaintext_2, provenance="model_parameter", constant_id="layer0_weights"
    )
    ciph_b = cc.Encrypt(keys.publicKey, cc.MakeCKKSPackedPlaintext(inputs_b))
    out_b = cc.EvalMult(ciph_b, weights_plaintext_2)

    cc.Decrypt(out_a, keys.secretKey)
    cc.Decrypt(out_b, keys.secretKey)

report = analyze_encoding(session.to_trace())
print(f"encoding analysis: {report['analysis_status']}")
for finding in report["findings"]:
    evidence = finding["evidence"]
    print(
        f"  constant '{evidence['constant_id']}' encoded "
        f"{evidence['encoding_count']} times"
    )
