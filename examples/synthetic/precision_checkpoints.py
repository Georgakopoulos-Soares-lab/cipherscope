#!/usr/bin/env python3
"""Measure CKKS precision loss across a computation with checkpoints.

Real OpenFHE program using CipherScope's opt-in shadow mode. Two checkpoints
decrypt the ciphertext, compare against the expected plaintext values, and record
only aggregate precision metrics. The precision analyzer ranks the absolute-bit
drop between the checkpoints. Shadow mode is explicit and off by default, so this
program only works when run directly (it self-manages the secret key).
"""

from __future__ import annotations

import cipherscope
import openfhe
from cipherscope.analyzers.precision import analyze_precision

parameters = openfhe.CCParamsCKKSRNS()
parameters.SetMultiplicativeDepth(4)
parameters.SetScalingModSize(50)
parameters.SetScalingTechnique(openfhe.ScalingTechnique.FLEXIBLEAUTO)

context = openfhe.GenCryptoContext(parameters)
context.Enable(openfhe.PKESchemeFeature.PKE)
context.Enable(openfhe.PKESchemeFeature.KEYSWITCH)
context.Enable(openfhe.PKESchemeFeature.LEVELEDSHE)
keys = context.KeyGen()
context.EvalMultKeyGen(keys.secretKey)

data = [0.2, 0.4, 0.6, 0.8]

with cipherscope.trace(
    context,
    name="precision_checkpoints",
    secret_key=keys.secretKey,
    shadow_mode=True,
) as session:
    cc = session.context
    ciph = cc.Encrypt(keys.publicKey, cc.MakeCKKSPackedPlaintext(data))
    session.checkpoint("fresh_encryption", ciphertext=ciph, expected=data)

    # Three successive squarings accumulate rescaling error.
    current = list(data)
    for _ in range(3):
        ciph = cc.EvalSquare(ciph)
        current = [value * value for value in current]
    session.checkpoint("after_three_squarings", ciphertext=ciph, expected=current)

report = analyze_precision(session.to_trace())
print(f"precision analysis: {report['analysis_status']}")
for finding in report["findings"]:
    drop = finding["evidence"]
    print(
        f"  {drop['from_checkpoint']} -> {drop['to_checkpoint']}: "
        f"{drop['absolute_bits_lost']:.2f} absolute bits lost"
    )
