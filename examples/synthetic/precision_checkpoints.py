#!/usr/bin/env python3
"""Measure CKKS precision loss across a computation with checkpoints.

Real OpenFHE program using CipherScope's opt-in shadow mode. Two checkpoints
decrypt the ciphertext and record the expected and observed values; the
precision analyzer ranks the absolute-bit drop between them. The inputs are
above 1 so that three squarings grow the magnitudes and the absolute error with
them (about 14 bits lost on this build); values below 1 shrink the error and
report clean. Each checkpoint also declares an absolute tolerance; the
tolerance rule reports the first checkpoint that breaks it. Shadow mode is
explicit and off by default; this program opts in with its own secret key, which
works when run directly or under cipherscope run.
"""

from __future__ import annotations

import cipherscope
import openfhe
from cipherscope.analyzers.precision import analyze_precision, analyze_tolerance

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

data = [1.5, 2.0, 2.5, 3.0]

with cipherscope.trace(
    context,
    name="precision_checkpoints",
    secret_key=keys.secretKey,
    shadow_mode=True,
) as session:
    cc = session.context
    ciph = cc.Encrypt(keys.publicKey, cc.MakeCKKSPackedPlaintext(data))
    tolerance = {"absolute": 1e-6}
    session.checkpoint(
        "fresh_encryption", ciphertext=ciph, expected=data, tolerance=tolerance
    )

    # Three successive squarings accumulate rescaling error.
    current = list(data)
    for _ in range(3):
        ciph = cc.EvalSquare(ciph)
        current = [value * value for value in current]
    session.checkpoint(
        "after_three_squarings", ciphertext=ciph, expected=current, tolerance=tolerance
    )

trace = session.to_trace()
report = analyze_precision(trace)
print(f"precision analysis: {report['analysis_status']}")
for finding in report["findings"]:
    drop = finding["evidence"]
    print(
        f"  {drop['from_checkpoint']} -> {drop['to_checkpoint']}: "
        f"{drop['absolute_bits_lost']:.2f} absolute bits lost"
    )
contract = analyze_tolerance(trace)
print(f"tolerance analysis: {contract['analysis_status']}")
for finding in contract["findings"]:
    evidence = finding["evidence"]
    print(
        f"  first violation at {evidence['violated_checkpoint']!r} "
        f"(max abs error {evidence['max_abs_error']:.2e} > {evidence['tolerance']})"
    )
