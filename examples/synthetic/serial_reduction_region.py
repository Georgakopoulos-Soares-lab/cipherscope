"""Reduce a product of five ciphertexts serially inside an associative region.

Real OpenFHE program using CipherScope's region API. The five encrypted factors
are multiplied left-to-right, a chain that costs four sequential multiplicative
levels. Declaring the region as an associative multiply lets the serial-reduction
analyzer propose a balanced (log-depth) tree instead. The region assertions are
the user's claim; CipherScope does not assume associativity on its own.
"""

from __future__ import annotations

import cipherscope
import openfhe
from cipherscope.analyzers.serial_reduction import analyze_serial_reductions

FACTORS = [1.10, 1.05, 0.95, 1.20, 0.90]

parameters = openfhe.CCParamsCKKSRNS()
parameters.SetMultiplicativeDepth(len(FACTORS))
parameters.SetScalingModSize(50)
parameters.SetScalingTechnique(openfhe.ScalingTechnique.FLEXIBLEAUTO)

context = openfhe.GenCryptoContext(parameters)
context.Enable(openfhe.PKESchemeFeature.PKE)
context.Enable(openfhe.PKESchemeFeature.KEYSWITCH)
context.Enable(openfhe.PKESchemeFeature.LEVELEDSHE)
keys = context.KeyGen()
context.EvalMultKeyGen(keys.secretKey)

with cipherscope.trace(context, name="serial_reduction_region") as session:
    cc = session.context
    ciphertexts = [
        cc.Encrypt(
            keys.publicKey, cc.MakeCKKSPackedPlaintext([value, value, value, value])
        )
        for value in FACTORS
    ]

    with session.region(
        "product", operator="multiply", associative=True, commutative=True
    ):
        accumulator = ciphertexts[0]
        for factor in ciphertexts[1:]:
            accumulator = cc.EvalMult(accumulator, factor)

    decrypted = cc.Decrypt(accumulator, keys.secretKey)

decrypted.SetLength(1)
expected = 1.0
for value in FACTORS:
    expected *= value
print(
    f"serial product: {decrypted.GetRealPackedValue()[0]:.4f} (expected {expected:.4f})"
)

report = analyze_serial_reductions(session.to_trace())
print(f"serial-reduction analysis: {report['analysis_status']}")
for finding in report["findings"]:
    evidence = finding["evidence"]
    print(
        f"  region '{evidence['region']}': serial depth "
        f"{evidence['serial_multiplicative_depth']} vs balanced "
        f"{evidence['balanced_multiplicative_depth']}"
    )
