#!/usr/bin/env python3
"""Annotate low slot utilization on a real CKKS ciphertext.

Real OpenFHE program using CipherScope's session annotation API. Only eight of
the thousands of available CKKS slots carry meaningful data, and the explicit
``meaningful_slots`` annotation lets the packing analyzer report that as low
utilization. CipherScope never infers utilization from the ciphertext contents.
"""

from __future__ import annotations

import cipherscope
import openfhe
from cipherscope.analyzers.packing import analyze_packing

MEANINGFUL = 8

parameters = openfhe.CCParamsCKKSRNS()
parameters.SetMultiplicativeDepth(2)
parameters.SetScalingModSize(50)

context = openfhe.GenCryptoContext(parameters)
context.Enable(openfhe.PKESchemeFeature.PKE)
context.Enable(openfhe.PKESchemeFeature.KEYSWITCH)
context.Enable(openfhe.PKESchemeFeature.LEVELEDSHE)
keys = context.KeyGen()
context.EvalMultKeyGen(keys.secretKey)

values = [float(i) for i in range(MEANINGFUL)]

with cipherscope.trace(context, name="annotate_packing") as session:
    cc = session.context
    ciph = cc.Encrypt(keys.publicKey, cc.MakeCKKSPackedPlaintext(values))
    # Assert that only MEANINGFUL slots are used out of the full CKKS capacity.
    session.annotate(
        ciph, shape=[MEANINGFUL], packing="row_major", meaningful_slots=MEANINGFUL
    )
    doubled = cc.EvalAdd(ciph, ciph)
    decrypted = cc.Decrypt(doubled, keys.secretKey)

decrypted.SetLength(MEANINGFUL)
print(f"doubled slot 0: {decrypted.GetRealPackedValue()[0]:.4f} (expected 0.0000)")

report = analyze_packing(session.to_trace())
print(f"packing analysis: {report['analysis_status']}")
for finding in report["findings"]:
    slots = finding["evidence"]["meaningful_slots"]
    available = finding["evidence"]["available_slots"]
    print(f"  low utilization: {slots}/{available} slots used")
