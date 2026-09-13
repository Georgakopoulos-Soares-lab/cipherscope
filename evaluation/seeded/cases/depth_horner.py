"""Seeded value check: Horner evaluation of a degree-4 polynomial.

Hand-derived nonlinear depth: the first step multiplies by a scalar (depth 0),
then three ciphertext-by-ciphertext multiplications chain on the accumulator,
so the deepest ciphertext-only path is 3.
Expected: depth.critical_path.v1 reports nonlinear_ciphertext.max_depth == 3.
"""

from _kernel import check_close, decode, make_context

import cipherscope

COEFFS = [1.0, 2.0, 3.0, 4.0, 5.0]  # p(x) = 1 + 2x + 3x^2 + 4x^3 + 5x^4
data = [-1.0, -0.5, 0.0, 0.5, 1.0]

context, keys = make_context(len(COEFFS), batch=8)

with cipherscope.trace(context, name="depth_horner") as session:
    cc = session.context
    ciph = cc.Encrypt(keys.publicKey, cc.MakeCKKSPackedPlaintext(data))
    acc = cc.EvalAdd(cc.EvalMult(ciph, COEFFS[-1]), COEFFS[-2])
    for coeff in reversed(COEFFS[:-2]):
        acc = cc.EvalMult(acc, ciph)
        acc = cc.EvalAdd(acc, coeff)
    result = cc.Decrypt(acc, keys.secretKey)


def horner(x: float) -> float:
    value = 0.0
    for coeff in reversed(COEFFS):
        value = value * x + coeff
    return value


check_close(decode(result, len(data)), [horner(x) for x in data])
