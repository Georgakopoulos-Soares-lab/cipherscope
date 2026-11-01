"""rotation.hoist_same_input.v1 -- 9-wide moving sum over packed series.

Workload: for each of four encrypted series, a moving sum of width 9 needs the
same ciphertext rotated by 1..8 and the eight rotations added together.

before: eight EvalRotate calls on the same ciphertext version. Every call
        repeats the digit decomposition of the same input before its own
        automorphism + key switch. CipherScope's rotation analyzer reports the
        eight rotations as compatible with one shared precomputation.
after:  rewritten from that finding exactly as its recommendation says: one
        EvalFastRotationPrecompute per input ciphertext, then eight
        EvalFastRotation calls that reuse the decomposed digits (Halevi-Shoup
        hoisting). Rotation keys are unchanged; only the workload changes.
"""

from __future__ import annotations

from _base import Case, ckks_context, decode, max_abs_error

SERIES = 4
LENGTH = 64
WINDOW = list(range(1, 9))


class RotationHoist(Case):
    rule = "rotation.hoist_same_input.v1"
    name = "rotation_hoist"

    def prepare(self) -> None:
        self.context, self.parameters = ckks_context(1, batch=LENGTH)
        self.keys = self.context.KeyGen()
        self.context.EvalRotateKeyGen(self.keys.secretKey, WINDOW)
        self.cyclotomic_order = int(self.context.GetCyclotomicOrder())
        self.trace_kwargs = {"parameters": self.parameters}
        self.series = [[0.05 * ((i * (s + 3)) % 11) + 0.1 for i in range(LENGTH)] for s in range(SERIES)]

    def workload(self, cc, session=None):
        outputs = []
        for values in self.series:
            ciph = cc.Encrypt(self.keys.publicKey, cc.MakeCKKSPackedPlaintext(values))
            if self.variant == "before":
                rotated = [cc.EvalRotate(ciph, k) for k in WINDOW]
            else:
                digits = cc.EvalFastRotationPrecompute(ciph)
                rotated = [cc.EvalFastRotation(ciph, k, self.cyclotomic_order, digits) for k in WINDOW]
            acc = ciph
            for term in rotated:
                acc = cc.EvalAdd(acc, term)
            outputs.append(cc.Decrypt(acc, self.keys.secretKey))
        return outputs

    def check(self, result) -> float:
        worst = 0.0
        for values, plaintext in zip(self.series, result):
            expected = [sum(values[(i + k) % LENGTH] for k in [0, *WINDOW]) for i in range(LENGTH)]
            worst = max(worst, max_abs_error(decode(plaintext, LENGTH), expected))
        return worst


def build(variant: str) -> Case:
    return RotationHoist(variant)
