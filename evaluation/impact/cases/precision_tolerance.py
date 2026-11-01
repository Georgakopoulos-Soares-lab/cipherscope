"""precision.tolerance_violated.v1 (+ precision.checkpoint_drop.v1) -- x^8 on values above 1.

Workload: eight encrypted vectors of values in [1.1, 1.6] are raised to the
eighth power by three squarings (outputs up to ~43), with a shadow-mode
checkpoint on the fresh ciphertext and one on the result. The final
checkpoint declares an absolute tolerance of 1e-4.

before: ScalingModSize 30 / FirstModSize 40 -- a "small and fast" setting.
        The result comes back with ~11 absolute bits (error ~5e-4), so the
        declared tolerance is violated; the drop rule localizes ~7 bits of
        loss to the squaring block between the two checkpoints.
after:  rewritten from the tolerance finding: ScalingModSize 40 /
        FirstModSize 50 (same ring dimension at these sizes). The result
        comes back with ~21 absolute bits (error ~4e-7): inside tolerance.

What the drop rule does and does not do here: squaring values above 1
amplifies absolute error whatever the scale, so the ~7-bit loss between
the checkpoints is intrinsic to this arithmetic and the drop rule still
reports it after the fix -- it is the diagnostic that pointed at the block;
the metric the fix improves is absolute precision at the final checkpoint
(final_absolute_bits), which is what the tolerance contract checks. (A
59-bit scale is *not* a fix: 43 x 2^59 overflows a 60-bit first modulus and
the result is garbage -- the tolerance contract catches that too.)
"""

from __future__ import annotations

import math

from _base import Case, ckks_context, decode, max_abs_error

VECTORS = 8
SLOTS = 8
LEVELS = 3
TOLERANCE = {"absolute": 1e-4}


class PrecisionTolerance(Case):
    rule = "precision.tolerance_violated.v1"
    name = "precision_tolerance"
    tolerance = 1e-2  # correctness floor for the run itself; the contract under test is 1e-4

    def prepare(self) -> None:
        scaling, first = (30, 40) if self.variant == "before" else (40, 50)
        self.context, self.parameters = ckks_context(LEVELS, scaling_mod_size=scaling, first_mod_size=first, batch=SLOTS)
        self.keys = self.context.KeyGen()
        self.context.EvalMultKeyGen(self.keys.secretKey)
        self.trace_kwargs = {"parameters": self.parameters, "secret_key": self.keys.secretKey, "shadow_mode": True}
        self.vectors = [[1.1 + 0.5 * ((i * 3 + v) % 8) / 7.0 for i in range(SLOTS)] for v in range(VECTORS)]

    def workload(self, cc, session=None):
        outputs = []
        for index, values in enumerate(self.vectors):
            ciph = cc.Encrypt(self.keys.publicKey, cc.MakeCKKSPackedPlaintext(values))
            if session is not None:
                session.checkpoint(f"fresh_{index}", ciphertext=ciph, expected=values)
            current = list(values)
            for _ in range(LEVELS):
                ciph = cc.EvalMult(ciph, ciph)
                current = [v * v for v in current]
            if session is not None:
                session.checkpoint(f"result_{index}", ciphertext=ciph, expected=current, tolerance=TOLERANCE)
            outputs.append(cc.Decrypt(ciph, self.keys.secretKey))
        return outputs

    def check(self, result) -> float:
        worst = 0.0
        for values, plaintext in zip(self.vectors, result):
            expected = [v ** (2 ** LEVELS) for v in values]
            worst = max(worst, max_abs_error(decode(plaintext, SLOTS), expected))
        self.extra_metrics["final_absolute_bits"] = -math.log2(max(worst, 1e-300))
        self.extra_metrics["tolerance_met"] = 1.0 if worst <= TOLERANCE["absolute"] else 0.0
        return worst


def build(variant: str) -> Case:
    return PrecisionTolerance(variant)
