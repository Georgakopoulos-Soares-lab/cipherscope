"""keys.unused_in_observed_run.v1 -- moving-window statistics over a packed series.

Workload (identical in both variants): a 3-wide moving sum over each of eight
encrypted time series, i.e. rotations by 1 and 2 plus two additions per
series, then decryption.

before: the program generates rotation keys for every index 1..64 "in case",
        the way a reusable helper often does. CipherScope reports 62 generated
        indices that no covered rotation used in this run.
after:  rewritten from the finding's unused_generated_indices list: generate
        keys only for the indices the run actually rotates by (1 and 2).

Where the benefit lands: setup time (EvalRotateKeyGen) and process memory
(every rotation key is a full key-switching key), not in the workload, which
is byte-for-byte the same.
"""

from __future__ import annotations

from _base import Case, ckks_context, decode, max_abs_error

SERIES = 8
LENGTH = 64
USED = [1, 2]
OVERPROVISIONED = list(range(1, 65))


class KeysUnused(Case):
    rule = "keys.unused_in_observed_run.v1"
    name = "keys_unused"

    def prepare(self) -> None:
        self.context, self.parameters = ckks_context(1, batch=LENGTH)
        self.keys = self.context.KeyGen()
        self.trace_kwargs = {"parameters": self.parameters}
        self.series = [
            [((s + 1) * 0.01 * (i % 7) + 0.1) for i in range(LENGTH)] for s in range(SERIES)
        ]

    def setup(self, cc) -> None:
        indices = OVERPROVISIONED if self.variant == "before" else USED
        cc.EvalRotateKeyGen(self.keys.secretKey, indices)

    def workload(self, cc, session=None):
        outputs = []
        for values in self.series:
            ciph = cc.Encrypt(self.keys.publicKey, cc.MakeCKKSPackedPlaintext(values))
            window = cc.EvalAdd(cc.EvalAdd(ciph, cc.EvalRotate(ciph, 1)), cc.EvalRotate(ciph, 2))
            outputs.append(cc.Decrypt(window, self.keys.secretKey))
        return outputs

    def check(self, result) -> float:
        worst = 0.0
        for values, plaintext in zip(self.series, result):
            expected = [values[i] + values[(i + 1) % LENGTH] + values[(i + 2) % LENGTH] for i in range(LENGTH)]
            worst = max(worst, max_abs_error(decode(plaintext, LENGTH), expected))
        return worst


def build(variant: str) -> Case:
    return KeysUnused(variant)
