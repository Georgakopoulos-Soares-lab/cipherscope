"""parameters.depth_headroom_observed.v1 -- a fixed 3-level kernel on over-provisioned parameters.

Workload (identical in both variants): eight encrypted vectors each raised to
the eighth power by three squarings, each followed by an explicit Rescale
(FIXEDMANUAL, so every multiplication consumes exactly one observable level),
then decrypted. The kernel consumes 3 levels, no more, no less.

before: the context is configured for multiplicative depth 12 -- the "leave
        plenty of room" setting that development configs tend to keep.
        CipherScope observes 3 levels consumed against 12 configured and
        reports 9 levels of headroom.
after:  rewritten from the finding's observed_max_levels_consumed_in_epoch:
        depth 3. At 128-bit security that drops the ring dimension from
        32768 to 8192 and the modulus chain from 13 limbs to 4, so every key,
        ciphertext and operation is smaller, with the arithmetic untouched.

Where the benefit lands: everything -- key generation, workload, memory.
This is the same finding CipherScope raised on two of the external corpus
programs (evaluation/adjudication/findings.csv, TP-ACTIONABLE).
"""

from __future__ import annotations

from _base import Case, ckks_context, decode, max_abs_error

VECTORS = 8
SLOTS = 32
LEVELS = 3


class DepthHeadroom(Case):
    rule = "parameters.depth_headroom_observed.v1"
    name = "depth_headroom"

    def prepare(self) -> None:
        depth = 12 if self.variant == "before" else LEVELS
        self.context, self.parameters = ckks_context(depth, batch=SLOTS, technique="FIXEDMANUAL")
        self.keys = self.context.KeyGen()
        self.context.EvalMultKeyGen(self.keys.secretKey)
        self.trace_kwargs = {"parameters": self.parameters}
        self.vectors = [[0.5 + 0.02 * ((i * (v + 1)) % 30) for i in range(SLOTS)] for v in range(VECTORS)]

    def workload(self, cc, session=None):
        outputs = []
        for values in self.vectors:
            ciph = cc.Encrypt(self.keys.publicKey, cc.MakeCKKSPackedPlaintext(values))
            for _ in range(LEVELS):
                ciph = cc.Rescale(cc.EvalMult(ciph, ciph))
            outputs.append(cc.Decrypt(ciph, self.keys.secretKey))
        return outputs

    def check(self, result) -> float:
        worst = 0.0
        for values, plaintext in zip(self.vectors, result):
            expected = [v ** (2 ** LEVELS) for v in values]
            worst = max(worst, max_abs_error(decode(plaintext, SLOTS), expected))
        return worst


def build(variant: str) -> Case:
    return DepthHeadroom(variant)
