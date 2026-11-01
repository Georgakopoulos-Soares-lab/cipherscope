"""configuration.testing_only_security.v1 -- a development parameter set that reached a real run.

Workload (identical in both variants): a two-level scoring kernel on 16
encrypted records -- multiply by public weights, add a public bias, square --
then decryption.

before: SecurityLevel HEStd_NotSet with a hand-picked ring dimension of
        4096, the prototyping shortcut the OpenFHE tutorials themselves
        recommend ("turn off the security setting"). Fast, and with no
        enforced security level at all. CipherScope reports the declared
        HEStd_NotSet as a testing-only configuration.
after:  rewritten from the finding: SecurityLevel HEStd_128_classic and let
        OpenFHE choose the ring dimension (16384 at this depth and scale).

This is the one pair whose "improvement" is not a speedup: the metric that
improves is the enforced security level (0 -> 128 bits, `security_bits`),
and the honest cost of that -- larger ring, slower keys and operations, more
memory -- is what the other columns measure. It is also the finding that was
true on three of the four external corpus programs.
"""

from __future__ import annotations

from _base import Case, ckks_context, decode, max_abs_error

RECORDS = 16
SLOTS = 64


class SecurityConfig(Case):
    rule = "configuration.testing_only_security.v1"
    name = "security_config"

    def prepare(self) -> None:
        if self.variant == "before":
            self.context, self.parameters = ckks_context(2, batch=SLOTS, security="HEStd_NotSet", ring_dim=1 << 12)
            self.trace_kwargs = {"parameters": self.parameters, "allow_testing_security": True}
            self.extra_metrics["security_bits"] = 0.0
        else:
            self.context, self.parameters = ckks_context(2, batch=SLOTS, security="HEStd_128_classic")
            self.trace_kwargs = {"parameters": self.parameters}
            self.extra_metrics["security_bits"] = 128.0
        self.keys = self.context.KeyGen()
        self.context.EvalMultKeyGen(self.keys.secretKey)
        self.weights = [0.3 + 0.05 * (i % 7) for i in range(SLOTS)]
        self.bias = [0.1 * (i % 4) for i in range(SLOTS)]
        self.records = [[0.2 + ((i * (r + 1)) % 11) / 11.0 for i in range(SLOTS)] for r in range(RECORDS)]

    def workload(self, cc, session=None):
        weights_pt = cc.MakeCKKSPackedPlaintext(self.weights)
        bias_pt = cc.MakeCKKSPackedPlaintext(self.bias)
        outputs = []
        for record in self.records:
            ciph = cc.Encrypt(self.keys.publicKey, cc.MakeCKKSPackedPlaintext(record))
            scored = cc.EvalAdd(cc.EvalMult(ciph, weights_pt), bias_pt)
            outputs.append(cc.Decrypt(cc.EvalMult(scored, scored), self.keys.secretKey))
        return outputs

    def check(self, result) -> float:
        worst = 0.0
        for record, plaintext in zip(self.records, result):
            expected = [(x * w + b) ** 2 for x, w, b in zip(record, self.weights, self.bias)]
            worst = max(worst, max_abs_error(decode(plaintext, SLOTS), expected))
        return worst


def build(variant: str) -> Case:
    return SecurityConfig(variant)
