"""multiplication.serial_reduction_review.v1 -- product of 16 encrypted factors.

Workload: four independent products of 16 encrypted factors each (e.g. a
compounded growth series, or a joint probability), inside a
session.region(operator="multiply", associative=True) assertion.

before: left-to-right fold: acc = ((f1*f2)*f3)*...*f16 -- 15 multiplications
        deep, so the context must be configured for multiplicative depth 15
        (at 128-bit security that forces ring dimension 32768 with a 16-limb
        modulus chain). CipherScope reports the region as a 15-deep serial
        chain over 16 terms where a balanced tree needs 4.
after:  rewritten from the finding: a balanced pairwise tree -- the same 15
        multiplications, but only 4 deep -- so the context is configured for
        depth 4 (ring dimension 16384, 5 limbs). Every operation, key and
        ciphertext shrinks with the parameters.

Where the benefit lands: context/key setup, workload time, memory.
"""

from __future__ import annotations

from _base import Case, ckks_context, decode, max_abs_error

PRODUCTS = 4
FACTORS = 16
SLOTS = 8


class SerialReduction(Case):
    rule = "multiplication.serial_reduction_review.v1"
    name = "serial_reduction"

    def prepare(self) -> None:
        depth = FACTORS - 1 if self.variant == "before" else 4
        self.context, self.parameters = ckks_context(depth, batch=SLOTS)
        self.keys = self.context.KeyGen()
        self.context.EvalMultKeyGen(self.keys.secretKey)
        self.trace_kwargs = {"parameters": self.parameters}
        self.factors = [
            [[1.0 + 0.02 * (((p * FACTORS + f) * (s + 1)) % 5 - 2) for s in range(SLOTS)] for f in range(FACTORS)]
            for p in range(PRODUCTS)
        ]

    def _product(self, cc, ciphertexts):
        if self.variant == "before":
            acc = ciphertexts[0]
            for factor in ciphertexts[1:]:
                acc = cc.EvalMult(acc, factor)
            return acc
        level = list(ciphertexts)
        while len(level) > 1:
            level = [cc.EvalMult(level[i], level[i + 1]) for i in range(0, len(level), 2)]
        return level[0]

    def workload(self, cc, session=None):
        outputs = []
        for factors in self.factors:
            ciphertexts = [cc.Encrypt(self.keys.publicKey, cc.MakeCKKSPackedPlaintext(values)) for values in factors]
            if session is not None:
                with session.region("product", operator="multiply", associative=True, commutative=True):
                    product = self._product(cc, ciphertexts)
            else:
                product = self._product(cc, ciphertexts)
            outputs.append(cc.Decrypt(product, self.keys.secretKey))
        return outputs

    def check(self, result) -> float:
        worst = 0.0
        for factors, plaintext in zip(self.factors, result):
            expected = [1.0] * SLOTS
            for values in factors:
                expected = [e * v for e, v in zip(expected, values)]
            worst = max(worst, max_abs_error(decode(plaintext, SLOTS), expected))
        return worst


def build(variant: str) -> Case:
    return SerialReduction(variant)
