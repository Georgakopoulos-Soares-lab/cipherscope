"""packing.low_utilization_annotated.v1 -- affine transform of many short vectors.

Workload: N independent 64-element vectors each need y = x * w + b (w, b
public per-position constants). Every ciphertext in this context has
ring_dim/2 slots (4096 at these parameters).

before: one ciphertext per vector, 64 meaningful slots each, annotated as
        such: utilization 64/4096 = 1.6 %. N encryptions, N multiplications,
        N additions, N decryptions. CipherScope flags every ciphertext.
after:  rewritten from the finding: the N vectors are concatenated into one
        full-slot ciphertext (utilization 100 %) and the same three
        operations run once. Same arithmetic per element, N times fewer
        OpenFHE calls.
"""

from __future__ import annotations

from _base import Case, ckks_context, decode, max_abs_error

LENGTH = 64


class PackingLow(Case):
    rule = "packing.low_utilization_annotated.v1"
    name = "packing_low"

    def prepare(self) -> None:
        self.context, self.parameters = ckks_context(1)
        self.keys = self.context.KeyGen()
        self.trace_kwargs = {"parameters": self.parameters}
        self.slots = int(self.context.GetRingDimension()) // 2
        self.count = self.slots // LENGTH
        self.vectors = [[0.01 * ((i * 3 + v) % 50) for i in range(LENGTH)] for v in range(self.count)]
        self.w = [0.5 + 0.01 * (i % 10) for i in range(LENGTH)]
        self.b = [0.1 * (i % 3) for i in range(LENGTH)]

    def _affine(self, cc, session, values, w, b, meaningful):
        ciph = cc.Encrypt(self.keys.publicKey, cc.MakeCKKSPackedPlaintext(values))
        if session is not None:
            session.annotate(ciph, shape=[meaningful], packing="row_major", meaningful_slots=meaningful)
        scaled = cc.EvalMult(ciph, cc.MakeCKKSPackedPlaintext(w))
        shifted = cc.EvalAdd(scaled, cc.MakeCKKSPackedPlaintext(b))
        return cc.Decrypt(shifted, self.keys.secretKey)

    def workload(self, cc, session=None):
        if self.variant == "before":
            return [self._affine(cc, session, values, self.w, self.b, LENGTH) for values in self.vectors]
        flat = [x for values in self.vectors for x in values]
        w = self.w * self.count
        b = self.b * self.count
        return [self._affine(cc, session, flat, w, b, self.slots)]

    def check(self, result) -> float:
        expected_all = [[x * w + b for x, w, b in zip(values, self.w, self.b)] for values in self.vectors]
        if self.variant == "before":
            return max(max_abs_error(decode(pt, LENGTH), exp) for pt, exp in zip(result, expected_all))
        flat_expected = [y for row in expected_all for y in row]
        return max_abs_error(decode(result[0], self.slots), flat_expected)


def build(variant: str) -> Case:
    return PackingLow(variant)
