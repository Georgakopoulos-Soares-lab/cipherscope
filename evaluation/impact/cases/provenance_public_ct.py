"""provenance.public_value_ciphertext_mult.v1 -- weighting private records with public weights.

Workload: 16 encrypted records (full-slot packed) are multiplied elementwise
by a public weight vector and decrypted.

before: the public weights are encrypted too and the product is a
        ciphertext x ciphertext EvalMult: a tensor product of two size-2
        ciphertexts followed by relinearization (a key switch) on every
        record. The program annotates the weight ciphertext as
        provenance="public_constant"; CipherScope reports 16 ct x ct
        multiplications whose one operand is declared public.
after:  rewritten from the finding: the weights stay a plaintext and each
        product is ciphertext x plaintext -- no tensor product, no
        relinearization, one fewer encryption, and a smaller output.
"""

from __future__ import annotations

from _base import Case, ckks_context, decode, max_abs_error

RECORDS = 16


class ProvenancePublicCt(Case):
    rule = "provenance.public_value_ciphertext_mult.v1"
    name = "provenance_public_ct"

    def prepare(self) -> None:
        self.context, self.parameters = ckks_context(1)
        self.keys = self.context.KeyGen()
        self.context.EvalMultKeyGen(self.keys.secretKey)
        self.trace_kwargs = {"parameters": self.parameters}
        self.slots = int(self.context.GetRingDimension()) // 2
        self.weights = [0.25 + 0.05 * (i % 9) for i in range(self.slots)]
        self.records = [[0.2 + ((i * (r + 1)) % 17) / 17.0 for i in range(self.slots)] for r in range(RECORDS)]

    def workload(self, cc, session=None):
        weights_pt = cc.MakeCKKSPackedPlaintext(self.weights)
        if self.variant == "before":
            weights_operand = cc.Encrypt(self.keys.publicKey, weights_pt)
            if session is not None:
                session.annotate(weights_operand, provenance="public_constant")
        else:
            weights_operand = weights_pt
        outputs = []
        for record in self.records:
            ciph = cc.Encrypt(self.keys.publicKey, cc.MakeCKKSPackedPlaintext(record))
            outputs.append(cc.Decrypt(cc.EvalMult(ciph, weights_operand), self.keys.secretKey))
        return outputs

    def check(self, result) -> float:
        worst = 0.0
        for record, plaintext in zip(self.records, result):
            expected = [w * x for w, x in zip(self.weights, record)]
            worst = max(worst, max_abs_error(decode(plaintext, self.slots), expected))
        return worst


def build(variant: str) -> Case:
    return ProvenancePublicCt(variant)
