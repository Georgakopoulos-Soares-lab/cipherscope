"""encoding.repeated_public_constant.v1 -- scoring a batch against one public model.

Workload: 32 encrypted feature vectors (full-slot packed) are each multiplied
by the same public weight vector and the products decrypted -- the shape of
scoring many records against one fixed, public model.

before: the weight vector is re-encoded with MakeCKKSPackedPlaintext inside
        the per-record loop, 32 times, every encoding annotated with the same
        constant_id. CipherScope reports 32 encodings of one public constant.
after:  rewritten from the finding's recommendation ("encode this public
        constant once and reuse the plaintext"): one encoding hoisted out of
        the loop, reused for all 32 multiplications.

Where the benefit lands: workload time (an encoding is an inverse FFT over
every slot) and event count; the arithmetic is unchanged.
"""

from __future__ import annotations

from _base import Case, ckks_context, decode, max_abs_error

RECORDS = 32
CONSTANT_ID = "model_weights"


class EncodingRepeated(Case):
    rule = "encoding.repeated_public_constant.v1"
    name = "encoding_repeated"

    def prepare(self) -> None:
        self.context, self.parameters = ckks_context(1)
        self.keys = self.context.KeyGen()
        self.trace_kwargs = {"parameters": self.parameters}
        self.slots = int(self.context.GetRingDimension()) // 2
        self.weights = [0.5 + 0.25 * ((i * 7) % 5) / 5.0 for i in range(self.slots)]
        self.records = [
            [0.1 + ((i + r) % 13) / 13.0 for i in range(self.slots)] for r in range(RECORDS)
        ]

    def _encode_weights(self, cc, session):
        plaintext = cc.MakeCKKSPackedPlaintext(self.weights)
        if session is not None:
            session.annotate_plaintext(plaintext, provenance="model_parameter", constant_id=CONSTANT_ID)
        return plaintext

    def workload(self, cc, session=None):
        outputs = []
        weights_pt = None if self.variant == "before" else self._encode_weights(cc, session)
        for record in self.records:
            ciph = cc.Encrypt(self.keys.publicKey, cc.MakeCKKSPackedPlaintext(record))
            pt = self._encode_weights(cc, session) if self.variant == "before" else weights_pt
            outputs.append(cc.Decrypt(cc.EvalMult(ciph, pt), self.keys.secretKey))
        return outputs

    def check(self, result) -> float:
        worst = 0.0
        for record, plaintext in zip(self.records, result):
            expected = [w * x for w, x in zip(self.weights, record)]
            worst = max(worst, max_abs_error(decode(plaintext, self.slots), expected))
        return worst


def build(variant: str) -> Case:
    return EncodingRepeated(variant)
