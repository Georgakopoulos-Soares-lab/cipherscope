"""bootstrap.restored_levels_underused.v1 -- a long multiplicative chain that bootstraps too late to matter.

Workload: a running product over a chain of encrypted factors (e.g. an
iteratively updated model quantity), long enough to exhaust the leveled
budget, followed by a two-multiplication tail and decryption.

Parameters follow OpenFHE's own simple-ckks-bootstrapping example and the
seeded corpus: HEStd_NotSet with ring dimension 4096 so a bootstrap runs in
seconds rather than minutes (declared to CipherScope with
allow_testing_security=True; the configuration rule reports it in both
variants and is not the rule under test).

before: multiplicative depth = 10 + bootstrap depth; the chain runs the
        ciphertext down near its last level, EvalBootstrap refreshes it (ten
        levels restored), and then only two of those ten levels are used.
        That needs EvalBootstrapSetup, EvalBootstrapKeyGen, and the bootstrap
        itself. CipherScope reports restored_levels > suffix_levels_consumed.
after:  rewritten from the finding: the whole chain plus tail fits in
        (bootstrap depth + 8) leveled levels -- two fewer than the bootstrap
        configuration already had -- so the bootstrap and its keys are
        removed and the context is leveled-only.

Where the benefit lands: setup (no bootstrap keys), workload (no bootstrap),
memory (bootstrap keys are large), and a shorter modulus chain.
"""

from __future__ import annotations

from _base import Case, ckks_context, decode, max_abs_error

SLOTS = 8
LEVEL_BUDGET = [4, 4]
LEVELS_AFTER_BOOTSTRAP = 10
TAIL = 2


class BootstrapUnderused(Case):
    rule = "bootstrap.restored_levels_underused.v1"
    name = "bootstrap_underused"
    tolerance = 2e-2

    def prepare(self) -> None:
        import openfhe

        dist = openfhe.SecretKeyDist.UNIFORM_TERNARY
        boot_depth = int(openfhe.FHECKKSRNS.GetBootstrapDepth(LEVEL_BUDGET, dist))
        # Chain length chosen so the bootstrap input sits well below the fixed
        # post-bootstrap level (a real restoration) while the whole computation
        # still fits in fewer levels than the bootstrap configuration has.
        self.chain = boot_depth + 6
        if self.variant == "before":
            depth = LEVELS_AFTER_BOOTSTRAP + boot_depth
            features = ("PKE", "KEYSWITCH", "LEVELEDSHE", "ADVANCEDSHE", "FHE")
        else:
            depth = self.chain + TAIL
            features = ("PKE", "KEYSWITCH", "LEVELEDSHE")
        parameters = openfhe.CCParamsCKKSRNS()
        parameters.SetSecretKeyDist(dist)
        parameters.SetSecurityLevel(openfhe.SecurityLevel.HEStd_NotSet)
        parameters.SetRingDim(1 << 12)
        parameters.SetScalingModSize(59)
        parameters.SetFirstModSize(60)
        parameters.SetScalingTechnique(openfhe.ScalingTechnique.FLEXIBLEAUTO)
        parameters.SetMultiplicativeDepth(depth)
        parameters.SetBatchSize(SLOTS)
        context = openfhe.GenCryptoContext(parameters)
        for feature in features:
            context.Enable(getattr(openfhe.PKESchemeFeature, feature))
        self.context, self.parameters = context, parameters
        self.keys = context.KeyGen()
        context.EvalMultKeyGen(self.keys.secretKey)
        self.trace_kwargs = {"parameters": parameters, "allow_testing_security": True}
        total = self.chain + TAIL + 1
        self.factors = [[1.0 + 0.004 * (((f + 1) * (s + 2)) % 9 - 4) for s in range(SLOTS)] for f in range(total)]

    def setup(self, cc) -> None:
        if self.variant == "before":
            cc.EvalBootstrapSetup(LEVEL_BUDGET, [0, 0], SLOTS)
            cc.EvalBootstrapKeyGen(self.keys.secretKey, SLOTS)

    def workload(self, cc, session=None):
        # Encode into exactly SLOTS slots so the ciphertexts match the bootstrap precomputation.
        encrypted = [
            cc.Encrypt(self.keys.publicKey, cc.MakeCKKSPackedPlaintext(values, 1, 0, None, SLOTS))
            for values in self.factors
        ]
        acc = encrypted[0]
        for factor in encrypted[1 : 1 + self.chain]:
            acc = cc.EvalMult(acc, factor)
        if self.variant == "before":
            acc = cc.EvalBootstrap(acc)
        for factor in encrypted[1 + self.chain :]:
            acc = cc.EvalMult(acc, factor)
        return cc.Decrypt(acc, self.keys.secretKey)

    def check(self, result) -> float:
        expected = [1.0] * SLOTS
        for values in self.factors:
            expected = [e * v for e, v in zip(expected, values)]
        return max_abs_error(decode(result, SLOTS), expected)


def build(variant: str) -> Case:
    return BootstrapUnderused(variant)
