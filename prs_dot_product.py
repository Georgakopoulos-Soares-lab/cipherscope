#!/usr/bin/env python3
"""Polygenic Risk Score (PRS): an encrypted dot product over chunked genotype
data, scored for a small patient cohort against public GWAS effect weights.

This is a real OpenFHE program, structured to mirror how a real PRS
calculator (e.g. HEPRS) actually has to work, not a toy:

  * Effect-size weights come from published GWAS summary statistics, so they
    are PUBLIC -> kept as plaintext. Only the patient's genotype is private,
    so only the genotype is encrypted. The homomorphic operation is therefore
    ciphertext x plaintext, not ciphertext x ciphertext.
  * One CKKS ciphertext only has `ring_dim / 2` usable slots. A real PRS
    panel has hundreds of thousands of SNPs, far more than fit in one
    ciphertext, so the genome is chunked into BLOCK_SIZE-sized blocks, each
    contributing a partial score that gets summed across blocks.
  * The cohort loop deliberately RE-ENCODES the same weight block for every
    patient instead of caching it once outside the loop. This is a common,
    realistic inefficiency in this exact kind of pipeline -- scoring many
    patients against one fixed public model -- and it is here on purpose so
    CipherScope's encoding analyzer has a real, genuine finding to report,
    not a synthetic one.

The crypto logic lives in build_context()/run_cohort() below, callable with
or without an active CipherScope session, so a benchmarking harness (see
benchmark_prs_overhead.py) can time the identical workload both ways for a
true traced-vs-untraced overhead comparison.

Run standalone (no CipherScope, plain correctness check, untraced):
    python3 prs_dot_product.py

Run instrumented (produces a full CipherScope analysis bundle):
    cipherscope run prs_dot_product.py --output prs_run/
    cipherscope view prs_run/          # path to summary.html
    cat prs_run/recommendations.json   # analyzer findings

Adjust BLOCK_SIZE / NUM_BLOCKS / NUM_PATIENTS below to scale this up further
for overhead/profiling work -- the structure stays the same.
"""

from __future__ import annotations

import contextlib
import random

import openfhe

import cipherscope

BLOCK_SIZE = 8192  # SNPs packed per ciphertext slot-block (<= ring_dim / 2)
NUM_BLOCKS = 122  # 977 * 1024 2248 1,000,448 SNPs
NUM_PATIENTS = 1  # single patient, keep runtime bounded

random.seed(0)

# ---------------------------------------------------------------------------
# Synthetic data standing in for a real panel + cohort.
#   - GWAS effect weights: public, fixed once, defines the "model".
#   - Per-patient genotype dosages: private, one SNP allele count in {0,1,2}.
# Module-level and seeded, so every run (traced or not, ls6 or Vista) scores
# the exact same numbers -- required for a fair overhead/correctness compare.
# ---------------------------------------------------------------------------
weight_blocks: list[list[float]] = [
    [random.gauss(0.0, 0.05) for _ in range(BLOCK_SIZE)] for _ in range(NUM_BLOCKS)
]
cohort_genotypes: list[list[list[float]]] = [
    [[float(random.randint(0, 2)) for _ in range(BLOCK_SIZE)] for _ in range(NUM_BLOCKS)]
    for _ in range(NUM_PATIENTS)
]


def expected_score(patient_index: int) -> float:
    """Plain-Python reference score, to sanity-check the encrypted result."""
    return sum(
        genotype * weight
        for block_genotypes, block_weights in zip(
            cohort_genotypes[patient_index], weight_blocks
        )
        for genotype, weight in zip(block_genotypes, block_weights)
    )


def build_context():
    """Build the CKKS context, keys, once. Not part of the measured region."""
    parameters = openfhe.CCParamsCKKSRNS()
    parameters.SetMultiplicativeDepth(3)
    parameters.SetScalingModSize(50)
    parameters.SetBatchSize(BLOCK_SIZE)

    context = openfhe.GenCryptoContext(parameters)
    context.Enable(openfhe.PKESchemeFeature.PKE)
    context.Enable(openfhe.PKESchemeFeature.KEYSWITCH)
    context.Enable(openfhe.PKESchemeFeature.LEVELEDSHE)
    context.Enable(openfhe.PKESchemeFeature.ADVANCEDSHE)  # EvalSum needs this

    keys = context.KeyGen()
    context.EvalMultKeyGen(keys.secretKey)
    context.EvalSumKeyGen(keys.secretKey)  # log-step rotation keys for EvalSum
    return context, keys


def run_cohort(cc, keys, session=None, on_block=None) -> list[float]:
    """The measured region: score every patient in the cohort.

    `cc` is either the raw native context (untraced) or a CipherScope-traced
    proxy (instrumented) -- the crypto calls are identical either way.
    `session` is the active CipherScope Session when tracing, or None; all
    annotation/region calls are skipped when session is None so this same
    function works for a true untraced baseline.
    `on_block`, if given, is called as on_block(global_block_index) once per
    completed block (counting across all patients) -- used for memory/timing
    instrumentation without touching the crypto logic itself.
    """
    scores: list[float] = []
    global_block_index = 0
    for patient_index in range(NUM_PATIENTS):
        total_score = None

        region_cm = (
            session.region(
                f"patient_{patient_index}_cross_block_sum",
                operator="add",
                associative=True,
                commutative=True,
            )
            if session is not None
            else contextlib.nullcontext()
        )
        with region_cm:
            for block_index in range(NUM_BLOCKS):
                genotypes = cohort_genotypes[patient_index][block_index]
                pt_genotypes = cc.MakeCKKSPackedPlaintext(genotypes)
                ct_genotypes = cc.Encrypt(keys.publicKey, pt_genotypes)
                if session is not None:
                    session.annotate(
                        ct_genotypes,
                        shape=[BLOCK_SIZE],
                        packing="row_major",
                        meaningful_slots=BLOCK_SIZE,
                    )

                # Deliberately re-encoded every patient iteration instead of
                # being hoisted out of the cohort loop -- see module
                # docstring. Same constant_id every time so the encoding
                # analyzer can recognize it as the same logical constant.
                pt_weights = cc.MakeCKKSPackedPlaintext(weight_blocks[block_index])
                if session is not None:
                    session.annotate_plaintext(
                        pt_weights,
                        provenance="gwas_effect_weights",
                        constant_id=f"gwas_weight_block_{block_index}",
                    )

                product = cc.EvalMult(ct_genotypes, pt_weights)  # ct x pt, no relin
                block_partial = cc.EvalSum(product, BLOCK_SIZE)

                total_score = (
                    block_partial
                    if total_score is None
                    else cc.EvalAdd(total_score, block_partial)
                )

                global_block_index += 1
                if on_block is not None:
                    on_block(global_block_index)

        decrypted = cc.Decrypt(total_score, keys.secretKey)
        decrypted.SetLength(1)
        scores.append(decrypted.GetRealPackedValue()[0])
    return scores


def report_correctness(scores: list[float]) -> None:
    for patient_index, observed in enumerate(scores):
        expected = expected_score(patient_index)
        print(
            f"patient {patient_index}: PRS = {observed:.4f} "
            f"(expected {expected:.4f}, abs err {abs(observed - expected):.2e})"
        )


if __name__ == "__main__":
    context, keys = build_context()

    # Always traced when run as a script (either standalone or under
    # `cipherscope run`, since trace() joins an already-active runner
    # session if one exists). For a true UNTRACED timing run, import
    # build_context/run_cohort from benchmark_prs_overhead.py instead.
    with cipherscope.trace(context, name="prs_dot_product") as session:
        cc = session.context
        scores = run_cohort(cc, keys, session)

    report_correctness(scores)

    # When run standalone (not under `cipherscope run`), also print the two
    # analyzer reports directly, matching the pattern used by the synthetic
    # examples -- useful for a quick check without needing the full CLI.
    try:
        from cipherscope.analyzers.encoding import analyze_encoding
        from cipherscope.analyzers.packing import analyze_packing

        trace = session.to_trace()

        encoding_report = analyze_encoding(trace)
        print(f"\nencoding analysis: {encoding_report['analysis_status']}")
        for finding in encoding_report["findings"]:
            evidence = finding["evidence"]
            print(
                f"  constant '{evidence['constant_id']}' encoded "
                f"{evidence['encoding_count']} times (expected: cache it once "
                f"outside the cohort loop)"
            )

        packing_report = analyze_packing(trace)
        print(f"packing analysis: {packing_report['analysis_status']}")
        if not packing_report["findings"]:
            print("  no low-utilization ciphertexts found (blocks are fully packed)")
    except ImportError:
        pass
