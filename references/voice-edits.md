# Voice edits: original bad/better examples for a CipherScope paper

**Purpose:** teach Fable to write like a careful systems/PL/cryptographic-engineering researcher, not to “humanize” text by replacing adjectives. All examples below are **original to this reference**, not borrowed from the five primary papers. Project facts refer to the **uploaded 2026-09-18 archive**. Verify newer results before reusing quantitative sentences in a manuscript. Examples marked *illustrative* describe a plausible explanation or code scenario, **not** a measured improvement.

## Ground rule: natural prose carries an argument

A natural technical sentence usually answers one question: *What was missing? What did you implement? What did the run show? What is still unknown?* It may be short. It does not need a dramatic opening, a “Furthermore,” or a closing flourish. Preserve explicit definitions and the author's existing good sentences; do not rewrite solely to sound more scholarly.

- Prefer **“records,” “matches,” “rejects,” “flags,” “compares,” “reports,” “could test”** when those are the operations actually implemented.
- Reserve **“improves,” “outperforms,” “detects in real workloads,” “proves,” “guarantees”** for specifically cited evidence that warrants them.
- Name OpenFHE Python, CKKS, a ciphertext version, the source line, the coverage class, the experiment, or the denominator rather than defaulting to “framework,” “capabilities,” “insights,” or “novel approach.”
- A hard technical noun is fine. “Ciphertext version,” “key-switching technique,” and “observed critical path” are precise; replacing them with “data object,” “smart adaptation,” or “dependency intelligence” makes the prose worse.

## 1. Abstract: begin with the observability gap, not a field-wide slogan

**Bad (overclaiming and generic):**

> Homomorphic encryption is a revolutionary technology that has the potential to transform privacy-preserving computing. However, its complexity presents unprecedented challenges. In this paper, we introduce CipherScope, a novel, comprehensive, and efficient framework that leverages advanced profiling to unlock powerful optimizations. Extensive experiments demonstrate its exceptional accuracy and speedups.

**Better (snapshot-grounded, with pending work explicit):**

> A timing profile can identify an expensive OpenFHE call, but it cannot say whether successive calls operate on the same ciphertext version or use compatible CKKS state. CipherScope records covered calls from OpenFHE Python programs and builds a source-attributed graph of ciphertext versions, state transitions, and rotation-key use. Analyses over that graph report candidate optimization and correctness issues together with the evidence for each finding. In the archived evaluation, the primary source-built OpenFHE environment passed 38 integration checks; a 27-program controlled suite matched 13 expected-positive rule/case judgments without firing on 18 negative judgments. The repository does not yet contain adjudicated real-workload precision or before/after performance improvements.

**Why this is better:** It distinguishes observability, mechanism, and evidence. It does **not** call the seed results “real-world accuracy,” and it does not imply every available diagnostic has a real-positive case (bootstrap does not). This is a **working abstract example**, not recommended final abstract copy: after new data exists, replace the status sentence with an actual supported contribution, and avoid spending half the submitted abstract describing unfinished work.

## 2. Introduction: one program decision is better than five stakes-setting paragraphs

**Bad:**

> As the demand for privacy continues to grow at an unprecedented pace, developers increasingly require sophisticated tools to navigate the intricate landscape of fully homomorphic encryption. Existing profilers are fundamentally inadequate because they fail to capture deep semantic insights. To bridge this gap, we propose a paradigm-shifting solution.

**Better:**

> Consider a CKKS program that rotates a ciphertext by several indices before combining the results. A line-level profile may show that the rotations are expensive. To decide whether a shared precomputation is worth testing, however, the developer needs to know which ciphertext **version** each rotation read, how the relevant state was configured, and whether the program already performed that precomputation. Those facts are not contained in a list of call durations. CipherScope records them for calls that pass through its OpenFHE context proxy.

**Why:** A concrete decision makes the problem falsifiable. Do not jump from this example to “therefore hoisting is faster”: the analyzer's conditions are a conservative suggestion, not an outcome. If detailed state conditions matter, the next paragraph should explain the HYBRID key-switching and compatibility restrictions from `src/cipherscope/analyzers/rotations.py`.

## 3. The contribution statement: separate the system from the evaluation method

**Bad:**

> Our contributions are threefold: (1) a novel semantic profiling framework; (2) an innovative graph-based intelligence layer; and (3) an advanced and comprehensive analytics suite for actionable optimization insights.

**Better:**

> CipherScope contributes a runtime record that connects covered OpenFHE calls to source locations and ciphertext versions, and a set of conservative analyses over the resulting graph. The evaluation separates binding fidelity, observation coverage, controlled detection tests, human-reviewed real findings, optimization impact, and measurement cost. Several of those evaluations are not complete in the archived repository.

**Why:** The original makes three labels for overlapping mechanisms. The better version names distinct technical/evaluation objects without asserting that a pending experiment was performed. Reconcile the frozen “ten rules” against the current twelve rule IDs before stating an exact inventory.

## 4. Design / mechanism: follow one call from execution to finding

**Bad:**

> CipherScope seamlessly integrates cutting-edge instrumentation and state-of-the-art provenance analytics to provide an end-to-end unified visibility pipeline. The core architecture intelligently processes events to enable robust, comprehensive diagnosis across the encryption stack.

**Better:**

> The program calls a method on `session.context`. The proxy reads the exposed metadata, invokes the underlying OpenFHE method once, and records an event associated with the calling Python source site. The recorder assigns a new ciphertext version when a covered in-place operation changes an existing object. Offline processing turns these events into a validated graph, which the analyzers use to generate findings. A call made on the original context instead of the proxy is outside this event history.

**Why:** The verbs map to components (`context.py`, `registry.py`, `graph.py`) and the final sentence gives the observation boundary. It does **not** imply internal native calls are recorded.

## 5. Ciphertext identity: explain why `:vN` exists

**Bad:**

> Our advanced lineage engine provides immutable state-of-the-art ciphertext tracking for highly accurate dynamic provenance at unprecedented granularity.

**Better:**

> A Python variable may still refer to the same ciphertext object after an in-place operation, even though its value has changed. CipherScope therefore distinguishes the object from its recorded versions: a first observation may be `ct_0001:v0`, and a subsequent covered in-place update becomes `ct_0001:v1`. A dependency through `v0` must not silently be treated as a dependency through `v1`.

**Why:** The explanation shows a reason for the representation. The IDs are **illustrative of the implemented format**, not pasted from a particular measured workload. Do not suggest every pybind mutation or alias outside covered calls is tracked.

## 6. A rule: preconditions are part of its meaning

**Bad:**

> Our sophisticated rotation-hoisting algorithm autonomously discovers redundant transformations and generates optimal schedules that dramatically enhance encrypted computation efficiency.

**Better:**

> The rotation analysis looks for multiple distinct rotation indices applied to the same recorded ciphertext version. It also checks the required scaling and key-switching state, including the validated `HYBRID` condition, and avoids groups for which a compatible earlier fast-rotation precompute is already recorded. When these conditions hold, it identifies a precomputation experiment worth evaluating. It does not rewrite the program or predict the experiment's speedup.

**Why:** It ties a recommendation to evidence and explicitly declines a performance guarantee. The strict real-binding negative for an earlier `EvalFastRotationPrecompute` is unavailable in this archive; the rule's code path exists, but avoid asserting that every precompute-negative case has been tested end-to-end on the pinned real binding.

## 7. Precision and correctness: separate a measurement from a requirement

**Bad:**

> CipherScope guarantees precision and automatically prevents numerical errors by ensuring that encrypted computations remain safe.

**Better:**

> The precision-drop analysis compares observed checkpoints and ignores changes smaller than one absolute precision bit in the archived implementation. A separate analysis compares checkpoint results with tolerances supplied by the developer and reports when a declared tolerance is violated. Neither check supplies a general error bound for other inputs, nor does it prove that the chosen CKKS parameters are cryptographically secure.

**Why:** `precision.py` defines `MIN_BITS_LOST = 1.0`; `paper/claims.md` has an outdated statement that the rule lacks a threshold. Decryption noise and a user-specified tolerance are not interchangeable with mathematical correctness guarantees.

## 8. Fidelity results: say what passed and what a pass means

**Bad:**

> CipherScope exhibits flawless compatibility and 100% correctness across a diverse range of platforms, demonstrating unmatched robustness and reliability.

**Better:**

> All 38 checks passed on the archived primary Ubuntu 24.04, Python 3.11.15, source-built OpenFHE 1.5.1.0/1.5.1 lane. A native Rocky Linux build also passed 38 checks. The macOS developer run passed 37 and skipped the Linux-only `/proc` check. These results establish the tested API and numerical behaviors on the pinned builds, not support for every OpenFHE release or workload.

**Why:** The key facts are the environment, denominator, expected skip and limit. Source: `docs/evidence.md` and the lane's `feasibility.json`.

## 9. Seeded recall: distinguish cases, assertions, and real findings

**Bad:**

> Our system achieves perfect accuracy, with 100% recall and zero false positives, establishing its effectiveness across realistic security and performance problems.

**Better:**

> The controlled benchmark contains 27 OpenFHE programs. Across their declared rule/case expectations, the archived results match 13 of 13 positives and record no unexpected firing on 18 negative expectations, two of which are `not_applicable` outcomes. This checks analyzer behavior for the planted cases; it does not measure precision or recall on independently authored workloads. The bootstrap-underuse rule has no real-binding positive in this suite.

**Why:** The 13 positives are **rule/case assertions**, not 13 programs or 13 discovered vulnerabilities. Sources: `evaluation/raw/seeded/case_results.json`, `evaluation/tables/recall.csv`, `evaluation/seeded/README.md`.

## 10. Ablation: don't turn a projection into a competing-tool benchmark

**Bad:**

> We comprehensively outperform cProfile and Scalene, which cannot detect the rich semantic patterns identified by our superior profiling approach.

**Better:**

> We re-analyzed the same traces with three information views: call timing only, per-call state without ciphertext identity, and the full recorded graph. The comparison isolates which diagnostics depend on state or provenance. It is an internal semantic ablation; the archived repository does not contain end-to-end runs of cProfile or Scalene on these workloads.

**Why:** This preserves the demonstrated difference without inventing a head-to-head competitor evaluation. If naming a particular finding, read its row in `evaluation/tables/semantic_ablation.csv` first—do not assume every rule requires the full graph.

## 11. Overhead: retain a nonuniform result

**Bad:**

> Our lightweight architecture achieves near-zero instrumentation overhead while maintaining excellent scalability across all hardware settings.

**Better:**

> The archived scaling experiment measures an untraced baseline and traced recording modes from roughly 10² to 10⁵ events. Its wall-time ratios differ across the recorded machines and conditions, while trace storage is roughly 2.2 kB per event and the largest run materializes a multi-gigabyte trace during finalization and analysis. These are single-run synthetic measurements, not an estimate of median overhead on independently authored OpenFHE programs.

**Why:** It avoids declaring “negative overhead” as a speedup when some single x86 observations happen to run faster than baseline. For publication, show the *actual table* with precise event counts and separately named machines; add repetitions and uncertainty before a broad overhead claim. Sources: `evaluation/raw/scaling.csv`, `evaluation/tables/scaling.csv`, `docs/ARTIFACT.md`.

## 12. Security: don't upgrade configuration telemetry into an audit

**Bad:**

> CipherScope proactively detects insecure configurations and ensures end-to-end security compliance for FHE deployments.

**Better:**

> When a tracing session supplies the context parameters, CipherScope can flag a declaration of `HEStd_NotSet`, which disables OpenFHE's standard security-level enforcement. The live context does not expose that setting through the getter used here, so an undeclared setting is not assessed. This is a configuration warning, not a bit-security estimate or a certification of the application.

**Why:** It names both what is detected and what is missing. Source: `src/cipherscope/analyzers/configuration.py` and `evaluation/seeded/README.md`.

## 13. Limitations: give the failure mechanism, not a ceremonial disclaimer

**Bad:**

> While our approach has several limitations, these do not detract from its substantial advantages. Future work will further enhance robustness, scalability, and generalizability.

**Better:**

> CipherScope only records calls made through the wrapped context. Calls through the original context or module-level functions can leave dependencies out of the trace; the preflight scan detects some of these patterns but cannot rule out all bypasses. Analysis also materializes the full trace, which raises peak memory use for long runs. Finally, `GetLevel()` on the tested OpenFHE Python 1.5.1.0 binding did not expose the level restoration needed for a real positive bootstrap-underuse diagnosis.

**Why:** Each limitation identifies its cause and consequence. An honest limitation is *not* followed by an apology or unsubstantiated claim that it hardly matters.

## 14. Related work: describe the question answered at each layer

**Bad:**

> Unlike prior profilers and compilers, which lack semantic awareness and comprehensive observability, CipherScope presents a unique and universally applicable solution to FHE optimization.

**Better:**

> HEProfiler compares CKKS libraries under controlled workloads and parameter-selection policies. EVA and HEIR construct and optimize encrypted programs using compiler representations. CipherScope works on a different input: the OpenFHE calls observed while a Python program executes through its wrapped context. It uses source-associated ciphertext versions to explain candidate diagnoses. These approaches are complementary; the current artifact does not show that CipherScope produces faster programs than the compiler systems.

**Why:** Every comparison is about input, representation and task—not a made-up deficiency in another paper. Cite HEProfiler, EVA and HEIR at the individual comparison statements.

## 15. A restrained miniature introduction (original, illustrative)

> Developers often know where their encrypted program is slow before they know what to change. A profile of an OpenFHE Python workload can attribute time to a rotation, multiplication, or bootstrap call. It usually cannot answer a narrower question: which version of the ciphertext reached that call, and what did the program already do to it?
>
> This distinction matters when the proposed change depends on relationships among operations. Consider several rotations over one ciphertext. If the rotations read different versions, a shared precomputation may not be applicable. If the recorded state is incompatible, it may be the wrong experiment. A source location and a duration do not establish either condition.
>
> CipherScope records these relationships at the Python/OpenFHE boundary. A traced context invokes covered operations and records their source locations, arguments, results, and available CKKS metadata. The resulting graph preserves ciphertext versions and supports offline analyses. A finding is accompanied by the observations that triggered it; it is not a program rewrite or a prediction of speedup.
>
> This boundary is deliberate. The proxy sees neither unwrapped calls nor the work hidden inside a native OpenFHE operation. Accordingly, the evaluation must establish what execution was observed, whether the reconstructed state agrees with the binding, whether controlled diagnostics behave as expected, and whether any proposed code change improves the program once tested. The uploaded artifact supports the first set of checks and controlled diagnostics, but does not yet contain the adjudicated real-workload and before/after studies needed to claim general performance impact.

This is a *voice reference*, not prose to copy verbatim into a publication. A finished introduction should incorporate the current complete evaluation and exact related-work citations.

## Mechanical anti-slop edits Fable should actually perform

| Pattern to inspect | Preferred edit | Exception |
|---|---|---|
| “In today's rapidly evolving landscape,” “with the exponential growth of,” “a pivotal challenge” | Delete; begin with the actual program failure or constraint. | A historical/context claim may remain if it has evidence and helps a specific argument. |
| “novel,” “groundbreaking,” “state of the art,” “seamless,” “powerful,” “robust,” “comprehensive” | Replace with an operation, condition, measured comparison, or delete. | “Robust” can be precise when a well-defined perturbation test is reported. |
| “leverages,” “utilizes,” “facilitates,” “enables actionable insights” | Usually “uses,” “records,” “checks,” “compares,” “returns,” “lets a developer test.” | Don't ban a word if it has an exact technical meaning. |
| “Furthermore,” “Moreover,” “Additionally,” in consecutive paragraphs | Usually delete or make the logical relationship explicit (“Because…”, “By contrast…”, “In this case…”). | Keep when the additive relationship really matters. |
| “This highlights the importance of…” / “Taken together, these findings demonstrate…” | Delete unless the sentence states a *new supported inference*. | A concluding sentence may be needed when drawing a non-obvious inference from several results. |
| “100% accuracy” / “zero false positives” without a population | Replace with numerator, denominator, evaluation design, and exclusions. | None in a research results section. |
| “We optimize,” “we prove,” “we secure” without a corresponding algorithm or validation | Write “we identify a candidate,” “we check a declaration,” or flag `[VERIFY]`. | Strong verbs are appropriate if the mechanism and evidence truly support them. |
| Repetitive “First…Second…Third…” contributions that paraphrase one mechanism | Merge, reorganize by distinct deliverable, or remove duplicates. | Numbered contributions are normal if each is genuinely separate. |
| A complete mini-conclusion at the end of every paragraph | Stop when the paragraph's point is made. | Keep a synthesis when it changes what the reader should infer. |

## Editing protocol (use with an actual draft)

1. **Preserve factual content first.** Don't replace measured results with prettier unmeasured results. Keep source citations, numerical bounds, and notation intact.
2. **Perform a fact pass:** mark `[VERIFY: source path, unit, or experiment]`; distinguish seeded/real, measured/proposed, detection/precision, CKKS accuracy/security, and semantic observation/optimization.
3. **Perform an argument pass:** ensure each paragraph contributes one relevant fact, technical dependency, comparison, or legitimate inference. Remove recycled stakes and non-conclusions.
4. **Perform a voice pass:** read aloud; prefer shorter concrete verbs, vary sentence rhythm naturally, and let necessary technical detail occupy the sentence. Do **not** deliberately introduce errors, anecdotes, choppy grammar, or colloquialisms to disguise AI authorship.
5. **Perform a skeptical reviewer pass:** a PL reviewer asks what is new about the representation; a systems reviewer asks what the workload population and overhead baseline are; a cryptoengineering reviewer asks what security and numerical-error statements are actually warranted. Fix those questions with evidence, not tone.
6. **Return clean prose plus a short evidence-gap note.** Do not append a long self-congratulatory “changes made” section to a manuscript draft.

**One-line test:** If “CipherScope” could be replaced by the name of any AI product or scientific framework without changing the sentence, that sentence probably needs an actual mechanism, measurement, or deletion.
