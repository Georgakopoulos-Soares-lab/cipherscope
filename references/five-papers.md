# Five papers: a genre study for writing CipherScope

**Purpose.** These five *primary research papers* are models for the *reasoning and reporting* expected in systems, programming languages, cryptographic engineering, and FHE. They are not a phrasebook. Do not copy sentences, metaphors, figure designs, or contribution formulas from them. Use the linked original publications to check any technical comparison before it goes into a submission.

**Research checked:** 2026-11-01. **CipherScope source:** the user-supplied `cipherscope-main (3).zip` (archive root commit recorded as `2c1d02710e1300a3193258ac70b4ce6f11b44c34`). An archive cannot establish what changed in a live checkout after export.

## At a glance

| Paper and primary link | Genre function | What the reader learns | Boundary to maintain for CipherScope |
|---|---|---|---|
| Curtsinger & Berger, [**Coz: Finding Code that Counts with Causal Profiling**](https://doi.org/10.1145/2815400.2815409), SOSP 2015 ([author-hosted manuscript](https://web.cs.umass.edu/publication/docs/2015/UM-CS-2015-008.pdf)) | Systems profiler | Why time spent is not identical to potential performance gain; how the proposed measurement changes the decision | CipherScope records evidence and suggests experiments; it does **not** virtually speed up code or estimate causal speedup |
| Berger, Stern & Altmayer Pizzorno, [**Triangulating Python Performance Issues with SCALENE**](https://www.usenix.org/conference/osdi23/presentation/berger), OSDI 2023 | Language-aware performance profiler | Why the Python/native boundary changes what a useful profiler should attribute | Scalene profiles CPU, memory, GPU and copying; CipherScope records covered OpenFHE call semantics, not native-internal costs |
| Takeshita, Koirala, McKechney & Jung, [**HEProfiler: An In-Depth Profiler of Approximate Homomorphic Encryption Libraries**](https://doi.org/10.1007/s13389-025-00377-5), *Journal of Cryptographic Engineering* 15:14, 2025 | Cryptographic engineering / comparative evaluation | What fair CKKS library comparisons must hold constant, vary, and disclose | HEProfiler compares CKKS implementations; CipherScope diagnoses traced behavior *within* an application's OpenFHE execution |
| Dathathri et al., [**EVA: An Encrypted Vector Arithmetic Language and Compiler for Efficient Homomorphic Computation**](https://www.microsoft.com/en-us/research/publication/eva-an-encrypted-vector-arithmetic-language-and-compiler-for-efficient-homomorphic-computation/), PLDI 2020 | PL / FHE compiler | How to motivate an abstraction from the awkward operations it removes and evaluate its transformations | CipherScope neither supplies an FHE language nor compiles/rewrites the workload |
| Ali et al., [**HEIR: A Universal Compiler for Homomorphic Encryption**](https://arxiv.org/abs/2508.11095), arXiv 2025 | PL architecture / FHE compiler infrastructure | How a layered intermediate representation makes the responsibility of each phase understandable | HEIR's compile-time IR and CipherScope's executed runtime graph answer different questions; do not assert the former can never observe runtime facts |

## 1. Coz — make the missing information consequential

**Paper:** Charlie Curtsinger and Emery D. Berger. *Coz: Finding Code that Counts with Causal Profiling.* SOSP 2015, pp. 184–197. DOI: `10.1145/2815400.2815409`. [Publisher/DOI](https://doi.org/10.1145/2815400.2815409).

**Actual contribution:** A causal profiler uses performance experiments that *virtually* accelerate a selected line, implemented by delaying other concurrent work, to estimate the program-level effect of speeding up that line. The paper motivates its tool with the mismatch between a conventional time profile and an optimization that improves throughput or latency. It evaluates the method on real systems, including Memcached, SQLite, and PARSEC programs.

**Borrow:** Start with an engineering decision a conventional observable cannot justify. For CipherScope: knowing that a Python source line spent time in `EvalRotate` does not tell us whether several rotations consumed the *same ciphertext version*, whether their scales and key-switching state are compatible, or whether a fast-rotation precompute already occurred. A motivating example should show a case where the extra metadata changes the *candidate investigation*. Then explain the mechanism before naming all analyses. Report changed program performance only if independently measured before and after.

**Do not claim:** Coz's causal predictions, virtual-speedup technique, or validated speedups belong to CipherScope. It would also be false to imply a timing profiler cannot detect that rotations consume time; the distinction is between time attribution and **semantic conditions for a particular diagnosis**. Don't treat a suggestion to try rotation hoisting as a measured improvement.

**Useful editorial pattern (original):** “The slowest operation is not always the best place to edit. For this FHE workload, the more useful question is whether the expensive calls share an input that permits a different implementation.” This is an illustrative argument, not a claim that the repository's current evaluations demonstrate savings.

## 2. Scalene — treat the language/library boundary as a design constraint

**Paper:** Emery D. Berger, Sam Stern, and Juan Altmayer Pizzorno. *Triangulating Python Performance Issues with SCALENE.* OSDI 2023, pp. 51–64. [USENIX paper page](https://www.usenix.org/conference/osdi23/presentation/berger). An [earlier Scalene preprint](https://arxiv.org/abs/2006.03879) appeared in 2020 with a different title and scope; use the **2023 OSDI paper** for the cited conference version, not “Scalene, OSDI 2020.”

**Actual contribution:** A Python profiler combining CPU, memory, and GPU attribution, with special attention to Python/native execution and data-copying boundaries. The paper ties its choice of measurements to the optimizations Python developers can actually perform.

**Borrow:** Explain the boundary *before* describing the proxy. A Python call into OpenFHE often performs substantial native work; line-level CPU or wall time alone does not reveal which ciphertext version, rotation index, declared configuration, or CKKS state was involved. CipherScope's proxy adds these *application-semantic* facts for covered calls. Describe what comes from a Python call site, what comes from exposed binding metadata, and what remains hidden inside OpenFHE's native execution.

**Do not claim:** Scalene is oblivious to native code or lacks detailed Python/native attribution: distinguishing them is central to its contribution. Neither claim that CipherScope supersedes Scalene for CPU/memory profiling nor that CipherScope measures native kernel internals, GPU activity, allocations, or copying merely because it measures whole-call time.

**Useful editorial pattern (original):** “The Python call identifies where evaluation was requested. The ciphertext record identifies which value was evaluated. Neither tells us what happened inside the native routine.”

## 3. HEProfiler — get CKKS evaluation and fairness right

**Paper:** Jonathan Takeshita, Nirajan Koirala, Colin McKechney, and Taeho Jung. *HEProfiler: An In-Depth Profiler of Approximate Homomorphic Encryption Libraries.* *Journal of Cryptographic Engineering* **15**, article 14 (2025), published May 27, 2025. [Open-access version of record](https://link.springer.com/article/10.1007/s13389-025-00377-5).

**Actual contribution:** A C++ benchmarking framework and comparison of **PALISADE, Microsoft SEAL, HElib, and HEAAN** for CKKS. The authors consider differing parameter-selection strategies rather than treating nominally equal library settings as fair by default. They report metrics including latency, throughput, memory, and numerical error; they also study bootstrapping for implementations that support it. **OpenFHE is not one of the four measured libraries** in this study (the paper notes that OpenFHE appeared during its preparation).

**Borrow:** Specify the context that makes a measurement interpretable. For CipherScope, write the OpenFHE wrapper and native versions, Python version, CPU/OS or environment lane, CKKS setup, whether a run is synthetic or external, how the baseline was run, and whether timing includes recording/finalization/analysis. For accuracy, distinguish CKKS's approximate numerical behavior, a user-specified error tolerance, and a cryptographic security estimate. State denominators next to ratios; use a table rather than a persuasive adjective when several settings matter.

**Do not claim:** HEProfiler reconstructs user-level ciphertext provenance or that it directly benchmarked the OpenFHE version in this repository. Conversely, do not declare CipherScope the first profiler for FHE; HEProfiler and other profiling efforts predate it. A cross-library ranking in HEProfiler is not a speed claim about CipherScope.

**Useful editorial pattern (original):** “The reported overhead is specific to the operation count, machine, build, and recording mode; these dimensions are retained rather than pooled into one number.”

## 4. EVA — introduce the mechanism through the burden it removes

**Paper:** Roshan Dathathri, Blagovesta Kostova, Olli Saarikivi, Wei Dai, Kim Laine, and Madan Musuvathi. *EVA: An Encrypted Vector Arithmetic Language and Compiler for Efficient Homomorphic Computation.* PLDI 2020. [Microsoft Research publication](https://www.microsoft.com/en-us/research/publication/eva-an-encrypted-vector-arithmetic-language-and-compiler-for-efficient-homomorphic-computation/) ([preprint linked there](https://www.microsoft.com/en-us/research/publication/eva-an-encrypted-vector-arithmetic-language-and-compiler-for-efficient-homomorphic-computation/)).

**Actual contribution:** A language and optimizing compiler for encrypted vector arithmetic, also usable as an intermediate representation. It addresses burdensome FHE programming constraints through compilation and optimization. The authors retarget CHET to EVA and report a **5.3× average advantage against CHET-generated programs on their evaluated workloads**—that result belongs to EVA's experimental setup.

**Borrow:** A PL paper makes abstractions concrete. Describe the engineering consequence of needing manual level/scale/key coordination, then show the actual representation CipherScope constructs: covered calls become source-associated events, ciphertext object identities become immutable `:vN` versions on mutation, and relationships become a graph on which specific conservative rules operate. A tiny before/after *representation* example is stronger than a catalogue of classes.

**Do not claim:** CipherScope inherits EVA's optimizations, compiler correctness claims, parameter-selection guarantees, or speedups. EVA's compiled IR is not the same as a runtime graph reconstructed from OpenFHE's executed calls. Do not frame these as mutually exclusive approaches: they operate at different points in the workflow.

**Useful editorial pattern (original):** “The graph is not an alternative syntax for the source program. It records the subset of its encrypted computation that passed through the wrapped context during this run.”

## 5. HEIR — explain the responsibility of each layer

**Paper:** Asra Ali, Jaeho Choi, Bryant Gipson, Shruthi Gorantala, Jeremy Kun, Wouter Legiest, Lawrence Lim, Alexander Viand, Meron Zerihun Demissie, and Hongren Zheng. *HEIR: A Universal Compiler for Homomorphic Encryption.* arXiv:2508.11095, initially posted August 2025. [Primary preprint](https://arxiv.org/abs/2508.11095). Check the latest arXiv revision and publication status before freezing the bibliography.

**Actual contribution:** A homomorphic-encryption compiler framework built on MLIR with HE-specific representation layers and transformations. It aims to make optimization techniques and FHE targets easier to express, integrate, and compare; the authors present implemented components and design ambitions. “Universal” is the paper's title/goal, not evidence that every conceivable backend or operation is already supported.

**Borrow:** Use architecture as an explanation of *information flow*. For CipherScope: executed wrapped call → event and captured state → validated version graph → offline rule evaluation → finding with source location and evidence. Explain why the layers are separate (e.g., offline analyzer failure cannot retroactively alter a native call). Describe semantic loss at each boundary; e.g., the Python proxy does not expose native internal operations or unexecuted branches.

**Do not claim:** A compilation pipeline and a runtime tracer have identical inputs, security assurances, or evaluation metrics. Avoid straw men such as “HEIR cannot reason about program state”; it reasons about compiler-represented state. The defensible distinction is that CipherScope models **observed execution through a specified proxy**, whereas HEIR's primary mechanism is **compiler IR and lowering**. Do not claim absolute priority over HEIR or that compilers cannot be augmented with dynamic profiling.

**Useful editorial pattern (original):** “The event log states what occurred; the graph links versions of values; the analyzer decides whether those links satisfy a rule. Keeping these separate lets us distinguish observation from interpretation.”

## Transferable editorial techniques (not a template to recite)

1. **A small counterexample earns the motivation.** Name a plausible profiler observation and demonstrate a distinct semantic fact it lacks. Avoid broad introductory claims that FHE is “revolutionizing” anything.
2. **A mechanism earns a design section.** State the inputs, the necessary invariant, the actual stored representation, and the cases it declines to handle. Show a version change, not “rich insights.”
3. **An experimental result has a population.** Write “13 expected-positive rule/case assertions over 27 controlled programs” rather than “100% accurate” or “13 real-world vulnerabilities found.”
4. **Related work compares *questions*, not just checkmarks.** Coz: effect of hypothetical code acceleration; Scalene: cost attribution across a language boundary; HEProfiler: library comparison; EVA/HEIR: construction and optimization of encrypted programs; CipherScope: semantic evidence from covered OpenFHE Python calls in an observed run.
5. **Criticism improves credibility.** State proxy bypass, bootstrap level visibility, CKKS noise, incomplete real-workload adjudication, and unsafe-to-publish trace contents where relevant. These are meaningful constraints, not obligatory concluding disclaimers.

## Citation discipline for Fable

- Cite each paper for **what that paper demonstrated**, never for CipherScope's unmeasured capabilities.
- Never borrow quantitative results from these papers as if they were measured by CipherScope. Even verbatim numbers (e.g., EVA's 5.3×) require the original baseline, workload, and citation.
- If a comparison column in `paper/prior_art_matrix.csv` says `verify`, check the linked primary source before converting it into an assertion.
- Use the **publisher/USENIX/source manuscript** when available. For HEIR, use the dated primary arXiv record and verify revisions.
- No unattributed prose imitation. The “useful editorial pattern” sentences above are **new examples written for this skill**, not quotations from the five papers.
