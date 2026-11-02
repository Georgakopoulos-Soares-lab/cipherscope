<!-- SUPERSEDED 2026-11-01: paper/manuscript.tex is now the canonical
manuscript. This markdown was the first-draft source and is retained for
history only; it predates the venue restructure (threat model, setup
section, reordered results, named authors). Do not edit results here. -->

# CipherScope: Runtime Semantic Observability and Diagnosis for OpenFHE Programs

<!--
DRAFT STATUS: first full draft, 2026-11-01. Every number is bound to a
repository artifact; see paper/manuscript_notes.md for the claim ledger,
open [VERIFY] items, and resumption instructions. Numbers were verified
against the working tree at 8e55b53 + uncommitted changes; re-verify after
commit and after any LS6 rerun.
-->

## Abstract

A timing profile of a fully homomorphic encryption (FHE) program can show that
`EvalRotate` is expensive. It cannot show whether successive rotations read the
same ciphertext version, whether a rotation key generated at setup was ever
used, or how many multiplicative levels the executed computation actually
consumed — the facts that decide whether an optimization is worth attempting.
CipherScope records those facts. It traces OpenFHE programs at the application
boundary — in Python through a proxy around the live crypto context, and in
C++ through a GCC plugin that instruments an unmodified program at compile
time — and reconstructs immutable ciphertext versions, per-scheme state
transitions, and provenance into a validated graph. Twelve conservative rules
over that graph report candidate optimizations and misconfigurations, each
with the evidence that triggered it and the conditions under which it
abstains. On the pinned OpenFHE 1.5.1 build, tracing preserves program output
(maximum CKKS deviation 2×10⁻¹³ across the equivalence checks; BFV and BGV
results are bit-identical), and the platform-independent results are identical
across four OS/toolchain lanes. A 61-case known-answer benchmark across CKKS,
BFV, and BGV yields 31/31 recall with no false positives on 44 hard negatives.
On an independently authored four-workload corpus, 6 of 8 adjudicated findings
were actionable true positives; all six patches were applied and measured: the
three performance findings yielded 1.09×–4.03×, the three security findings
surfaced measured security/performance trades, and one adjudicated false
positive led to a rule correction. Tracing adds a fixed absolute cost of roughly 0.4–2.3 s per
run, under 2% on workloads that run 100 s or longer. The principal limitation
is the observation boundary: CipherScope sees only covered calls, and the
corpus study itself shows two OpenFHE feature families (threshold FHE and
proxy re-encryption) outside it.

## 1. Introduction

Consider an OpenFHE program that encrypts a packed vector, rotates the
ciphertext by four different indices, and combines the results. A line-level
profiler reports that the four `EvalRotate` calls dominate the run time. The
developer who wants to act on that observation needs answers to questions the
profile does not contain. Did all four rotations read the *same* recorded
ciphertext version, so that a single hoisted precomputation could serve them
all? Is the context's key-switching technique one under which that shared
precomputation is known to reproduce the regular rotation exactly? Was one of
the rotation keys generated at setup never used by the executed run, wasting
key-generation time and memory? None of these are timing facts. They are facts
about ciphertext identity, library configuration, and executed provenance, and
they are exactly what a conventional profile discards.

CipherScope is a runtime observability and diagnosis system for OpenFHE
programs that records these facts while the program runs. It observes the
application's own calls into OpenFHE — not the library's internals — and
builds an explicit model of the execution: every covered call attributed to
its source line, every ciphertext result assigned an immutable version
identifier, every in-place mutation producing a new version, and every
version carrying the state its scheme exposes (level, scale, noise degree,
slot count, key tag, key-switching technique). Offline analyses over the
resulting graph report findings such as "these four rotations read ciphertext
version `ct_0001:v0` under BV key switching and no compatible precomputation
precedes them," each tied to the evidence events and source lines that
justify it.

Three design decisions distinguish this from both profilers and FHE
compilers. First, the unit of observation is the *application-level semantic
call*, not a native kernel or a compiler IR node: CipherScope answers
questions about the program the developer wrote and ran, including branches
the compiler cannot see taken and configurations fixed only at run time.
Second, the rules are deliberately conservative: each fires only on recorded
evidence and explicit user assertions, abstains (`not_applicable`, with a
stated reason) when its preconditions are unobserved, and recommends a
measured experiment rather than promising a speedup. Third, the coverage
boundary is itself measured: every run is classified `COMPLETE`,
`PARTIAL-PERMISSIVE`, or `UNSUPPORTED`, and only `COMPLETE` runs enter any
quality table in this paper.

The same canonical trace is produced by two frontends. The Python frontend
wraps a live crypto context in a proxy; a runner intercepts the program's
`GenCryptoContext` call so that existing scripts run unmodified. The C++
frontend is a GCC plugin that instruments the OpenFHE call boundary of an
unmodified program in a shadow build, leaving the source tree and the
original binary untouched. Validation, the ciphertext graph, all twelve
analyzers, and every exporter are shared; a gate check asserts that the C++
and Python traces of twin programs are semantically equivalent.

This paper makes four contributions.

1. **A source-attributed runtime model of FHE execution** (Section 3):
   immutable ciphertext versions, per-scheme state transitions, rotation-key
   use, and lineage, reconstructed from covered calls into a validated graph,
   with the coverage boundary explicit and measured. The model is
   scheme-parametric: CKKS, BFV, and BGV are identified from a live context
   with no declared parameters, and depth is read from whichever coordinate
   the scheme actually moves — the level ladder for CKKS and BGV, and the
   recorded multiplication count for BFV, whose level never changes and whose
   noise-scale degree we measured to be non-cumulative (Section 3.4).
2. **Conservative diagnoses over that model** (Section 4): twelve rules
   covering repeated compatible rotations, rotation keys unused in the
   observed run, observed depth headroom, bootstrap restoration use,
   annotated packing utilization, public-value provenance, repeated public
   encodings, serial associative reductions, precision checkpoints and
   declared tolerances, testing-only security configuration, and the depth
   critical path.
3. **An evidence methodology for FHE tooling** (Section 5): coverage classes
   that keep incomplete traces out of quality claims; a seeded known-answer
   benchmark with hard negatives for recall; adjudication of every real
   finding under a fixed rubric for precision; before/after patches for every
   actionable finding; and a data contract under which every table in this
   paper regenerates byte-identically from checksummed raw records.
4. **Measured results on real workloads** (Section 5): on an independently
   authored corpus, 6 of 8 adjudicated findings were actionable; all six
   patches were applied and measured (1.09×–4.03×, plus one
   configuration fix that restored standard security enforcement at no
   measurable cost), and the two false positives are analyzed rather than
   discarded — one exposed a missing level reservation that is now part of
   the depth rule.

We do not claim that CipherScope is the first FHE profiler, that it replaces
compilers or library benchmarks, or that its suggestions are guaranteed
improvements. Section 7 positions it against systems that answer adjacent
questions; Section 6 states what it cannot see.

## 2. Background and a Motivating Example

### 2.1 What the example needs from FHE

The schemes relevant here are CKKS, which computes on encrypted
fixed-point-like approximations of real vectors, and BFV and BGV, which
compute exactly on packed integer vectors modulo a plaintext modulus `t`.
Three properties drive the diagnostics in this paper.

**Depth is a budget.** A context is configured with a multiplicative depth;
each ciphertext–ciphertext multiplication consumes from it. In OpenFHE's
CKKS and BGV, consumption is visible as a per-ciphertext *level* that
increases monotonically within a bootstrap epoch. BFV exposes no such ladder
(Section 3.4). Exceeding the budget does not necessarily raise an error: a
BGV result can silently decrypt to a wrong value, which makes depth
accounting a correctness concern rather than only a performance one.

**Rotations need keys, and keys are per index.** Rotating packed slots by
index *i* requires a rotation key generated for *i* at setup. Generating
keys for indices the run never uses costs time and memory. Several rotations
of the *same* ciphertext can share one expensive precomputation
(`EvalFastRotationPrecompute`) — but only of the same ciphertext version,
and the equivalence of the shared form depends on the key-switching
technique in use.

**CKKS is approximate; BFV and BGV are exact.** A CKKS value carries noise
that grows with computation, so precision loss is a measurable, meaningful
quantity. An exact scheme that produces a wrong value has not "lost
precision"; it has failed, typically by exceeding the noise budget or
overflowing `t`. Diagnostics designed for approximation error have nothing
to measure on exact schemes, and the tool must say so rather than report a
vacuously clean result.

### 2.2 The running example

The OpenFHE project ships `simple-integers.py`, a 103-line BFV example that
encrypts three integer vectors, adds and multiplies them, and rotates the
first ciphertext by indices 1, 2, −1, and −2. We use it as the running
example because we did not write it, and because tracing it end-to-end
exercises the exact chain of facts the Introduction claims a profile lacks.

A timing profile of this program attributes some milliseconds to each
`EvalRotate` line. CipherScope's trace of the same run records, in addition:
that all four rotations read ciphertext version `ct_0001:v0`; that the
requested indices were {−2, −1, 1, 2}; that the context's key-switching
technique is BV (the BFV default, unlike the HYBRID default of CKKS and
BGV); and that no `EvalFastRotationPrecompute` for that version precedes the
group. The rotation-hoisting rule therefore fires with `confidence:
measured`, naming the four evidence events and the shared source version,
and recommends testing a hoisted precomputation — a recommendation the rule
is only entitled to make under BV because a gate check (ROT-04,
Section 5.1) first established that a shared precomputation reproduces
regular rotations exactly under that technique. On the same trace the
depth-critical-path rule reports the executed multiplication chain, and the
unused-key rule stays silent because every generated key was used. When we
ran this program and its BGV twin under the tracer, both completed with
strict coverage (`COMPLETE`, 17 semantic calls) and byte-identical decrypted
output (Section 5.3).

This is the pattern for everything that follows: a fact a profile cannot
express, a recorded representation of that fact, a rule that uses it under
stated preconditions, and an abstention path when the preconditions fail.

## 3. Design

### 3.1 The trace model

A run produces a validated bundle: a schema-versioned `trace.json` (events,
ciphertext versions, context description, coverage record), a derived
`ciphertext_graph.json`, analyzer output in `recommendations.json`, and
exporters (CSV, Perfetto, a static HTML report). Each event records the
operation's canonical name, its source attribution (file, line, function,
call-site identifier), wall and process-CPU duration for the whole call,
input and output ciphertext versions with their state snapshots, semantic
arguments (for example, the requested rotation index), and status — a
failing call becomes an error event rather than a gap.

Ciphertext identity is version-based. A ciphertext result is assigned an
identifier such as `ct_0002:v0`; an in-place operation (`EvalAddInPlace`,
`RescaleInPlace`) produces the next version of its operand, and later reads
observe the new version. Aliasing — handle copies, moves, container storage
— preserves identity; destroyed objects never leak their identifier to a
reused address. These properties are asserted by gate checks on the real
library (ID-01..03, MUT-01..03), not assumed.

### 3.2 Two frontends, one boundary

The **Python frontend** wraps a native crypto context in a proxy. Only calls
through the proxy are observed. In strict mode, a call the compatibility
registry cannot classify is rejected and named; in permissive mode it is
forwarded and the trace is marked incomplete. The `cipherscope run` launcher
executes an unmodified script by intercepting its `GenCryptoContext` call
and attaching the returned context, so corpus programs run without edits;
programs that obtain contexts by other means must call `attach()`
themselves.

The **C++ frontend** is a GCC plugin. `cipherscope profile <binary>`
discovers the target's CMake build, creates an instrumented *shadow* build
without touching the source tree or the original binary, and the plugin
instruments each application-level OpenFHE call site during compilation.
Instrumentation precedes optimization: a gate check (SRC-02) asserts that
the same events and source lines are recorded at -O0, -O2, and -O3.
Operator overloads (`*`, `+`, `+=`, unary `-`) normalize to the same
canonical events as named calls; concurrent calls from OpenMP threads are
recorded once each (THR-01). A spooled native trace is normalized into the
same canonical schema the Python frontend emits, and the entire downstream
pipeline — validation, graph, analyzers, exporters — is shared. PARITY-01
asserts that C++ traces of eight twin programs are semantically equivalent
to the Python frontend's traces of the same computations.

### 3.3 Coverage as a first-class measurement

Because the tool cannot see calls that bypass its boundary, every run is
classified. `COMPLETE` requires strict mode, a finished run, at least one
traced semantic call, nothing forwarded untraced, and no bypass pattern in
the target's source (an AST preflight scans for raw-context use, module-level
`Eval*` free functions, and `GetCryptoContext()` escapes). `PARTIAL-
PERMISSIVE` and `UNSUPPORTED` runs are excluded from every quality table.
The classification is operational, not a proof: a clean scan does not
demonstrate the absence of every possible bypass, and we state it as such.

Rejections are informative. When we traced the five upstream OpenFHE
integer-scheme examples (Section 5.3), three failed in strict mode, naming
`MultipartyKeyGen` and `ReKeyGen` — the threshold-FHE and proxy-re-encryption
families, which the operation manifest does not cover. The failure mode is
the designed one: the unsupported operation is named in the coverage record
rather than silently forwarded.

### 3.4 A scheme-parametric state model

The trace records the scheme, and the analyzers read state through it. Three
measured facts on the pinned build (OpenFHE 1.5.1, Python wrapper 1.5.1.0)
shape the model; none of them is documented behavior we could have assumed.

**Scheme identification without declared parameters.** The wrapper exposes
no scheme getter. We identify CKKS by probing `GetModulusCKKS()`, which
answers for a CKKS context and raises for the integer schemes; among the
rest, only BFV runs with the `NORESCALE` scaling technique, which separates
it from BGV. Declared parameters, when present, take precedence, and the
trace records which evidence named the scheme. A gate check (API-09) holds
this for all three schemes across the supported scaling techniques.

**BFV has no level ladder, and its noise-scale degree is not a substitute.**
`GetLevel()` returns 0 for every BFV ciphertext in a run. The noise-scale
degree looks like a replacement — it is 1 on a fresh ciphertext and rises by
one per multiplication — but it is not cumulative: measured on the pinned
build, `EvalAdd` of a degree-1 and a degree-2 ciphertext returns degree 1,
erasing the record of the multiplication upstream. Our first implementation
used the degree and was caught not by our seeded tests (pure multiplication
chains, which the degree tracks) but by a C++ fixture whose final addition
mixes depths. BFV depth is therefore counted from the recorded
multiplications along the deepest lineage, every depth finding names its
coordinate in a `depth_evidence` field (`ciphertext_levels` or
`recorded_multiplications`), and BFV findings carry `confidence: inferred`
rather than `measured`.

**BFV's configured depth is a noise budget, not a multiplication counter.**
On the pinned build, a depth-2 BFV context completed three successive
multiplications correctly, and depth 2 and depth 3 had the same capacity for
the operands we tested; capacity is value-dependent, and exceeding it
decrypts to a wrong plaintext without raising. The BFV depth-headroom
finding therefore carries explicit limitations saying exactly this, and its
numeric headroom is labeled an inference about the observed inputs, not a
measurement of a ladder.

Where the schemes are uniform, the model says so: BGV spends levels exactly
as CKKS does (one per multiplication, same minimum depth across all four
scaling techniques we tested), packing capacity is N slots for the integer
schemes versus N/2 for CKKS, and bootstrapping is simply unavailable for BFV
and BGV on this build (`EvalBootstrapSetup` raises "Not supported"), which
the bootstrap rule reports as its reason for abstaining.

### 3.5 Bounded recording

Events and finalized ciphertext states spool to disk during the run;
`--max-events` and `--max-trace-bytes` stop recording (never the workload) at
a hard limit and mark the trace truncated. Finalization is not streamed:
building and analyzing the trace materializes it, at about 2.2 KB and 30 KB
of peak memory per event on the scaling kernel (Section 5.6).

## 4. Diagnosis Rules

Each rule states its preconditions, the evidence it records, the diagnosis,
and the experiment it suggests; each abstains with a reason when a
precondition is unobserved. We describe four in detail and summarize the
rest; Section 5.2 evaluates all twelve.

**Repeated compatible rotations** (`rotation.hoist_same_input.v1`). Fires
when at least two `EvalRotate` calls with distinct requested indices read the
same ciphertext version, their context, key tag, scaling state, and
key-switching technique match, the technique is one for which shared
precomputation has gate-level equivalence evidence (HYBRID via ROT-02, BV
via ROT-04), no compatible precomputation precedes the group, and no
in-place mutation intervenes. The suggestion is to test a hoisted
`EvalFastRotationPrecompute`; the finding reports the combined wall time of
the group as the stake, not a predicted saving. The rule abstains, naming
the ciphertext, when metadata is missing or the technique lacks evidence.

**Rotation keys unused in the observed run**
(`keys.unused_in_observed_run.v1`). Compares the indices requested in
`EvalRotateKeyGen` against the indices of executed rotations and reports the
difference. The scope is deliberately "in the observed run": a key unused on
this input may be needed on another, and the finding says so.

**Observed depth headroom** (`parameters.depth_headroom_observed.v1`).
Compares the configured multiplicative depth against the executed depth
requirement, read from the scheme's coordinate (Section 3.4), and reserves
one level when the deepest ciphertext still carries a deferred FLEXIBLEAUTO
rescale — a reservation added after an adjudicated false positive showed the
level field lagging a committed level (Section 5.4). It abstains when the
depth model is not fully resolved, for example when an opaque call
(`EvalChebyshevSeries`, `EvalLogistic`) hides part of the path. Headroom is
an upper bound: levels a library call consumes internally are not observed,
and the finding's limitations say so.

**Testing-only security configuration**
(`configuration.testing_only_security.v1`). The security level is not
readable from a live context, so this rule assesses only runs that declare
their parameters; it reports a declared `HEStd_NotSet` as a testing-only
configuration. It is a configuration observation, never a bit-security
estimate, and it abstains on undeclared runs rather than inferring from ring
size.

The remaining rules follow the same contract. Bootstrap restoration
(`bootstrap.restored_levels_underused.v1`) reports a bootstrap that restored
more levels than its epoch then consumed; it requires an input deeper than
the fixed level OpenFHE returns every bootstrap output at, and it abstains
on BFV/BGV with the measured "Not supported" reason. Packing utilization,
public-value provenance, and repeated public encodings fire only on explicit
developer annotations (`meaningful_slots`, `provenance`, `constant_id`) —
CipherScope never infers semantic content from ciphertexts. Serial
reduction review fires only inside regions the developer declares
associative. The two precision rules require shadow mode with a supplied
secret key; checkpoint drops below 3.0 absolute bits are ignored because
CKKS decryption is noise-flooded (measured jitter stdev 0.68 bits; an
earlier 1.0-bit threshold produced a ~5% false-positive rate on noise
alone), and both rules abstain on exact schemes. The depth critical path is
informational: it always reports when lineage exists and is not counted in
precision (Section 5.4).

## 5. Evaluation

Six questions organize the evaluation. RQ1: does tracing preserve behavior
and reconstruct state correctly, on every supported scheme? RQ2: what
fraction of real workloads is completely observable? RQ3: what are recall on
known-answer programs and precision on real findings? RQ4: do validated
findings produce measured improvements? RQ5: what does tracing cost? RQ6:
does the tool expose real misconfigurations? Every table regenerates from
checksummed raw records (`evaluation/raw/`, 8 files) via a deterministic
generator; regeneration is byte-identical and asserted by a test.

### 5.1 RQ1: Fidelity

**Tracing preserves program output.** The real-binding gate runs 40–42
checks against the pinned build (the count grew during development; see
below). The numerical checks compare traced against direct execution:
maximum CKKS deviation across them is 2.2×10⁻¹³ on the primary lane
(3.4×10⁻¹³ worst-case across lanes, within the golden tolerance), and the
bootstrap check's traced-vs-direct error is 1.7×10⁻⁵, within its tolerance.
BFV and BGV comparisons are exact: the instrumented runs reproduce direct
results bit for bit, both in the 61-case seeded benchmark's `check_exact`
assertions and in the C++ gate's NUM-01, which requires the instrumented
binary to print exactly what the plain binary prints.

**The gate holds across four OS/toolchain lanes.** The authoritative lane
(Ubuntu 24.04 x86_64 container, GCC 13.3, built and run on a TACC Lonestar6
node) passes 40/40; a bare-metal Rocky Linux 8.10 lane with GCC 15.2 passes
the same 40; the macOS arm64 developer lane passes 41/42 (the skip reads
`/proc` and is Linux-only); and an emulated x86_64 Docker lane passes 42/42
— the only lane to have run every check, because two checks (API-09 scheme
identification, ROT-04 BV fast-rotation equivalence) postdate the cluster
archives. [VERIFY: rerun the two cluster lanes at 42 checks before
submission; docs/evidence.md and the parity report state this gap
explicitly.] The emulated lane is a different binary (its native-module hash
differs) and is never authoritative; we quote cluster numerics. A parity
comparator asserts that the platform-independent artifacts — seeded
outcomes, ablation rows, example diagnoses — are identical across lanes: 0
disagreements, with the macOS `/proc` skip and the two postdating checks as
the only allowed differences.

**The C++ frontend agrees with the Python frontend.** The 21-check C++ gate
passes on GCC 15.2 (Rocky, native), GCC 13.3 (Ubuntu container), and GCC
13.3 under emulation, including SCHEME-01 (BFV and BGV report their scheme,
N packed slots, and plaintext modulus; CKKS keeps N/2 slots and none) and
PARITY-01 (semantic equivalence of eight twin programs spanning rotations,
in-place operators, aliasing, exceptions, vector composites, BFV, BGV, and
checkpoints).

### 5.2 RQ3a: Recall on seeded known-answer programs

Recall cannot be measured on real programs — nothing says what a rule
*missed* — so we maintain a seeded corpus: for each rule, programs that must
fire and near-misses that must not. The corpus holds 61 real-binding
programs (28 CKKS, 17 BFV, 16 BGV): 31 expected positives, 44 hard-negative
expectations (of which 6 assert that a rule must *abstain*, for example that
a declared tolerance on an exact scheme must make both precision rules
decline), with every declared number hand-derivable from the case's source.

The result is 31/31 positives detected and 0 false positives on the 44
negatives, across all twelve rules and all three schemes. Two caveats keep
this honest. First, seeded recall is a property of these controlled
programs, not of real workloads. Second, the corpus itself caught our
mistakes during development — the non-cumulative BFV noise degree
(Section 3.4) survived the seeded multiplication chains and was caught only
by a C++ fixture, after which we added a seeded regression case
(`bfv.positive.mixed_add_depth`) that pins the corrected model's evidence.

A semantic ablation re-analyzes the same traces under three views:
TIMING_ONLY (operation names, timings, source lines — what a generic
profiler records), STATE (adds per-call level/scale/configuration metadata,
no ciphertext identity), and FULL. Of the twelve rules, one
(the declared-configuration rule) survives TIMING_ONLY; five more are
recovered by STATE; six — including rotation hoisting, provenance, packing,
and serial reduction — require FULL, i.e. ciphertext version identity. This
is a projection of CipherScope's own trace, not a benchmark against an
actual external profiler, and we label it so.

### 5.3 RQ2: Coverage on real workloads

On the CKKS corpus — 16 gallery programs plus the four workloads of an
independently authored regression suite (`python-log-reg-examples`, pinned
by commit) — 20 of 20 runs classify `COMPLETE` in strict mode. Reaching
20/20 required covering operations the corpus actually used
(`EvalLogistic`, `EvalSumRows`, `EvalSumCols`); before that, three of the
four external workloads were only partially observable, which the coverage
class reported.

For the integer schemes we traced the five BFV/BGV examples shipped inside
the pinned OpenFHE Python wrapper itself: **2 of 5 complete**. The two
single-party examples (`simple-integers.py`, BFV; `simple-integers-bgvrns.py`,
BGV) trace `COMPLETE` with 17 semantic calls each, and both yield a measured
rotation-hoisting finding on code we did not write — the BFV one assessable
only because ROT-04 validated BV key switching. The other three fail in
strict mode on `MultipartyKeyGen` (threshold FHE) and `ReKeyGen` (proxy
re-encryption): two feature families outside the operation manifest, named
in the coverage record. Running this corpus also exposed three read-only
context getters (`GetPlaintextModulus`, `GetModulus`, `GetDigitSize`)
missing from the non-semantic allowlist — an omission, fixed, that had
failed three of the five programs outright. We report the fraction as 2/5,
not "two workloads traced." The C++ frontend's coverage evidence is
separate: 6 of 6 upstream OpenFHE C++ examples profile `COMPLETE`.

### 5.4 RQ3b: Precision on real findings

Every finding from every `COMPLETE` run of the external CKKS corpus was
exported and adjudicated under a fixed rubric. Twelve findings resulted.
Four are depth-critical-path reports, which are informational (the rule
always fires when lineage exists) and were classified not-in-scope for
precision, leaving a denominator of eight: six actionable true positives and
two false positives, precision 6/8 = 0.75.

Adjudication was performed by two AI reviewers, not humans: a first pass,
then a blind second pass by a different model with no access to the first
verdicts and the ability to run depth-reduction experiments on a scratch
copy of the corpus. Both disagreements were resolved toward the reviewer who
executed the experiment. We state this plainly as a methodological limit:
the rubric, verdicts, and experiment transcripts are in the artifact, and
nothing prevents re-adjudication by humans. [VERIFY: consider an
independent human pass before submission.]

The two false positives are more informative than the six hits, and they
have different causes. In `sol_nag_log_reg`, the rule reported headroom 2,
but depths 32 and 31 both abort inside a two-iteration `EvalBootstrap`
whose internal level consumption no ciphertext state exposes — the
documented upper-bound limitation of the rule, live and unfixable at this
observation boundary. In `sol_encrypted_inference`, the reported headroom
of 1 did not exist because the final ciphertext carried a deferred
FLEXIBLEAUTO rescale: one more level was committed than the level field
showed. That diagnosis became a rule change — the depth rule now reserves a
pending-rescale level — and the analyzer reports that run clean today. The
precision table deliberately keeps the verdict as adjudicated rather than
retroactively crediting the fix; we quote 0.75 and explain it, rather than
7/8.

### 5.5 RQ4: Impact of validated findings

All six actionable findings were patched and measured; the patches are
single-purpose diffs in the artifact, with before/after repetitions in fresh
processes and the program's own correctness check as the acceptance
criterion. Reducing `sol_lin_reg`'s configured depth from 12 to the observed
7 gave the largest effect, 4.03×; regenerating its rotation keys by feature
count instead of sample count gave 1.21×; reducing `sol_log_reg`'s depth
from 33 to 31 gave 1.09× at the four-epoch training scale. The three
`HEStd_NotSet` findings were fixed by enabling standard 128-bit
enforcement, with three different outcomes, all reported: on the inference
workload the fix was free (its parameters already satisfied the standard
ring size); on the two training workloads it cost 3.5–4× *and changed the
numerical results*, because enforcement enlarges the ring. A security fix is
not a speedup, and on these workloads it is a measured
security/performance/accuracy trade that the finding surfaces for the
developer to decide. The transformation attempted for the
adjudicated false positive was refused by OpenFHE at run time — retained in
the table as evidence of the adjudication, not deleted.

Separately, a designed before/after suite pairs every prescriptive rule
with a minimal program where the finding fires, a patch that follows the
rule's suggestion, and a re-trace that must come back clean or inapplicable;
all ten pairs behave as designed, with numerics preserved. One pair is a
deliberate caution: fixing the testing-only security configuration makes the
toy program ~4× slower — the "fix" buys security, not speed, and the table
says so.

### 5.6 RQ5: Cost

Tracing cost has a fixed and a variable component, and pooling them would
mislead. Across the twelve-workload overhead corpus (three matched
baseline/traced repetitions each, same machine, OMP_NUM_THREADS=1), the
absolute overhead is roughly 0.4–2.3 s per run — recording plus
finalization plus analysis. On workloads running 100–180 s (bootstrapping,
linear regression training) that is 0.7–1.8% wall overhead; on sub-second
gallery programs the same fixed cost is a 1.5–2.6× ratio. We report both
rather than the pooled mean. CPU overhead on long workloads is within
noise of zero.

An event-count scaling sweep (10²–10⁵ events, baseline/streaming/buffered,
run on both arm64 and x86_64 and reported per machine, never pooled) shows
run-phase overhead bounded and trace size linear at ~2.2 KB/event, with
analysis ~190 ms per thousand events. The known memory limit is
finalization: at 10⁵ events, materializing and analyzing the trace peaked at
3.2 GB RSS. A second practical limit surfaced while validating on a
memory-capped VM: the deep-bootstrap seeded case itself peaks at 6.98 GB and
is OOM-killed below ~8 GB, which presents as a missing bundle; the artifact
documentation names the symptom. Scaling points are single runs on shared
machines and we treat them as observations, not stable estimates.

### 5.7 RQ6: Misconfigurations in real programs

A hunt across ten real programs (the four external workloads plus six
upstream OpenFHE examples) applied the configuration rule to every run with
declared parameters: five `HEStd_NotSet` true positives (three actionable in
the external suite — all later fixed and measured under RQ4 — and two in
upstream examples where the setting is deliberate for tractability and
classified non-actionable), five clean, no false positives. The precision
rules abstained on all ten programs, correctly: unmodified programs declare
no checkpoints, and the rules' annotation requirement is a deployment
constraint we count rather than hide.

## 6. Limitations

**The observation boundary.** CipherScope sees calls that cross its
boundary and nothing else: raw-context calls, module-level free functions,
`GetCryptoContext()` escapes, and native-internal work are invisible.
Coverage classes measure this operationally; they do not prove completeness.
Threshold FHE and proxy re-encryption are outside the manifest today and
fail strict runs by name.

**Scheme asymmetries.** BFV depth findings are inferences from recorded
operations against a value-dependent noise budget, stated as such and
down-weighted to `inferred` confidence. Bootstrap analysis requires inputs
deeper than OpenFHE's fixed return level, and is unavailable on the integer
schemes on this build. Precision rules are CKKS-only by construction and
require shadow mode, a secret key, and developer checkpoints.

**Evidence limits.** Depth headroom is an upper bound in the presence of
opaque calls, and one of our two real false positives is exactly that case.
Seeded recall is not real-workload recall. Precision rests on eight
adjudicated findings judged by AI reviewers under a fixed rubric.
Timing-only comparisons are ablations of our own trace, not a benchmark of
an external profiler. The two cluster gate archives predate the two newest
checks. Scaling points are single runs.

**Traces are sensitive.** A trace records argument and result
representations, exception messages, absolute paths, and, in shadow mode,
decrypted checkpoint values. It records no key material or ciphertext
coefficients, but we claim no leakage guarantee, and traces should not be
published as-is.

**No security claims.** The configuration rule reports a declared
enforcement setting. CipherScope never estimates bit security and does not
validate parameter choices.

## 7. Related Work

Each neighboring system answers a different question with different
information, and the comparisons below are scoped to that.

**Library profilers and benchmark harnesses.** HEProfiler profiles and
compares C++ CKKS library implementations through a per-library harness
subclass; it characterizes libraries, not a particular application's
executed semantics. [VERIFY: per-call attribution and lineage cells are
unconfirmed; the ePrint PDF resists automated fetch and the JCE version is
paywalled — read before submission.] CryptOracle packages an OpenFHE
benchmark suite with hardware and energy prediction. Neither traces a user's
own program at the application boundary, which is the question CipherScope
answers; conversely, CipherScope measures nothing about library internals
or energy.

**Language-level profilers.** Scalene attributes Python versus native cost,
memory, and copying at the language boundary; Coz estimates the causal
effect of speeding up a line via virtual-speedup experiments. Both answer
"where does time go / what would speed things up" without FHE semantics:
neither can state that two rotations consumed one ciphertext version or
that a rotation key went unused, and CipherScope does not attempt their
measurements — it records whole-call times only as context for its semantic
findings, and suggests experiments rather than estimating causal speedups.

**FHE compilers.** EVA and HEIR construct or optimize FHE programs through
compiler representations; Rotom derives packing layouts; their analyses are
static over an IR. CipherScope's graph is the *executed* run of an
already-written program — it observes taken branches, runtime-chosen
parameters, and library behavior as shipped, and it rewrites nothing. The
approaches are complementary: a compiler could consume facts CipherScope
observes, and several of its diagnoses (hoisting, layout) correspond to
transformations compilers perform when the program is written in their
input language.

**FHE testing.** HERTA metamorphically tests FHE frameworks using generated
programs; it targets library correctness, not application diagnosis.

## 8. Conclusion

CipherScope demonstrates that application-level FHE execution can be
observed precisely enough to support conservative, evidence-carrying
diagnoses — across three schemes, two languages, and four toolchains — and
that the observations are worth having: on an independently authored corpus,
six of eight adjudicated findings were actionable, and acting on them
produced measured improvements up to 4.03×. The methodology may travel
further than the tool: measured coverage boundaries, known-answer corpora
with hard negatives and abstention assertions, adjudication with preserved
false positives, and byte-reproducible tables are applicable to any FHE
tooling claim. The artifact contains every raw record, checksum, patch, and
regeneration command behind every number in this paper.

<!-- References to be added with the .bib; see manuscript_notes.md -->
