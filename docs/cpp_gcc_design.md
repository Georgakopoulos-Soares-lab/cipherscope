
# CipherScope C++ / GCC Transparent Tracing Design

## A GCC-only design for zero-source-change OpenFHE profiling with a language-independent trace boundary

**This is the original design proposal, kept for historical/rationale
reference.** The C++ frontend it proposes has since been implemented; for how
it actually works today, read [cpp_frontend.md](cpp_frontend.md) instead. Where
the two disagree, the implementation and `cpp_frontend.md` are authoritative.

**Status:** Proposed implementation architecture based on the current CipherScope repository uploaded September 2026.
**Scope:** OpenFHE C++ programs compiled with GCC.
**Explicitly out of scope here:** Clang/LLVM, MSVC, generic binary instrumentation, `LD_PRELOAD`-only tracing, and rewriting the CipherScope analyzers in C++.

---

## 1. Objective

The C++ extension should preserve the same user-facing philosophy as the current Python profiler:

```bash
cipherscope profile ./my_fhe_program
```

The user must **not** have to edit the FHE program:

* no `#include <cipherscope/...>`;
* no replacement `CryptoContext` type;
* no `CS_TRACE(...)` macros;
* no manual wrappers around `EvalMult`, `EvalRotate`, etc.;
* no source-to-source rewrite committed into the user's tree;
* no requirement to restructure the application around CipherScope.

At the same time, the C++ implementation should be designed so that the tracing frontend is completely decoupled from analysis after one explicit boundary:

> **Canonical CipherScope Trace Schema**

Everything before this boundary is responsible for observing a C++/OpenFHE execution. Everything after it must remain independent of C++, GCC, OpenFHE bindings, and the instrumentation mechanism.

The desired architecture is therefore:

```text`
                      TARGET PROGRAM
                           C++
                            │
                            ▼
                  transparent GCC build
                            │
                            ▼
              ┌─────────────────────────┐
              │ CipherScope GCC frontend│
              │ + OpenFHE adapter       │
              │ + native trace runtime  │
              └────────────┬────────────┘`
                           │
                           │ canonical trace
                           ▼
        ╔══════════════════════════════════════╗
        ║       CipherScope Trace Schema       ║
        ║     language-neutral contract        ║
        ╚══════════════════╤═══════════════════╝
                           │
                           ▼
                current Python pipeline
                           │
                 trace validation
                           │
                  graph construction
                           │
                     analyzers
                           │
                     exporters
                           │
                           ▼
                    run bundle/report
```

The C++ frontend is therefore **not another CipherScope implementation**. It is only another **trace producer**.

---

# 2. Why this design fits the current CipherScope refactor

The current repository has already moved in the right direction.

The key existing boundary is:

```python
build_analysis_bundle(trace)
```

in `src/cipherscope/pipeline.py`.

The pipeline performs the following independently from the live Python tracing mechanism:

1. validate the trace;
2. construct the ciphertext graph;
3. execute all analyzers;
4. validate findings;
5. construct the bundle manifest;
6. export the resulting artifacts.

The CLI already exposes this separation through:

```bash
cipherscope analyze trace.json --output RUN_DIRECTORY
```

This is extremely important for the C++ architecture. It means the existing repository already supports the fundamental design goal:

```text
trace acquisition != trace analysis
```

The C++ extension should strengthen this separation rather than introduce C++-specific analysis logic.

The current conceptual Python path is approximately:

```text
OpenFHE Python call
      ↓
TracedCryptoContext
      ↓
Recorder
      ↓
trace.json
      ↓
build_analysis_bundle(trace)
      ↓
Graph + analyzers + exporters
```

The new C++ path should be:

```text
OpenFHE C++ call
      ↓
GCC-inserted instrumentation
      ↓
native CipherScope runtime
      ↓
trace.json
      ↓
build_analysis_bundle(trace)
      ↓
Graph + analyzers + exporters
```

Everything beginning with `trace.json` is shared.

---

# 3. Central architectural rule

The strongest rule to impose on the implementation is:

> **No CipherScope analyzer may depend on how a trace was produced.**

An analyzer may read fields in the canonical trace schema. It must never:

* import a GCC component;
* call the native runtime;
* depend on a C++ pointer;
* understand C++ name mangling;
* understand a GIMPLE node;
* call OpenFHE directly;
* inspect a Python proxy object;
* branch on `frontend == cpp` for semantic correctness.

The same should apply to graph construction.

This gives the project three clean layers:

```text
Layer A — Acquisition
    Python frontend
    GCC/OpenFHE C++ frontend

Layer B — Canonical semantic trace
    schemas/trace.schema.json

Layer C — Interpretation
    validation.py
    graph.py
    analyzers/*
    exporters/*
```

The trace is the only interface between A and C.

---

# 4. User experience

## 4.1 Primary command

The intended user interface should be:

```bash
cipherscope profile ./build/app
```

Optional arguments after a separator should be forwarded to the target:

```bash
cipherscope profile ./build/app -- --dataset input.csv --threads 8
```

Possible explicit options:

```bash
cipherscope profile ./build/app \
    --output runs/app-001 \
    --build-dir ./build \
    --source-dir . \
    -- --dataset input.csv
```

But the normal case should not require `--build-dir` or `--source-dir` if they can be discovered.

## 4.2 What `profile` means

`profile` is a high-level orchestration command. It is not itself the instrumentation mechanism.

Conceptually:

```text
cipherscope profile TARGET
        │
        ├─ Is TARGET already a CipherScope-instrumented binary?
        │       │
        │       ├─ yes → run it
        │       │
        │       └─ no
        │
        ├─ discover reproducible build metadata
        │
        ├─ create an isolated shadow build
        │
        ├─ compile target through GCC + CipherScope plugin
        │
        ├─ run shadow target
        │
        ├─ finalize canonical trace
        │
        ├─ invoke existing `analyze` pipeline
        │
        └─ write normal CipherScope bundle
```

The source tree remains unchanged.

---

# 5. Why an arbitrary already-built binary cannot be the completeness boundary

For a C++ system, the following requirement is impossible to guarantee simultaneously:

1. only receive an arbitrary optimized binary;
2. make no assumptions about how it was built;
3. require no debug/build metadata;
4. recover every semantic OpenFHE operation;
5. guarantee completeness.

A compiler can:

* inline functions;
* clone functions;
* eliminate functions;
* merge equivalent code;
* specialize templates;
* fold wrappers;
* transform call boundaries;
* perform link-time optimization.

OpenFHE is C++ and heavily uses templates and header-defined functionality. Therefore an API call present in the source may not survive as an independently hookable dynamic function in the final executable.

For this reason, the complete design should **not** claim:

```text
any arbitrary ELF → complete CipherScope trace
```

Instead, it should guarantee completeness for a supported build path:

```text
source/build metadata
       +
GCC supported version
       +
OpenFHE supported version
       +
CipherScope semantic operation manifest
       ↓
complete trace of supported semantic operations
```

`cipherscope profile ./app` can still be the user-facing command. The difference is that the command transparently creates or locates an instrumented build before execution.

---

# 6. Build discovery: `CMakeCache.txt` and `compile_commands.json`

This is a central piece of the transparent workflow.

For a target such as:

```text
project/
├── CMakeLists.txt
├── src/
│   └── main.cpp
└── build/
    ├── CMakeCache.txt
    ├── compile_commands.json
    └── my_program
```

when the user runs:

```bash
cipherscope profile ./build/my_program
```

CipherScope should discover the existing build configuration rather than asking the user to manually reproduce compiler flags.

## 6.1 What `CMakeCache.txt` gives us

`CMakeCache.txt` can help establish:

* the source directory;
* the build directory;
* the configured C++ compiler;
* build type;
* project variables;
* OpenFHE paths or package configuration values;
* generator information;
* toolchain information.

Useful fields commonly include:

```text
CMAKE_HOME_DIRECTORY
CMAKE_CXX_COMPILER
CMAKE_BUILD_TYPE
CMAKE_GENERATOR
```

The exact set varies by project and CMake version.

CipherScope should treat the cache as **build-discovery metadata**, not as an executable build recipe by itself.

## 6.2 What `compile_commands.json` gives us

`compile_commands.json` is more important for compilation fidelity.

Each entry describes a translation unit using fields conceptually like:

```json
{
  "directory": "/project/build",
  "file": "/project/src/main.cpp",
  "command": "g++ -I... -O3 ... -c /project/src/main.cpp -o ..."
}
```

or the `arguments` form.

This gives CipherScope the real per-file compiler invocation, including:

* include directories;
* macro definitions;
* language standard;
* warning/optimization flags;
* architecture flags;
* OpenFHE include locations;
* project-specific compile options.

This is ideal for constructing an equivalent shadow compilation.

## 6.3 Discovery order

A robust initial implementation can use the following discovery order:

```text
1. User supplied --build-dir
2. Target parent directory
3. Walk target ancestors looking for CMakeCache.txt
4. Find compile_commands.json in that build tree
5. Resolve CMAKE_HOME_DIRECTORY
6. Confirm target/source relationship
7. Reproduce the build in a CipherScope shadow directory
```

Do not search arbitrary unrelated directories on the host.

## 6.4 When `compile_commands.json` is absent

CMake only writes it when configured to do so on supported generators.

CipherScope has two safe choices:

### Choice A — automatically create a shadow CMake configuration

If `CMakeCache.txt` proves this is a CMake project, CipherScope can configure a new build with:

```bash
cmake -S SOURCE \
      -B .cipherscope/builds/BUILD_ID \
      -DCMAKE_EXPORT_COMPILE_COMMANDS=ON \
      ...
```

while preserving relevant original configuration values.

### Choice B — fail closed initially

For the earliest research prototype, it is defensible to require a reproducible CMake configuration and report:

```text
Build metadata exists, but no safe reproducible instrumentation build could be established.
Coverage class: UNSUPPORTED
```

This is preferable to claiming complete tracing when the build differs silently from the original.

---

# 7. Shadow build design

CipherScope must not modify the user's normal binary or build tree.

Use a dedicated directory such as:

```text
project/.cipherscope/
└── builds/
    └── 6a8e2c.../
        ├── build/
        ├── metadata.json
        ├── instrumented-target
        └── compile_commands.json
```

or a user cache outside the source tree.

The build identifier should be derived from stable inputs such as:

```text
source tree/build identity
CMake cache fingerprint
compiler path + version
OpenFHE version
CipherScope GCC plugin version
trace schema major version
instrumentation manifest version
relevant build flags
```

The purpose is to avoid rebuilding when an equivalent instrumented target already exists.

## 7.1 Preserve original behavior

The shadow build must preserve the target's semantic build settings as closely as possible:

* same GCC major/minor where possible;
* same `-std=` mode;
* same definitions;
* same include paths;
* same library paths;
* same optimization level;
* same architecture flags;
* same OpenMP/threading settings;
* same OpenFHE build;
* same relevant link options.

CipherScope should **not** make completeness easier by compiling with artificial settings such as:

```bash
-O0
-fno-inline
```

if the original application uses `-O3`.

That would change the workload being measured.

The point of compiler instrumentation is specifically to preserve the optimized program while inserting observation before compiler transformations erase the semantic boundary.

---

# 8. GCC plugin: the acquisition frontend

The core C++ acquisition mechanism should be a GCC plugin.

Proposed component:

```text
libcipherscope_gcc.so
```

Loaded through the normal GCC plugin mechanism during the shadow build.

The plugin should register an instrumentation pass early enough that supported OpenFHE semantic calls remain identifiable.

Conceptually:

```text
C++ source
   ↓
GCC front end
   ↓
early GIMPLE
   ↓
┌─────────────────────────────┐
│ CipherScope semantic pass   │
└─────────────────────────────┘
   ↓
normal GCC optimizations
   ↓
inlining / IPA / vectorization / etc.
   ↓
machine code
```

The instrumentation pass should **not** perform CipherScope analysis. Its job is only to normalize recognized semantic operations into runtime events.

---

# 9. Semantic operation manifest

A major maintainability requirement is to avoid scattering hard-coded OpenFHE function matching throughout the GCC plugin.

Define a versioned operation manifest, for example:

```text
native/openfhe/openfhe-1.5.operations.yaml
```

Conceptually:

```yaml
version: 1
framework: openfhe
framework_version: "1.5.x"
operations:
  - canonical_name: EvalMult
    kind: crypto_operation
    matches:
      - qualified_function: "lbcrypto::CryptoContextImpl<*>::EvalMult"
    overloads:
      - ct_ct
      - ct_pt
    mutates: false
    input_roles:
      - ciphertext_or_plaintext
      - ciphertext_or_plaintext
    output_roles:
      - ciphertext

  - canonical_name: EvalRotate
    kind: crypto_operation
    mutates: false
    semantic_arguments:
      - rotation_index

  - canonical_name: RescaleInPlace
    kind: crypto_operation
    mutates: true
    mutated_argument: 0
```

The exact matching representation can be refined during implementation, but the architectural principle matters:

> C++ spelling and overload information is frontend metadata; `EvalMult` in the canonical trace is the normalized semantic operation.

This manifest becomes the basis for completeness testing.

---

# 10. Instrument one semantic boundary, not every internal OpenFHE function

A key correctness requirement is to avoid duplicate events.

For example, an application-level operation may internally involve:

```text
operator*
  ↓
CryptoContextImpl::EvalMult
  ↓
Scheme::EvalMult
  ↓
LeveledSHE implementation
```

CipherScope must record **one canonical FHE operation**, not every internal function participating in the implementation.

Choose and document one semantic boundary.

For the GCC/OpenFHE frontend, the recommended initial boundary is the public `CryptoContext` / `CryptoContextImpl` semantic API that corresponds to the operations already understood by the current trace and analyzers.

Therefore:

```cpp
auto z = cc->EvalMult(a, b);
```

should produce:

```text
EvalMult × 1
```

not a stack of duplicated multiplication events.

Likewise, if OpenFHE's overloaded operator form ultimately expresses the same semantic API operation:

```cpp
auto z = a * b;
```

it should normalize to the same trace operation where coverage can be proven:

```json
{
  "operation": "EvalMult"
}
```

---

# 11. Compiler transformation model

Suppose application source contains:

```cpp
auto y = cc->EvalMult(x, w);
```

The GCC pass should conceptually transform the intermediate representation into the equivalent of:

```cpp
cs_token token = cs_before_eval_mult(
    SITE_1042,
    cc,
    x,
    w
);

try {
    auto y = cc->EvalMult(x, w);
    cs_after_eval_mult(token, y);
    return y;
} catch (...) {
    cs_operation_failed(token);
    throw;
}
```

This is conceptual pseudocode, not necessarily the literal ABI.

The implementation must preserve these existing CipherScope properties:

* native OpenFHE operation executes exactly once;
* a tracing failure must not cause the operation to execute twice;
* failed native calls are represented as failed events;
* output state is not fabricated for failed calls;
* tracing should not rewrite application results;
* instrumentation metadata must not expose secret material.

The current architecture document explicitly values the property that the native call is invoked once and analysis failures cannot rewrite history. The native frontend should maintain that invariant.

---

# 12. Native runtime

Proposed component:

```text
libcipherscope_runtime.so
```

The runtime is responsible for efficient dynamic state that cannot be handled statically by the GCC pass.

Its responsibilities should include:

1. run initialization;
2. per-event sequencing;
3. timestamps;
4. thread identifiers;
5. native-object → opaque CipherScope ID mapping;
6. ciphertext versioning;
7. before/after state snapshots;
8. event buffering;
9. truncation limits;
10. crash-safe best-effort spool finalization;
11. coverage counters;
12. run metadata;
13. final raw-trace emission.

It should **not** perform:

* critical path analysis;
* rotation-hoisting analysis;
* parameter analysis;
* key-use interpretation;
* recommendation generation;
* graph construction.

Those remain offline.

---

# 13. Keep the runtime ABI small and stable

Use a small C-compatible ABI between GCC-generated instrumentation and the runtime.

For example, conceptually:

```c
typedef uint64_t cs_event_token;
typedef uint32_t cs_operation_id;
typedef uint32_t cs_site_id;

cs_event_token cs_event_begin(
    cs_operation_id operation,
    cs_site_id site,
    const cs_native_arg* args,
    size_t arg_count
);

void cs_event_success(
    cs_event_token token,
    const cs_native_arg* outputs,
    size_t output_count
);

void cs_event_error(
    cs_event_token token,
    const char* error_class
);
```

The native ABI should not directly expose JSON structures.

Reasons:

* lower instrumentation overhead;
* avoids coupling generated code to schema layout;
* easier versioning;
* easier testing;
* prevents frontend code from implementing its own serializer;
* gives one place to enforce privacy/sanitization rules.

---

# 14. OpenFHE adapter

The runtime needs OpenFHE-specific knowledge to obtain safe semantic metadata from native objects.

Keep that knowledge in a dedicated adapter layer:

```text
libcipherscope_openfhe.so
```

or a corresponding native module.

The separation should be:

```text
GCC plugin
    understands source/GIMPLE call sites and argument positions

OpenFHE adapter
    understands how to inspect supported OpenFHE objects safely

runtime
    understands IDs, versions, sequencing, buffering and run state

trace normalizer
    understands the canonical CipherScope schema
```

The OpenFHE adapter can extract only the fields needed by the canonical trace, for example where available:

* ciphertext level;
* scale/noise-scale degree;
* slot count;
* key tag;
* crypto-context identity;
* scaling technique;
* key-switch technique;
* configured multiplicative depth/context metadata;
* rotation index from the call argument;
* relevant key-generation semantic arguments.

If a field is unavailable, preserve current CipherScope semantics:

```text
unknown / null / missing evidence
```

Do not invent values.

---

# 15. Opaque identity and ciphertext versions

The current Python registry maps Python object identity to opaque IDs such as:

```text
ct_0001:v0
```

The native runtime should preserve exactly this external model.

Internally, it can identify native ciphertext objects through a process-local stable representation suitable for the actual OpenFHE object type. Whatever native identity is used must never be serialized directly.

Conceptually:

```text
native identity
0x7f19...
      │
      ▼
runtime identity table
      │
      ▼
ct_0042
```

The canonical trace contains only:

```text
ct_0042:v0
ct_0042:v1
ct_0042:v2
```

## 15.1 Non-mutating output

```cpp
auto c = cc->EvalMult(a, b);
```

can produce:

```text
ct_0007:v1 ──┐
              ├─ EvalMult ──▶ ct_0019:v0
ct_0012:v0 ──┘
```

## 15.2 In-place operation

```cpp
cc->RescaleInPlace(c);
```

becomes:

```text
ct_0019:v0
      │
    RescaleInPlace
      │
      ▼
ct_0019:v1
```

This preserves the current graph semantics and lets the existing analyzers work unchanged.

## 15.3 Aliasing must be tested explicitly

C++ smart-pointer copies and OpenFHE aliasing behavior must be part of the native feasibility suite.

For example:

```cpp
auto b = a;
```

must not automatically create a new semantic ciphertext if both handles refer to the same underlying native ciphertext.

The native registry needs tests for:

* copy of handle;
* move of handle;
* assignment;
* return from function;
* vector/container storage;
* in-place mutation through an alias;
* destruction and possible allocator address reuse.

Address reuse is particularly important: a raw memory address must not accidentally inherit an older ciphertext ID after the previous object has been destroyed.

---

# 16. Source attribution

Compiler instrumentation gives the C++ frontend a major advantage over runtime binary hooking.

The GCC pass sees source locations associated with the semantic call site.

At compile time, assign each relevant site a stable ID:

```text
site_0001042
```

with a static site table such as:

```json
{
  "site_id": "site_0001042",
  "file": "src/inference.cpp",
  "line": 217,
  "column": 18,
  "function": "run_layer",
  "qualified_function": "model::run_layer"
}
```

At runtime, an event only needs the compact site ID.

This avoids:

* stack walking on every event;
* post-hoc `addr2line` as the primary mechanism;
* dependence on frame pointers;
* source ambiguity introduced by optimization.

The normalizer can expand site IDs into the existing `source` object used by the trace schema.

---

# 17. The canonical trace should be producer-neutral

The current trace schema is already mostly producer-neutral.

It contains fields such as:

* `schema_version`;
* `run`;
* `context`;
* `events`;
* `ciphertexts`;
* operation names;
* input/output ciphertext IDs;
* semantic arguments;
* source information;
* timing;
* before/after state snapshots.

Those are appropriate for both Python and C++.

The main refactor should therefore be **additive**, not a separate C++ schema.

## 17.1 Recommended producer metadata

Add explicit producer/frontend metadata under `run`, for example:

```json
{
  "run": {
    "producer": {
      "frontend": "gcc-openfhe",
      "frontend_version": "0.1.0",
      "instrumentation_manifest": "openfhe-1.5-v1"
    },
    "runtime": {
      "language": "c++",
      "compiler": "gcc",
      "compiler_version": "15.2.0",
      "platform": "linux",
      "architecture": "x86_64"
    }
  }
}
```

For Python, the same location could become:

```json
{
  "producer": {
    "frontend": "python-openfhe",
    "frontend_version": "..."
  }
}
```

No analyzer should need this to understand an `EvalMult`; it is provenance/reproducibility metadata.

## 17.2 Remove Python-specific assumptions from canonical semantics

The current recorder includes `python_thread_id` as an optional event property. That can remain optional for backward compatibility, but canonical analysis should rely on the generic:

```json
"thread_id": 1234
```

and never require `python_thread_id`.

Similarly, runtime metadata should evolve from assuming Python is the only runtime to representing language/frontend-specific metadata under optional fields.

---

# 18. Two-stage native trace generation

Do **not** make every C++ event directly append a full JSON object.

A better path is:

```text
instrumented application
        ↓
compact native event records
        ↓
raw spool
        ↓
trace finalizer / normalizer
        ↓
canonical trace.json
        ↓
existing `cipherscope analyze`
```

## 18.1 Runtime spool

For performance, use a compact internal format with records such as:

```text
EVENT_BEGIN
  sequence
  operation_id
  site_id
  native-object handles
  timestamp

EVENT_END
  output handles
  state metadata
  duration
```

The spool is an implementation detail and is **not a public research artifact contract**.

The only public contract is the finalized canonical trace.

## 18.2 Why this matters

It prevents the following bad coupling:

```text
GCC plugin → JSON schema internals
```

Instead:

```text
GCC plugin → stable native ABI → runtime record
                                   ↓
                              normalizer
                                   ↓
                              trace schema
```

Schema evolution then does not require injecting complicated JSON code into every target application.

---

# 19. Threading and event ordering

C++ workloads may be more heavily multi-threaded than the existing Python path.

The runtime should therefore explicitly support concurrent event recording.

Recommended design:

```text
thread 1 → thread-local buffer ─┐
thread 2 → thread-local buffer ─┼→ final merge
thread 3 → thread-local buffer ─┘
```

Each event receives:

* a globally unique event ID;
* a process-wide sequence/order token where meaningful;
* a native thread ID;
* monotonic timestamps.

Do not assume total program order implies causal order between threads.

For the initial OpenFHE evaluation, if OpenFHE semantic operations are invoked concurrently, the trace format should preserve enough information to distinguish:

```text
trace serialization order
```

from:

```text
actual overlapping execution
```

The existing timing representation can continue to use `start_ns` and duration.

---

# 20. Completeness and coverage in the C++ frontend

The updated repository already treats coverage seriously and classifies runs as:

```text
COMPLETE
PARTIAL-PERMISSIVE
UNSUPPORTED
```

The C++ implementation should integrate into this model rather than create a separate notion of completeness.

However, the evidence used to establish C++ completeness differs from the Python proxy model.

## 20.1 C++ COMPLETE should require all of the following

At minimum:

1. target was built with the supported CipherScope GCC plugin;
2. plugin version is recorded;
3. compiler/version is supported;
4. OpenFHE/version is supported;
5. operation manifest is supported;
6. instrumentation did not report unmatched candidate OpenFHE semantic calls;
7. no runtime truncation occurred;
8. native state reads required by a rule did not silently fail;
9. target executed the instrumented binary, not the original one;
10. the emitted trace validates against the canonical schema.

## 20.2 Instrumentation coverage counters

Add C++-appropriate fields such as:

```json
{
  "coverage": {
    "strict": true,
    "traced_semantic_calls": 18421,
    "unsupported_operations": [],
    "unmatched_openfhe_candidates": 0,
    "instrumented_translation_units": 37,
    "expected_translation_units": 37,
    "instrumentation_manifest": "openfhe-1.5-v1",
    "truncated": false
  }
}
```

The current Python-specific fields can remain optional but should no longer be globally required as the only completeness evidence.

## 20.3 Fail closed

If the compiler pass sees something that looks like a relevant OpenFHE semantic operation but cannot classify it under strict mode, the build or run should be marked unsupported/incomplete.

Do not silently emit a complete-looking trace.

This matches the research discipline already present in the current project.

---

# 21. Instrumented-binary marker

Every shadow binary should contain a small metadata marker indicating that it was compiled with CipherScope instrumentation.

For ELF, one option is a dedicated note/section conceptually containing:

```text
cipherscope.instrumented = true
frontend = gcc-openfhe
frontend_version = 0.1.0
schema_major = 1
operation_manifest = openfhe-1.5-v1
build_fingerprint = ...
```

Then:

```bash
cipherscope profile ./build/my_program
```

can distinguish:

### Already instrumented

```text
TARGET
  ↓
verify marker
  ↓
execute directly
```

### Normal binary with reproducible build metadata

```text
TARGET
  ↓
discover CMake/build metadata
  ↓
create/reuse shadow build
  ↓
execute shadow target
```

### Opaque unsupported binary

```text
TARGET
  ↓
no marker
no safe build metadata
  ↓
UNSUPPORTED for complete semantic tracing
```

---

# 22. Target-to-shadow-target mapping

One practical difficulty is determining which CMake target produced the binary passed to `profile`.

The first implementation should support CMake projects and establish the mapping using a combination of:

* target binary path;
* CMake-generated metadata;
* link command files where available;
* build system target queries;
* `compile_commands.json` translation units;
* optional explicit `--cmake-target TARGET` escape hatch.

Desired normal case:

```bash
cipherscope profile ./build/bin/prs
```

Fallback:

```bash
cipherscope profile ./build/bin/prs --cmake-target prs
```

The fallback does not alter source and therefore remains compatible with the zero-code-change goal.

---

# 23. Proposed CLI refactor

The current repository has a Python-oriented command:

```bash
cipherscope run script.py ...
```

and an independent:

```bash
cipherscope analyze trace.json ...
```

A cleaner long-term CLI is:

```text
cipherscope profile TARGET
cipherscope analyze TRACE
cipherscope validate BUNDLE
cipherscope view BUNDLE
...
```

`profile` chooses a producer based on the target/build:

```text
.py target
   ↓
Python producer

ELF C++ target + CMake/GCC support
   ↓
GCC/OpenFHE producer
```

For backward compatibility:

```bash
cipherscope run foo.py
```

can remain as an alias/specialized command.

The important point is that `profile` returns the same kind of bundle regardless of frontend.

---

# 24. Proposed native repository layout

A concrete layout could be:

```text
cipherscope/
├── schemas/
│   └── trace.schema.json
│
├── src/cipherscope/
│   ├── pipeline.py
│   ├── graph.py
│   ├── analyzers/
│   ├── validation.py
│   ├── native_profile.py
│   └── build_discovery.py
│
├── native/
│   ├── CMakeLists.txt
│   │
│   ├── include/cipherscope/
│   │   ├── runtime.h
│   │   ├── event.h
│   │   └── version.h
│   │
│   ├── gcc/
│   │   ├── plugin.cpp
│   │   ├── semantic_pass.cpp
│   │   ├── call_matcher.cpp
│   │   └── site_table.cpp
│   │
│   ├── runtime/
│   │   ├── runtime.cpp
│   │   ├── registry.cpp
│   │   ├── buffer.cpp
│   │   ├── timing.cpp
│   │   └── spool.cpp
│   │
│   ├── openfhe/
│   │   ├── adapter.cpp
│   │   ├── state_reader.cpp
│   │   └── operation_manifest.yaml
│   │
│   └── tools/
│       └── trace_finalize.cpp
│
└── tests/
    └── cpp/
        ├── fixtures/
        ├── integration/
        ├── aliasing/
        ├── coverage/
        └── equivalence/
```

An alternative is to implement final normalization in Python. That is likely simpler initially because schema validation/export already lives there:

```text
native binary → raw native spool → Python normalizer → canonical trace
```

This is a good first implementation.

---

# 25. Normalizer responsibilities

Create one component, for example:

```text
src/cipherscope/native_trace.py
```

that turns native runtime data into the exact canonical document consumed by `pipeline.py`.

Responsibilities:

* parse native spool;
* expand operation IDs to canonical operation strings;
* expand site IDs to source objects;
* convert native runtime IDs to canonical ciphertext version IDs;
* convert state snapshots;
* build `run.runtime` and producer metadata;
* build `run.coverage`;
* populate context metadata;
* preserve truncation information;
* emit strict JSON;
* validate through existing `validate_trace` before analysis.

The normalizer must not run analyzers.

---

# 26. Example canonical event from C++

A native C++ call:

```cpp
auto z = cc->EvalMult(x, y);
```

should ultimately produce an event structurally indistinguishable from a Python-produced event:

```json
{
  "event_id": "evt_000184",
  "sequence": 184,
  "kind": "crypto_operation",
  "operation": "EvalMult",
  "overload": "ct_ct",
  "status": "ok",
  "source": {
    "file": "src/model.cpp",
    "line": 217,
    "function": "run_layer",
    "qualified_function": "model::run_layer",
    "call_site_id": "site_0001042"
  },
  "input_ciphertexts": [
    "ct_0007:v1",
    "ct_0012:v0"
  ],
  "output_ciphertexts": [
    "ct_0019:v0"
  ],
  "operand_kinds": [
    "ciphertext",
    "ciphertext"
  ],
  "timing": {
    "start_ns": 92741994001,
    "wall_duration_ns": 8132147,
    "process_cpu_duration_ns": 8091000,
    "thread_cpu_duration_ns": 8084000
  },
  "input_states": [
    {
      "id": "ct_0007:v1",
      "level": 2,
      "noise_scale_degree": 1,
      "scale": null,
      "slots": 8192,
      "context_id": "ctx_0001",
      "key_tag": "key_0001",
      "scaling_technique": "FLEXIBLEAUTO",
      "key_switch_technique": "HYBRID"
    },
    {
      "id": "ct_0012:v0",
      "level": 2,
      "noise_scale_degree": 1,
      "scale": null,
      "slots": 8192,
      "context_id": "ctx_0001",
      "key_tag": "key_0001",
      "scaling_technique": "FLEXIBLEAUTO",
      "key_switch_technique": "HYBRID"
    }
  ],
  "output_states": [
    {
      "id": "ct_0019:v0",
      "level": 2,
      "noise_scale_degree": 2,
      "scale": null,
      "slots": 8192,
      "context_id": "ctx_0001",
      "key_tag": "key_0001",
      "scaling_technique": "FLEXIBLEAUTO",
      "key_switch_technique": "HYBRID"
    }
  ],
  "semantic_arguments": {},
  "thread_id": 18438,
  "missing": []
}
```

The values above are illustrative. The important property is structural compatibility.

`graph.py` and the analyzers should not care whether this event originated in Python or C++.

---

# 27. Context creation and setup events

The current Python tracer can attach to a live `CryptoContext` and obtain context metadata.

The C++ frontend needs equivalent handling for setup operations.

Support at least:

* context generation;
* PKE enablement where relevant to semantics;
* key generation;
* multiplication/relinearization key generation;
* rotation key generation;
* bootstrap setup/key generation where applicable;
* plaintext construction/encoding where analyzers depend on it;
* encrypt/decrypt.

The key principle is that the canonical trace should continue to distinguish operational kinds such as:

```text
setup
key_generation
crypto_operation
checkpoint
annotation
resource_sample
```

where these already have meaning in the current system.

---

# 28. Checkpoint / precision functionality

The existing precision analyzer can rely on explicit checkpoints and optional shadow behavior in Python.

This feature cannot simply be assumed to transfer transparently to arbitrary C++ applications because a checkpoint is a user-declared semantic contract.

For the first C++ version:

* preserve all analyzers that depend only on observable OpenFHE operations/state;
* mark checkpoint-dependent precision/tolerance rules as `not_applicable` when no equivalent evidence exists;
* do not fake C++ checkpoints.

A later C++ API could add optional checkpoint annotations, but that would violate the strict zero-code-change goal if required. Therefore checkpoints should not be necessary for **core C++ completeness**.

This is an example of why analyzer applicability should continue to be evidence-based rather than language-specific.

---

# 29. What should work unchanged after trace emission

Once the C++ trace validates, the following current components should work without a C++ fork:

```text
validation.py
pipeline.py
graph.py
analyzers/depth.py
analyzers/keys.py
analyzers/rotations.py
analyzers/bootstrap.py
analyzers/parameters.py
analyzers/packing.py
analyzers/encoding.py
analyzers/provenance.py
analyzers/serial_reduction.py
exporters/*
```

Some analyzers may return `not_applicable` if the C++ producer cannot provide the evidence they require. That is correct behavior.

The engineering test should be:

> If an equivalent Python and C++ program produces semantically equivalent traces, `build_analysis_bundle()` produces equivalent graph/analyzer conclusions modulo source IDs, timing, and frontend provenance.

---

# 30. Native security/privacy requirements

The current trace security philosophy should apply unchanged.

Never record:

* ciphertext coefficient arrays;
* plaintext values by default;
* secret-key material;
* private-key contents;
* evaluation-key contents;
* raw native pointers;
* arbitrary application memory;
* command-line secrets unless explicitly allowed/sanitized.

Potentially sensitive but necessary metadata remains explicit:

* operation sequence;
* timing;
* source paths/lines;
* rotation indices;
* ciphertext lineage;
* levels/scales;
* key tags represented opaquely;
* bootstrap placement.

Use opaque IDs such as:

```text
ctx_0001
key_0001
ct_0042:v3
```

rather than native identities.

Native exception/error messages should receive the same sanitation treatment as Python-side errors before entering a trace.

---

# 31. Runtime overhead strategy

FHE calls are expensive, which gives some budget for tracing, but the runtime should still be designed efficiently.

Avoid:

```text
one JSON serialization + file flush per Eval* call
```

Use:

```text
semantic call
   ↓
small fixed/variable binary record
   ↓
thread-local buffer
   ↓
batched append to spool
```

State reads should be restricted to the metadata required by the canonical trace/analyzers.

Measure tracing overhead separately for:

* instrumentation with timing only;
* identity/version tracking;
* FHE state metadata;
* full trace;

This also maps naturally to the updated repository's semantic ablation philosophy.

---

# 32. Truncation behavior

The current recorder already has strong semantics for:

* `max_events`;
* `max_trace_bytes`;
* truncation reason;
* calls dropped after the limit;
* preserving resolvable references within the retained trace.

The native runtime should implement the same contract.

After a hard limit:

```text
FHE application continues normally
trace recorder stops accepting semantic records
calls are counted as dropped
trace marked truncated
coverage != COMPLETE
```

Never terminate the target merely because the profiler reached a trace limit unless the user explicitly requests fail-fast behavior.

---

# 33. Failure semantics

A robust instrumented call must handle three categories separately.

## 33.1 OpenFHE operation succeeds

```text
begin
native operation
success record
```

## 33.2 OpenFHE operation throws

```text
begin
native operation throws
error record
rethrow original exception
```

CipherScope should not swallow or replace the application's exception.

## 33.3 CipherScope recorder itself fails

The design must define a safe policy.

For research profiling, the preferred behavior is:

* never re-execute the OpenFHE operation;
* mark recording failure/incomplete when possible;
* allow target behavior to remain as close as possible to uninstrumented execution;
* mark run `failed` or `incomplete` rather than emit apparently complete evidence.

---

# 34. Build and execution reproducibility metadata

The native trace/bundle should record enough information to reproduce the instrumented build:

```text
GCC executable path
GCC version
CMake version
CMake generator
source root
normal build root
shadow build root or fingerprint
original target path
instrumented target path
CMake target
build type
important compile flags hash
OpenFHE version
OpenFHE location/build ID where available
CipherScope native plugin version
operation manifest version
trace schema version
```

Do not serialize the entire environment indiscriminately because it may contain secrets.

---

# 35. GCC version support policy

Do not initially claim arbitrary GCC compatibility.

Choose one exact supported baseline for the paper artifact, for example:

```text
Linux x86-64
GCC X.Y
CMake-supported project
OpenFHE 1.5.x
```

Then add an explicit compatibility matrix as versions are tested.

Example:

| Component | Version | Status                       |
| --------- | ------: | ---------------------------- |
| GCC       |    13.x | supported                    |
| GCC       |    14.x | tested/supported             |
| GCC       |    15.x | experimental until validated |
| OpenFHE   |   1.5.0 | supported                    |
| OpenFHE   |   1.5.1 | supported after gate         |

The actual versions should reflect what is really tested, not this illustrative table.

GCC's plugin internals are not a forever-stable compiler ABI, so explicit version gating is a strength, not a weakness.

---

# 36. Minimum operation coverage for C++ v1

The first complete C++ frontend should cover at least every operation required by the current central analyzers and common OpenFHE CKKS programs.

Suggested initial set:

### Core

```text
Encrypt
Decrypt
EvalAdd
EvalAddInPlace
EvalSub
EvalSubInPlace
EvalNegate
EvalNegateInPlace
EvalMult
EvalMultNoRelin
EvalSquare
EvalSquareInPlace
Relinearize
RelinearizeInPlace
Rescale
RescaleInPlace
ModReduce
ModReduceInPlace
```

### Rotation/reduction

```text
EvalRotate
EvalFastRotationPrecompute
EvalFastRotation
EvalSum
EvalInnerProduct
```

### Polynomial/nonlinear helper APIs

```text
EvalPoly
EvalChebyshevFunction
```

### Bootstrap

```text
EvalBootstrap
```

### Key/setup events needed by current rules

```text
KeyGen
EvalMultKeyGen
EvalRotateKeyGen
bootstrap key/setup APIs as required
```

### Plaintext/encoding evidence

Whatever public API calls are necessary to support current encoding/provenance/packing rules conservatively.

Do not declare C++ COMPLETE until every operation in the supported manifest has a tested classification path and unsupported semantic calls cannot silently bypass the profiler.

---

# 37. Testing strategy

The native extension needs a dedicated test program corpus rather than only unit tests of the compiler pass.

## 37.1 Compiler transformation tests

For each supported operation:

```text
input source
  ↓
compile with plugin
  ↓
inspect instrumentation manifest / trace
  ↓
exactly one expected canonical event
```

Test overloads separately.

## 37.2 Native equivalence tests

Run:

```text
normal binary
vs
instrumented shadow binary
```

and verify:

* same exit status;
* equivalent decrypted outputs within CKKS tolerance;
* same exceptions for negative tests;
* same externally visible control result where deterministic;
* no additional FHE operation execution.

## 37.3 Identity/alias tests

Explicit tests for:

* handle copies;
* moves;
* aliases;
* vectors/containers;
* function parameter passing;
* function returns;
* in-place mutation;
* address reuse after destruction.

## 37.4 Source attribution tests

Verify exact:

```text
file
line
function
call_site_id
```

for calls under at least:

```text
-O0
-O2
-O3
```

## 37.5 Coverage tests

Construct a fixture for every operation in the manifest and prove:

```text
expected executed semantic calls == traced semantic calls
```

Also include an intentionally unsupported OpenFHE call and prove strict mode refuses `COMPLETE` classification.

## 37.6 Cross-language semantic parity

Where Python and C++ implementations of the same FHE workload can be written, compare normalized traces.

Ignore:

* absolute event IDs;
* timestamps;
* source paths;
* language-specific runtime metadata.

Compare:

* operation sequence/partial order;
* operand kinds;
* lineage shape;
* levels;
* rotation indices;
* bootstrap epochs;
* analyzer conclusions.

This is a strong validation of the new language-neutral trace architecture.

---

# 38. End-to-end C++ feasibility gate

Before claiming C++ support, require a gate analogous in spirit to the current real-OpenFHE Python feasibility work.

Suggested gate categories:

1. build discovery from `CMakeCache.txt`;
2. `compile_commands.json` reproduction;
3. GCC plugin loads correctly;
4. exact operation interception;
5. overloaded functions;
6. operator forms where supported;
7. source location capture;
8. ciphertext identity;
9. aliases;
10. in-place mutations;
11. level/state getters;
12. rotations;
13. fast rotations;
14. key-generation events;
15. bootstrap;
16. exceptions;
17. multi-threading;
18. trace limits/truncation;
19. native-vs-instrumented numerical equivalence;
20. canonical trace validation;
21. existing graph pipeline succeeds;
22. existing analyzers execute unchanged;
23. run bundle validates.

The result should be a machine-readable artifact, not just a README statement.

---

# 39. Concrete implementation phases

## Phase 0 — Refactor trace ownership

Before writing the GCC plugin:

### Task 0.1

Make the trace schema explicitly frontend-neutral.

### Task 0.2

Add `run.producer` metadata.

### Task 0.3

Remove any analyzer dependence on Python-only fields.

### Task 0.4

Add tests that `cipherscope analyze` can consume hand-built producer-neutral traces.

### Exit criterion

A valid canonical trace can be produced without constructing a Python `Session`/`Recorder`, and the full existing graph/analyzer/export path succeeds.

---

## Phase 1 — Minimal native runtime

Implement:

```text
native runtime initialization
site table loading
opaque object registry
versioning
monotonic event IDs
wall timing
single-thread event buffer
raw spool
normalizer → trace.json
```

Do not support all OpenFHE calls yet.

### Exit criterion

A synthetic native fixture can emit a valid CipherScope trace without importing OpenFHE.

---

## Phase 2 — GCC semantic pass POC

Recognize only:

```text
Encrypt
Decrypt
EvalAdd
EvalMult
EvalRotate
Rescale
```

Insert begin/end hooks.

### Exit criterion

An unchanged OpenFHE C++ example compiles and produces the expected canonical trace.

---

## Phase 3 — OpenFHE state adapter

Add:

```text
ciphertext ID
level
scale/noise-scale degree
slots/context/key metadata
in-place version transitions
```

### Exit criterion

Current depth/rotation/parameter graph logic operates on a C++ trace unchanged.

---

## Phase 4 — Complete semantic manifest

Expand to the full supported operation set.

Add strict unmatched-call detection.

### Exit criterion

Every operation declared supported has:

* fixture;
* instrumentation test;
* trace contract test;
* negative/exception behavior where applicable.

---

## Phase 5 — CMake transparent shadow build

Implement:

```text
CMakeCache discovery
compile_commands discovery
source/build root resolution
CMake target mapping
shadow directory
plugin injection
build fingerprint/cache
```

### Exit criterion

Given a supported normal CMake/OpenFHE build:

```bash
cipherscope profile ./build/app
```

works without source modification or manually rebuilding the target.

---

## Phase 6 — Coverage classification integration

Extend the current coverage model to use native frontend evidence.

### Exit criterion

A C++ run can be objectively classified as:

```text
COMPLETE
PARTIAL-PERMISSIVE
UNSUPPORTED
```

using recorded build/instrumentation evidence.

---

## Phase 7 — Performance and multi-threading

Add thread-local buffers and batch spool writes.

Measure overhead.

### Exit criterion

Profiling overhead is characterized on real OpenFHE C++ workloads and does not invalidate measurements.

---

# 40. Proposed `profile` flow in detail

Pseudo-algorithm:

```text
profile(target, argv):

    target = resolve(target)

    if has_valid_cipherscope_marker(target):
        instrumented = target
        build_metadata = read_marker(target)

    else:
        build = discover_build(target)

        if build is not safely reproducible:
            fail UNSUPPORTED

        assert build.compiler == GCC-supported
        assert build.framework == OpenFHE-supported

        fingerprint = compute_instrumented_build_fingerprint(build)
        shadow_dir = cache/fingerprint

        if cached shadow target valid:
            instrumented = cached target
        else:
            configure shadow build
            inject GCC plugin flags
            inject/link runtime + OpenFHE adapter
            compile requested CMake target
            verify instrumented marker
            instrumented = shadow target

    create run directory/temp spool

    execute instrumented with original argv/environment policy

    finalize native spool
    normalize to canonical trace
    validate canonical trace

    classify acquisition completeness

    call existing build_analysis_bundle(trace)
    call existing exporters

    return target exit code / profiler status according to policy
```

---

# 41. Compiler flag injection

For a CMake shadow build, plugin loading should be added transparently to C++ compilation commands.

Conceptually:

```text
-fplugin=/path/to/libcipherscope_gcc.so
-fplugin-arg-cipherscope-...
```

and the final target must link/load the CipherScope runtime as required.

Do not edit the project's checked-in `CMakeLists.txt`.

Prefer one of:

* CMake cache/toolchain-level flag injection in the isolated shadow configuration;
* compiler launcher/wrapper that delegates to the real GCC with additional plugin options;
* CMake-supported per-build configuration mechanisms.

A compiler wrapper is attractive for initial engineering because it can preserve the original compile command while appending the plugin flag:

```text
original:
/usr/bin/g++ ARGS...

shadow:
cipherscope-g++ ARGS...

wrapper executes:
/usr/bin/g++ -fplugin=... ARGS...
```

The wrapper must be transparent and deterministic; it should not parse/reinvent all GCC options.

---

# 42. Why not `LD_PRELOAD` as the primary solution

`LD_PRELOAD` is insufficient for the completeness goal because C++/OpenFHE calls may be:

* inline;
* templates;
* statically linked;
* optimized away as independent symbols;
* invoked through paths that do not cross an interposable dynamic symbol.

It could be a debugging fallback someday, but it should not underpin the paper's claim of complete semantic observation.

The GCC plugin gives CipherScope visibility **before** optimization destroys the API-level semantic site.

---

# 43. Why not patch OpenFHE itself

Another possible solution is to maintain a CipherScope-patched OpenFHE build.

That can capture operations, but it is inferior as the main architecture because:

* users must substitute a framework build;
* it complicates artifact deployment;
* source attribution points into OpenFHE unless extra machinery is added;
* it couples tracing to the library implementation;
* OpenFHE upgrades require patch maintenance;
* it weakens the general “transparent observability frontend” abstraction.

A GCC semantic pass observing the user application's API call sites gives a cleaner boundary.

OpenFHE-specific metadata extraction still belongs in the adapter, not in a fork of the entire framework.

---

# 44. Why this is stronger scientifically than the current Python-only architecture

The current Python path is based on proxy/runtime attachment semantics. Its coverage logic must account for bypasses such as raw context references or operations that do not pass through the traced proxy.

A successful GCC frontend changes the claim from:

> CipherScope wraps OpenFHE Python calls and analyzes the resulting trace.

into:

> CipherScope defines a language-neutral semantic execution trace for FHE programs and provides transparent frontends that emit this representation.

Even if the paper initially evaluates only Python and GCC/C++, the architecture becomes much more defensible:

```text
OpenFHE Python frontend ─┐
                         ├─ canonical FHE execution trace ─ analyzers
OpenFHE GCC/C++ frontend ┘
```

More importantly, the analysis layer becomes independently testable from instrumentation.

---

# 45. Conference-facing claims that become possible

If fully implemented and evaluated, reasonable claims include:

### Claim A — Zero source modification

For supported CMake/GCC/OpenFHE applications, CipherScope profiles native C++ programs without modifying application source.

### Claim B — Semantic completeness under an explicit support contract

For the supported compiler/framework/operation manifest, every executed supported OpenFHE semantic operation at the designated boundary is represented in the trace, unless the run is explicitly marked incomplete/truncated.

### Claim C — Language-neutral analysis

Python and C++ traces use the same schema, graph builder, analyzers, and exporters.

### Claim D — Optimization-preserving instrumentation

CipherScope does not require disabling normal GCC optimization merely to keep hookable function boundaries.

### Claim E — Auditable coverage

Completeness is an explicit property backed by compiler/build/runtime evidence, not assumed from successful execution.

These are stronger claims than “we also have a C++ wrapper.”

---

# 46. Things the first C++ implementation should explicitly NOT claim

Do not claim:

```text
supports arbitrary C++ binaries
supports all GCC versions
supports all OpenFHE versions
supports every OpenFHE operation
supports statically unreproducible third-party binaries
supports source-free profiling with completeness
supports Clang/MSVC
```

Instead define a precise supported envelope and expand it only after testing.

---

# 47. Recommended changes to the existing trace schema

Keep schema evolution minimal.

## Required/additional recommended metadata

Add or standardize:

```text
run.producer.frontend
run.producer.frontend_version
run.producer.instrumentation_manifest
run.runtime.language
run.runtime.compiler
run.runtime.compiler_version
run.runtime.framework
run.runtime.framework_version
```

Add native coverage evidence as optional fields under:

```text
run.coverage
```

Potential fields:

```text
instrumented_translation_units
expected_translation_units
unmatched_openfhe_candidates
instrumentation_manifest
instrumented_binary_verified
```

Keep current semantic event fields.

Do not create:

```text
trace-cpp.schema.json
```

unless an unavoidable semantic difference is discovered. The goal is one canonical trace.

---

# 48. Recommended refactor of current Python metadata

The current `Recorder.to_trace()` builds runtime metadata around Python, including:

```text
runtime.python
backend
backend_representation
```

Refactor toward:

```json
{
  "runtime": {
    "language": "python",
    "language_version": "3.12.x",
    "platform": "linux",
    "architecture": "x86_64",
    "framework": "openfhe",
    "framework_version": "..."
  },
  "producer": {
    "frontend": "python-openfhe",
    "frontend_version": "..."
  }
}
```

while retaining old optional keys during schema transition if needed.

Then the C++ runtime naturally writes:

```json
{
  "runtime": {
    "language": "c++",
    "compiler": "gcc",
    "compiler_version": "...",
    "platform": "linux",
    "architecture": "x86_64",
    "framework": "openfhe",
    "framework_version": "..."
  },
  "producer": {
    "frontend": "gcc-openfhe",
    "frontend_version": "..."
  }
}
```

Again, analyzers ignore these differences.

---

# 49. Build discovery module design

Implement a Python module such as:

```text
src/cipherscope/build_discovery.py
```

with data structures conceptually like:

```python
@dataclass(frozen=True)
class CMakeBuild:
    source_root: Path
    build_root: Path
    cache_path: Path
    compile_commands_path: Path | None
    compiler: Path
    compiler_version: str
    generator: str
    build_type: str | None

@dataclass(frozen=True)
class NativeTarget:
    binary: Path
    cmake_target: str
    build: CMakeBuild
```

Core functions:

```python
discover_cmake_build(binary: Path) -> CMakeBuild | None
resolve_cmake_target(binary: Path, build: CMakeBuild) -> NativeTarget
create_shadow_build(target: NativeTarget, config: ...) -> InstrumentedTarget
```

This keeps build-system logic out of `cli.py`.

---

# 50. Native profile orchestration module

Create:

```text
src/cipherscope/native_profile.py
```

Responsibilities:

```text
verify instrumented marker
build discovery
shadow build caching
launch target
collect raw spool
normalize trace
call common pipeline
write bundle
```

This module should end by passing a plain Python mapping representing the canonical trace to:

```python
build_analysis_bundle(trace)
```

That one call is the proof that acquisition remains decoupled.

---

# 51. Reuse existing bundle/export structure

The C++ frontend should produce the same final bundle shape as Python:

```text
run-directory/
├── manifest.json
├── trace.json
├── ciphertext_graph.json
├── recommendations.json
├── operations.csv
├── perfetto-trace.json
├── summary.html
└── schemas/
```

Do not create a separate C++ report format.

A reviewer should be able to compare Python and C++ runs without learning two artifact layouts.

---

# 52. End-to-end example

User project:

```text
~/fhe-logreg/
├── CMakeLists.txt
├── src/main.cpp
└── build/
    ├── CMakeCache.txt
    ├── compile_commands.json
    └── logreg
```

User executes:

```bash
cd ~/fhe-logreg
cipherscope profile ./build/logreg -- --epochs 10
```

Internally:

```text
1. Resolve ./build/logreg
2. No CipherScope ELF marker found
3. Find ./build/CMakeCache.txt
4. Read CMAKE_HOME_DIRECTORY = ~/fhe-logreg
5. Read ./build/compile_commands.json
6. Verify compiler = supported GCC
7. Detect/link supported OpenFHE
8. Resolve `logreg` CMake target
9. Compute build fingerprint
10. Create/reuse .cipherscope/builds/<hash>/
11. Configure equivalent shadow build
12. Inject CipherScope GCC plugin/runtime
13. Build target `logreg`
14. Verify instrumented marker
15. Run shadow binary with `--epochs 10`
16. Native runtime writes raw semantic spool
17. Normalizer emits canonical trace.json
18. `validate_trace(trace)`
19. coverage classifier proves/denies COMPLETE
20. `build_analysis_bundle(trace)`
21. existing exporters create normal bundle
22. return target status and report location
```

To the user, the source never changed.

---

# 53. Example CLI output

```text
$ cipherscope profile ./build/logreg -- --epochs 10

CipherScope
Target:        ./build/logreg
Frontend:      GCC/OpenFHE
Compiler:      GCC 14.x
Build:         CMake

Discovering build configuration ... ok
Creating instrumented shadow target ... ok
Instrumentation manifest ............. openfhe-1.5-v1
Running target ......................... ok
Finalizing semantic trace ............. ok
Trace validation ....................... ok
Coverage ............................... COMPLETE

Semantic calls:        18,421
Ciphertext versions:    2,104
Threads observed:           4
Truncated:                 no

Findings:                  11

Bundle:
.cipherscope/runs/<run-id>/
```

If build metadata is unavailable:

```text
$ cipherscope profile ./downloaded_binary

CipherScope cannot establish complete semantic tracing for this target.

Reason:
  Binary is not CipherScope-instrumented and no supported reproducible
  GCC/CMake build metadata was found.

Coverage: UNSUPPORTED

No analysis-quality bundle was produced.
```

This is preferable to silently producing partial evidence.

---

# 54. MVP acceptance criteria

The GCC/C++ feature should not be called complete until all of the following are true.

## Transparency

* [ ] No source edits required.
* [ ] Existing CMake target remains unchanged.
* [ ] Normal binary remains untouched.
* [ ] `cipherscope profile ./build/app` creates/reuses an isolated shadow target.

## Acquisition

* [ ] GCC plugin observes every supported operation in the manifest.
* [ ] Each semantic operation is emitted exactly once.
* [ ] In-place operations create correct versions.
* [ ] aliases behave correctly.
* [ ] source locations refer to user call sites.
* [ ] failed calls preserve application exception behavior.

## Trace boundary

* [ ] C++ produces the same `trace.schema.json` contract as Python.
* [ ] No C++-only graph schema exists.
* [ ] No C++-only analyzer exists.
* [ ] existing `validate_trace` accepts the output.

## Analysis

* [ ] existing `build_graph` runs unchanged.
* [ ] existing analyzers run unchanged where evidence exists.
* [ ] missing evidence results in `not_applicable`, not fabricated conclusions.
* [ ] existing exporters generate a normal bundle.

## Completeness

* [ ] supported GCC versions are explicitly listed.
* [ ] supported OpenFHE versions are explicitly listed.
* [ ] operation manifest is versioned.
* [ ] unmatched candidates prevent COMPLETE status.
* [ ] truncation prevents COMPLETE status.
* [ ] native feasibility gate passes.

## Equivalence

* [ ] instrumented and uninstrumented targets produce equivalent FHE results.
* [ ] instrumentation does not execute semantic operations twice.
* [ ] cross-language equivalent fixtures yield equivalent graph/analyzer semantics.

---

# 55. Suggested implementation priority

If the goal is the conference version, do this in the following order:

```text
P0.1  Formalize frontend-neutral Trace Schema
P0.2  Add run.producer / runtime language metadata
P0.3  Prove analysis pipeline consumes producer-neutral traces

P0.4  Build tiny native runtime + spool
P0.5  Build trace normalizer
P0.6  GCC plugin for six core operations
P0.7  OpenFHE state adapter
P0.8  identity/version/alias correctness

P0.9  Full supported operation manifest
P0.10 strict unmatched-call handling
P0.11 native feasibility/equivalence suite

P0.12 CMakeCache + compile_commands discovery
P0.13 isolated shadow build
P0.14 `cipherscope profile BINARY`
P0.15 native coverage classification

P1.1  thread-local buffering
P1.2  native overhead experiment
P1.3  cross-language semantic parity experiment
P1.4  real external C++ workload evaluation
```

Do **not** spend the first iteration implementing every analyzer-specific feature before the architecture above works end-to-end.

The first important milestone is:

```text
unchanged C++ source
      ↓
GCC shadow build
      ↓
canonical trace
      ↓
existing Python graph + analyzer
```

Once that works, breadth is incremental.

---

# 56. Key design decisions summary

| Question                                          | Decision                                         |
| ------------------------------------------------- | ------------------------------------------------ |
| Modify user C++ source?                           | **No**                                           |
| Require CipherScope macros?                       | **No**                                           |
| Main instrumentation mechanism?                   | **GCC plugin / GIMPLE semantic instrumentation** |
| Use `LD_PRELOAD` for completeness?                | **No**                                           |
| Patch OpenFHE as main strategy?                   | **No**                                           |
| Analyze inside the GCC plugin?                    | **No**                                           |
| Analyze inside native runtime?                    | **No**                                           |
| Separate C++ trace schema?                        | **No**                                           |
| Canonical boundary?                               | **`trace.schema.json`**                          |
| Existing Python analyzers reused?                 | **Yes**                                          |
| Existing graph builder reused?                    | **Yes**                                          |
| Existing exporters reused?                        | **Yes**                                          |
| Preserve optimized GCC build?                     | **Yes**                                          |
| Main build system for first version?              | **CMake**                                        |
| Primary discovery metadata?                       | **`CMakeCache.txt` + `compile_commands.json`**   |
| Modify original build tree?                       | **No; use shadow build**                         |
| Arbitrary source-free binary guaranteed complete? | **No**                                           |
| Incomplete run presented as complete?             | **Never**                                        |

---

# 57. Final proposed architecture

```text
                                  USER
                                   │
                    cipherscope profile ./build/app
                                   │
                                   ▼
                     ┌────────────────────────┐
                     │ Native profile driver  │
                     └────────────┬───────────┘
                                  │
                    already instrumented?
                     │                         │
                    yes                       no
                     │                         │
                     │              ┌──────────▼──────────┐
                     │              │ Build discovery     │
                     │              │ CMakeCache.txt      │
                     │              │ compile_commands    │
                     │              └──────────┬──────────┘
                     │                         │
                     │              ┌──────────▼──────────┐
                     │              │ Isolated shadow     │
                     │              │ CMake/GCC build     │
                     │              └──────────┬──────────┘
                     │                         │
                     │              ┌──────────▼──────────┐
                     │              │ GCC semantic plugin │
                     │              └──────────┬──────────┘
                     │                         │
                     │              ┌──────────▼──────────┐
                     │              │ OpenFHE adapter     │
                     │              └──────────┬──────────┘
                     │                         │
                     └───────────────┬─────────┘
                                     ▼
                         ┌────────────────────┐
                         │ Native runtime     │
                         │ IDs / versions     │
                         │ timing / buffering │
                         └──────────┬─────────┘
                                    │
                              raw native spool
                                    │
                                    ▼
                         ┌────────────────────┐
                         │ Trace normalizer   │
                         └──────────┬─────────┘
                                    │
          ╔═════════════════════════▼═════════════════════════╗
          ║        CANONICAL CIPHERSCOPE TRACE SCHEMA         ║
          ║                                                   ║
          ║ No GCC concepts                                   ║
          ║ No C++ pointers                                   ║
          ║ No Python object assumptions                      ║
          ║ Semantic FHE operations + state + provenance      ║
          ╚═════════════════════════╤═════════════════════════╝
                                    │
                                    ▼
                         existing validation.py
                                    │
                                    ▼
                           existing graph.py
                                    │
                                    ▼
                         existing analyzers/*
                                    │
                                    ▼
                         existing exporters/*
                                    │
                                    ▼
                            standard run bundle
```

This is the architecture I would use for the C++ conference implementation.

The most important design choice is not simply “use a GCC plugin.” It is:

> **Treat the GCC implementation as a replaceable trace-producing frontend, and treat the canonical semantic trace as the permanent CipherScope interface.**

That gives CipherScope a much cleaner research abstraction, preserves the existing refactor, allows C++ support without duplicating analysis logic, and makes `cipherscope profile ./app` possible without touching the base program.
