# C++ frontend (GCC / OpenFHE)

CipherScope profiles OpenFHE C++ programs without any change to their source:

```bash
cipherscope profile ./build/my_program -- --dataset input.csv
```

The C++ frontend is a second *trace producer*, not a second CipherScope. It
observes an execution and emits the same canonical trace
(`schemas/trace.schema.json`) the Python proxy emits; validation, the
ciphertext graph, every analyzer, and every exporter are shared and cannot
tell the producers apart except through the `run.producer` provenance block.

```text
C++ source ─► shadow GCC build (+ CipherScope plugin) ─► instrumented binary
                                                              │ runs unchanged
                                                              ▼
                                         native runtime ─► spool (internal)
                                                              │
                                        cipherscope.native_trace.normalize
                                                              ▼
                                  ╔═══ canonical trace.json (one schema) ═══╗
                                                              ▼
                              validation → graph → analyzers → exporters → bundle
```

## What `profile` does for a C++ target

1. **Marker check.** An ELF section `.cipherscope.marker` proves a binary was
   built through the plugin. If present, the binary is run directly.
2. **Build discovery** (`cipherscope.build_discovery`). The nearest
   `CMakeCache.txt` at or above the binary gives the source root, the C++
   compiler (must be GCC), generator, build type, and — via `OpenFHE_DIR` —
   `OpenFHEConfig.cmake` with OpenFHE's include/lib directories, flags and
   version. The CMake target defaults to the binary's name (`--cmake-target`
   overrides). Nothing outside the target's build tree is read.
3. **Toolchain** (`cipherscope.native_profile.ensure_toolchain`). The GCC
   plugin (`native/gcc/plugin.cpp`) and the runtime library
   (`native/runtime/{runtime,adapter}.cpp`) are compiled with the *target's
   own* GCC against the *target's own* OpenFHE into a fingerprinted cache
   (`<source>/.cipherscope/native/<hash>/`, or `$CIPHERSCOPE_CACHE`). A GCC
   plugin only loads into the compiler that built it, so this is what makes
   the frontend follow the project's toolchain instead of imposing one.
4. **Shadow build.** An isolated CMake configuration under
   `.cipherscope/builds/<fingerprint>/build` reproduces the original
   configuration (every user-supplied and semantic cache entry is forwarded:
   compiler, standard, flags, `*_DIR` package locations, project options),
   adds `CMAKE_CXX_COMPILER_LAUNCHER` = a one-line script that appends
   `-fplugin=…` to the real compiler command, and links the runtime library
   through `CMAKE_EXE_LINKER_FLAGS`. Optimization level and every other flag
   stay as they were: instrumentation happens before optimization, so
   `-O3` builds are traced as `-O3` builds. Only the requested CMake target
   is built; the shadow is reused while its fingerprint is unchanged.
5. **Run.** The shadow binary runs with the original arguments and
   environment plus `CIPHERSCOPE_NATIVE_SPOOL` (and the `--max-events` /
   `--max-trace-bytes` limits). Its exit status is the command's exit status.
6. **Normalize, analyze, export.** The spool and the per-translation-unit
   site tables become the canonical trace; `build_analysis_bundle` and
   `write_bundle` produce the same bundle layout as a Python run, plus
   `native/{spool.jsonl,sites/,build-metadata.json}` for audit.

If the binary carries no marker and no reproducible CMake build is found, the
command reports `Coverage: UNSUPPORTED` and writes no bundle. It never guesses.

## The acquisition boundary

The plugin registers a GIMPLE pass right after CFG construction — before
early inlining — and looks at every direct call made **from application
code** (functions outside the `lbcrypto` namespace and its classes). For a
call to a `lbcrypto::CryptoContextImpl<…>` member or to one of the ciphertext
operator templates (`a * b`, `a += b`, `-a`, …) that the operation manifest
(`native/openfhe/openfhe-1.5.operations.json`) lists, it inserts

```text
token = cs_event_begin("EvalMult", "site_…");
cs_event_arg(token, kind, &operand, …);     // one per argument, `this` first
result = cc->EvalMult(a, b);                 // the original call, untouched
cs_event_end(token, result_kind, &result);
```

Operand kinds are decided statically from the declared C++ types
(`shared_ptr<CiphertextImpl>` → ciphertext, `shared_ptr<PlaintextImpl>` →
plaintext, `Plaintext*` → output parameter, keys, integers, vectors, …). Calls
to `CryptoContextImpl` members that are neither in the manifest nor in its
allowed non-semantic list (accessors, `Enable`, key-store bookkeeping) are
reported with `cs_unmatched_call`; they still execute, and the run cannot be
`COMPLETE`. Calls made from inside OpenFHE's own header templates (which are
instantiated in the user's translation unit) are never instrumented: the
boundary is the public API as the application calls it, which is exactly what
the Python proxy observes (`granularity: openfhe_api_inclusive`). Each
instrumented translation unit also receives the `.cipherscope.marker` section.

## The runtime

`libcipherscope_openfhe.so` implements the C ABI in
`native/include/cipherscope/runtime.h`:

* **identity**: `CiphertextImpl*` → `ct_NNNN`, guarded by a weak reference so
  an address reused after destruction never inherits an old ID; handle
  copies and moves share one ID;
* **versions**: in-place operations (`EvalAddInPlace`, `RescaleInPlace`, …)
  advance the operand's version, `ct_0004:v0 → ct_0004:v1`;
* **compound operators**: `c += d` records the assigned-to operand as the
  result;
* **exceptions**: a call that unwinds past its `cs_event_end` is closed as an
  `error` event (`error_class: native_unwound`) at the thread's next event or
  at exit; the application's own `catch` is untouched;
* **threads**: any thread may record; each event carries its `gettid()`;
* **clocks**: `CLOCK_MONOTONIC`, `CLOCK_PROCESS_CPUTIME_ID`,
  `CLOCK_THREAD_CPUTIME_ID`, named in `run.clocks`;
* **limits**: `CIPHERSCOPE_MAX_EVENTS` / `CIPHERSCOPE_MAX_TRACE_BYTES` stop
  recording, never the program; the trace is marked truncated;
* **privacy**: no pointer, key, coefficient or plaintext value is written;
  vectors of plaintext values are recorded as their length only.

The OpenFHE adapter (`adapter.cpp`) is the only code that includes OpenFHE
headers. It reads level, noise-scale degree, scaling factor, slots, key tag,
context identity, and the scaling/key-switch techniques; anything unreadable
becomes `null` and is listed under `missing`. It also reads the
`CCParams<CryptoContextCKKSRNS>` passed to `GenCryptoContext` (security
level, ring dimension, depth, scaling mod size), which is what lets the
`configuration.testing_only_security.v1` rule assess a C++ run exactly as a
Python run launched through `profile_unmodified.py`.

## Parity with the Python frontend

`cipherscope.frontend_parity.compare_traces` reduces a trace to the content
that must not depend on the producer — operation sequence and kinds,
overloads, operand roles, lineage as first-appearance indices, level and
noise transitions, semantic arguments, analyzer statuses and finding IDs — and
lists every difference. `tests/cpp/fixtures/repeated_rotations.cpp` and
`examples/synthetic/repeated_rotations.py` are twins; their traces are
equivalent and both produce the same four findings (`PARITY-01`,
`tests/test_native_frontend.py`). Where the two APIs differ the normalizer
takes the Python shape: `Decrypt(key, ct, &pt)` is recorded with operands
`ciphertext, key`; defaulted C++ parameters are dropped from role-labelled
operations; Python labels plaintext operands and `ct_pt` overloads the way
the C++ side derives them from types.

## Coverage classes for C++ runs

`classify_run` uses the same three classes. For a native run `COMPLETE`
requires: run completed, strict mode, no truncation, no executed unmatched
candidate, every compiled translation unit instrumented
(`instrumented_translation_units == expected_translation_units`), and the
binary that ran verified to carry the marker. `PARTIAL-PERMISSIVE` names the
unmatched calls (`coverage.unmatched_candidate_names`, mirrored into
`unsupported_operations`). `UNSUPPORTED` covers failed runs and unmarked
binaries. Python's proxy pass-through counters are `0` for native runs and its
static source scan is not applied to C++ files.

## Overhead

`evaluation/native_overhead/run_native_overhead.py` runs a C++ twin of the
Python scaling kernel (`tests/cpp/fixtures/scaling_kernel.cpp`: N operations
in a fixed EvalAdd/EvalSub/EvalRotate mix on a depth-1 context) in three arms,
one fresh process per point, with wall time measured outside the process and
peak RSS from `wait4`: **plain** (the user's binary), **hooks** (the
instrumented build with no spool — every `cs_event_*` call runs, nothing is
written), **full** (spool enabled, what `profile` measures). LS6 `vm-small`,
GCC 15.2.0, OpenFHE 1.5.1, `OMP_NUM_THREADS=1`, three repetitions per point
(`evaluation/raw/native_overhead.csv`, `evaluation/native_overhead/summarize.py`):

| events | hooks / plain | full / plain | plain peak RSS | full peak RSS | spool bytes / event |
|---|---|---|---|---|---|
| 10³ | 1.004 | 1.069 | 25 MB | 25 MB | 1 195 |
| 10⁴ | 1.015 | 0.987 | 26 MB | 26 MB | 1 197 |
| 10⁵ | 1.003 | 1.007 | 26 MB | 26 MB | 1 201 |

Those rows pin glibc's allocator (`MALLOC_TRIM_THRESHOLD_`/`MALLOC_TOP_PAD_`);
under the default allocator the instrumented arms ran 6–16 % *faster* than
the plain binary at 10⁴–10⁵ because glibc trims and re-faults the heap after
each freed ~500 KB ciphertext buffer and the runtime's few long-lived
allocations suppress that. Both settings are in the raw record with an
`allocator` column; only the pinned rows measure instrumentation itself. The
tracing cost is within run-to-run noise of the FHE work, memory is flat
(the registry prunes entries whose ciphertext has been destroyed), and the
spool grows linearly at ~1.2 KB per event. The runtime writes one locked
record per event; with a millisecond-scale FHE operation per event, a
thread-local buffer (design §31) was not needed to reach this result, and
`threads.cpp` shows four OpenMP threads recording concurrently.

## Supported envelope

| Component | Status |
|---|---|
| GCC 15.2.0 on Rocky 8.10, GCC 13.3.0 on Ubuntu 24.04 (x86_64) | tested, 18/18 each (`artifact/feasibility/cpp-gcc152-openfhe151/`, `cpp-gcc133-openfhe151/`) |
| other GCC versions with plugin headers | expected to work; plugins are version-locked, so each is built on demand — untested |
| Clang, MSVC, `LD_PRELOAD` | not supported by design |
| OpenFHE 1.5.1 C++ API (CKKS) | tested; manifest `openfhe-1.5-v2`, 38 operations + 7 operator aliases |
| build systems | CMake only (`CMakeCache.txt` + `compile_commands.json`) |
| already-instrumented binaries | run directly when the marker is present |

Known limits: an instrumented call made from a user callback that OpenFHE
invokes during another instrumented call is read as an unwound call; only the
first `GenCryptoContext(CCParams<CryptoContextCKKSRNS>)` populates the
declared parameters; precision checkpoints and annotations have no C++
counterpart yet, so those rules report `not_applicable` (they are never
faked); `EvalAddMany`/`EvalMultMany`, `EvalChebyshevSeries` and the BGV/BFV
API are outside the manifest in both frontends.

## Files

| Path | Role |
|---|---|
| `native/include/cipherscope/runtime.h` | C ABI between compiler-inserted calls and the runtime |
| `native/gcc/plugin.cpp` | GIMPLE instrumentation pass, site tables, marker |
| `native/runtime/runtime.cpp` | identity, versions, clocks, threads, limits, spool |
| `native/runtime/adapter.cpp` | OpenFHE metadata reader (only OpenFHE-including TU) |
| `native/openfhe/openfhe-1.5.operations.json` | versioned operation manifest, bound to the Python table by `tests/test_operation_manifest.py` |
| `src/cipherscope/native_trace.py` | spool → canonical trace |
| `src/cipherscope/build_discovery.py` | CMake/OpenFHE discovery |
| `src/cipherscope/native_profile.py` | toolchain cache, shadow build, run, bundle |
| `src/cipherscope/frontend_parity.py` | cross-frontend semantic comparison |
| `tests/cpp/fixtures/` | plain OpenFHE CMake project used by the gate |
| `tests/integration_cpp/run_gate.py` | the 18-check feasibility gate |
