# C++ frontend fixtures

`fixtures/` is an ordinary OpenFHE CMake project — no CipherScope include,
macro, wrapper or build hook. Each program exercises one property the native
frontend must get right; `tests/integration_cpp/run_gate.py` builds the
project plainly, profiles every binary with `cipherscope profile`, and checks
the traces (see [docs/cpp_frontend.md](../../docs/cpp_frontend.md)).

| Fixture | Property | Twin |
|---|---|---|
| `repeated_rotations.cpp` | exact interception, source lines, analyzers (hoisting, unused key 5) | `examples/synthetic/repeated_rotations.py` |
| `operators_inplace.cpp` | `a * b`, `a + b`, `c += d`, `-a` fold to one event each; `EvalAddInPlace`/`RescaleInPlace` version their operand; `ct * pt` | `twins/operators_inplace.py` (`a + b` through the binding's `__add__`, rerouted by the session; the other operators, which the binding does not define, as explicit calls) |
| `aliasing.cpp` | copies, moves, container storage keep one identity; destroyed temporaries never hand their ID to a reused address | `twins/aliasing.py` |
| `exception.cpp` | a throwing call becomes an error event; the application's `catch` and later calls are untouched | `twins/exception.py` |
| `threads.cpp` | OpenMP threads record concurrently with their own thread IDs | — |
| `unmatched.cpp` | `EvalAddMany`/`EvalMultMany` outside the manifest deny `COMPLETE` and are named | — |

`expected/<fixture>/` holds the runtime spool, the site table and the Python
twin's `trace.json` recorded on LS6 (GCC 15.2.0, OpenFHE 1.5.1) so that
`tests/test_native_frontend.py` can exercise normalization and cross-frontend
parity without a compiler or the binding. Regenerate them from a
`cipherscope profile` bundle's `native/` directory and a
`cipherscope run examples/profile_unmodified.py -- twins/<name>.py` bundle.

Build and run the fixtures by hand:

```bash
cmake -S tests/cpp/fixtures -B tests/cpp/fixtures/build -DOpenFHE_DIR=/path/to/lib/OpenFHE
cmake --build tests/cpp/fixtures/build
PYTHONPATH=src python3 -m cipherscope profile --output out/rr tests/cpp/fixtures/build/repeated_rotations
```
