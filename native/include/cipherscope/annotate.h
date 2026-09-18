/* CipherScope optional annotation API for C++ programs.
 *
 * Everything the GCC frontend records comes from the OpenFHE calls a program
 * already makes; this header is the one opt-in addition, the counterpart of
 * the Python session's annotate() / annotate_plaintext() / checkpoint(). A
 * program that includes it stays an ordinary OpenFHE program: unless the
 * translation unit is compiled through the CipherScope compiler launcher
 * (which defines CIPHERSCOPE_INSTRUMENTED), every call below is an inline
 * no-op, nothing is decrypted and no CipherScope symbol is referenced. In a
 * `cipherscope profile` shadow build the runtime library provides the entry
 * points and records `annotation` / `checkpoint` events with the caller's
 * file, line and function. Analyzers that need this evidence stay
 * `not_applicable` for programs that do not use it; nothing is ever inferred
 * in its place.
 *
 * No OpenFHE header is included here; handles are passed as the
 * std::shared_ptr objects OpenFHE already uses (Ciphertext<DCRTPoly>,
 * Plaintext, CryptoContext<DCRTPoly>, PrivateKey<DCRTPoly>).
 */
#ifndef CIPHERSCOPE_ANNOTATE_H
#define CIPHERSCOPE_ANNOTATE_H

#include <cstddef>
#include <cstdint>
#include <memory>
#include <string>
#include <vector>

#ifdef CIPHERSCOPE_INSTRUMENTED
/* Provided by libcipherscope_openfhe, which the shadow build links. */
extern "C" {
void cs_annotate_ciphertext(const char* file, int line, const char* function, const void* ciphertext,
                            const int64_t* shape, size_t shape_length, const char* packing,
                            int64_t meaningful_slots, const char* provenance);
void cs_annotate_plaintext(const char* file, int line, const char* function, const void* plaintext,
                           const char* provenance, const char* constant_id);
void cs_checkpoint(const char* file, int line, const char* function, const char* name,
                   const void* context, const void* ciphertext, const void* secret_key,
                   const double* expected, size_t expected_length,
                   const double* tolerance_absolute, const double* tolerance_relative,
                   const double* tolerance_min_bits);
}
#define CIPHERSCOPE_ACTIVE 1
#else
/* Plain build: no-ops, no runtime dependency. */
static inline void cs_annotate_ciphertext(const char*, int, const char*, const void*, const int64_t*, size_t,
                                          const char*, int64_t, const char*) {}
static inline void cs_annotate_plaintext(const char*, int, const char*, const void*, const char*, const char*) {}
static inline void cs_checkpoint(const char*, int, const char*, const char*, const void*, const void*, const void*,
                                 const double*, size_t, const double*, const double*, const double*) {}
#define CIPHERSCOPE_ACTIVE 0
#endif

namespace cipherscope {

/* User assertions about a ciphertext's contents (same fields as the Python
 * session.annotate keyword arguments; unset fields are not recorded). */
struct Annotation {
    std::vector<int64_t> shape;      // logical shape of the packed data
    std::string packing;             // e.g. "row_major"
    int64_t meaningful_slots = -1;   // slots that carry data; -1 = unset
    std::string provenance;          // e.g. "public_constant", "model_parameter"
};

/* Optional precision contract for a checkpoint; negative = not declared. */
struct Tolerance {
    double absolute = -1.0;
    double relative = -1.0;
    double min_bits = -1.0;
};

/* True when this translation unit was compiled through the CipherScope launcher. */
inline constexpr bool active() { return CIPHERSCOPE_ACTIVE != 0; }

/* Record an annotation for `ciphertext`; returns the handle unchanged. */
template <typename Handle>
inline const Handle& annotate(const Handle& ciphertext, const Annotation& annotation,
                              const char* file = __builtin_FILE(), int line = __builtin_LINE(),
                              const char* function = __builtin_FUNCTION()) {
    if (active()) {
        cs_annotate_ciphertext(file, line, function, static_cast<const void*>(&ciphertext),
                               annotation.shape.empty() ? nullptr : annotation.shape.data(), annotation.shape.size(),
                               annotation.packing.empty() ? nullptr : annotation.packing.c_str(),
                               annotation.meaningful_slots,
                               annotation.provenance.empty() ? nullptr : annotation.provenance.c_str());
    }
    return ciphertext;
}

/* Record a plaintext's declared provenance and, optionally, a constant identity
 * shared by every encoding of the same public value. */
template <typename Handle>
inline const Handle& annotate_plaintext(const Handle& plaintext, const std::string& provenance,
                                        const std::string& constant_id = std::string(),
                                        const char* file = __builtin_FILE(), int line = __builtin_LINE(),
                                        const char* function = __builtin_FUNCTION()) {
    if (active()) {
        cs_annotate_plaintext(file, line, function, static_cast<const void*>(&plaintext), provenance.c_str(),
                              constant_id.empty() ? nullptr : constant_id.c_str());
    }
    return plaintext;
}

/* Precision checkpoint: under CipherScope the runtime decrypts `ciphertext`
 * with `secret_key` (the program's own key; nothing else can) and records the
 * expected and observed values. In a plain build nothing happens. */
template <typename Context, typename Handle, typename Key>
inline void checkpoint(const std::string& name, const Context& context, const Handle& ciphertext,
                       const Key& secret_key, const std::vector<double>& expected,
                       const Tolerance& tolerance = Tolerance(),
                       const char* file = __builtin_FILE(), int line = __builtin_LINE(),
                       const char* function = __builtin_FUNCTION()) {
    if (active()) {
        cs_checkpoint(file, line, function, name.c_str(), static_cast<const void*>(&context),
                      static_cast<const void*>(&ciphertext), static_cast<const void*>(&secret_key),
                      expected.empty() ? nullptr : expected.data(), expected.size(),
                      tolerance.absolute >= 0 ? &tolerance.absolute : nullptr,
                      tolerance.relative >= 0 ? &tolerance.relative : nullptr,
                      tolerance.min_bits >= 0 ? &tolerance.min_bits : nullptr);
    }
}

}  // namespace cipherscope

#endif /* CIPHERSCOPE_ANNOTATE_H */
