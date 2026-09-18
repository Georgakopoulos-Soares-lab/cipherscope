/* CipherScope native runtime ABI.
 *
 * This is the whole contract between compiler-inserted instrumentation and the
 * runtime library. It is deliberately small, C-compatible, and free of any JSON
 * or schema knowledge: the GCC plugin emits calls to these functions around a
 * recognised OpenFHE semantic call, the runtime writes compact records to a
 * spool, and the Python normalizer (cipherscope.native_trace) turns the spool
 * into the canonical trace. Nothing here performs analysis.
 */
#ifndef CIPHERSCOPE_RUNTIME_H
#define CIPHERSCOPE_RUNTIME_H

#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

#define CIPHERSCOPE_RUNTIME_ABI_VERSION 1
#define CIPHERSCOPE_FRONTEND_NAME "gcc-openfhe"
#define CIPHERSCOPE_FRONTEND_VERSION "0.1.0"

/* Argument and result kinds. The plugin decides these statically from the
 * declared C++ types at the call site; the OpenFHE adapter interprets the
 * pointer accordingly. Pointers always point at the C++ object itself (for a
 * smart pointer, at the std::shared_ptr, never at the pointee). */
enum cs_kind {
    CS_KIND_UNKNOWN = 0,
    CS_KIND_CONTEXT = 1,          /* lbcrypto::CryptoContextImpl<DCRTPoly>* (the `this` pointer)      */
    CS_KIND_CIPHERTEXT = 2,       /* std::shared_ptr<lbcrypto::CiphertextImpl<DCRTPoly>>* (const or not) */
    CS_KIND_PLAINTEXT = 3,        /* std::shared_ptr<lbcrypto::PlaintextImpl>*                          */
    CS_KIND_PUBLIC_KEY = 4,       /* std::shared_ptr<lbcrypto::PublicKeyImpl<DCRTPoly>>*                */
    CS_KIND_PRIVATE_KEY = 5,      /* std::shared_ptr<lbcrypto::PrivateKeyImpl<DCRTPoly>>*               */
    CS_KIND_INTEGER = 6,          /* ivalue                                                              */
    CS_KIND_SCALAR = 7,           /* dvalue                                                              */
    CS_KIND_VECTOR_INT32 = 8,     /* std::vector<int32_t>*                                               */
    CS_KIND_VECTOR_UINT32 = 9,    /* std::vector<uint32_t>*                                              */
    CS_KIND_VECTOR_DOUBLE = 10,   /* std::vector<double>*                                                */
    CS_KIND_VECTOR_COMPLEX = 11,  /* std::vector<std::complex<double>>*                                  */
    CS_KIND_CCPARAMS = 12,        /* lbcrypto::CCParams<lbcrypto::CryptoContextCKKSRNS>*                */
    CS_KIND_KEYPAIR = 13,         /* lbcrypto::KeyPair<DCRTPoly>*                                        */
    CS_KIND_BOOL = 14,            /* ivalue                                                              */
    CS_KIND_PLAINTEXT_OUT = 15,   /* lbcrypto::Plaintext* (an output parameter, e.g. Decrypt)            */
    CS_KIND_STRING = 16,          /* std::string*                                                        */
    CS_KIND_FUNCTION = 17,        /* std::function<...>*                                                 */
    CS_KIND_CRYPTOCONTEXT_PTR = 18, /* std::shared_ptr<lbcrypto::CryptoContextImpl<DCRTPoly>>* (a result) */
    CS_KIND_VECTOR_INT64 = 19,    /* std::vector<int64_t>*                                               */
    CS_KIND_VOID = 20             /* no result                                                           */
};

typedef uint64_t cs_token;

/* Begin one semantic event. `operation` is the canonical name from the
 * operation manifest and `site_id` the compile-time site identifier; both are
 * string literals owned by the instrumented binary. Returns 0 when the event is
 * not recorded (nested inside another instrumented call, or recording stopped)
 * -- the matching cs_event_end must still be called with that token. */
cs_token cs_event_begin(const char* operation, const char* site_id);

/* Describe one argument of the call, in call order (`this` first). */
void cs_event_arg(cs_token token, int kind, const void* pointer, int64_t ivalue, double dvalue);

/* The native call returned normally; `result` describes its return value. */
void cs_event_end(cs_token token, int result_kind, const void* result);

/* Executed call that the manifest does not cover (still runs untraced). */
void cs_unmatched_call(const char* site_id, const char* qualified_name);

/* Executed call the manifest lists as non-semantic (accessor, Enable, ...). */
void cs_allowed_call(const char* site_id);

/* A CCParams object observed at GenCryptoContext(): declared parameters. */
void cs_declared_parameters(const char* site_id, const void* ccparams);

/* Flush buffered records to the spool and write the run footer. Called from a
 * destructor/atexit handler; safe to call more than once. */
void cs_finalize(void);

#ifdef __cplusplus
}
#endif

#endif /* CIPHERSCOPE_RUNTIME_H */
