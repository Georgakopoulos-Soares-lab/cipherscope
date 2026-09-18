// OpenFHE adapter interface used by the runtime. Only adapter.cpp includes
// OpenFHE headers; the runtime hands it raw argument descriptions and a
// registry handle and receives JSON fragments back.
#pragma once

#include <cstdint>
#include <memory>
#include <string>
#include <utility>
#include <vector>

namespace cs::adapter {

// Registry access implemented in runtime.cpp (opaque handle = cs::Registry*).
std::pair<std::string, uint32_t> registry_ciphertext(void* registry, const void* raw,
                                                     std::shared_ptr<const void> witness, bool* is_new);
uint32_t registry_bump_version(void* registry, const void* raw);
std::string registry_context(void* registry, const void* raw);

// OpenFHE version string ("1.5.1"), read from the library headers.
std::string framework_version();

// Index of the in-place operand for a canonical operation, or -1.
int mutated_argument(const char* operation);

// Append the JSON body (no braces) describing one argument. Ciphertext
// arguments are registered and their "ct_NNNN:vK" IDs appended to `ids`.
void describe_argument(std::string& out, void* registry, int kind, const void* pointer,
                       int64_t ivalue, double dvalue,
                       std::vector<const void*>* ciphertext_args, std::vector<std::string>* ids);

// Append the JSON body describing the call's result: output ciphertext IDs and
// states, or the new version of the mutated operand for in-place operations.
void describe_result(std::string& out, void* registry, const char* operation, int result_kind,
                     const void* result, int mutated_argument,
                     const std::vector<const void*>& ciphertext_args,
                     const std::vector<std::string>& ciphertext_ids);

// Append the JSON body describing declared CCParams<CryptoContextCKKSRNS>.
void describe_ccparams(std::string& out, const void* params);

// Append JSON objects (comma separated) for every context seen.
void describe_contexts(std::string& out, void* registry);

}  // namespace cs::adapter
