// OpenFHE adapter: the only translation unit that includes OpenFHE headers.
//
// It reads exactly the metadata the canonical trace carries (level, noise
// scale degree, scaling factor, slots, key tag, context identity, scaling and
// key-switch technique, declared CCParams) from native objects and writes JSON
// fragments for the runtime's spool. Anything it cannot read becomes null and
// is listed under "missing" -- values are never invented. It never touches
// ciphertext coefficients, keys, or plaintext values.

#include "adapter.h"

#include <complex>
#include <cstdio>
#include <cstring>
#include <sstream>
#include <string>
#include <vector>

#include "openfhe.h"  // pke/openfhe.h umbrella header (OpenFHE_INCLUDE/pke on the include path)
#include "cipherscope/runtime.h"

namespace cs::adapter {
namespace {

using lbcrypto::CiphertextImpl;
using lbcrypto::CryptoContextImpl;
using lbcrypto::DCRTPoly;

using CtPtr = std::shared_ptr<CiphertextImpl<DCRTPoly>>;
using ConstCtPtr = std::shared_ptr<const CiphertextImpl<DCRTPoly>>;

void json_string(std::string& out, const std::string& text) {
    out.push_back('"');
    for (unsigned char c : text) {
        switch (c) {
            case '"': out += "\\\""; break;
            case '\\': out += "\\\\"; break;
            case '\n': out += "\\n"; break;
            case '\r': out += "\\r"; break;
            case '\t': out += "\\t"; break;
            default:
                if (c < 0x20) { char b[8]; std::snprintf(b, sizeof b, "\\u%04x", c); out += b; }
                else out.push_back(static_cast<char>(c));
        }
    }
    out.push_back('"');
}

template <typename T>
std::string enum_name(const T& value) {
    std::ostringstream stream;
    stream << value;
    return stream.str();
}

std::string json_double(double value) {
    char buffer[64];
    std::snprintf(buffer, sizeof buffer, "%.17g", value);
    std::string text = buffer;
    if (text == "inf" || text == "-inf" || text == "nan" || text == "-nan") return "null";
    return text;
}

// The ciphertext object behind either a mutable or a const shared_ptr. The
// pointer passed by the plugin points at the shared_ptr itself.
const CiphertextImpl<DCRTPoly>* ciphertext_of(const void* pointer, std::shared_ptr<const void>* witness) {
    if (pointer == nullptr) return nullptr;
    // Both shared_ptr<T> and shared_ptr<const T> have the same layout; read as const.
    const ConstCtPtr& handle = *static_cast<const ConstCtPtr*>(pointer);
    if (!handle) return nullptr;
    if (witness) *witness = std::shared_ptr<const void>(handle, static_cast<const void*>(handle.get()));
    return handle.get();
}

// Level/scale/slots/key metadata for one ciphertext; the trace's state_snapshot.
void append_state(std::string& out, void* registry, const std::string& id_with_version,
                  const CiphertextImpl<DCRTPoly>* ct) {
    out += "{\"id\":"; json_string(out, id_with_version);
    std::vector<std::string> missing;
    if (ct == nullptr) {
        out += ",\"level\":null,\"noise_scale_degree\":null,\"scale\":null,\"slots\":null,\"context_id\":null,"
               "\"key_tag\":null,\"scaling_technique\":null,\"key_switch_technique\":null,"
               "\"missing\":[\"level\",\"noise_scale_degree\",\"scale\",\"slots\",\"context_id\",\"key_tag\","
               "\"scaling_technique\",\"key_switch_technique\"]}";
        return;
    }
    try { out += ",\"level\":" + std::to_string(ct->GetLevel()); }
    catch (...) { out += ",\"level\":null"; missing.push_back("level"); }
    try { out += ",\"noise_scale_degree\":" + std::to_string(ct->GetNoiseScaleDeg()); }
    catch (...) { out += ",\"noise_scale_degree\":null"; missing.push_back("noise_scale_degree"); }
    try { out += ",\"scale\":" + json_double(ct->GetScalingFactor()); }
    catch (...) { out += ",\"scale\":null"; missing.push_back("scale"); }
    try { out += ",\"slots\":" + std::to_string(ct->GetSlots()); }
    catch (...) { out += ",\"slots\":null"; missing.push_back("slots"); }
    std::shared_ptr<CryptoContextImpl<DCRTPoly>> cc;
    try { cc = ct->GetCryptoContext(); } catch (...) { cc = nullptr; }
    if (cc) { out += ",\"context_id\":"; json_string(out, registry_context(registry, cc.get())); }
    else { out += ",\"context_id\":null"; missing.push_back("context_id"); }
    try { out += ",\"key_tag\":"; json_string(out, ct->GetKeyTag()); }
    catch (...) { out += "null"; missing.push_back("key_tag"); }
    std::shared_ptr<lbcrypto::CryptoParametersRNS> rns;
    if (cc) {
        try { rns = std::dynamic_pointer_cast<lbcrypto::CryptoParametersRNS>(cc->GetCryptoParameters()); } catch (...) {}
    }
    if (rns) {
        out += ",\"scaling_technique\":"; json_string(out, enum_name(rns->GetScalingTechnique()));
        out += ",\"key_switch_technique\":"; json_string(out, enum_name(rns->GetKeySwitchTechnique()));
    } else {
        out += ",\"scaling_technique\":null,\"key_switch_technique\":null";
        missing.push_back("scaling_technique");
        missing.push_back("key_switch_technique");
    }
    out += ",\"missing\":[";
    for (size_t i = 0; i < missing.size(); ++i) { if (i) out += ","; json_string(out, missing[i]); }
    out += "]}";
}

template <typename T>
void append_int_vector(std::string& out, const void* pointer) {
    const auto& values = *static_cast<const std::vector<T>*>(pointer);
    out += "[";
    for (size_t i = 0; i < values.size(); ++i) { if (i) out += ","; out += std::to_string(static_cast<long long>(values[i])); }
    out += "]";
}

}  // namespace

std::string framework_version() {
    // core/version.h stringifies the OPENFHE_VERSION build definition.
    return GetOPENFHEVersion();
}

int mutated_argument(const char* operation) {
    static const char* const in_place[] = {
        "EvalAddInPlace", "EvalSubInPlace", "EvalSquareInPlace", "RelinearizeInPlace",
        "EvalNegateInPlace", "ModReduceInPlace", "RescaleInPlace", nullptr,
    };
    for (const char* const* name = in_place; *name; ++name) {
        if (std::strcmp(*name, operation) == 0) return 0;
    }
    return -1;
}

void describe_argument(std::string& out, void* registry, int kind, const void* pointer,
                       int64_t ivalue, double dvalue,
                       std::vector<const void*>* ciphertext_args, std::vector<std::string>* ids) {
    switch (kind) {
        case CS_KIND_CONTEXT: {
            out += "\"kind\":\"context\",\"context_id\":";
            json_string(out, registry_context(registry, pointer));
            return;
        }
        case CS_KIND_CRYPTOCONTEXT_PTR: {
            const auto& handle = *static_cast<const std::shared_ptr<CryptoContextImpl<DCRTPoly>>*>(pointer);
            out += "\"kind\":\"context\",\"context_id\":";
            if (handle) json_string(out, registry_context(registry, handle.get())); else out += "null";
            return;
        }
        case CS_KIND_CIPHERTEXT: {
            std::shared_ptr<const void> witness;
            const CiphertextImpl<DCRTPoly>* ct = ciphertext_of(pointer, &witness);
            if (ct == nullptr) {
                out += "\"kind\":\"ciphertext\",\"id\":null,\"state\":null";
                ciphertext_args->push_back(nullptr);
                ids->push_back("");
                return;
            }
            bool is_new = false;
            auto [id, version] = registry_ciphertext(registry, ct, witness, &is_new);
            std::string full = id + ":v" + std::to_string(version);
            ciphertext_args->push_back(pointer);
            ids->push_back(full);
            out += "\"kind\":\"ciphertext\",\"id\":"; json_string(out, full);
            out += ",\"first_seen\":" + std::string(is_new ? "true" : "false");
            out += ",\"state\":"; append_state(out, registry, full, ct);
            return;
        }
        case CS_KIND_PLAINTEXT: out += "\"kind\":\"plaintext\""; return;
        case CS_KIND_PLAINTEXT_OUT: out += "\"kind\":\"plaintext_out\""; return;
        case CS_KIND_PUBLIC_KEY: out += "\"kind\":\"key\",\"key_kind\":\"public\""; return;
        case CS_KIND_PRIVATE_KEY: out += "\"kind\":\"key\",\"key_kind\":\"private\""; return;
        case CS_KIND_KEYPAIR: out += "\"kind\":\"key_pair\""; return;
        case CS_KIND_INTEGER: out += "\"kind\":\"integer\",\"value\":" + std::to_string(ivalue); return;
        case CS_KIND_BOOL: out += "\"kind\":\"boolean\",\"value\":" + std::string(ivalue ? "true" : "false"); return;
        case CS_KIND_SCALAR: out += "\"kind\":\"scalar\",\"value\":" + json_double(dvalue); return;
        case CS_KIND_VECTOR_INT32: out += "\"kind\":\"integer_vector\",\"values\":"; append_int_vector<int32_t>(out, pointer); return;
        case CS_KIND_VECTOR_UINT32: out += "\"kind\":\"integer_vector\",\"values\":"; append_int_vector<uint32_t>(out, pointer); return;
        case CS_KIND_VECTOR_INT64: out += "\"kind\":\"integer_vector\",\"values\":"; append_int_vector<int64_t>(out, pointer); return;
        case CS_KIND_VECTOR_DOUBLE: {
            // Plaintext values are never recorded; only their count.
            const auto& values = *static_cast<const std::vector<double>*>(pointer);
            out += "\"kind\":\"real_vector\",\"length\":" + std::to_string(values.size());
            return;
        }
        case CS_KIND_VECTOR_COMPLEX: {
            const auto& values = *static_cast<const std::vector<std::complex<double>>*>(pointer);
            out += "\"kind\":\"complex_vector\",\"length\":" + std::to_string(values.size());
            return;
        }
        case CS_KIND_CCPARAMS: out += "\"kind\":\"ccparams\""; return;
        case CS_KIND_STRING: out += "\"kind\":\"string\""; return;
        case CS_KIND_FUNCTION: out += "\"kind\":\"function\""; return;
        default: out += "\"kind\":\"unknown\""; return;
    }
}

void describe_result(std::string& out, void* registry, const char* operation, int result_kind,
                     const void* result, int mutated,
                     const std::vector<const void*>& ciphertext_args,
                     const std::vector<std::string>& ciphertext_ids) {
    (void)operation;
    if (mutated >= 0) {
        // In-place: the mutated operand gains a version; its new state is the output.
        if (static_cast<size_t>(mutated) < ciphertext_args.size() && ciphertext_args[mutated] != nullptr) {
            std::shared_ptr<const void> witness;
            const CiphertextImpl<DCRTPoly>* ct = ciphertext_of(ciphertext_args[mutated], &witness);
            if (ct != nullptr) {
                uint32_t version = registry_bump_version(registry, ct);
                std::string base = ciphertext_ids[mutated].substr(0, ciphertext_ids[mutated].find(":v"));
                std::string full = base + ":v" + std::to_string(version);
                out += "\"kind\":\"ciphertext\",\"mutated_input\":"; json_string(out, ciphertext_ids[mutated]);
                out += ",\"id\":"; json_string(out, full);
                out += ",\"state\":"; append_state(out, registry, full, ct);
                return;
            }
        }
        out += "\"kind\":\"none\",\"mutation_unobserved\":true";
        return;
    }
    if (result_kind == CS_KIND_CIPHERTEXT && result != nullptr) {
        std::shared_ptr<const void> witness;
        const CiphertextImpl<DCRTPoly>* ct = ciphertext_of(result, &witness);
        if (ct == nullptr) { out += "\"kind\":\"ciphertext\",\"id\":null"; return; }
        bool is_new = false;
        auto [id, version] = registry_ciphertext(registry, ct, witness, &is_new);
        if (!is_new) {
            // The call handed back an object that already had an identity (an
            // operator returning its own left operand, for instance): that is a
            // new version of that object, never a fresh ciphertext.
            version = registry_bump_version(registry, ct);
        }
        std::string full = id + ":v" + std::to_string(version);
        out += "\"kind\":\"ciphertext\",\"id\":"; json_string(out, full);
        out += ",\"fresh\":" + std::string(is_new ? "true" : "false");
        out += ",\"state\":"; append_state(out, registry, full, ct);
        return;
    }
    switch (result_kind) {
        case CS_KIND_PLAINTEXT: out += "\"kind\":\"plaintext\""; return;
        case CS_KIND_KEYPAIR: out += "\"kind\":\"key_pair\""; return;
        case CS_KIND_CRYPTOCONTEXT_PTR: out += "\"kind\":\"context\""; return;
        case CS_KIND_VOID: out += "\"kind\":\"none\""; return;
        default: out += "\"kind\":\"other\""; return;
    }
}

void describe_ccparams(std::string& out, const void* pointer) {
    if (pointer == nullptr) { out += "\"available\":false"; return; }
    const auto& params = *static_cast<const lbcrypto::CCParams<lbcrypto::CryptoContextCKKSRNS>*>(pointer);
    out += "\"available\":true";
    out += ",\"scheme\":\"CKKS\"";
    out += ",\"security_level\":"; json_string(out, enum_name(params.GetSecurityLevel()));
    out += ",\"ring_dimension\":" + std::to_string(params.GetRingDim());
    out += ",\"multiplicative_depth\":" + std::to_string(params.GetMultiplicativeDepth());
    out += ",\"scaling_mod_size\":" + std::to_string(params.GetScalingModSize());
    out += ",\"first_mod_size\":" + std::to_string(params.GetFirstModSize());
    out += ",\"batch_size\":" + std::to_string(params.GetBatchSize());
    out += ",\"scaling_technique\":"; json_string(out, enum_name(params.GetScalingTechnique()));
    out += ",\"key_switch_technique\":"; json_string(out, enum_name(params.GetKeySwitchTechnique()));
}

}  // namespace cs::adapter

// Context snapshots need the registry's ordered view; declared here to keep
// runtime.cpp free of OpenFHE types.
namespace cs { class Registry; std::vector<std::pair<const void*, std::string>> registry_contexts(void* registry); }

namespace cs::adapter {

void describe_contexts(std::string& out, void* registry) {
    auto entries = cs::registry_contexts(registry);
    bool first = true;
    for (const auto& [raw, id] : entries) {
        if (!first) out += ",";
        first = false;
        const auto* cc = static_cast<const CryptoContextImpl<DCRTPoly>*>(raw);
        out += "{\"context_id\":"; json_string(out, id);
        std::vector<std::string> missing;
        try { out += ",\"ring_dimension\":" + std::to_string(cc->GetRingDimension()); }
        catch (...) { out += ",\"ring_dimension\":null"; missing.push_back("ring_dimension"); }
        try { out += ",\"cyclotomic_order\":" + std::to_string(cc->GetCyclotomicOrder()); }
        catch (...) { out += ",\"cyclotomic_order\":null"; missing.push_back("cyclotomic_order"); }
        try { out += ",\"batch_size\":" + std::to_string(cc->GetEncodingParams()->GetBatchSize()); }
        catch (...) { out += ",\"batch_size\":null"; missing.push_back("batch_size"); }
        std::shared_ptr<lbcrypto::CryptoParametersRNS> rns;
        try { rns = std::dynamic_pointer_cast<lbcrypto::CryptoParametersRNS>(cc->GetCryptoParameters()); } catch (...) {}
        if (rns) {
            out += ",\"configured_multiplicative_depth\":" + std::to_string(rns->GetMultiplicativeDepth());
            out += ",\"scaling_technique\":"; json_string(out, enum_name(rns->GetScalingTechnique()));
            out += ",\"key_switch_technique\":"; json_string(out, enum_name(rns->GetKeySwitchTechnique()));
        } else {
            out += ",\"configured_multiplicative_depth\":null,\"scaling_technique\":null,\"key_switch_technique\":null";
            missing.push_back("configured_multiplicative_depth");
            missing.push_back("scaling_technique");
            missing.push_back("key_switch_technique");
        }
        out += ",\"missing\":[";
        for (size_t i = 0; i < missing.size(); ++i) { if (i) out += ","; json_string(out, missing[i]); }
        out += "]}";
    }
}

}  // namespace cs::adapter
