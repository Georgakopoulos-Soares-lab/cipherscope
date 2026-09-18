// CipherScope GCC plugin: the C++ acquisition frontend.
//
// A GIMPLE pass that runs right after CFG construction, before any inlining,
// and wraps every direct call to a public lbcrypto::CryptoContextImpl<...>
// method (or one of the ciphertext operator templates that forward to one)
// named in the operation manifest:
//
//     token = cs_event_begin("EvalMult", "site_...");
//     cs_event_arg(token, kind, &arg, ...);   // one per argument, `this` first
//     result = cc->EvalMult(a, b);            // the original call, untouched
//     cs_event_end(token, result_kind, &result);
//
// If the call throws, control leaves through the EH edge and cs_event_end is
// never reached; the runtime closes the event as an error. The plugin performs
// no analysis and knows nothing about the trace schema: it only names the
// canonical operation, the call site, and the static kind of each operand.
//
// Every call to a CryptoContextImpl member that is neither in the manifest nor
// in its allowed non-semantic list is reported with cs_unmatched_call so the
// run can never look complete while an uncovered semantic call executed.
//
// Build:  g++ -shared -fPIC -fno-rtti -std=c++17 -I$(g++ -print-file-name=plugin)/include \
//              native/gcc/plugin.cpp -o libcipherscope_gcc.so
// Use:    g++ -fplugin=libcipherscope_gcc.so \
//              -fplugin-arg-libcipherscope_gcc-manifest=native/openfhe/openfhe-1.5.operations.txt \
//              -fplugin-arg-libcipherscope_gcc-site-dir=/path/to/sites ...

#include "gcc-plugin.h"
#include "plugin-version.h"
#include "cp/cp-tree.h"

#include "tree.h"
#include "tree-pass.h"
#include "context.h"
#include "function.h"
#include "basic-block.h"
#include "gimple.h"
#include "gimple-iterator.h"
#include "gimple-expr.h"
#include "gimplify.h"
#include "gimplify-me.h"
#include "cgraph.h"
#include "varasm.h"
#include "stringpool.h"
#include "langhooks.h"
#include "diagnostic.h"
#include "fold-const.h"
#include "tree-cfg.h"
#include "cfghooks.h"
#include "attribs.h"
#include "print-tree.h"

#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <fstream>
#include <map>
#include <set>
#include <string>
#include <vector>

int plugin_is_GPL_compatible;

namespace {

constexpr const char* kFrontendVersion = "0.1.0";

// Mirrors enum cs_kind in include/cipherscope/runtime.h.
enum Kind {
    K_UNKNOWN = 0, K_CONTEXT = 1, K_CIPHERTEXT = 2, K_PLAINTEXT = 3, K_PUBLIC_KEY = 4, K_PRIVATE_KEY = 5,
    K_INTEGER = 6, K_SCALAR = 7, K_VECTOR_INT32 = 8, K_VECTOR_UINT32 = 9, K_VECTOR_DOUBLE = 10,
    K_VECTOR_COMPLEX = 11, K_CCPARAMS = 12, K_KEYPAIR = 13, K_BOOL = 14, K_PLAINTEXT_OUT = 15,
    K_STRING = 16, K_FUNCTION = 17, K_CRYPTOCONTEXT_PTR = 18, K_VECTOR_INT64 = 19, K_VOID = 20,
};

struct Config {
    std::string manifest_path;
    std::string site_dir;
    std::string manifest_name = "openfhe-1.5-v1";
    bool debug = false;
    bool strict = true;
};

struct Manifest {
    std::set<std::string> operations;                  // canonical method names on CryptoContextImpl
    std::map<std::string, std::string> operator_alias;  // "operator*" -> EvalMult (binary), "operator-/1" -> EvalNegate
    std::set<std::string> allowed_names;
    std::vector<std::string> allowed_prefixes;
};

Config g_config;
Manifest g_manifest;
std::ofstream g_sites;
unsigned g_site_count = 0, g_unmatched_sites = 0, g_allowed_sites = 0;
bool g_marker_emitted = false;

// Runtime ABI declarations, built lazily per translation unit.
struct RuntimeDecls {
    tree begin = NULL_TREE, arg = NULL_TREE, end = NULL_TREE, unmatched = NULL_TREE, allowed = NULL_TREE, params = NULL_TREE;
    tree const_char_ptr = NULL_TREE;
} g_rt;

// ---------------------------------------------------------------------------
// Manifest: a small line-oriented file generated from the JSON manifest by
// cipherscope.native_profile so the plugin needs no JSON parser.
//   op <CanonicalName>
//   alias <operator-name>/<arity> <CanonicalName>
//   allow <Name>
//   allow-prefix <Prefix>
// ---------------------------------------------------------------------------
bool load_manifest(const std::string& path) {
    std::ifstream in(path);
    if (!in) return false;
    std::string kind, a, b;
    while (in >> kind) {
        if (kind == "op") { in >> a; g_manifest.operations.insert(a); }
        else if (kind == "alias") { in >> a >> b; g_manifest.operator_alias[a] = b; }
        else if (kind == "allow") { in >> a; g_manifest.allowed_names.insert(a); }
        else if (kind == "allow-prefix") { in >> a; g_manifest.allowed_prefixes.push_back(a); }
        else if (kind == "name") { in >> a; g_config.manifest_name = a; }
        else { std::getline(in, a); }
    }
    return !g_manifest.operations.empty();
}

bool allowed_nonsemantic(const std::string& name) {
    if (g_manifest.allowed_names.count(name)) return true;
    for (const auto& prefix : g_manifest.allowed_prefixes) {
        if (name.compare(0, prefix.size(), prefix) == 0) return true;
    }
    return false;
}

// ---------------------------------------------------------------------------
// Names.
// ---------------------------------------------------------------------------
std::string decl_name(tree decl) {
    if (decl == NULL_TREE || DECL_NAME(decl) == NULL_TREE) return "";
    return IDENTIFIER_POINTER(DECL_NAME(decl));
}

std::string qualified_name(tree decl) {
    if (decl == NULL_TREE) return "";
    const char* text = lang_hooks.decl_printable_name(decl, 1);
    return text ? text : "";
}

// Full C++ spelling of a type, template arguments included, e.g.
// "std::shared_ptr<lbcrypto::CiphertextImpl<lbcrypto::DCRTPolyImpl<...> > >".
std::string type_name(tree type) {
    if (type == NULL_TREE) return "";
    type = TYPE_MAIN_VARIANT(type);
    const char* text = type_as_string(type, TFF_SCOPE | TFF_CHASE_TYPEDEF);
    return text ? text : "";
}

bool contains(const std::string& text, const char* needle) { return text.find(needle) != std::string::npos; }

// The class an instrumented method belongs to, if it is CryptoContextImpl<...>.
bool is_cryptocontext_method(tree fndecl) {
    tree ctx = DECL_CONTEXT(fndecl);
    if (ctx == NULL_TREE || TREE_CODE(ctx) != RECORD_TYPE) return false;
    // Prefix, not substring: std::__shared_ptr_access<lbcrypto::CryptoContextImpl<...>>
    // (the smart pointer's operator->) must not count as a context method.
    // ... and the class itself, not a closure type nested inside one of its
    // methods (a lambda's operator() lives in a record whose scope is the method).
    tree scope = TYPE_CONTEXT(ctx);
    if (scope == NULL_TREE || TREE_CODE(scope) != NAMESPACE_DECL) return false;
    std::string name = type_name(ctx);
    return name.compare(0, 28, "lbcrypto::CryptoContextImpl<") == 0;
}

// Declared type of the callee's i-th parameter (`this` included for methods),
// or NULL_TREE. By-value class parameters reach GIMPLE as references, so only
// the declaration tells a `Plaintext*` output parameter from a `Plaintext`.
tree declared_parameter_type(tree fndecl, unsigned index) {
    unsigned i = 0;
    for (tree parm = DECL_ARGUMENTS(fndecl); parm != NULL_TREE; parm = DECL_CHAIN(parm), ++i) {
        if (i == index) return TREE_TYPE(parm);
    }
    i = 0;
    for (tree t = TYPE_ARG_TYPES(TREE_TYPE(fndecl)); t != NULL_TREE && t != void_list_node; t = TREE_CHAIN(t), ++i) {
        if (i == index) return TREE_VALUE(t);
    }
    return NULL_TREE;
}

bool in_lbcrypto_namespace(tree fndecl) {
    tree ctx = DECL_CONTEXT(fndecl);
    return ctx != NULL_TREE && TREE_CODE(ctx) == NAMESPACE_DECL && decl_name(ctx) == "lbcrypto";
}

// Is this function OpenFHE's own code (a lbcrypto:: member or free function,
// including template instantiations that land in the user's translation
// unit)? Calls made from there are the library's internals, not the
// application's semantic boundary, and are never instrumented or reported.
bool is_framework_code(tree fndecl) {
    for (tree ctx = fndecl ? DECL_CONTEXT(fndecl) : NULL_TREE; ctx != NULL_TREE; ) {
        if (TREE_CODE(ctx) == NAMESPACE_DECL) {
            std::string ns = decl_name(ctx);
            return ns == "lbcrypto" || ns == "bigintdyn" || ns == "bigintfxd" || ns == "bigintnat" || ns == "intnat" || ns == "cereal";
        }
        if (TREE_CODE(ctx) == RECORD_TYPE || TREE_CODE(ctx) == UNION_TYPE) {
            std::string name = type_name(ctx);
            if (name.compare(0, 10, "lbcrypto::") == 0) return true;
            ctx = TYPE_CONTEXT(ctx);
            continue;
        }
        if (TREE_CODE(ctx) == FUNCTION_DECL) { ctx = DECL_CONTEXT(ctx); continue; }
        if (TREE_CODE(ctx) == TRANSLATION_UNIT_DECL) return false;
        break;
    }
    return false;
}

// Static operand classification from the declared type at the call site.
// `by_pointer` reports whether the GIMPLE operand already is an address.
Kind classify_type(tree type, bool* is_pointer_param) {
    *is_pointer_param = false;
    if (type == NULL_TREE) return K_UNKNOWN;
    enum tree_code code = TREE_CODE(type);
    if (code == BOOLEAN_TYPE) return K_BOOL;
    if (code == INTEGER_TYPE || code == ENUMERAL_TYPE) return K_INTEGER;
    if (code == REAL_TYPE) return K_SCALAR;
    bool pointer = (code == POINTER_TYPE || code == REFERENCE_TYPE);
    tree record = pointer ? TREE_TYPE(type) : type;
    if (record == NULL_TREE) return K_UNKNOWN;
    if (TREE_CODE(record) != RECORD_TYPE) {
        if (pointer && code == POINTER_TYPE) *is_pointer_param = true;
        return K_UNKNOWN;
    }
    std::string name = type_name(record);
    if (contains(name, "lbcrypto::CryptoContextImpl<") && !contains(name, "shared_ptr")) return K_CONTEXT;
    if (contains(name, "shared_ptr<lbcrypto::CiphertextImpl") || contains(name, "shared_ptr<const lbcrypto::CiphertextImpl")) return K_CIPHERTEXT;
    if (contains(name, "shared_ptr<lbcrypto::PlaintextImpl") || contains(name, "shared_ptr<const lbcrypto::PlaintextImpl")) {
        // Plaintext* (an output parameter, e.g. Decrypt) versus Plaintext / const Plaintext&.
        if (code == POINTER_TYPE) { *is_pointer_param = true; return K_PLAINTEXT_OUT; }
        return K_PLAINTEXT;
    }
    if (contains(name, "shared_ptr<lbcrypto::PublicKeyImpl") || contains(name, "shared_ptr<const lbcrypto::PublicKeyImpl")) return K_PUBLIC_KEY;
    if (contains(name, "shared_ptr<lbcrypto::PrivateKeyImpl") || contains(name, "shared_ptr<const lbcrypto::PrivateKeyImpl")) return K_PRIVATE_KEY;
    if (contains(name, "shared_ptr<lbcrypto::CryptoContextImpl")) return K_CRYPTOCONTEXT_PTR;
    if (contains(name, "lbcrypto::KeyPair<")) return K_KEYPAIR;
    if (contains(name, "lbcrypto::CCParams<")) return K_CCPARAMS;
    if (contains(name, "std::vector<std::complex<double")) return K_VECTOR_COMPLEX;
    if (contains(name, "std::vector<double")) return K_VECTOR_DOUBLE;
    if (contains(name, "std::vector<int,") || contains(name, "std::vector<int>")) return K_VECTOR_INT32;
    if (contains(name, "std::vector<unsigned int")) return K_VECTOR_UINT32;
    if (contains(name, "std::vector<long")) return K_VECTOR_INT64;
    if (contains(name, "basic_string<char")) return K_STRING;
    if (contains(name, "std::function<")) return K_FUNCTION;
    return K_UNKNOWN;
}

// ---------------------------------------------------------------------------
// Site identifiers: FNV-1a over file:line:column:callee, stable across builds.
// ---------------------------------------------------------------------------
std::string site_id_for(const std::string& file, int line, int column, const std::string& callee) {
    std::string key = file + ":" + std::to_string(line) + ":" + std::to_string(column) + ":" + callee;
    unsigned long long hash = 1469598103934665603ULL;
    for (unsigned char c : key) { hash ^= c; hash *= 1099511628211ULL; }
    char buffer[32];
    std::snprintf(buffer, sizeof buffer, "site_%016llx", hash);
    return buffer;
}

void json_escape(std::string& out, const std::string& text) {
    out.push_back('"');
    for (unsigned char c : text) {
        if (c == '"') out += "\\\""; else if (c == '\\') out += "\\\\";
        else if (c < 0x20) { char b[8]; std::snprintf(b, sizeof b, "\\u%04x", c); out += b; }
        else out.push_back(static_cast<char>(c));
    }
    out.push_back('"');
}

void record_site(const std::string& site_id, const char* role, const std::string& operation, const std::string& callee,
                 const std::string& file, int line, int column, const std::string& function, const std::string& qualified) {
    if (!g_sites.is_open()) return;
    std::string out = "{\"record\":\"site\",\"site_id\":";
    json_escape(out, site_id);
    out += ",\"role\":"; json_escape(out, role);
    out += ",\"operation\":"; if (operation.empty()) out += "null"; else json_escape(out, operation);
    out += ",\"callee\":"; json_escape(out, callee);
    out += ",\"file\":"; json_escape(out, file);
    out += ",\"line\":" + std::to_string(line) + ",\"column\":" + std::to_string(column);
    out += ",\"function\":"; json_escape(out, function);
    out += ",\"qualified_function\":"; json_escape(out, qualified);
    out += ",\"translation_unit\":"; json_escape(out, main_input_filename ? main_input_filename : "");
    out += "}\n";
    g_sites << out;
}

// ---------------------------------------------------------------------------
// Runtime declarations and the instrumentation marker.
// ---------------------------------------------------------------------------
tree external_function(const char* name, tree type) {
    tree decl = build_fn_decl(name, type);
    DECL_EXTERNAL(decl) = 1;
    TREE_PUBLIC(decl) = 1;
    DECL_ARTIFICIAL(decl) = 1;
    TREE_NOTHROW(decl) = 1;
    return decl;
}

void ensure_runtime_decls() {
    if (g_rt.begin != NULL_TREE) return;
    g_rt.const_char_ptr = build_pointer_type(build_qualified_type(char_type_node, TYPE_QUAL_CONST));
    tree u64 = uint64_type_node;
    g_rt.begin = external_function("cs_event_begin",
        build_function_type_list(u64, g_rt.const_char_ptr, g_rt.const_char_ptr, NULL_TREE));
    g_rt.arg = external_function("cs_event_arg",
        build_function_type_list(void_type_node, u64, integer_type_node, const_ptr_type_node,
                                 long_long_integer_type_node, double_type_node, NULL_TREE));
    g_rt.end = external_function("cs_event_end",
        build_function_type_list(void_type_node, u64, integer_type_node, const_ptr_type_node, NULL_TREE));
    g_rt.unmatched = external_function("cs_unmatched_call",
        build_function_type_list(void_type_node, g_rt.const_char_ptr, g_rt.const_char_ptr, NULL_TREE));
    g_rt.allowed = external_function("cs_allowed_call",
        build_function_type_list(void_type_node, g_rt.const_char_ptr, NULL_TREE));
    g_rt.params = external_function("cs_declared_parameters",
        build_function_type_list(void_type_node, g_rt.const_char_ptr, const_ptr_type_node, NULL_TREE));
}

tree string_literal(const std::string& text) {
    return build_string_literal(text.size() + 1, text.c_str());
}

// Every instrumented translation unit carries a marker so `cipherscope
// profile` can prove it is running the instrumented binary.
void emit_marker() {
    if (g_marker_emitted) return;
    g_marker_emitted = true;
    std::string text = std::string("cipherscope.instrumented=true;frontend=gcc-openfhe;frontend_version=") + kFrontendVersion +
                       ";schema_major=1;manifest=" + g_config.manifest_name + ";gcc=" + gcc_version.basever;
    tree array_type = build_array_type_nelts(char_type_node, text.size() + 1);
    std::string name = "cipherscope_marker_" + std::to_string(std::hash<std::string>{}(main_input_filename ? main_input_filename : "tu"));
    tree decl = build_decl(UNKNOWN_LOCATION, VAR_DECL, get_identifier(name.c_str()), array_type);
    TREE_STATIC(decl) = 1;
    TREE_PUBLIC(decl) = 0;
    TREE_READONLY(decl) = 1;
    DECL_ARTIFICIAL(decl) = 1;
    DECL_PRESERVE_P(decl) = 1;  // like __attribute__((used))
    DECL_INITIAL(decl) = build_string(text.size() + 1, text.c_str());
    TREE_TYPE(DECL_INITIAL(decl)) = array_type;
    set_decl_section_name(decl, ".cipherscope.marker");
    varpool_node::finalize_decl(decl);
}

// ---------------------------------------------------------------------------
// The pass.
// ---------------------------------------------------------------------------
const pass_data cs_pass_data = {
    GIMPLE_PASS, "cipherscope", OPTGROUP_NONE, TV_NONE,
    PROP_gimple_any | PROP_cfg, 0, 0, 0, 0,
};

class cs_pass : public gimple_opt_pass {
public:
    cs_pass(gcc::context* ctxt) : gimple_opt_pass(cs_pass_data, ctxt) {}
    opt_pass* clone() override { return new cs_pass(m_ctxt); }
    bool gate(function*) override { return true; }
    unsigned int execute(function* fun) override;
};

struct CallSite {
    std::string file, function, qualified;
    int line = 0, column = 0;
};

CallSite site_of(gimple* stmt) {
    CallSite site;
    location_t loc = gimple_location(stmt);
    expanded_location xloc = expand_location(loc);
    site.file = xloc.file ? xloc.file : "";
    site.line = xloc.line;
    site.column = xloc.column;
    site.function = decl_name(current_function_decl);
    site.qualified = qualified_name(current_function_decl);
    return site;
}

// Address of a GIMPLE operand that denotes a class object (RECORD_TYPE), or
// the operand itself when it is already a pointer/reference. NULL_TREE if the
// operand cannot be addressed.
tree operand_address(gimple_stmt_iterator* gsi, tree operand, Kind kind, bool pointer_param) {
    (void)kind; (void)pointer_param;
    tree type = TREE_TYPE(operand);
    if (POINTER_TYPE_P(type)) {
        // A conversion is not a GIMPLE operand; give it a temporary.
        return force_gimple_operand_gsi(gsi, fold_convert(const_ptr_type_node, unshare_expr(operand)),
                                        true, NULL_TREE, true, GSI_SAME_STMT);
    }
    if (TREE_CODE(type) == RECORD_TYPE) {
        if (!is_gimple_addressable(operand)) return NULL_TREE;
        mark_addressable(operand);
        tree addr = build_fold_addr_expr(unshare_expr(operand));
        addr = fold_convert(const_ptr_type_node, addr);
        return force_gimple_operand_gsi(gsi, addr, true, NULL_TREE, true, GSI_SAME_STMT);
    }
    return NULL_TREE;
}

void insert_arg_call(gimple_stmt_iterator* gsi, tree token, Kind kind, tree pointer, tree ivalue, tree dvalue) {
    if (pointer == NULL_TREE) pointer = fold_convert(const_ptr_type_node, null_pointer_node);
    if (ivalue == NULL_TREE) ivalue = build_int_cst(long_long_integer_type_node, 0);
    if (dvalue == NULL_TREE) dvalue = build_real(double_type_node, dconst0);
    gcall* call = gimple_build_call(g_rt.arg, 5, token, build_int_cst(integer_type_node, kind), pointer, ivalue, dvalue);
    gsi_insert_before(gsi, call, GSI_SAME_STMT);
}

// Insert `after` following `stmt`; when the call ends its block (it may throw),
// place it on every non-exceptional successor edge instead.
void insert_after_call(gimple_stmt_iterator* gsi, gimple* stmt, gimple* after, bool* used_edges) {
    basic_block bb = gimple_bb(stmt);
    if (stmt_ends_bb_p(stmt)) {
        edge e; edge_iterator ei;
        FOR_EACH_EDGE(e, ei, bb->succs) {
            if (e->flags & (EDGE_EH | EDGE_ABNORMAL)) continue;
            gsi_insert_on_edge(e, gimple_copy(after));
            *used_edges = true;
        }
        return;
    }
    gsi_insert_after(gsi, after, GSI_NEW_STMT);
}

unsigned int cs_pass::execute(function* fun) {
    if (g_manifest.operations.empty()) return 0;
    if (is_framework_code(fun->decl)) return 0;
    ensure_runtime_decls();
    if (!std::getenv("CIPHERSCOPE_PLUGIN_NO_MARKER")) emit_marker();
    bool used_edges = false;
    basic_block bb;
    FOR_EACH_BB_FN(bb, fun) {
        for (gimple_stmt_iterator gsi = gsi_start_bb(bb); !gsi_end_p(gsi); gsi_next(&gsi)) {
            gimple* stmt = gsi_stmt(gsi);
            if (!is_gimple_call(stmt) || gimple_call_internal_p(stmt)) continue;
            tree fndecl = gimple_call_fndecl(stmt);
            if (fndecl == NULL_TREE) continue;
            std::string name = decl_name(fndecl);
            if (name.empty()) continue;
            std::string operation;
            unsigned first_operand = 0;  // index of the first argument that is not `this`
            bool method = is_cryptocontext_method(fndecl);
            if (method) {
                if (g_manifest.operations.count(name)) { operation = name; first_operand = 1; }
                else if (allowed_nonsemantic(name)) {
                    CallSite site = site_of(stmt);
                    std::string callee = qualified_name(fndecl);
                    std::string sid = site_id_for(site.file, site.line, site.column, callee);
                    record_site(sid, "allowed", "", callee, site.file, site.line, site.column, site.function, site.qualified);
                    gcall* call = gimple_build_call(g_rt.allowed, 1, string_literal(sid));
                    gsi_insert_before(&gsi, call, GSI_SAME_STMT);
                    ++g_allowed_sites;
                    continue;
                } else {
                    CallSite site = site_of(stmt);
                    std::string callee = qualified_name(fndecl);
                    std::string sid = site_id_for(site.file, site.line, site.column, callee);
                    record_site(sid, "unmatched", "", callee, site.file, site.line, site.column, site.function, site.qualified);
                    gcall* call = gimple_build_call(g_rt.unmatched, 2, string_literal(sid), string_literal(name));
                    gsi_insert_before(&gsi, call, GSI_SAME_STMT);
                    ++g_unmatched_sites;
                    if (g_config.debug) inform(gimple_location(stmt), "cipherscope: unmatched CryptoContextImpl call %s", name.c_str());
                    continue;
                }
            } else if (in_lbcrypto_namespace(fndecl)) {
                if (name == "GenCryptoContext" && gimple_call_num_args(stmt) >= 1) {
                    tree arg0 = gimple_call_arg(stmt, 0);
                    bool pointer_param = false;
                    Kind kind = classify_type(TREE_TYPE(arg0), &pointer_param);
                    std::string tname = type_name(POINTER_TYPE_P(TREE_TYPE(arg0)) ? TREE_TYPE(TREE_TYPE(arg0)) : TREE_TYPE(arg0));
                    if (kind == K_CCPARAMS && contains(tname, "CryptoContextCKKSRNS")) {
                        CallSite site = site_of(stmt);
                        std::string callee = qualified_name(fndecl);
                        std::string sid = site_id_for(site.file, site.line, site.column, callee);
                        record_site(sid, "declared_parameters", "GenCryptoContext", callee, site.file, site.line, site.column, site.function, site.qualified);
                        tree addr = operand_address(&gsi, arg0, kind, pointer_param);
                        if (addr != NULL_TREE) {
                            gcall* call = gimple_build_call(g_rt.params, 2, string_literal(sid), addr);
                            gsi_insert_before(&gsi, call, GSI_SAME_STMT);
                        }
                    }
                    continue;
                }
                // Operator templates: alias keyed by name and arity.
                std::string key = name + "/" + std::to_string(gimple_call_num_args(stmt));
                auto alias = g_manifest.operator_alias.find(key);
                if (alias == g_manifest.operator_alias.end()) continue;
                // Only the ciphertext forms are aliases; check the first operand's type.
                bool pp = false;
                if (classify_type(TREE_TYPE(gimple_call_arg(stmt, 0)), &pp) != K_CIPHERTEXT) continue;
                operation = alias->second;
                first_operand = 0;
            } else {
                continue;
            }

            // ---- instrument one semantic call ----
            CallSite site = site_of(stmt);
            std::string callee = qualified_name(fndecl);
            std::string sid = site_id_for(site.file, site.line, site.column, callee);
            record_site(sid, "operation", operation, callee, site.file, site.line, site.column, site.function, site.qualified);
            ++g_site_count;

            tree token = create_tmp_var(uint64_type_node, "cs_token");
            gcall* begin = gimple_build_call(g_rt.begin, 2, string_literal(operation), string_literal(sid));
            gimple_call_set_lhs(begin, token);
            gsi_insert_before(&gsi, begin, GSI_SAME_STMT);

            unsigned nargs = gimple_call_num_args(stmt);
            for (unsigned i = 0; i < nargs; ++i) {
                tree a = gimple_call_arg(stmt, i);
                bool pointer_param = false;
                Kind kind = classify_type(TREE_TYPE(a), &pointer_param);
                if (i == 0 && method) kind = K_CONTEXT;
                if (kind == K_PLAINTEXT_OUT || kind == K_PLAINTEXT) {
                    tree declared = declared_parameter_type(fndecl, i);
                    kind = (declared != NULL_TREE && TREE_CODE(declared) == POINTER_TYPE) ? K_PLAINTEXT_OUT : K_PLAINTEXT;
                }
                if (g_config.debug) {
                    tree t = TREE_TYPE(a);
                    tree shown = POINTER_TYPE_P(t) ? TREE_TYPE(t) : t;
                    inform(gimple_location(stmt), "cipherscope: %s arg %u kind %d type %s", operation.c_str(), i, kind, type_name(shown).c_str());
                }
                tree pointer = NULL_TREE, ivalue = NULL_TREE, dvalue = NULL_TREE;
                switch (kind) {
                    case K_INTEGER: case K_BOOL:
                        ivalue = force_gimple_operand_gsi(&gsi, fold_convert(long_long_integer_type_node, unshare_expr(a)),
                                                          true, NULL_TREE, true, GSI_SAME_STMT);
                        break;
                    case K_SCALAR:
                        dvalue = force_gimple_operand_gsi(&gsi, fold_convert(double_type_node, unshare_expr(a)),
                                                          true, NULL_TREE, true, GSI_SAME_STMT);
                        break;
                    case K_UNKNOWN:
                        break;
                    default:
                        pointer = operand_address(&gsi, a, kind, pointer_param);
                        if (pointer == NULL_TREE) kind = K_UNKNOWN;
                        break;
                }
                insert_arg_call(&gsi, token, kind, pointer, ivalue, dvalue);
            }
            (void)first_operand;

            // Result.
            tree lhs = gimple_call_lhs(stmt);
            Kind result_kind = K_VOID;
            tree result_ptr = fold_convert(const_ptr_type_node, null_pointer_node);
            if (lhs != NULL_TREE) {
                bool pp = false;
                result_kind = classify_type(TREE_TYPE(lhs), &pp);
                if (result_kind == K_PLAINTEXT_OUT) result_kind = K_PLAINTEXT;
                tree type = TREE_TYPE(lhs);
                if (TREE_CODE(type) == RECORD_TYPE) {
                    if (is_gimple_addressable(lhs)) {
                        // The address of the result slot is known before the
                        // call; materialise it into a temporary here so the
                        // post-call statement only reads a plain operand.
                        mark_addressable(lhs);
                        tree addr = fold_convert(const_ptr_type_node, build_fold_addr_expr(unshare_expr(lhs)));
                        result_ptr = force_gimple_operand_gsi(&gsi, addr, true, NULL_TREE, true, GSI_SAME_STMT);
                    } else {
                        result_kind = K_UNKNOWN;
                    }
                } else if (POINTER_TYPE_P(type)) {
                    // A reference return (operator+= yields Ciphertext&): the
                    // pointer value only exists after the call, so convert it
                    // in a statement placed after the call.
                    result_ptr = NULL_TREE;
                } else {
                    result_kind = K_UNKNOWN;
                }
            }
            if (result_ptr == NULL_TREE) {
                // Pointer-typed lhs: copy it into a const void* temporary after the call.
                tree tmp = create_tmp_var(const_ptr_type_node, "cs_result");
                gassign* copy = gimple_build_assign(tmp, NOP_EXPR, lhs);
                insert_after_call(&gsi, stmt, copy, &used_edges);
                result_ptr = tmp;
            }
            gcall* end = gimple_build_call(g_rt.end, 3, token, build_int_cst(integer_type_node, result_kind), result_ptr);
            insert_after_call(&gsi, stmt, end, &used_edges);
        }
    }
    if (used_edges) gsi_commit_edge_inserts();
    return 0;
}

// ---------------------------------------------------------------------------
// Plugin lifecycle.
// ---------------------------------------------------------------------------
void on_start_unit(void*, void*) {
    if (g_config.site_dir.empty() || !main_input_filename) return;
    std::string base = main_input_filename;
    std::string safe;
    for (char c : base) safe.push_back((isalnum(static_cast<unsigned char>(c)) || c == '.' || c == '-' || c == '_') ? c : '_');
    std::string path = g_config.site_dir + "/" + std::to_string(std::hash<std::string>{}(base)) + "-" + safe + ".sites.jsonl";
    g_sites.open(path);
    if (g_sites.is_open()) {
        std::string out = "{\"record\":\"translation_unit\",\"file\":";
        json_escape(out, base);
        out += ",\"manifest\":"; json_escape(out, g_config.manifest_name);
        out += ",\"frontend_version\":\"" + std::string(kFrontendVersion) + "\",\"gcc\":\"" + gcc_version.basever + "\"}\n";
        g_sites << out;
    }
}

void on_finish_unit(void*, void*) {
    if (!g_sites.is_open()) return;
    std::string out = "{\"record\":\"translation_unit_end\",\"instrumented_sites\":" + std::to_string(g_site_count) +
                      ",\"unmatched_sites\":" + std::to_string(g_unmatched_sites) +
                      ",\"allowed_sites\":" + std::to_string(g_allowed_sites) + "}\n";
    g_sites << out;
    g_sites.close();
}

}  // namespace

int plugin_init(struct plugin_name_args* info, struct plugin_gcc_version* version) {
    if (!plugin_default_version_check(version, &gcc_version)) {
        error("cipherscope: plugin built for GCC %s cannot load into GCC %s", gcc_version.basever, version->basever);
        return 1;
    }
    for (int i = 0; i < info->argc; ++i) {
        std::string key = info->argv[i].key ? info->argv[i].key : "";
        std::string value = info->argv[i].value ? info->argv[i].value : "";
        if (key == "manifest") g_config.manifest_path = value;
        else if (key == "site-dir") g_config.site_dir = value;
        else if (key == "debug") g_config.debug = true;
        else if (key == "permissive") g_config.strict = false;
    }
    if (g_config.manifest_path.empty() || !load_manifest(g_config.manifest_path)) {
        error("cipherscope: -fplugin-arg-%s-manifest=<file> is required and must list operations", info->base_name);
        return 1;
    }
    static struct plugin_info cs_info = {kFrontendVersion, "CipherScope OpenFHE semantic instrumentation"};
    register_callback(info->base_name, PLUGIN_INFO, nullptr, &cs_info);

    struct register_pass_info pass_info;
    pass_info.pass = new cs_pass(g);
    pass_info.reference_pass_name = "cfg";
    pass_info.ref_pass_instance_number = 1;
    pass_info.pos_op = PASS_POS_INSERT_AFTER;
    register_callback(info->base_name, PLUGIN_PASS_MANAGER_SETUP, nullptr, &pass_info);
    register_callback(info->base_name, PLUGIN_START_UNIT, on_start_unit, nullptr);
    register_callback(info->base_name, PLUGIN_FINISH_UNIT, on_finish_unit, nullptr);
    return 0;
}
