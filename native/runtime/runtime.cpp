// CipherScope native runtime: identity, versions, nesting, timing, spool.
//
// Implements the C ABI in include/cipherscope/runtime.h for OpenFHE programs
// compiled with the CipherScope GCC plugin. The runtime records what it
// observes into a JSON Lines spool (an internal format, not the public trace);
// cipherscope.native_trace turns the spool into the canonical trace. The
// runtime never interprets FHE semantics beyond reading the metadata the trace
// schema carries, and never serialises native pointers, key material,
// coefficients or plaintext values.
//
// Invariants preserved from the Python frontend:
//   * the native call runs exactly once; nothing here re-invokes it;
//   * one semantic event per public-API call: instrumented calls made while
//     another instrumented call is open on the same thread are folded into the
//     outer event (openfhe_api_inclusive granularity);
//   * a call that unwinds (throws) past its cs_event_end is closed as an error
//     event the next time this thread begins an event or at finalisation;
//   * hard limits stop recording, never the workload.

#include "cipherscope/runtime.h"

#include <algorithm>
#include <atomic>
#include <cerrno>
#include <chrono>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <memory>
#include <mutex>
#include <string>
#include <thread>
#include <unordered_map>
#include <vector>

#include <pthread.h>
#include <sys/syscall.h>
#include <sys/types.h>
#include <time.h>
#include <unistd.h>

#include "adapter.h"

namespace cs {
namespace {

// ---------------------------------------------------------------------------
// Clocks. The manifest reports these names under run.clocks.
// ---------------------------------------------------------------------------
int64_t clock_ns(clockid_t id) {
    timespec ts{};
    clock_gettime(id, &ts);
    return static_cast<int64_t>(ts.tv_sec) * 1000000000LL + ts.tv_nsec;
}

int64_t native_thread_id() {
    return static_cast<int64_t>(syscall(SYS_gettid));
}

// ---------------------------------------------------------------------------
// Minimal JSON string escaping for the spool.
// ---------------------------------------------------------------------------
void append_json_string(std::string& out, const char* text) {
    out.push_back('"');
    for (const unsigned char* p = reinterpret_cast<const unsigned char*>(text); *p; ++p) {
        switch (*p) {
            case '"': out += "\\\""; break;
            case '\\': out += "\\\\"; break;
            case '\n': out += "\\n"; break;
            case '\r': out += "\\r"; break;
            case '\t': out += "\\t"; break;
            default:
                if (*p < 0x20) {
                    char buffer[8];
                    std::snprintf(buffer, sizeof buffer, "\\u%04x", *p);
                    out += buffer;
                } else {
                    out.push_back(static_cast<char>(*p));
                }
        }
    }
    out.push_back('"');
}

void append_json_string(std::string& out, const std::string& text) {
    append_json_string(out, text.c_str());
}

// ---------------------------------------------------------------------------
// Registry: native object -> opaque ID. Ciphertexts are versioned; a raw
// address that is reused after destruction never inherits the old ID because
// the stored weak reference no longer resolves to the same object.
// ---------------------------------------------------------------------------
}  // namespace

struct CiphertextEntry {
    std::string id;           // "ct_0042"
    uint32_t version = 0;     // current version
    std::weak_ptr<const void> witness;  // expires with the native object
};

class Registry {
public:
    // Returns "ct_NNNN" and the current version; registers unseen objects.
    std::pair<std::string, uint32_t> ciphertext(const void* raw, std::shared_ptr<const void> witness, bool* is_new) {
        auto found = ciphertexts_.find(raw);
        if (found != ciphertexts_.end()) {
            auto live = found->second.witness.lock();
            if (live && live.get() == raw) {
                if (is_new) *is_new = false;
                return {found->second.id, found->second.version};
            }
            // Address reuse: the previous object at this address is gone.
            ciphertexts_.erase(found);
        }
        CiphertextEntry entry;
        entry.id = format_id("ct_", ++ciphertext_counter_);
        entry.witness = witness;
        auto inserted = ciphertexts_.emplace(raw, std::move(entry)).first;
        if (is_new) *is_new = true;
        return {inserted->second.id, inserted->second.version};
    }

    uint32_t bump_version(const void* raw) {
        auto found = ciphertexts_.find(raw);
        if (found == ciphertexts_.end()) return 0;
        return ++found->second.version;
    }

    std::string context(const void* raw) {
        auto found = contexts_.find(raw);
        if (found != contexts_.end()) return found->second;
        std::string id = format_id("context_", contexts_.size() + 1);
        contexts_.emplace(raw, id);
        return id;
    }

    bool context_known(const void* raw) const { return contexts_.count(raw) != 0; }
    size_t context_count() const { return contexts_.size(); }

    static std::string format_id(const char* prefix, size_t number) {
        char buffer[32];
        std::snprintf(buffer, sizeof buffer, "%s%04zu", prefix, number);
        return buffer;
    }

private:
    std::unordered_map<const void*, CiphertextEntry> ciphertexts_;
    std::unordered_map<const void*, std::string> contexts_;
    size_t ciphertext_counter_ = 0;

public:
    // Ordered view for the contexts record at finalisation.
    std::vector<std::pair<const void*, std::string>> contexts_ordered() const {
        std::vector<std::pair<const void*, std::string>> out(contexts_.begin(), contexts_.end());
        std::sort(out.begin(), out.end(), [](auto& a, auto& b) { return a.second < b.second; });
        return out;
    }
};

namespace {

// ---------------------------------------------------------------------------
// One open event on a thread.
// ---------------------------------------------------------------------------
struct OpenEvent {
    cs_token token = 0;
    const char* operation = nullptr;
    const char* site_id = nullptr;
    int64_t sequence = 0;
    int64_t wall_start = 0, cpu_start = 0, thread_start = 0;
    std::string record;      // partially built JSON line: arguments and input states
    std::vector<const void*> ciphertext_args;    // raw shared_ptr addresses, call order
    std::vector<std::string> ciphertext_ids;     // "ct_0007:v1" per ciphertext arg
    int mutated_argument = -1;                    // manifest: index of the in-place operand
    size_t argument_index = 0;
    bool recorded = false;
};

class Runtime;

struct ThreadState {
    OpenEvent open;      // token != 0 while a recorded event is open
    ThreadState();
    ~ThreadState();      // closes an event left open by an unwinding call
    ThreadState(const ThreadState&) = delete;
    ThreadState& operator=(const ThreadState&) = delete;
};

// ---------------------------------------------------------------------------
// The runtime singleton.
// ---------------------------------------------------------------------------
class Runtime {
public:
    static Runtime& instance() {
        static Runtime runtime;
        return runtime;
    }

    Runtime() {
        const char* spool = std::getenv("CIPHERSCOPE_NATIVE_SPOOL");
        spool_path_ = spool ? spool : "";
        if (const char* limit = std::getenv("CIPHERSCOPE_MAX_EVENTS")) max_events_ = std::strtoll(limit, nullptr, 10);
        if (const char* limit = std::getenv("CIPHERSCOPE_MAX_TRACE_BYTES")) max_bytes_ = std::strtoll(limit, nullptr, 10);
        if (!spool_path_.empty()) {
            file_ = std::fopen(spool_path_.c_str(), "w");
            if (file_) {
                std::string header = "{\"record\":\"run_begin\",\"abi_version\":" +
                    std::to_string(CIPHERSCOPE_RUNTIME_ABI_VERSION) +
                    ",\"frontend\":\"" CIPHERSCOPE_FRONTEND_NAME "\",\"frontend_version\":\"" CIPHERSCOPE_FRONTEND_VERSION "\"" +
                    ",\"pid\":" + std::to_string(getpid()) +
                    ",\"wall_start_ns\":" + std::to_string(clock_ns(CLOCK_MONOTONIC)) +
                    ",\"framework_version\":" ;
                append_json_string(header, adapter::framework_version());
                header += "}\n";
                write_locked(header);
            }
        }
        std::atexit([] { cs_finalize(); });
    }

    ~Runtime() { finalize(); }

    ThreadState& thread_state() {
        thread_local ThreadState state;
        return state;
    }

    cs_token begin(const char* operation, const char* site_id) {
        ThreadState& ts = thread_state();
        if (ts.open.token != 0) {
            // The previous instrumented call on this thread never reached
            // cs_event_end: it left by exception. Close it as an error event
            // before opening the next one. (The plugin never instruments
            // OpenFHE's own code, so an instrumented call cannot legitimately
            // be nested inside another; a user callback invoked by OpenFHE
            // that itself calls the API would be misread as an unwind.)
            close_unwound(ts);
        }
        if (!accepting()) {
            calls_dropped_.fetch_add(1, std::memory_order_relaxed);
            return 0;
        }
        OpenEvent& ev = ts.open;
        ev = OpenEvent{};
        ev.token = next_token_.fetch_add(1, std::memory_order_relaxed) + 1;
        ev.operation = operation;
        ev.site_id = site_id;
        ev.sequence = next_sequence_.fetch_add(1, std::memory_order_relaxed) + 1;
        ev.mutated_argument = adapter::mutated_argument(operation);
        ev.wall_start = clock_ns(CLOCK_MONOTONIC);
        ev.cpu_start = clock_ns(CLOCK_PROCESS_CPUTIME_ID);
        ev.thread_start = clock_ns(CLOCK_THREAD_CPUTIME_ID);
        ev.record.reserve(512);
        ev.record += "{\"record\":\"event\",\"sequence\":" + std::to_string(ev.sequence);
        ev.record += ",\"operation\":"; append_json_string(ev.record, operation);
        ev.record += ",\"site_id\":"; append_json_string(ev.record, site_id);
        ev.record += ",\"thread_id\":" + std::to_string(native_thread_id());
        ev.record += ",\"arguments\":[";
        return ev.token;
    }

    void argument(cs_token token, int kind, const void* pointer, int64_t ivalue, double dvalue) {
        if (token == 0) return;
        ThreadState& ts = thread_state();
        OpenEvent& ev = ts.open;
        if (ev.token != token) return;
        std::lock_guard<std::mutex> guard(registry_mutex_);
        if (ev.argument_index++ > 0) ev.record += ",";
        ev.record += "{";
        adapter::describe_argument(ev.record, &registry_, kind, pointer, ivalue, dvalue, &ev.ciphertext_args, &ev.ciphertext_ids);
        ev.record += "}";
    }

    void end(cs_token token, int result_kind, const void* result) {
        if (token == 0) return;
        ThreadState& ts = thread_state();
        OpenEvent& ev = ts.open;
        if (ev.token != token) return;
        int64_t wall_end = clock_ns(CLOCK_MONOTONIC);
        int64_t cpu_end = clock_ns(CLOCK_PROCESS_CPUTIME_ID);
        int64_t thread_end = clock_ns(CLOCK_THREAD_CPUTIME_ID);
        {
            std::lock_guard<std::mutex> guard(registry_mutex_);
            ev.record += "],\"status\":\"ok\"";
            ev.record += ",\"result\":{";
            adapter::describe_result(ev.record, &registry_, ev.operation, result_kind, result,
                                     ev.mutated_argument, ev.ciphertext_args, ev.ciphertext_ids);
            ev.record += "}";
        }
        ev.record += ",\"timing\":{\"start_ns\":" + std::to_string(ev.wall_start) +
                     ",\"wall_duration_ns\":" + std::to_string(wall_end - ev.wall_start) +
                     ",\"process_cpu_duration_ns\":" + std::to_string(cpu_end - ev.cpu_start) +
                     ",\"thread_cpu_duration_ns\":" + std::to_string(thread_end - ev.thread_start) + "}}\n";
        emit(ts, ev.record);
        traced_.fetch_add(1, std::memory_order_relaxed);
        ev = OpenEvent{};
    }

    void unmatched(const char* site_id, const char* name) {
        unmatched_.fetch_add(1, std::memory_order_relaxed);
        std::string line = "{\"record\":\"unmatched\",\"site_id\":";
        append_json_string(line, site_id);
        line += ",\"name\":"; append_json_string(line, name);
        line += ",\"sequence\":" + std::to_string(next_sequence_.fetch_add(1) + 1) + "}\n";
        emit(thread_state(), line);
    }

    void allowed(const char*) { allowed_.fetch_add(1, std::memory_order_relaxed); }

    void declared_parameters(const char* site_id, const void* params) {
        std::string line = "{\"record\":\"declared_parameters\",\"site_id\":";
        append_json_string(line, site_id);
        line += ",\"parameters\":{";
        adapter::describe_ccparams(line, params);
        line += "}}\n";
        emit(thread_state(), line);
    }

    // Thread states register themselves so finalisation can close events left
    // open on threads that are still alive; a thread that exits first closes
    // its own in ~ThreadState. Never touch thread_local storage from here: at
    // process exit the main thread's TLS is destroyed before this object.
    void register_thread(ThreadState* state) {
        std::lock_guard<std::mutex> guard(threads_mutex_);
        threads_.push_back(state);
    }

    void unregister_thread(ThreadState* state) {
        std::lock_guard<std::mutex> guard(threads_mutex_);
        threads_.erase(std::remove(threads_.begin(), threads_.end(), state), threads_.end());
    }

    void close_open_event(ThreadState& ts) {
        if (ts.open.token != 0) close_unwound(ts);
    }

    void finalize() {
        std::lock_guard<std::mutex> guard(finalize_mutex_);
        if (finalized_) return;
        finalized_ = true;
        {
            std::lock_guard<std::mutex> threads_guard(threads_mutex_);
            for (ThreadState* state : threads_) close_open_event(*state);
            threads_.clear();
        }
        {
            std::lock_guard<std::mutex> registry_guard(registry_mutex_);
            std::string contexts = "{\"record\":\"contexts\",\"contexts\":[";
            adapter::describe_contexts(contexts, &registry_);
            contexts += "]}\n";
            write_locked(contexts);
        }
        std::string footer = "{\"record\":\"run_end\"";
        footer += ",\"traced_semantic_calls\":" + std::to_string(traced_.load());
        footer += ",\"nested_internal_calls\":" + std::to_string(nested_internal_.load());
        footer += ",\"unmatched_candidates\":" + std::to_string(unmatched_.load());
        footer += ",\"allowed_passthrough_calls\":" + std::to_string(allowed_.load());
        footer += ",\"unwound_calls\":" + std::to_string(unwound_.load());
        footer += ",\"calls_dropped\":" + std::to_string(calls_dropped_.load());
        footer += ",\"truncated\":" + std::string(truncated_ ? "true" : "false");
        footer += ",\"truncation_reason\":";
        if (truncated_) append_json_string(footer, truncation_reason_); else footer += "null";
        footer += ",\"events_written\":" + std::to_string(events_written_.load());
        footer += ",\"bytes_written\":" + std::to_string(bytes_written_.load());
        footer += ",\"wall_end_ns\":" + std::to_string(clock_ns(CLOCK_MONOTONIC)) + "}\n";
        write_locked(footer);
        if (file_) { std::fclose(file_); file_ = nullptr; }
    }

    // Called by the adapter with the registry lock held.
    Registry& registry() { return registry_; }

private:
    bool accepting() { std::lock_guard<std::mutex> guard(write_mutex_); return !truncated_; }

    void close_unwound(ThreadState& ts) {
        OpenEvent& ev = ts.open;
        int64_t now = clock_ns(CLOCK_MONOTONIC);
        ev.record += "],\"status\":\"error\",\"error_class\":\"native_unwound\"";
        ev.record += ",\"error_message\":\"the native call exited by exception before the instrumentation observed a result\"";
        ev.record += ",\"result\":{\"kind\":\"none\"}";
        ev.record += ",\"timing\":{\"start_ns\":" + std::to_string(ev.wall_start) +
                     ",\"wall_duration_ns\":" + std::to_string(now - ev.wall_start) +
                     ",\"process_cpu_duration_ns\":" + std::to_string(clock_ns(CLOCK_PROCESS_CPUTIME_ID) - ev.cpu_start) +
                     ",\"thread_cpu_duration_ns\":" + std::to_string(clock_ns(CLOCK_THREAD_CPUTIME_ID) - ev.thread_start) + "}}\n";
        emit(ts, ev.record);
        unwound_.fetch_add(1, std::memory_order_relaxed);
        traced_.fetch_add(1, std::memory_order_relaxed);
        ev = OpenEvent{};
    }

    // One locked append per record. FHE operations cost milliseconds, so the
    // lock is not a bottleneck, and no per-thread buffer can be lost when a
    // worker thread exits before finalisation.
    void emit(ThreadState&, const std::string& line) {
        std::lock_guard<std::mutex> guard(write_mutex_);
        if (truncated_) return;
        events_written_.fetch_add(1, std::memory_order_relaxed);
        int64_t bytes = bytes_written_.fetch_add(static_cast<int64_t>(line.size()), std::memory_order_relaxed) + static_cast<int64_t>(line.size());
        if (file_) {
            std::fwrite(line.data(), 1, line.size(), file_);
            std::fflush(file_);
        }
        if (max_events_ > 0 && events_written_.load() >= max_events_) { truncated_ = true; truncation_reason_ = "max_events"; }
        else if (max_bytes_ > 0 && bytes >= max_bytes_) { truncated_ = true; truncation_reason_ = "max_trace_bytes"; }
    }

    void write_locked(const std::string& text) {
        std::lock_guard<std::mutex> guard(write_mutex_);
        if (!file_) return;
        std::fwrite(text.data(), 1, text.size(), file_);
        std::fflush(file_);
    }

    std::string spool_path_;
    FILE* file_ = nullptr;
    std::mutex write_mutex_;
    std::mutex registry_mutex_;
    std::mutex finalize_mutex_;
    std::mutex threads_mutex_;
    std::vector<ThreadState*> threads_;
    Registry registry_;
    std::atomic<int64_t> next_token_{0};
    std::atomic<int64_t> next_sequence_{0};
    std::atomic<int64_t> traced_{0};
    std::atomic<int64_t> nested_internal_{0};
    std::atomic<int64_t> unmatched_{0};
    std::atomic<int64_t> allowed_{0};
    std::atomic<int64_t> unwound_{0};
    std::atomic<int64_t> calls_dropped_{0};
    std::atomic<int64_t> events_written_{0};
    std::atomic<int64_t> bytes_written_{0};
    int64_t max_events_ = 0;
    int64_t max_bytes_ = 0;
    bool truncated_ = false;
    std::string truncation_reason_;
    bool finalized_ = false;
};

ThreadState::ThreadState() { Runtime::instance().register_thread(this); }

ThreadState::~ThreadState() {
    Runtime& runtime = Runtime::instance();
    runtime.close_open_event(*this);
    runtime.unregister_thread(this);
}

}  // namespace

}  // namespace cs

namespace cs {
std::vector<std::pair<const void*, std::string>> registry_contexts(void* registry) {
    return static_cast<cs::Registry*>(registry)->contexts_ordered();
}
}  // namespace cs

// ---------------------------------------------------------------------------
// Registry access for the adapter (see adapter.h).
// ---------------------------------------------------------------------------
namespace cs::adapter {

std::pair<std::string, uint32_t> registry_ciphertext(void* registry, const void* raw, std::shared_ptr<const void> witness, bool* is_new) {
    return static_cast<cs::Registry*>(registry)->ciphertext(raw, std::move(witness), is_new);
}
uint32_t registry_bump_version(void* registry, const void* raw) {
    return static_cast<cs::Registry*>(registry)->bump_version(raw);
}
std::string registry_context(void* registry, const void* raw) {
    return static_cast<cs::Registry*>(registry)->context(raw);
}

}  // namespace cs::adapter

// ---------------------------------------------------------------------------
// C ABI.
// ---------------------------------------------------------------------------
extern "C" {

cs_token cs_event_begin(const char* operation, const char* site_id) {
    return cs::Runtime::instance().begin(operation, site_id);
}

void cs_event_arg(cs_token token, int kind, const void* pointer, int64_t ivalue, double dvalue) {
    cs::Runtime::instance().argument(token, kind, pointer, ivalue, dvalue);
}

void cs_event_end(cs_token token, int result_kind, const void* result) {
    cs::Runtime::instance().end(token, result_kind, result);
}

void cs_unmatched_call(const char* site_id, const char* qualified_name) {
    cs::Runtime::instance().unmatched(site_id, qualified_name);
}

void cs_allowed_call(const char* site_id) {
    cs::Runtime::instance().allowed(site_id);
}

void cs_declared_parameters(const char* site_id, const void* ccparams) {
    cs::Runtime::instance().declared_parameters(site_id, ccparams);
}

void cs_finalize(void) {
    cs::Runtime::instance().finalize();
}

}  // extern "C"

// The instrumented binary carries this marker in its own section so that
// `cipherscope profile` can tell an instrumented target from a plain one.
__attribute__((used, section(".cipherscope.marker")))
static const char cipherscope_marker[] =
    "cipherscope.instrumented=true;frontend=" CIPHERSCOPE_FRONTEND_NAME
    ";frontend_version=" CIPHERSCOPE_FRONTEND_VERSION ";schema_major=1;abi=1";
