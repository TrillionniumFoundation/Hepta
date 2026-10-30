// Authored native boundary for the source-pinned partial INIReader migration.
// The real C parser/STL implementation remains foreign code, not proved Hepta.
#ifndef HEPTA_INIH_CALLBACK_HPP
#define HEPTA_INIH_CALLBACK_HPP

#include <array>
#include <atomic>
#include <cstdint>
#include <cstdlib>
#include <exception>
#include <limits>
#include <stdexcept>

#if INI_HANDLER_LINENO != 0 || INI_STOP_ON_FIRST_ERROR != 1
#error The scoped INIReader adapter requires the registered callback ABI and first-error exit.
#endif

extern "C" {
uint32_t hia_ini_bool_step(uint32_t state, uint32_t byte);
uint32_t hia_ini_bool_finish(uint32_t state, uint32_t fallback);
uint32_t hia_ini_error_kind(int32_t error);
uint32_t hia_ini_callback_action(uint32_t has_name, uint32_t has_value, uint32_t nonempty);
uint32_t hia_ini_lease_step(uint32_t phase, uint32_t event);
}

namespace hepta_ini {

static_assert(sizeof(uintptr_t) == sizeof(uint64_t), "qualified LP64 callback token profile");

struct Lease {
    uintptr_t token;
    void* owner;
    uint32_t phase;
    std::exception_ptr failure;
};

// Actual owner addresses stay in this thread's private, allocation-free table.
// The C parser receives only an opaque integer token, never a dereferenceable
// pointer to a stack lease. Tokens are process-unique and never recycled.
inline thread_local std::array<Lease*, 32> leases{};
inline std::atomic<uint64_t> next_token{1};
inline thread_local uintptr_t last_token = 0;
inline thread_local uint64_t accepted_callbacks = 0;
inline thread_local uint64_t denied_callbacks = 0;

inline uintptr_t fresh_token() {
    uint64_t value = next_token.load(std::memory_order_relaxed);
    for (;;) {
        if (value == std::numeric_limits<uint64_t>::max()) {
            throw std::overflow_error("Hepta INIReader callback token space exhausted");
        }
        if (next_token.compare_exchange_weak(value, value + 1, std::memory_order_relaxed)) {
            return static_cast<uintptr_t>(value);
        }
    }
}

inline size_t active_leases() noexcept {
    size_t count = 0;
    for (auto* lease : leases) { count += lease != nullptr; }
    return count;
}

class ScopedBorrow final {
    Lease lease_{};
    size_t slot_ = 0;
public:
    explicit ScopedBorrow(void* owner) {
        if (!owner) { throw std::invalid_argument("null INIReader callback owner"); }
        for (auto* existing : leases) {
            if (existing && existing->owner == owner) {
                throw std::logic_error("INIReader owner already has a live callback lease");
            }
        }
        while (slot_ < leases.size() && leases[slot_] != nullptr) { ++slot_; }
        if (slot_ == leases.size()) {
            throw std::overflow_error("Hepta INIReader callback nesting quota exceeded");
        }
        const uint32_t phase = hia_ini_lease_step(0, 0);
        if (phase != 1) { throw std::logic_error("invalid Hepta callback admission"); }
        lease_.token = fresh_token();
        lease_.owner = owner;
        lease_.phase = phase;
        leases[slot_] = &lease_;
        last_token = lease_.token;
    }
    ScopedBorrow(const ScopedBorrow&) = delete;
    ScopedBorrow& operator=(const ScopedBorrow&) = delete;
    ScopedBorrow(ScopedBorrow&&) = delete;
    ScopedBorrow& operator=(ScopedBorrow&&) = delete;
    ~ScopedBorrow() noexcept {
        // A live nested callback would invalidate a pointer into this scope.
        // Refuse by terminating before destroying the owner's registration.
        const uint32_t phase = hia_ini_lease_step(lease_.phase, 3);
        if (phase != 3 || leases[slot_] != &lease_) { std::abort(); }
        lease_.phase = phase;
        leases[slot_] = nullptr;
        lease_.owner = nullptr;
    }
    void* user() const noexcept { return reinterpret_cast<void*>(lease_.token); }
    uintptr_t token() const noexcept { return lease_.token; }
    void rethrow_pending() const {
        if (lease_.failure) { std::rethrow_exception(lease_.failure); }
    }
};

class CallbackInvocation final {
    Lease* lease_ = nullptr;
public:
    explicit CallbackInvocation(void* user) noexcept {
        const uintptr_t token = reinterpret_cast<uintptr_t>(user);
        // Only compare opaque token integers. No untrusted user pointer is read.
        for (auto* candidate : leases) {
            if (candidate && candidate->token == token) {
                const uint32_t phase = hia_ini_lease_step(candidate->phase, 1);
                if (phase == 2 && !candidate->failure) {
                    candidate->phase = phase;
                    lease_ = candidate;
                    ++accepted_callbacks;
                    return;
                }
                break;
            }
        }
        ++denied_callbacks;
    }
    CallbackInvocation(const CallbackInvocation&) = delete;
    CallbackInvocation& operator=(const CallbackInvocation&) = delete;
    CallbackInvocation(CallbackInvocation&&) = delete;
    CallbackInvocation& operator=(CallbackInvocation&&) = delete;
    ~CallbackInvocation() noexcept {
        if (lease_) {
            const uint32_t phase = hia_ini_lease_step(lease_->phase, 2);
            if (phase != 1) { std::abort(); }
            lease_->phase = phase;
        }
    }
    explicit operator bool() const noexcept { return lease_ != nullptr; }
    void* owner() const noexcept { return lease_ ? lease_->owner : nullptr; }
    void capture_failure() noexcept {
        if (lease_) { lease_->failure = std::current_exception(); }
    }
};

} // namespace hepta_ini
#endif
