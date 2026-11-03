// Synthetic C++ compatibility/RAII/upgrade pilot: not a third-party library.
#include <cstdint>
#include <climits>
#include <map>
#include <memory>
#include <mutex>
#include <new>
#include <atomic>

#ifndef HIA_CPP_RELEASE
#define HIA_CPP_RELEASE 1
#endif

class Counter final {
public:
    explicit Counter(int32_t value) noexcept : count_(value) { live_.fetch_add(1); }
    ~Counter() noexcept { live_.fetch_sub(1); }
    int status_add(int32_t delta, int32_t* out) noexcept {
        const int64_t next = static_cast<int64_t>(count_) + delta;
        if (next > INT32_MAX || next < INT32_MIN) return 3;
#if HIA_CPP_RELEASE == 2
        // Synthetic upstream maintenance revision with the same observable ABI.
        count_ = static_cast<int32_t>(next);
#else
        count_ = static_cast<int32_t>(next);
#endif
        *out = count_;
        return 0;
    }
    static int live() noexcept { return live_.load(); }
private:
    int32_t count_;
    static std::atomic<int> live_;
};
std::atomic<int> Counter::live_{0};

static std::mutex registry_mutex;
static std::map<uint64_t, std::unique_ptr<Counter>> registry;
static uint64_t next_id = 1;

extern "C" int counter_create(int32_t value, uint64_t* out) noexcept {
    if (!out) return 1;
    try {
        std::lock_guard<std::mutex> guard(registry_mutex);
        if (next_id == UINT64_MAX) return 3;
        const uint64_t id = next_id;
        auto created = std::make_unique<Counter>(value);
        registry.emplace(id,std::move(created));
        ++next_id;
        *out = id;
        return 0;
    } catch (...) { return 4; }
}
extern "C" int counter_add(uint64_t handle,int32_t delta,int32_t* out) noexcept {
    if (!out) return 1;
    try {
        std::lock_guard<std::mutex> guard(registry_mutex);
        auto it=registry.find(handle);
        if (it==registry.end()) return 2;
        return it->second->status_add(delta,out);
    } catch (...) { return 4; }
}
extern "C" int counter_destroy(uint64_t handle) noexcept {
    try {
        std::lock_guard<std::mutex> guard(registry_mutex);
        auto it=registry.find(handle);
        if (it==registry.end()) return 2;
        registry.erase(it);
        return 0;
    } catch (...) { return 4; }
}
extern "C" int counter_live_count() noexcept {
    return Counter::live();
}
