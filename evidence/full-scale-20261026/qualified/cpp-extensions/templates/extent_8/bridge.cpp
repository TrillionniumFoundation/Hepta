// Generated bridge: foreign code and caller pointers remain unverified.
#include "bridge.h"
#include "/workspace/scratch/100b1728036f/Hepta-work/examples/cpp/template_sizes/foreign.hpp"
#include <cstdint>
#include <cstddef>
#include <type_traits>
#include <span>
#include <memory>
#include <mutex>
#include <thread>
#include <unordered_map>
#include <limits>
#include <utility>
#include <atomic>
using hepta_cpp_sized_add_signature = std::uint32_t(*)(std::uint32_t) noexcept;
static constexpr hepta_cpp_sized_add_signature hepta_cpp_sized_add_target = static_cast<hepta_cpp_sized_add_signature>(&sized_example::add_size<static_cast<std::size_t>(8)>);
extern "C" std::uint32_t hepta_cpp_sized_add(std::uint32_t hepta_arg0) noexcept {
    auto result = hepta_cpp_sized_add_target(static_cast<std::uint32_t>(hepta_arg0));
    return result;
}
namespace {
std::atomic<std::uint64_t> hepta_cpp_sized_next_handle{1};
std::uint64_t hepta_cpp_sized_allocate_handle() noexcept {
    auto current = hepta_cpp_sized_next_handle.load(std::memory_order_relaxed);
    while (current) {
        if (hepta_cpp_sized_next_handle.compare_exchange_weak(current, current + 1, std::memory_order_relaxed)) return current;
    }
    return 0;
}
[[maybe_unused]] const std::shared_ptr<const std::uint8_t>& hepta_cpp_sized_thread_token() {
    // A retained token distinguishes thread instances even when std::thread::id is reused.
    static thread_local const auto token = std::make_shared<const std::uint8_t>(0);
    return token;
}
}
namespace {
using hepta_cpp_sized_Array_object = std::array<std::uint32_t, static_cast<std::size_t>(8)>;
static_assert(std::is_nothrow_destructible_v<std::array<std::uint32_t, static_cast<std::size_t>(8)>>);
struct hepta_cpp_sized_Array_entry { std::recursive_mutex mutex; std::shared_ptr<std::array<std::uint32_t, static_cast<std::size_t>(8)>> object; std::shared_ptr<const std::uint8_t> creator; unsigned active = 0; };
struct hepta_cpp_sized_Array_registry { std::mutex mutex; std::unordered_map<std::uint64_t, std::shared_ptr<hepta_cpp_sized_Array_entry>> objects; };
// Process-lifetime registry avoids destroying abandoned affine objects on an arbitrary shutdown thread.
hepta_cpp_sized_Array_registry& hepta_cpp_sized_Array_registry_get() { static auto* r = new hepta_cpp_sized_Array_registry; return *r; }
struct hepta_cpp_sized_Array_active { hepta_cpp_sized_Array_entry& e; explicit hepta_cpp_sized_Array_active(hepta_cpp_sized_Array_entry& v): e(v) { ++e.active; } ~hepta_cpp_sized_Array_active() { --e.active; } };
}
static_assert(std::is_constructible_v<std::array<std::uint32_t, static_cast<std::size_t>(8)>>);
static_assert(std::is_nothrow_constructible_v<std::array<std::uint32_t, static_cast<std::size_t>(8)>>);
extern "C" std::int32_t hepta_cpp_sized_Array_new(std::uint64_t* out) noexcept {
    if (!out) return 1;
    if (reinterpret_cast<std::uintptr_t>(out) % alignof(std::uint64_t)) return 8;
    try {
        auto entry = std::make_shared<hepta_cpp_sized_Array_entry>();
        entry->object = std::make_shared<std::array<std::uint32_t, static_cast<std::size_t>(8)>>();
        auto handle = hepta_cpp_sized_allocate_handle();
        if (!handle) return 4;
        auto& registry = hepta_cpp_sized_Array_registry_get();
        std::lock_guard<std::mutex> lock(registry.mutex);
        if (!registry.objects.emplace(handle, entry).second) return 4;
        *out = handle;
        return 0;
    } catch (...) { return 3; }
}
extern "C" std::int32_t hepta_cpp_sized_Array_destroy(std::uint64_t handle) noexcept {
    try {
        auto& registry = hepta_cpp_sized_Array_registry_get();
        std::shared_ptr<hepta_cpp_sized_Array_entry> entry;
        {
            std::lock_guard<std::mutex> lock(registry.mutex);
            auto it = registry.objects.find(handle);
            if (it == registry.objects.end()) return 2;
            entry = it->second;
        }
        std::lock_guard<std::recursive_mutex> lock(entry->mutex);
        if (!entry->object) return 2;
        if (entry->active) return 6;
        {
            std::lock_guard<std::mutex> registry_lock(registry.mutex);
            auto it = registry.objects.find(handle);
            if (it == registry.objects.end() || it->second != entry) return 2;
            registry.objects.erase(it);
        }
        entry->object.reset();
        return 0;
    } catch (...) { return 3; }
}
static_assert(std::is_same_v<decltype(std::declval<std::array<std::uint32_t, static_cast<std::size_t>(8)>&>().fill(std::declval<const std::uint32_t&>())), void>);
extern "C" std::int32_t hepta_cpp_sized_Array_fill(std::uint64_t handle, std::uint32_t hepta_arg0) noexcept {
    try {
        auto& registry = hepta_cpp_sized_Array_registry_get();
        std::shared_ptr<hepta_cpp_sized_Array_entry> entry;
        {
            std::lock_guard<std::mutex> lock(registry.mutex);
            auto it = registry.objects.find(handle);
            if (it == registry.objects.end()) return 2;
            entry = it->second;
        }
        std::lock_guard<std::recursive_mutex> lock(entry->mutex);
        if (!entry->object) return 2;
        if (entry->active) return 6;
        auto object = entry->object;
        hepta_cpp_sized_Array_active active(*entry);
        std::array<std::uint32_t, static_cast<std::size_t>(8)>& receiver = *object;
        receiver.fill(static_cast<const std::uint32_t&>(hepta_arg0));
        return 0;
    } catch (...) { return 3; }
}
static_assert(std::is_reference_v<decltype(std::declval<const std::array<std::uint32_t, static_cast<std::size_t>(8)>&>().at(std::declval<std::size_t>()))> && std::is_same_v<std::remove_cvref_t<decltype(std::declval<const std::array<std::uint32_t, static_cast<std::size_t>(8)>&>().at(std::declval<std::size_t>()))>, std::uint32_t>);
extern "C" std::int32_t hepta_cpp_sized_Array_at(std::uint64_t handle, std::size_t hepta_arg0, std::uint32_t* out) noexcept {
    if (!out) return 1;
    if (reinterpret_cast<std::uintptr_t>(out) % alignof(std::uint32_t)) return 8;
    try {
        auto& registry = hepta_cpp_sized_Array_registry_get();
        std::shared_ptr<hepta_cpp_sized_Array_entry> entry;
        {
            std::lock_guard<std::mutex> lock(registry.mutex);
            auto it = registry.objects.find(handle);
            if (it == registry.objects.end()) return 2;
            entry = it->second;
        }
        std::lock_guard<std::recursive_mutex> lock(entry->mutex);
        if (!entry->object) return 2;
        if (entry->active) return 6;
        auto object = entry->object;
        hepta_cpp_sized_Array_active active(*entry);
        const std::array<std::uint32_t, static_cast<std::size_t>(8)>& receiver = *object;
        auto result = receiver.at(static_cast<std::size_t>(hepta_arg0));
        *out = result;
        return 0;
    } catch (...) { return 3; }
}
namespace {
using hepta_cpp_sized_Counted_object = sized_example::CountedArray<std::uint32_t, static_cast<std::size_t>(8)>;
static_assert(std::is_nothrow_destructible_v<sized_example::CountedArray<std::uint32_t, static_cast<std::size_t>(8)>>);
struct hepta_cpp_sized_Counted_entry { std::recursive_mutex mutex; std::shared_ptr<sized_example::CountedArray<std::uint32_t, static_cast<std::size_t>(8)>> object; std::shared_ptr<const std::uint8_t> creator; unsigned active = 0; };
struct hepta_cpp_sized_Counted_registry { std::mutex mutex; std::unordered_map<std::uint64_t, std::shared_ptr<hepta_cpp_sized_Counted_entry>> objects; };
// Process-lifetime registry avoids destroying abandoned affine objects on an arbitrary shutdown thread.
hepta_cpp_sized_Counted_registry& hepta_cpp_sized_Counted_registry_get() { static auto* r = new hepta_cpp_sized_Counted_registry; return *r; }
struct hepta_cpp_sized_Counted_active { hepta_cpp_sized_Counted_entry& e; explicit hepta_cpp_sized_Counted_active(hepta_cpp_sized_Counted_entry& v): e(v) { ++e.active; } ~hepta_cpp_sized_Counted_active() { --e.active; } };
}
static_assert(std::is_constructible_v<sized_example::CountedArray<std::uint32_t, static_cast<std::size_t>(8)>, std::uint32_t>);
extern "C" std::int32_t hepta_cpp_sized_Counted_new(std::uint32_t hepta_arg0, std::uint64_t* out) noexcept {
    if (!out) return 1;
    if (reinterpret_cast<std::uintptr_t>(out) % alignof(std::uint64_t)) return 8;
    try {
        auto entry = std::make_shared<hepta_cpp_sized_Counted_entry>();
        entry->object = std::make_shared<sized_example::CountedArray<std::uint32_t, static_cast<std::size_t>(8)>>(static_cast<std::uint32_t>(hepta_arg0));
        auto handle = hepta_cpp_sized_allocate_handle();
        if (!handle) return 4;
        auto& registry = hepta_cpp_sized_Counted_registry_get();
        std::lock_guard<std::mutex> lock(registry.mutex);
        if (!registry.objects.emplace(handle, entry).second) return 4;
        *out = handle;
        return 0;
    } catch (...) { return 3; }
}
extern "C" std::int32_t hepta_cpp_sized_Counted_destroy(std::uint64_t handle) noexcept {
    try {
        auto& registry = hepta_cpp_sized_Counted_registry_get();
        std::shared_ptr<hepta_cpp_sized_Counted_entry> entry;
        {
            std::lock_guard<std::mutex> lock(registry.mutex);
            auto it = registry.objects.find(handle);
            if (it == registry.objects.end()) return 2;
            entry = it->second;
        }
        std::lock_guard<std::recursive_mutex> lock(entry->mutex);
        if (!entry->object) return 2;
        if (entry->active) return 6;
        {
            std::lock_guard<std::mutex> registry_lock(registry.mutex);
            auto it = registry.objects.find(handle);
            if (it == registry.objects.end() || it->second != entry) return 2;
            registry.objects.erase(it);
        }
        entry->object.reset();
        return 0;
    } catch (...) { return 3; }
}
static_assert(std::is_same_v<decltype(std::declval<sized_example::CountedArray<std::uint32_t, static_cast<std::size_t>(8)>&>().fill(std::declval<const std::uint32_t&>())), void>);
extern "C" std::int32_t hepta_cpp_sized_Counted_fill(std::uint64_t handle, std::uint32_t hepta_arg0) noexcept {
    try {
        auto& registry = hepta_cpp_sized_Counted_registry_get();
        std::shared_ptr<hepta_cpp_sized_Counted_entry> entry;
        {
            std::lock_guard<std::mutex> lock(registry.mutex);
            auto it = registry.objects.find(handle);
            if (it == registry.objects.end()) return 2;
            entry = it->second;
        }
        std::lock_guard<std::recursive_mutex> lock(entry->mutex);
        if (!entry->object) return 2;
        if (entry->active) return 6;
        auto object = entry->object;
        hepta_cpp_sized_Counted_active active(*entry);
        sized_example::CountedArray<std::uint32_t, static_cast<std::size_t>(8)>& receiver = *object;
        receiver.fill(static_cast<const std::uint32_t&>(hepta_arg0));
        return 0;
    } catch (...) { return 3; }
}
static_assert(std::is_reference_v<decltype(std::declval<const sized_example::CountedArray<std::uint32_t, static_cast<std::size_t>(8)>&>().at(std::declval<std::size_t>()))> && std::is_same_v<std::remove_cvref_t<decltype(std::declval<const sized_example::CountedArray<std::uint32_t, static_cast<std::size_t>(8)>&>().at(std::declval<std::size_t>()))>, std::uint32_t>);
extern "C" std::int32_t hepta_cpp_sized_Counted_at(std::uint64_t handle, std::size_t hepta_arg0, std::uint32_t* out) noexcept {
    if (!out) return 1;
    if (reinterpret_cast<std::uintptr_t>(out) % alignof(std::uint32_t)) return 8;
    try {
        auto& registry = hepta_cpp_sized_Counted_registry_get();
        std::shared_ptr<hepta_cpp_sized_Counted_entry> entry;
        {
            std::lock_guard<std::mutex> lock(registry.mutex);
            auto it = registry.objects.find(handle);
            if (it == registry.objects.end()) return 2;
            entry = it->second;
        }
        std::lock_guard<std::recursive_mutex> lock(entry->mutex);
        if (!entry->object) return 2;
        if (entry->active) return 6;
        auto object = entry->object;
        hepta_cpp_sized_Counted_active active(*entry);
        const sized_example::CountedArray<std::uint32_t, static_cast<std::size_t>(8)>& receiver = *object;
        auto result = receiver.at(static_cast<std::size_t>(hepta_arg0));
        *out = result;
        return 0;
    } catch (...) { return 3; }
}
extern "C" std::int32_t hepta_cpp_sized_array_roundtrip(std::uint32_t hepta_arg0, std::size_t hepta_arg1, std::uint32_t* out) noexcept {
    if (!out) return 1;
    if (reinterpret_cast<std::uintptr_t>(out) % alignof(std::uint32_t)) return 8;
    try {
        auto _hepta_scoped_result = [&]() -> std::uint32_t {
            auto _hepta_scoped_object = std::array<std::uint32_t, static_cast<std::size_t>(8)>();
            (void)static_cast<std::array<std::uint32_t, static_cast<std::size_t>(8)>&>(_hepta_scoped_object).fill(static_cast<const std::uint32_t&>(hepta_arg0));
            return static_cast<const std::array<std::uint32_t, static_cast<std::size_t>(8)>&>(_hepta_scoped_object).at(static_cast<std::size_t>(hepta_arg1));
        }();
        *out = _hepta_scoped_result;
        return 0;
    } catch (...) { return 3; }
}
extern "C" std::int32_t hepta_cpp_sized_counted_roundtrip(std::uint32_t hepta_arg0, std::uint32_t hepta_arg1, std::size_t hepta_arg2, std::uint32_t* out) noexcept {
    if (!out) return 1;
    if (reinterpret_cast<std::uintptr_t>(out) % alignof(std::uint32_t)) return 8;
    try {
        auto _hepta_scoped_result = [&]() -> std::uint32_t {
            auto _hepta_scoped_object = sized_example::CountedArray<std::uint32_t, static_cast<std::size_t>(8)>(static_cast<std::uint32_t>(hepta_arg0));
            (void)static_cast<sized_example::CountedArray<std::uint32_t, static_cast<std::size_t>(8)>&>(_hepta_scoped_object).fill(static_cast<const std::uint32_t&>(hepta_arg1));
            return static_cast<const sized_example::CountedArray<std::uint32_t, static_cast<std::size_t>(8)>&>(_hepta_scoped_object).at(static_cast<std::size_t>(hepta_arg2));
        }();
        *out = _hepta_scoped_result;
        return 0;
    } catch (...) { return 3; }
}
