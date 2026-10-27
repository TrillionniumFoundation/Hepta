// Generated bridge: foreign code and caller pointers remain unverified.
#include "bridge.h"
#include "/workspace/scratch/c7c6ee414a6c/hepta-research/artifacts/cpp-upgrade-20261025T171524382241Z/3.12.0/selected.hpp"
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
namespace {
std::atomic<std::uint64_t> hepta_cpp_json_upgrade_next_handle{1};
std::uint64_t hepta_cpp_json_upgrade_allocate_handle() noexcept {
    auto current = hepta_cpp_json_upgrade_next_handle.load(std::memory_order_relaxed);
    while (current) {
        if (hepta_cpp_json_upgrade_next_handle.compare_exchange_weak(current, current + 1, std::memory_order_relaxed)) return current;
    }
    return 0;
}
[[maybe_unused]] const std::shared_ptr<const std::uint8_t>& hepta_cpp_json_upgrade_thread_token() {
    // A retained token distinguishes thread instances even when std::thread::id is reused.
    static thread_local const auto token = std::make_shared<const std::uint8_t>(0);
    return token;
}
}
namespace {
using hepta_cpp_json_upgrade_Document_object = hepta_json_upgrade::Document;
static_assert(std::is_nothrow_destructible_v<hepta_json_upgrade::Document>);
struct hepta_cpp_json_upgrade_Document_entry { std::recursive_mutex mutex; std::shared_ptr<hepta_json_upgrade::Document> object; std::shared_ptr<const std::uint8_t> creator; unsigned active = 0; };
struct hepta_cpp_json_upgrade_Document_registry { std::mutex mutex; std::unordered_map<std::uint64_t, std::shared_ptr<hepta_cpp_json_upgrade_Document_entry>> objects; };
// Process-lifetime registry avoids destroying abandoned affine objects on an arbitrary shutdown thread.
hepta_cpp_json_upgrade_Document_registry& hepta_cpp_json_upgrade_Document_registry_get() { static auto* r = new hepta_cpp_json_upgrade_Document_registry; return *r; }
struct hepta_cpp_json_upgrade_Document_active { hepta_cpp_json_upgrade_Document_entry& e; explicit hepta_cpp_json_upgrade_Document_active(hepta_cpp_json_upgrade_Document_entry& v): e(v) { ++e.active; } ~hepta_cpp_json_upgrade_Document_active() { --e.active; } };
}
static_assert(std::is_constructible_v<hepta_json_upgrade::Document, std::span<const std::uint8_t>>);
extern "C" std::int32_t hepta_cpp_json_upgrade_Document_parse(const std::uint8_t* hepta_arg0, std::size_t hepta_arg0_len, std::uint64_t* out) noexcept {
    if (!out) return 1;
    if (reinterpret_cast<std::uintptr_t>(out) % alignof(std::uint64_t)) return 8;
    if (hepta_arg0_len && !hepta_arg0) return 1;
    if (hepta_arg0_len > static_cast<std::size_t>((std::numeric_limits<std::ptrdiff_t>::max)()) / sizeof(std::uint8_t)) return 7;
    if (reinterpret_cast<std::uintptr_t>(hepta_arg0) % alignof(std::uint8_t)) return 8;
    try {
        auto entry = std::make_shared<hepta_cpp_json_upgrade_Document_entry>();
        entry->object = std::make_shared<hepta_json_upgrade::Document>(std::span<const std::uint8_t>(hepta_arg0, hepta_arg0_len));
        auto handle = hepta_cpp_json_upgrade_allocate_handle();
        if (!handle) return 4;
        auto& registry = hepta_cpp_json_upgrade_Document_registry_get();
        std::lock_guard<std::mutex> lock(registry.mutex);
        if (!registry.objects.emplace(handle, entry).second) return 4;
        *out = handle;
        return 0;
    } catch (...) { return 3; }
}
extern "C" std::int32_t hepta_cpp_json_upgrade_Document_destroy(std::uint64_t handle) noexcept {
    try {
        auto& registry = hepta_cpp_json_upgrade_Document_registry_get();
        std::shared_ptr<hepta_cpp_json_upgrade_Document_entry> entry;
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
static_assert(std::is_same_v<decltype(std::declval<hepta_json_upgrade::Document&>().replace(std::declval<std::size_t>(), std::declval<std::int64_t>())), void>);
extern "C" std::int32_t hepta_cpp_json_upgrade_Document_replace(std::uint64_t handle, std::size_t hepta_arg0, std::int64_t hepta_arg1) noexcept {
    try {
        auto& registry = hepta_cpp_json_upgrade_Document_registry_get();
        std::shared_ptr<hepta_cpp_json_upgrade_Document_entry> entry;
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
        hepta_cpp_json_upgrade_Document_active active(*entry);
        hepta_json_upgrade::Document& receiver = *object;
        receiver.replace(static_cast<std::size_t>(hepta_arg0), static_cast<std::int64_t>(hepta_arg1));
        return 0;
    } catch (...) { return 3; }
}
static_assert(std::is_same_v<decltype(std::declval<const hepta_json_upgrade::Document&>().sum()), std::int64_t>);
extern "C" std::int32_t hepta_cpp_json_upgrade_Document_sum(std::uint64_t handle, std::int64_t* out) noexcept {
    if (!out) return 1;
    if (reinterpret_cast<std::uintptr_t>(out) % alignof(std::int64_t)) return 8;
    try {
        auto& registry = hepta_cpp_json_upgrade_Document_registry_get();
        std::shared_ptr<hepta_cpp_json_upgrade_Document_entry> entry;
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
        hepta_cpp_json_upgrade_Document_active active(*entry);
        const hepta_json_upgrade::Document& receiver = *object;
        auto result = receiver.sum();
        *out = result;
        return 0;
    } catch (...) { return 3; }
}
extern "C" std::int32_t hepta_cpp_json_upgrade_replace_sum(const std::uint8_t* hepta_arg0, std::size_t hepta_arg0_len, std::size_t hepta_arg1, std::int64_t hepta_arg2, std::int64_t* out) noexcept {
    if (!out) return 1;
    if (reinterpret_cast<std::uintptr_t>(out) % alignof(std::int64_t)) return 8;
    if (hepta_arg0_len && !hepta_arg0) return 1;
    if (hepta_arg0_len > static_cast<std::size_t>((std::numeric_limits<std::ptrdiff_t>::max)()) / sizeof(std::uint8_t)) return 7;
    if (reinterpret_cast<std::uintptr_t>(hepta_arg0) % alignof(std::uint8_t)) return 8;
    try {
        auto _hepta_scoped_result = [&]() -> std::int64_t {
            auto _hepta_scoped_object = hepta_json_upgrade::Document(std::span<const std::uint8_t>(hepta_arg0, hepta_arg0_len));
            (void)static_cast<hepta_json_upgrade::Document&>(_hepta_scoped_object).replace(static_cast<std::size_t>(hepta_arg1), static_cast<std::int64_t>(hepta_arg2));
            return static_cast<const hepta_json_upgrade::Document&>(_hepta_scoped_object).sum();
        }();
        *out = _hepta_scoped_result;
        return 0;
    } catch (...) { return 3; }
}
