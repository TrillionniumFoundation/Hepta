// Actual C caller ABI -> compiled Hepta -> generated bridge -> pinned C++ library.
#include "bridge.h"
#include "hepta.h"
#include "selected.hpp"
#include "cases.hpp"
#include <atomic>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <limits>
#include <new>
#include <thread>

namespace {
std::atomic<std::uint64_t> allocations{0}, releases{0};
constexpr std::int64_t sentinel = 9223372036854775807LL;
void require(bool ok, const char* message) {
    if (!ok) { std::fprintf(stderr, "%s\n", message); std::exit(2); }
}
std::uint64_t live() { return allocations.load() - releases.load(); }
const char json_text[] = "{\"values\":[1,2,3]}";
const std::uint8_t* bytes(const char* text) {
    return reinterpret_cast<const std::uint8_t*>(text);
}
}
void* operator new(std::size_t size) {
    if (auto* p = std::malloc(size ? size : 1)) { ++allocations; return p; }
    throw std::bad_alloc();
}
void operator delete(void* p) noexcept { if (p) { ++releases; std::free(p); } }
void operator delete(void* p, std::size_t) noexcept { ::operator delete(p); }
void* operator new[](std::size_t size) { return ::operator new(size); }
void operator delete[](void* p) noexcept { ::operator delete(p); }
void operator delete[](void* p, std::size_t) noexcept { ::operator delete(p); }

int main() {
    // The existing registry has process lifetime. Prime and separately count
    // its ordinary allocations; never label that retained state as freed.
    const auto before_registry = live();
    std::uint64_t warm[8]{};
    for (auto& handle : warm)
        require(hepta_json_host_parse(bytes(json_text), std::strlen(json_text), &handle) == 0,
                "registry warmup parse");
    for (auto handle : warm) require(hepta_json_host_destroy(handle) == 0, "registry warmup destroy");
    const auto registry_live = live() - before_registry;
    require(registry_live > 0, "process lifetime registry must be observed separately");
    const auto baseline = live();
    std::printf("{\"version\":\"%d.%d.%d\",\"cases\":[", NLOHMANN_JSON_VERSION_MAJOR,
                NLOHMANN_JSON_VERSION_MINOR, NLOHMANN_JSON_VERSION_PATCH);
    for (std::size_t i = 0; i < sizeof(cases) / sizeof(cases[0]); ++i) {
        const auto& c = cases[i];
        std::int64_t direct = sentinel, out = sentinel;
        int direct_status = 0;
        const auto before = live();
        try {
            hepta_json_upgrade::Document document(std::span<const std::uint8_t>(bytes(c.text), std::strlen(c.text)));
            document.replace(c.index, c.value);
            direct = document.sum();
        } catch (...) { direct_status = 3; }
        require(live() == before, "direct ordinary allocations leaked");
        const auto status = hepta_json_replace_sum(bytes(c.text), std::strlen(c.text), c.index, c.value, &out);
        require(live() == before, "scoped ordinary allocations leaked");
        require(status == direct_status && out == direct, "actual direct/Hepta result mismatch");
        std::printf("%s{\"id\":%zu,\"direct_status\":%d,\"direct_value\":%lld,"
                    "\"hepta_status\":%d,\"hepta_value\":%lld,\"live_delta\":0}",
                    i ? "," : "", i, direct_status, static_cast<long long>(direct),
                    status, static_cast<long long>(out));
    }
    constexpr unsigned lifecycle_cases = 32;
    for (unsigned i = 0; i < lifecycle_cases; ++i) {
        char caller_buffer[sizeof(json_text)];
        std::memcpy(caller_buffer, json_text, sizeof(json_text));
        std::uint64_t handle = 0;
        require(hepta_json_host_parse(bytes(caller_buffer), std::strlen(caller_buffer), &handle) == 0 && handle,
                "persistent parse");
        std::memset(caller_buffer, 'x', sizeof(caller_buffer));
        std::int64_t out = sentinel;
        require(hepta_json_host_sum(handle, &out) == 0 && out == 6,
                "parser retained borrowed caller bytes");
        require(hepta_json_host_replace(handle, 1, static_cast<std::int64_t>(i)) == 0, "replace");
        require(hepta_json_host_sum(handle, &out) == 0 && out == 4 + i, "persistent value");
        require(hepta_json_host_replace(handle, 3, 7) == 3, "invalid index must refuse");
        require(hepta_json_host_replace(handle, 0, 1000001) == 3, "invalid value must refuse");
        require(hepta_json_host_sum(handle, &out) == 0 && out == 4 + i, "refused call changed state");
        require(hepta_json_host_destroy(handle) == 0, "persistent destroy");
        out = sentinel;
        require(hepta_json_host_sum(handle, &out) == 2 && out == sentinel, "stale read");
        require(hepta_json_host_destroy(handle) == 2, "duplicate destroy");
        require(live() == baseline, "persistent ordinary allocations leaked");
    }
    std::uint64_t refused_handle = 777;
    require(hepta_json_host_parse(bytes("{"), 1, &refused_handle) == 3 && refused_handle == 777,
            "malformed constructor must preserve output");
    require(hepta_json_host_parse(nullptr, 1, &refused_handle) == 1 && refused_handle == 777, "null input");
    require(hepta_json_host_parse(bytes(json_text), std::strlen(json_text), nullptr) == 1, "null output");
    require(hepta_json_host_parse(bytes(json_text), (std::numeric_limits<std::size_t>::max)(), &refused_handle) == 7
            && refused_handle == 777, "oversized span");
    alignas(std::uint64_t) unsigned char storage[sizeof(std::uint64_t) * 2]{};
    require(hepta_json_host_parse(bytes(json_text), std::strlen(json_text),
            reinterpret_cast<std::uint64_t*>(storage + 1)) == 8, "misaligned output");
    require(live() == baseline, "refusal ordinary allocations leaked");

    // Cooperative cancellation is observed strictly between completed calls.
    // No claim of interrupting a foreign function or rolling back side effects.
    std::uint64_t cancel_handle = 0;
    require(hepta_json_host_parse(bytes(json_text), std::strlen(json_text), &cancel_handle) == 0, "cancel parse");
    unsigned committed = 0;
    bool cancelled = false;
    for (unsigned step = 0; step < 7; ++step) {
        if (step == 3) cancelled = true;
        if (cancelled) break;
        require(hepta_json_host_replace(cancel_handle, 0, 100 + step) == 0, "cancel prefix mutation");
        ++committed;
    }
    std::int64_t prefix = sentinel;
    require(committed == 3 && hepta_json_host_sum(cancel_handle, &prefix) == 0 && prefix == 107, "cancel prefix");
    require(hepta_json_host_destroy(cancel_handle) == 0 && live() == baseline, "cancel owner release");

    std::uint64_t shared = 0;
    require(hepta_json_host_parse(bytes(json_text), std::strlen(json_text), &shared) == 0, "concurrent parse");
    std::atomic<unsigned> completed{0}, failures{0};
    {
        std::thread workers[4];
        for (auto& worker : workers) worker = std::thread([&] {
            for (unsigned j = 0; j < 256; ++j) {
                std::int64_t out = sentinel;
                if (hepta_json_host_sum(shared, &out) != 0 || out != 6) ++failures;
                ++completed;
            }
        });
        for (auto& worker : workers) worker.join();
    }
    require(completed == 1024 && failures == 0, "serialized actual foreign calls");
    require(hepta_json_host_destroy(shared) == 0 && live() == baseline, "concurrent owner release");
    std::printf("],\"lifecycle_cases\":32,\"borrowed_input_overwritten\":32,"
                "\"stale_reads\":32,\"duplicate_destroys\":32,\"refused_mutations\":64,"
                "\"pointer_guards\":4,\"malformed_constructor\":1,"
                "\"cancellation\":{\"requested\":7,\"committed\":3,\"value\":107,\"replayed\":0},"
                "\"concurrent_calls\":1024,\"ordinary_live_delta\":0,"
                "\"registry_ordinary_allocations_retained\":%llu}\n",
                static_cast<unsigned long long>(registry_live));
}
