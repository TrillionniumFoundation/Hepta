#include "bridge.h"
#include "hepta.h"
#include "selected.hpp"
#include "cases.hpp"
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <new>

namespace {
std::uint64_t allocations = 0, releases = 0, attempts = 0, reject_at = 0;
constexpr std::int64_t sentinel = 9223372036854775807LL;
void require(bool condition, const char* message) {
    if (!condition) { std::fprintf(stderr, "%s\n", message); std::exit(2); }
}
std::uint64_t live() { return allocations - releases; }
}
void* operator new(std::size_t size) {
    ++attempts;
    if (reject_at && attempts == reject_at) throw std::bad_alloc();
    if (auto* p = std::malloc(size ? size : 1)) { ++allocations; return p; }
    throw std::bad_alloc();
}
void operator delete(void* p) noexcept { if (p) { ++releases; std::free(p); } }
void operator delete(void* p, std::size_t) noexcept { ::operator delete(p); }
void* operator new[](std::size_t size) { return ::operator new(size); }
void operator delete[](void* p) noexcept { ::operator delete(p); }
void operator delete[](void* p, std::size_t) noexcept { ::operator delete(p); }

int main(int argc, char** argv) {
    if (argc == 2 && std::strcmp(argv[1], "--calibrate") == 0) {
        const char* document = "{\"values\":[1,2,3]}";
        auto* text = reinterpret_cast<const std::uint8_t*>(document);
        const auto before = live(), start = attempts;
        std::int64_t out = sentinel;
        require(hepta_json_replace_sum(text, std::strlen(document), 1, 5, &out) == 0 && out == 9,
                "independent allocation calibration call");
        const auto sites = attempts - start;
        require(sites > 0 && sites < 128 && live() == before, "independent allocation denominator");
        std::printf("{\"version\":\"%d.%d.%d\",\"allocation_sites\":%llu,\"value\":9,\"live_delta\":0}\n",
                    NLOHMANN_JSON_VERSION_MAJOR, NLOHMANN_JSON_VERSION_MINOR, NLOHMANN_JSON_VERSION_PATCH,
                    static_cast<unsigned long long>(sites));
        return 0;
    }
    if (argc == 2) {
        const auto site = std::strtoull(argv[1], nullptr, 10);
        const char* document = "{\"values\":[1,2,3]}";
        auto* text = reinterpret_cast<const std::uint8_t*>(document);
        const auto size = std::strlen(document);
        std::int64_t out = sentinel;
        const auto before = live(), start = attempts;
        require(hepta_json_replace_sum(text, size, 1, 5, &out) == 0 && out == 9,
                "fault calibration call");
        const auto sites = attempts - start;
        require(site > 0 && site <= sites, "fault site outside observed denominator");
        out = sentinel;
        reject_at = attempts + site;
        const auto status = hepta_json_replace_sum(text, size, 1, 5, &out);
        reject_at = 0;
        require(status == 3 && out == sentinel && live() == before,
                "catchable allocation failure did not clean up and preserve output");
        require(hepta_json_replace_sum(text, size, 1, 5, &out) == 0 && out == 9 && live() == before,
                "post-refusal recovery");
        std::printf("{\"site\":%llu,\"status\":3,\"output_preserved\":true,\"live_delta\":0,"
                    "\"recovered_value\":9}\n", static_cast<unsigned long long>(site));
        return 0;
    }
    require(argc == 1, "unsupported harness arguments");
    std::printf("{\"version\":\"%d.%d.%d\",\"cases\":[", NLOHMANN_JSON_VERSION_MAJOR,
                NLOHMANN_JSON_VERSION_MINOR, NLOHMANN_JSON_VERSION_PATCH);
    for (std::size_t i = 0; i < sizeof(cases) / sizeof(cases[0]); ++i) {
        const auto& c = cases[i];
        auto* text = reinterpret_cast<const std::uint8_t*>(c.text);
        const auto size = std::strlen(c.text);
        auto before = live();
        std::int64_t direct = sentinel;
        int direct_status = 0;
        try {
            hepta_json_upgrade::Document document(std::span<const std::uint8_t>(text, size));
            document.replace(c.index, c.value);
            direct = document.sum();
        } catch (...) { direct_status = 3; }
        require(live() == before, "direct lifecycle did not release its ordinary allocations");
        std::int64_t out = sentinel;
        int status = hepta_json_replace_sum(text, size, c.index, c.value, &out);
        require(live() == before, "Hepta lifecycle did not release its ordinary allocations");
        std::printf("%s{\"id\":%zu,\"direct_status\":%d,\"direct_value\":%lld,"
                    "\"hepta_status\":%d,\"hepta_value\":%lld,\"live_delta\":0}",
                    i ? "," : "", i, direct_status, static_cast<long long>(direct),
                    status, static_cast<long long>(out));
    }
    const char* document = "{\"values\":[1,2,3]}";
    auto* text = reinterpret_cast<const std::uint8_t*>(document);
    const auto size = std::strlen(document);
    std::int64_t out = sentinel;
    auto before = live(), start = attempts;
    require(hepta_json_replace_sum(text, size, 1, 5, &out) == 0 && out == 9,
            "allocation calibration call");
    const auto sites = attempts - start;
    require(sites > 0 && sites < 128 && live() == before, "allocation site denominator");
    require(hepta_json_replace_sum(nullptr, 1, 0, 0, &out) == 1, "null input guard");
    require(hepta_json_replace_sum(text, size, 0, 0, nullptr) == 1, "null output guard");
    std::printf("],\"allocation_sites\":%llu,\"pointer_guards\":2,\"ordinary_live_delta\":0}\n",
                static_cast<unsigned long long>(sites));
}
