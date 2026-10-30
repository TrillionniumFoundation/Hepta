// One isolated invocation of the unchanged scoped C ABI. No foreign owner or
// pointer leaves this process. Transport parsing and JSON input use stack data.
#include "bridge.h"
#include "hepta.h"
#include "selected.hpp"
#include <charconv>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <new>
#include <system_error>

namespace {
std::uint64_t allocations = 0, releases = 0, attempts = 0, reject_at = 0;
bool injected = false;
constexpr std::int64_t sentinel = 9223372036854775807LL;
void require(bool condition) { if (!condition) std::exit(82); }
bool hex(const char* text, std::size_t length) {
    if (std::strlen(text) != length) return false;
    for (std::size_t i = 0; i < length; ++i)
        if (!((text[i] >= '0' && text[i] <= '9') || (text[i] >= 'a' && text[i] <= 'f'))) return false;
    return true;
}
std::int64_t number(const char*& cursor, const char* end) {
    std::int64_t value = 0;
    const auto result = std::from_chars(cursor, end, value);
    require(result.ec == std::errc{} && result.ptr != cursor);
    cursor = result.ptr;
    require(cursor < end && (*cursor == ' ' || *cursor == '\n'));
    ++cursor;
    return value;
}
std::uint64_t live() { return allocations - releases; }
}

void* operator new(std::size_t size) {
    ++attempts;
    if (reject_at && attempts == reject_at) { injected = true; throw std::bad_alloc(); }
    if (auto* p = std::malloc(size ? size : 1)) { ++allocations; return p; }
    throw std::bad_alloc();
}
void operator delete(void* p) noexcept { if (p) { ++releases; std::free(p); } }
void operator delete(void* p, std::size_t) noexcept { ::operator delete(p); }
void* operator new[](std::size_t size) { return ::operator new(size); }
void operator delete[](void* p) noexcept { ::operator delete(p); }
void operator delete[](void* p, std::size_t) noexcept { ::operator delete(p); }

int main(int argc, char** argv) {
    require(argc == 3 && hex(argv[1], 32) && hex(argv[2], 64));
    char input[2049];
    const auto length = std::fread(input, 1, sizeof(input), stdin);
    require(length > 0 && length < sizeof(input) && !std::ferror(stdin) && std::feof(stdin));
    const char* cursor = input;
    const char* end = input + length;
    const auto revision = number(cursor, end), sequence = number(cursor, end);
    const auto fault = number(cursor, end), count = number(cursor, end);
    const auto index = number(cursor, end), replacement = number(cursor, end);
    require(revision >= 0 && revision < 128 && sequence > 0 && sequence <= 128
            && fault >= 0 && fault <= 127 && count > 0 && count <= 64
            && index >= 0 && index < count && replacement >= -1000000 && replacement <= 1000000);
    char document[1024];
    std::size_t used = static_cast<std::size_t>(std::snprintf(document, sizeof(document), "{\"values\":["));
    for (std::int64_t i = 0; i < count; ++i) {
        const auto value = number(cursor, end);
        require(value >= -1000000 && value <= 1000000);
        const auto wrote = std::snprintf(document + used, sizeof(document) - used,
                                        "%s%lld", i ? "," : "", static_cast<long long>(value));
        require(wrote > 0 && static_cast<std::size_t>(wrote) < sizeof(document) - used);
        used += static_cast<std::size_t>(wrote);
    }
    require(cursor == end && used + 3 <= sizeof(document));
    std::memcpy(document + used, "]}", 3); used += 2;
    const auto before = live(), start = attempts;
    reject_at = fault ? attempts + static_cast<std::uint64_t>(fault) : 0;
    std::int64_t out = sentinel;
    const auto status = hepta_json_replace_sum(reinterpret_cast<const std::uint8_t*>(document),
                                               used, static_cast<std::size_t>(index), replacement, &out);
    reject_at = 0;
    const auto actual_attempts = attempts - start;
    // A noexcept destructor aborts before reaching this frame. Even a complete
    // frame cannot commit parent state unless the owned process exits normally.
    std::printf("{\"schema\":\"hepta.cpp-json-checkpoint-worker.v1\","
                "\"version\":\"%d.%d.%d\",\"nonce\":\"%s\",\"request_sha256\":\"%s\","
                "\"revision\":%lld,\"sequence\":%lld,\"status\":%d,\"result\":%lld,"
                "\"allocation_attempts\":%llu,\"failure_injected\":%s,\"live_delta\":%lld}\n",
                NLOHMANN_JSON_VERSION_MAJOR, NLOHMANN_JSON_VERSION_MINOR, NLOHMANN_JSON_VERSION_PATCH,
                argv[1], argv[2], static_cast<long long>(revision), static_cast<long long>(sequence),
                status, static_cast<long long>(out), static_cast<unsigned long long>(actual_attempts),
                injected ? "true" : "false", static_cast<long long>(live()) - static_cast<long long>(before));
    require(!std::ferror(stdout));
    return 0;
}
