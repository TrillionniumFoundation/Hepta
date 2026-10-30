// The same independent native client exercises original and migrated libraries.
#include "cpp/INIReader.h"
#include "ini.h"
#include <algorithm>
#include <atomic>
#include <climits>
#include <clocale>
#include <cstddef>
#include <cstdlib>
#include <cstring>
#include <iomanip>
#include <iostream>
#include <new>
#include <optional>
#include <string>
#include <thread>
#include <vector>
#ifdef HEPTA_INIH_MIGRATED
#include "inih_hepta_callback.hpp"
#endif

extern "C" {
extern int ini_fail_next_allocation;
size_t ini_live_allocations(void);
size_t ini_total_allocations(void);
void ini_probe_release_observed_leaks(void);
}

static std::atomic<long long> cpp_live{0};
static std::atomic<bool> fail_next_cpp{false};
void* operator new(std::size_t size) {
    if (fail_next_cpp.exchange(false)) { throw std::bad_alloc(); }
    void* p = std::malloc(size ? size : 1);
    if (!p) { throw std::bad_alloc(); }
    ++cpp_live;
    return p;
}
void operator delete(void* p) noexcept { if (p) { --cpp_live; std::free(p); } }
void operator delete(void* p, std::size_t) noexcept { ::operator delete(p); }
void* operator new[](std::size_t size) { return ::operator new(size); }
void operator delete[](void* p) noexcept { ::operator delete(p); }
void operator delete[](void* p, std::size_t) noexcept { ::operator delete(p); }

static std::string hex(const std::string& input) {
    const char* digits = "0123456789abcdef";
    std::string result;
    for (unsigned char byte : input) { result += digits[byte >> 4]; result += digits[byte & 15]; }
    return result;
}

class Probe final : public INIReader {
public:
    Probe() : INIReader("", 0) {}
    void error(int value) { _error = value; }
    static int callback(void* user, const char* section, const char* name, const char* value) {
        return ValueHandler(user, section, name, value);
    }
};

static void trace(size_t number, const std::string& text) {
    std::vector<char> owned_input(text.begin(), text.end());
    owned_input.push_back('\0');
    INIReader reader(owned_input.data(), text.size());
    // Upstream callback must copy borrowed parser/input bytes into its own map.
    std::fill(owned_input.begin(), owned_input.end(), '!');
    std::cout << "case=" << number << " error=" << reader.ParseError()
              << " message=" << hex(reader.ParseErrorMessage());
    for (const char* key : {"a", "b", "flag", "empty", "no_value", "number"}) {
        std::cout << " " << key << "=" << hex(reader.Get("section", key, "MISSING"));
        std::cout << ":" << reader.GetBoolean("section", key, false)
                  << ":" << reader.GetBoolean("section", key, true);
    }
    std::cout << " section=" << reader.HasSection("section")
              << " integer=" << reader.GetInteger64("section", "number", -99)
              << " unsigned=" << reader.GetUnsigned64("section", "number", 99);
    for (const auto& section : reader.Sections()) { std::cout << " S=" << hex(section); }
    for (const auto& key : reader.Keys("section")) { std::cout << " K=" << hex(key); }
    std::cout << '\n';
}

static int functional() {
    std::vector<std::string> traces = {
        "[section]\na=hello\nb=world\nflag=TrUe\nnumber=0x4d2\n",
        "[section]\na=one\na=two\nb=\nno_value\nflag=OFF\n",
        "[section]\na=\na=last\nflag=YES\n",
        "[bad\na=after-error\n", "[section]\n=bad\n",
        "[SECTION]\nFLAG=oN\n; ignored\nnumber=-42\n",
        "", "[section]\nempty=\nno_value\n",
        "[section]\na=" + std::string(240, 'x') + "\n",
        std::string("[section]\na=before\0ignored=after\n", sizeof("[section]\na=before\0ignored=after\n") - 1)
    };
    for (size_t index = 0; index < traces.size(); ++index) { trace(index, traces[index]); }
    Probe probe;
    for (int code : {INT_MIN, -5, -4, -3, -2, -1, 0, 1, 2, 999, INT_MAX}) {
        probe.error(code);
        std::cout << "error-dispatch=" << code << ":" << hex(probe.ParseErrorMessage()) << '\n';
    }
    const char* words[] = {"true", "yes", "on", "1", "false", "no", "off", "0", "", "truth", " true", "true ", "TRUE", "True"};
    size_t checks = 0;
    uint64_t digest = 1469598103934665603ULL;
    std::string observed_bits;
    observed_bits.reserve(11000);
    auto check_word = [&](const std::string& word) {
        Probe record;
#ifdef HEPTA_INIH_MIGRATED
        hepta_ini::ScopedBorrow lease(&record);
        void* owner = lease.user();
#else
        void* owner = &record;
#endif
        if (Probe::callback(owner, "section", "flag", word.c_str()) != 1) { std::abort(); }
        for (bool fallback : {false, true}) {
            const bool value = record.GetBoolean("section", "flag", fallback);
            observed_bits += value ? '1' : '0';
            digest ^= static_cast<uint64_t>(value);
            digest *= 1099511628211ULL;
            ++checks;
        }
    };
    for (const char* word : words) { check_word(word); }
    // Every possible single-byte substitution in each actual accepted word.
    for (size_t word_index = 0; word_index < 8; ++word_index) {
        std::string word(words[word_index]);
        for (size_t position = 0; position < word.size(); ++position) {
            for (unsigned int byte = 0; byte < 256; ++byte) {
                std::string changed = word;
                changed[position] = static_cast<char>(byte);
                check_word(changed);
            }
        }
    }
    std::cout << "boolean-checks=" << checks << " digest=" << digest << '\n';
    std::cout << "boolean-results=" << observed_bits << '\n';
    // Actual direct source callback branches: null name, null value, duplicate.
    Probe record;
#ifdef HEPTA_INIH_MIGRATED
    hepta_ini::ScopedBorrow lease(&record);
    void* owner = lease.user();
#else
    void* owner = &record;
#endif
    int result = Probe::callback(owner, "section", nullptr, "ignored");
    result += Probe::callback(owner, "section", "empty", nullptr);
    result += Probe::callback(owner, "section", "a", "first");
    result += Probe::callback(owner, "section", "a", nullptr);
    result += Probe::callback(owner, "section", "a", "last");
    std::cout << "callback-branches=" << result << ":" << hex(record.Get("section", "a", "missing"))
              << ":" << hex(record.Get("section", "empty", "missing")) << '\n';
    return result == 5 && ini_live_allocations() == 0 ? 0 : 9;
}

static int lifecycle() {
    const long long before = cpp_live.load();
    const char input[] = "[section]\na=a sufficiently long value to allocate independent storage\nflag=true\n";
    bool valid = true;
    for (int round = 0; round < 64; ++round) {
        char buffer[sizeof(input)];
        std::memcpy(buffer, input, sizeof(input));
        INIReader reader(buffer, sizeof(input) - 1);
        std::memset(buffer, 0, sizeof(buffer));
        valid = valid && reader.ParseError() == 0 && reader.GetBoolean("section", "flag", false)
            && reader.Get("section", "a", "") == "a sufficiently long value to allocate independent storage";
    }
    const bool balanced = cpp_live.load() == before && ini_live_allocations() == 0;
    std::cout << "lifetimes=64 valid=" << valid << " cpp-balanced=" << balanced
              << " c-live=" << ini_live_allocations() << '\n';
    return valid && balanced ? 0 : 10;
}

static int allocation_failure() {
    const char data[] = "[section]\na=value\n";
    ini_fail_next_allocation = 1;
    INIReader reader(data, sizeof(data) - 1);
    std::cout << "allocation-refusal=" << reader.ParseError() << ":" << hex(reader.ParseErrorMessage())
              << " c-live=" << ini_live_allocations() << '\n';
    return reader.ParseError() == -2 && ini_live_allocations() == 0 ? 0 : 11;
}

static int callback_exception() {
    const char data[] = "[section]\na=value\n";
    const long long before = cpp_live.load();
    bool caught = false;
    fail_next_cpp = true;
    try { INIReader reader(data, sizeof(data) - 1); }
    catch (const std::bad_alloc&) { caught = true; }
    fail_next_cpp = false;
    const size_t observed_live = ini_live_allocations();
    std::cout << "callback-bad-alloc=" << caught << " c-live=" << observed_live
              << " cpp-balanced=" << (cpp_live.load() == before)
              << " parser-allocations=" << ini_total_allocations() << '\n';
    ini_probe_release_observed_leaks();
#ifdef HEPTA_INIH_MIGRATED
    return caught && observed_live == 0 && cpp_live.load() == before
        && hepta_ini::active_leases() == 0 ? 0 : 12;
#else
    // Intentionally expose upstream's actual exceptional callback leak.
    return caught && observed_live == 1 && cpp_live.load() == before ? 0 : 13;
#endif
}

static int file_error(const char* directory) {
    INIReader reader{std::string(directory)};
    std::cout << "directory-read=" << reader.ParseError() << ":" << hex(reader.ParseErrorMessage()) << '\n';
    INIReader missing{std::string(directory) + "/absent.ini"};
    std::cout << "open-failure=" << missing.ParseError() << ":" << hex(missing.ParseErrorMessage()) << '\n';
    return ini_live_allocations() == 0 ? 0 : 14;
}

#ifdef HEPTA_INIH_MIGRATED
static int lease_controls() {
    Probe owner;
    uintptr_t expired = 0;
    unsigned checks = 0;
    {
        hepta_ini::ScopedBorrow scope(&owner);
        expired = scope.token();
        checks += Probe::callback(scope.user(), "s", "kept", "yes") == 1;
        bool duplicate_owner_refused = false;
        try { hepta_ini::ScopedBorrow duplicate(&owner); }
        catch (const std::logic_error&) { duplicate_owner_refused = true; }
        checks += duplicate_owner_refused;
        {
            hepta_ini::CallbackInvocation held(scope.user());
            checks += bool(held);
            checks += Probe::callback(scope.user(), "s", "reentered", "no") == 0;
        }
        bool cross_thread_refused = false;
        std::thread other([&] { cross_thread_refused = Probe::callback(scope.user(), "s", "thread", "no") == 0; });
        other.join();
        checks += cross_thread_refused;
        checks += Probe::callback(reinterpret_cast<void*>(UINTPTR_MAX), "s", "forged", "no") == 0;
    }
    checks += Probe::callback(reinterpret_cast<void*>(expired), "s", "stale", "no") == 0;
    checks += !owner.HasValue("s", "stale") && !owner.HasValue("s", "thread")
        && !owner.HasValue("s", "reentered") && !owner.HasValue("s", "forged")
        && owner.Get("s", "kept", "") == "yes";
    checks += hepta_ini::active_leases() == 0;
    {
        std::array<int, 33> distinct_owners{};
        std::array<std::optional<hepta_ini::ScopedBorrow>, 33> scoped;
        for (size_t index = 0; index < 32; ++index) { scoped[index].emplace(&distinct_owners[index]); }
        bool refused = false;
        try { scoped[32].emplace(&distinct_owners[32]); }
        catch (const std::overflow_error&) { refused = true; }
        checks += refused && hepta_ini::active_leases() == 32;
        for (auto& item : scoped) { item.reset(); }
        checks += hepta_ini::active_leases() == 0;
    }
    // Every supported and several malformed scalar transition inputs.
    unsigned transitions = 0;
    for (uint32_t phase = 0; phase < 6; ++phase) {
        for (uint32_t event = 0; event < 6; ++event) {
            uint32_t expected = 255;
            if (phase == 0 && event == 0) expected = 1;
            if (phase == 1 && event == 1) expected = 2;
            if (phase == 2 && event == 2) expected = 1;
            if (phase == 1 && event == 3) expected = 3;
            transitions += hia_ini_lease_step(phase, event) == expected;
        }
    }
    std::cout << "callback-controls=" << checks << "/11 transitions=" << transitions
              << "/36 leases=" << hepta_ini::active_leases() << '\n';
    return checks == 11 && transitions == 36 ? 0 : 15;
}
#endif

int main(int argc, char** argv) {
    if (!std::setlocale(LC_ALL, "C") || argc < 2) { return 2; }
    const std::string mode = argv[1];
    if (mode == "functional") return functional();
    if (mode == "lifecycle") return lifecycle();
    if (mode == "allocation-failure") return allocation_failure();
    if (mode == "callback-exception") return callback_exception();
    if (mode == "file-error" && argc == 3) return file_error(argv[2]);
#ifdef HEPTA_INIH_MIGRATED
    if (mode == "lease-controls") return lease_controls();
#endif
    return 3;
}
