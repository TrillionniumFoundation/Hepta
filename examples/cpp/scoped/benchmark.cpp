#include "bridge.h"
#include "hepta.h"
#include "foreign.hpp"
#include <array>
#include <chrono>
#include <cstdio>
#include <cstdlib>

using Operation = std::int64_t(*)(std::int64_t);
static std::int64_t native(std::int64_t value) {
    return scoped_example::native_vector(8, 17, value, 8);
}
static std::int64_t scoped(std::int64_t value) {
    std::int64_t out = 0;
    if (hepta_cpp_scoped_vector_roundtrip(8, 17, value, 8, &out)) std::abort();
    return out;
}
static std::int64_t hepta(std::int64_t value) {
    std::int64_t out = 0;
    if (hepta_scoped_vector(8, 17, value, 8, &out)) std::abort();
    return out;
}
static std::int64_t handles(std::int64_t value) {
    std::uint64_t handle = 0;
    std::int64_t out = 0;
    if (hepta_cpp_scoped_Vector_filled(8, 17, &handle)
        || hepta_cpp_scoped_Vector_append(handle, value)
        || hepta_cpp_scoped_Vector_at(handle, 8, &out)
        || hepta_cpp_scoped_Vector_destroy(handle)) std::abort();
    return out;
}
static void measure(const char* name, Operation operation, std::uint64_t iterations) {
    for (int i = 0; i < 200; ++i) if (operation(i) != i) std::abort();
    std::array<std::uint64_t, 7> samples{};
    std::uint64_t checksum = 0;
    for (auto& elapsed : samples) {
        checksum = 0;
        auto start = std::chrono::steady_clock::now();
        for (std::uint64_t i = 0; i < iterations; ++i)
            checksum += static_cast<std::uint64_t>(operation(static_cast<std::int64_t>(i & 31)));
        elapsed = static_cast<std::uint64_t>(std::chrono::duration_cast<std::chrono::nanoseconds>(
            std::chrono::steady_clock::now() - start).count());
    }
    std::printf("{\"case\":\"%s\",\"iterations\":%llu,\"checksum\":%llu,\"samples_ns\":[",
                name, (unsigned long long)iterations, (unsigned long long)checksum);
    for (std::size_t i = 0; i < samples.size(); ++i)
        std::printf("%s%llu", i ? "," : "", (unsigned long long)samples[i]);
    std::printf("]}\n");
}
int main(int argc, char** argv) {
    if (argc != 2) return 2;
    auto iterations = std::strtoull(argv[1], nullptr, 10);
    if (!iterations || iterations > 1000000) return 2;
    measure("native_cpp_lifecycle", native, iterations);
    measure("scoped_cpp_lifecycle", scoped, iterations);
    measure("hepta_scoped_lifecycle", hepta, iterations);
    measure("handle_cpp_lifecycle", handles, iterations);
}
