#include "bridge.h"
#include "foreign.hpp"
#include <array>
#include <chrono>
#include <cstdint>
#include <cstdlib>
#include <iostream>
#include <vector>

// Different translation units and no LTO keep the direct C++ function and
// wrapper paths observable. These measurements are for this host and build.
template<class F> void measure(const char* name, std::uint64_t iterations, F fn) {
    std::uint64_t checksum = 0;
    for (std::uint64_t i = 0; i < 10000; ++i) checksum += fn(i);
    std::cout << "{\"case\":\"" << name << "\",\"iterations\":" << iterations << ",\"samples_ns\":[";
    for (unsigned run = 0; run < 7; ++run) {
        auto before = std::chrono::steady_clock::now();
        for (std::uint64_t i = 0; i < iterations; ++i) checksum += fn(i);
        auto after = std::chrono::steady_clock::now();
        if (run) std::cout << ',';
        std::cout << std::chrono::duration_cast<std::chrono::nanoseconds>(after-before).count();
    }
    std::cout << "],\"checksum\":" << checksum << "}\n";
}

int main(int argc, char** argv) {
    std::uint64_t iterations = argc == 2 ? std::strtoull(argv[1], nullptr, 10) : 500000;
    if (!iterations || iterations > 10000000) return 1;
    std::uint64_t handle = 0;
    if (hepta_cpp_stdlib_IntVector_new(&handle) || hepta_cpp_stdlib_IntVector_push(handle, 5)) return 2;
    std::vector<std::int64_t> native{5};
    std::array<std::int64_t, 8> values{1,2,3,4,5,6,7,8};
    measure("native_scalar", iterations, [](std::uint64_t i) { return hepta_example::mix(i); });
    measure("direct_scalar", iterations, [](std::uint64_t i) { return hepta_cpp_stdlib_mix(i); });
    measure("native_borrow", iterations, [&](std::uint64_t) { return static_cast<std::uint64_t>(hepta_example::sum(values)); });
    measure("checked_borrow", iterations, [&](std::uint64_t) {
        std::int64_t result = 0;
        if (hepta_cpp_stdlib_sum(values.data(), values.size(), &result)) std::abort();
        return static_cast<std::uint64_t>(result);
    });
    measure("native_vector_size", iterations, [&](std::uint64_t) { return hepta_example::native_vector_size(native); });
    measure("handle_vector_size", iterations, [&](std::uint64_t) {
        std::size_t result = 0;
        if (hepta_cpp_stdlib_IntVector_size(handle, &result)) std::abort();
        return static_cast<std::uint64_t>(result);
    });
    return hepta_cpp_stdlib_IntVector_destroy(handle);
}
