#include "bridge.h"
#include "hepta.h"
#include "foreign.hpp"
#include <array>
#include <cstdint>
#include <cstdlib>
#include <iostream>
#include <limits>
#include <thread>
#include <vector>

static void require(bool value, const char* label) {
    if (!value) { std::cerr << label << '\n'; std::exit(1); }
}

int main() {
    for (std::uint64_t i = 0; i < 100; ++i) {
        require(hepta_cpp_round_mix(i) == hepta_example::mix(i), "C++ -> Hepta -> C++ scalar");
        require(hepta_cpp_stdlib_twice(i) == i * 2, "concrete C++ template instantiation");
    }
    auto pair = hepta_cpp_round_pair(-9, 27);
    require(pair.first == 27 && pair.second == -9, "C++ -> Hepta -> C++ POD return");
    std::array<std::int64_t, 4> values{2, 3, 5, 7};
    std::int64_t out = -99;
    require(hepta_cpp_round_sum(values.data(), values.size(), &out) == 0 && out == 17, "borrowed input");
    require(values == std::array<std::int64_t, 4>{2, 3, 5, 7}, "const borrow unchanged");
    require(hepta_cpp_round_sum(nullptr, 0, &out) == 0 && out == 0, "empty null span");
    out = 99;
    require(hepta_cpp_round_sum(nullptr, 1, &out) == 1 && out == 99, "null nonempty span rejected");
    require(hepta_cpp_round_sum(values.data(), (std::numeric_limits<std::size_t>::max)(), &out) == 7 && out == 99, "impossible extent rejected");
    require(hepta_cpp_round_sum(values.data(), values.size(), nullptr) == 1, "null output rejected");
    alignas(std::int64_t) unsigned char bad[16]{};
    require(hepta_cpp_round_sum(reinterpret_cast<const std::int64_t*>(bad + 1), 1, &out) == 8 && out == 99, "misaligned input rejected");
    require(hepta_cpp_stdlib_add(values.data(), values.size(), 4) == 0, "mutable borrow");
    require(values == std::array<std::int64_t, 4>{6, 7, 9, 11}, "mutable borrow updates original allocation");
    require(hepta_cpp_stdlib_add(values.data(), values.size(), -999) == 3, "C++ exception status");
    require(values[0] == -993 && values[1] == 7, "exception does not falsely promise side-effect rollback");
    const std::uint8_t text[] = {'h', 0, 'e', 'p', 't', 'a'};
    std::size_t size = 0;
    require(hepta_cpp_round_text(text, sizeof text, &size) == 0 && size == 6, "real std::string including embedded NUL");

    std::uint64_t handle = 0;
    require(hepta_cpp_round_vector_new(&handle) == 0 && handle, "std::vector creation in C++ through Hepta");
    require(hepta_cpp_round_vector_push(handle, 17) == 0, "std::vector push");
    require(hepta_cpp_round_vector_push(handle, 23) == 0, "second std::vector push");
    require(hepta_cpp_round_vector_at(handle, 1, &out) == 0 && out == 23, "copy a C++ reference into scalar ABI");
    require(hepta_cpp_round_vector_at(handle, 100, &out) == 3 && out == 23, "out_of_range caught and output unchanged");
    std::vector<std::thread> workers;
    std::array<int, 4> failures{};
    for (unsigned i = 0; i < 4; ++i) {
        workers.emplace_back([&, i] {
            for (int j = 0; j < 100; ++j) if (hepta_cpp_round_vector_push(handle, j) != 0) ++failures[i];
        });
    }
    for (auto& worker : workers) worker.join();
    require(failures == std::array<int, 4>{}, "serialized same-object native calls");
    require(hepta_cpp_stdlib_IntVector_size(handle, &size) == 0 && size == 402, "all concurrent pushes retained");
    require(hepta_cpp_round_vector_destroy(handle) == 0, "same C++ module destructor and allocator release");
    require(hepta_cpp_round_vector_destroy(handle) == 2, "double destroy rejected");
    require(hepta_cpp_round_vector_at(handle, 0, &out) == 2 && out == 23, "stale handle rejected");
    std::cout << "{\"bidirectional_native\":true,\"scalar_cases\":100,\"pod\":true,\"borrowed\":true,\"negative_boundaries\":true,\"cpp_templates\":true,\"std_string\":true,\"std_vector\":true,\"serialized_calls\":400}\n";
}
