#include "bridge.h"
#include "hepta.h"
#include "foreign.hpp"
#include <iostream>
#include <limits>
#include <sstream>

int main() {
    constexpr std::size_t extent = HEPTA_TEST_EXTENT;
    constexpr std::uint32_t sentinel = 0xface1234u;
    const std::uint32_t values[] = {0u, 1u, 0x7fffffffu, 0x80000000u, 0xfffffffeu, 0xffffffffu};
    const std::size_t indices[] = {0, extent - 1, extent, (std::numeric_limits<std::size_t>::max)()};
    unsigned cases = 0;
    unsigned functions = 0;
    std::ostringstream observations, function_observations;
    using Probe = sized_example::CountedArray<std::uint32_t, extent>;
    for (auto value : values) {
        auto added = sized_add(value);
        if (added != sized_example::add_size<extent>(value)) return 1;
        if (functions++) function_observations << ',';
        function_observations << "{\"value\":" << value << ",\"observed\":" << added << '}';
        for (auto index : indices) {
            std::array<std::uint32_t, extent> reference{};
            reference.fill(value);
            int expected_status = 0;
            auto expected = sentinel;
            try { expected = reference.at(index); }
            catch (const std::out_of_range&) { expected_status = 3; }
            std::uint32_t output = sentinel;
            auto array_status = sized_roundtrip(value, index, &output);
            if (array_status != expected_status || output != expected) return 2;
            auto array_output = output;
            auto destroyed = Probe::destroyed;
            output = sentinel;
            auto counted_status = sized_counted(0, value, index, &output);
            if (counted_status != expected_status || output != expected) return 3;
            if (sized_example::Member::live != 0 || Probe::destroyed != destroyed + 1) return 4;
            if (cases++) observations << ',';
            observations << "{\"value\":" << value << ",\"index\":" << index
                         << ",\"expected_status\":" << expected_status << ",\"expected_output\":" << expected
                         << ",\"array_status\":" << array_status << ",\"array_output\":" << array_output
                         << ",\"counted_status\":" << counted_status << ",\"counted_output\":" << output
                         << ",\"live_members\":" << sized_example::Member::live
                         << ",\"destroyed_delta\":" << Probe::destroyed - destroyed << '}';
        }
    }
    auto destroyed = Probe::destroyed;
    std::uint32_t output = sentinel;
    auto constructor_failure_status = sized_counted(1, 5, 0, &output);
    if (constructor_failure_status != 3 || output != sentinel) return 5;
    auto constructor_failure_output = output;
    if (sized_example::Member::live != 0 || Probe::destroyed != destroyed) return 6;
    auto counted_null_status = sized_counted(0, 5, 0, nullptr);
    if (counted_null_status != 1 || Probe::destroyed != destroyed) return 7;
    auto array_null_status = sized_roundtrip(5, 0, nullptr);
    if (array_null_status != 1) return 8;
    std::uint64_t handle = 0;
    int handle_status[7]{};
    handle_status[0] = hepta_cpp_sized_Array_new(&handle);
    if (handle_status[0] != 0 || handle == 0) return 9;
    handle_status[1] = hepta_cpp_sized_Array_fill(handle, 17);
    if (handle_status[1] != 0) return 10;
    handle_status[2] = hepta_cpp_sized_Array_at(handle, extent - 1, &output);
    if (handle_status[2] != 0 || output != 17) return 11;
    output = sentinel;
    handle_status[3] = hepta_cpp_sized_Array_at(handle, extent, &output);
    if (handle_status[3] != 3 || output != sentinel) return 12;
    handle_status[4] = hepta_cpp_sized_Array_destroy(handle);
    if (handle_status[4] != 0) return 13;
    handle_status[5] = hepta_cpp_sized_Array_at(handle, 0, &output);
    if (handle_status[5] != 2 || output != sentinel) return 14;
    handle_status[6] = hepta_cpp_sized_Array_destroy(handle);
    if (handle_status[6] != 2) return 15;
    std::cout << "{\"ok\":true,\"extent\":" << extent
              << ",\"std_array_differential_cases\":" << cases
              << ",\"counted_lifecycle_cases\":" << cases
              << ",\"function_template_cases\":6,\"constructor_failure_paths\":1,"
                 "\"null_output_paths\":2,\"handle_transitions\":7,\"live_members\":"
              << sized_example::Member::live << ",\"array_and_lifecycle_observations\":["
              << observations.str() << "],\"function_observations\":[" << function_observations.str()
              << "],\"constructor_failure_status\":" << constructor_failure_status
              << ",\"constructor_failure_output\":" << constructor_failure_output
              << ",\"null_output_statuses\":[" << counted_null_status << ',' << array_null_status
              << "],\"handle_statuses\":[";
    for (unsigned i = 0; i < 7; ++i) {
        if (i) std::cout << ',';
        std::cout << handle_status[i];
    }
    std::cout << "]}\n";
}
