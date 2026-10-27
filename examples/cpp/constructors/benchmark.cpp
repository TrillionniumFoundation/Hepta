#include "bridge.h"
#include "foreign.hpp"
#include <chrono>
#include <cstdint>
#include <cstdlib>
#include <iostream>

template<class F> void measure(const char* name, std::uint64_t iterations, F operation) {
    std::uint64_t checksum = 0;
    for (std::uint64_t i = 0; i < 1000; ++i) checksum += operation(i);
    std::cout << "{\"case\":\"" << name << "\",\"iterations\":" << iterations << ",\"samples_ns\":[";
    for (unsigned sample = 0; sample < 7; ++sample) {
        auto start = std::chrono::steady_clock::now();
        for (std::uint64_t i = 0; i < iterations; ++i) checksum += operation(i);
        auto stop = std::chrono::steady_clock::now();
        if (sample) std::cout << ',';
        std::cout << std::chrono::duration_cast<std::chrono::nanoseconds>(stop - start).count();
    }
    std::cout << "],\"checksum\":" << checksum << "}\n";
}

int main(int argc, char** argv) {
    std::uint64_t iterations = argc == 2 ? std::strtoull(argv[1], nullptr, 10) : 100000;
    if (!iterations || iterations > 1000000) return 1;
    measure("native_vector_create_destroy", iterations, [](std::uint64_t i) {
        auto count = 8 + i % 8;
        auto* object = hepta_ctor_example::native_vector_new(count);
        hepta_ctor_example::native_vector_destroy(object);
        return count;
    });
    measure("handle_vector_create_destroy", iterations, [](std::uint64_t i) {
        auto count = 8 + i % 8; std::uint64_t handle = 0;
        if (hepta_cpp_ctors_IntVector_sized(count, &handle) || hepta_cpp_ctors_IntVector_destroy(handle)) std::abort();
        return count;
    });
    measure("native_student_create_destroy", iterations, [](std::uint64_t i) {
        auto degrees = 1 + i % 32;
        auto* object = hepta_ctor_example::native_student_new(static_cast<double>(degrees));
        hepta_ctor_example::native_student_destroy(object);
        return degrees;
    });
    measure("handle_student_create_destroy", iterations, [](std::uint64_t i) {
        auto degrees = 1 + i % 32; std::uint64_t handle = 0;
        if (hepta_cpp_ctors_Student_new(static_cast<double>(degrees), &handle) || hepta_cpp_ctors_Student_destroy(handle)) std::abort();
        return degrees;
    });
    auto* native_vector = hepta_ctor_example::native_vector_new(16);
    auto* native_student = hepta_ctor_example::native_student_new(7);
    std::uint64_t vector_handle = 0, student_handle = 0;
    if (hepta_cpp_ctors_IntVector_sized(16, &vector_handle) || hepta_cpp_ctors_Student_new(7, &student_handle)) return 2;
    measure("native_vector_size", iterations, [&](std::uint64_t) {
        return hepta_ctor_example::native_vector_size(*native_vector);
    });
    measure("handle_vector_size", iterations, [&](std::uint64_t) {
        std::size_t out = 0;
        if (hepta_cpp_ctors_IntVector_size(vector_handle, &out)) std::abort();
        return out;
    });
    measure("native_student_degrees", iterations, [&](std::uint64_t) {
        return static_cast<std::uint64_t>(hepta_ctor_example::native_student_degrees(*native_student));
    });
    measure("handle_student_degrees", iterations, [&](std::uint64_t) {
        double out = 0;
        if (hepta_cpp_ctors_Student_degrees(student_handle, &out)) std::abort();
        return static_cast<std::uint64_t>(out);
    });
    hepta_ctor_example::native_vector_destroy(native_vector);
    hepta_ctor_example::native_student_destroy(native_student);
    return hepta_cpp_ctors_IntVector_destroy(vector_handle) || hepta_cpp_ctors_Student_destroy(student_handle);
}
