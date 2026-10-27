#include "bridge.h"
#include "hepta.h"
#include "foreign.hpp"
#include <array>
#include <atomic>
#include <cmath>
#include <cstdlib>
#include <iostream>
#include <limits>
#include <new>
#include <stdexcept>

namespace {
std::atomic<std::int64_t> live_allocations{0};
thread_local bool observe_allocations = false;
thread_local std::int64_t fail_after = -1;
thread_local std::uint64_t allocation_attempts = 0;
}

// Actual replaceable C++ allocation functions are used by std::make_shared,
// vector storage and unordered_map insertion. Injection is one-shot so that
// constructing an exception or diagnosing a failure cannot recursively fail.
void* operator new(std::size_t bytes) {
    if (observe_allocations) {
        ++allocation_attempts;
        if (fail_after == 0) {
            observe_allocations = false;
            throw std::bad_alloc();
        }
        if (fail_after > 0) --fail_after;
    }
    void* result = std::malloc(bytes ? bytes : 1);
    if (!result) throw std::bad_alloc();
    ++live_allocations;
    return result;
}
void operator delete(void* value) noexcept {
    if (value) { --live_allocations; std::free(value); }
}
void* operator new[](std::size_t bytes) { return ::operator new(bytes); }
void operator delete[](void* value) noexcept { ::operator delete(value); }
void operator delete(void* value, std::size_t) noexcept { ::operator delete(value); }
void operator delete[](void* value, std::size_t) noexcept { ::operator delete(value); }

static void require(bool condition, const char* message) {
    if (!condition) { std::cerr << message << '\n'; std::exit(1); }
}

static std::uint64_t vector_failure_trials() {
    std::uint64_t handle = 0;
    require(hepta_ctor_vector_sized(37, &handle) == 0, "warm vector registry");
    require(hepta_ctor_vector_destroy(handle) == 0, "warm vector destruction");
    auto baseline = live_allocations.load();
    fail_after = -1; allocation_attempts = 0; observe_allocations = true;
    auto status = hepta_ctor_vector_sized(37, &handle);
    observe_allocations = false;
    auto sites = allocation_attempts;
    require(status == 0 && sites >= 4, "actual vector creation allocation sites observed");
    require(hepta_ctor_vector_destroy(handle) == 0, "measured vector destruction");
    require(live_allocations.load() == baseline, "successful vector owner pair balances allocations");
    for (std::uint64_t site = 0; site < sites; ++site) {
        handle = 0x123456789abcdef0ULL;
        fail_after = static_cast<std::int64_t>(site); allocation_attempts = 0; observe_allocations = true;
        status = hepta_ctor_vector_sized(37, &handle);
        observe_allocations = false;
        require(status == 3 && handle == 0x123456789abcdef0ULL, "real allocation refusal preserves output");
        require(allocation_attempts == site + 1, "exact injected allocation site was reached");
        require(live_allocations.load() == baseline, "partial construction and registry insertion failure release owners");
        require(hepta_ctor_vector_sized(37, &handle) == 0, "allocation refusal recovery");
        std::size_t size = 0;
        require(hepta_ctor_vector_size(handle, &size) == 0 && size == 37, "recovered vector has intended size");
        require(hepta_ctor_vector_destroy(handle) == 0, "recovered vector destruction");
        require(live_allocations.load() == baseline, "recovered allocation pair balances");
    }
    return sites;
}

int main() {
    std::uint64_t handle = 0;
    std::size_t size = 0;
    std::int64_t element = 99;
    for (std::size_t n : {std::size_t(0), std::size_t(1), std::size_t(7), std::size_t(64)}) {
        require(hepta_ctor_vector_sized(n, &handle) == 0, "C++ to Hepta to parameterized std::vector constructor");
        require(hepta_ctor_vector_size(handle, &size) == 0 && size == n, "vector size constructor result");
        if (n) require(hepta_ctor_vector_at(handle, n - 1, &element) == 0 && element == 0, "vector value initialization");
        require(hepta_ctor_vector_destroy(handle) == 0, "vector destructor");
        require(hepta_ctor_vector_destroy(handle) == 2, "no reusable destroyed handle");
        require(hepta_ctor_vector_filled(n, -7, &handle) == 0, "const-ref scalar constructor parameter");
        if (n) require(hepta_ctor_vector_at(handle, n - 1, &element) == 0 && element == -7, "fill constructor selects intended overload");
        require(hepta_ctor_vector_destroy(handle) == 0, "filled vector destructor");
    }
    auto vector_baseline = live_allocations.load();
    handle = 777;
    require(hepta_ctor_vector_sized((std::numeric_limits<std::size_t>::max)(), &handle) == 3 && handle == 777,
            "oversized std::vector length exception preserves output");
    require(live_allocations.load() == vector_baseline, "length failure releases partial owners");
    bool native_length_error = false;
    try { hepta_ctor_example::IntVector impossible((std::numeric_limits<std::size_t>::max)()); }
    catch (const std::length_error&) { native_length_error = true; }
    require(native_length_error, "underlying installed vector rejects impossible length");

    for (double degrees : {0.5, 1.0, 2.5, 30.0, (std::numeric_limits<double>::infinity)()}) {
        double result = -1;
        require(hepta_ctor_student_new(degrees, &handle) == 0, "actual non-default-constructible Boost.Math type");
        require(hepta_ctor_student_degrees(handle, &result) == 0 && result == degrees, "actual Boost member call");
        require(hepta_ctor_student_destroy(handle) == 0, "Boost object destruction in its C++ module");
    }
    for (double invalid : {0.0, -1.0, (std::numeric_limits<double>::quiet_NaN)()}) {
        auto baseline = live_allocations.load(); handle = 888;
        require(hepta_ctor_student_new(invalid, &handle) == 3 && handle == 888, "Boost domain exception preserves handle output");
        require(live_allocations.load() == baseline, "Boost constructor exception releases partial owners");
    }

    std::array<std::int64_t, 4> values{-3, 5, 8, 13};
    require(hepta_ctor_span_new(91, -6, values.data(), values.size(), &handle) == 0, "POD plus call-only span constructor");
    require(hepta_cpp_ctors_live_span_owners() == 1, "span fixture owner was constructed");
    values.fill(0);
    require(hepta_ctor_span_at(handle, 3, &element) == 0 && element == 13, "fixture copied its span during construction");
    std::uint64_t tag = 0; std::int64_t bias = 0;
    require(hepta_cpp_ctors_SpanOwner_tag(handle, &tag) == 0 && tag == 91, "POD field conversion tag");
    require(hepta_cpp_ctors_SpanOwner_bias(handle, &bias) == 0 && bias == -6, "POD field conversion bias");
    require(hepta_ctor_span_destroy(handle) == 0 && hepta_cpp_ctors_live_span_owners() == 0, "fixture same-module cleanup");
    require(hepta_ctor_span_new(0, 0, nullptr, 0, &handle) == 0, "empty null span constructor");
    require(hepta_ctor_span_destroy(handle) == 0, "empty span destructor");
    handle = 999;
    require(hepta_ctor_span_new(0, 0, nullptr, 1, &handle) == 1 && handle == 999, "null nonempty span rejected before constructor");
    require(hepta_ctor_span_new(0, 0, values.data(), (std::numeric_limits<std::size_t>::max)(), &handle) == 7 && handle == 999,
            "impossible span extent rejected before constructor");
    alignas(std::int64_t) unsigned char misaligned[32]{};
    require(hepta_ctor_span_new(0, 0, reinterpret_cast<const std::int64_t*>(misaligned + 1), 1, &handle) == 8 && handle == 999,
            "misaligned span rejected before constructor");
    require(hepta_ctor_vector_sized(1, nullptr) == 1, "null handle output rejected");
    require(hepta_ctor_vector_sized(1, reinterpret_cast<std::uint64_t*>(misaligned + 1)) == 8,
            "misaligned handle output rejected");

    require(hepta_ctor_nothrow_new(43, &handle) == 0, "noexcept scalar object constructor");
    std::uint64_t value = 0;
    require(hepta_cpp_ctors_NoThrowValue_value(handle, &value) == 0 && value == 43, "noexcept constructor value category");
    require(hepta_ctor_nothrow_destroy(handle) == 0 && hepta_cpp_ctors_live_nothrow_values() == 0, "noexcept object destruction");
    auto nothrow_baseline = live_allocations.load();
    handle = 333; fail_after = 0; allocation_attempts = 0; observe_allocations = true;
    auto status = hepta_ctor_nothrow_new(43, &handle);
    observe_allocations = false;
    require(status == 3 && handle == 333 && allocation_attempts == 1, "noexcept constructor still catches wrapper allocation failure");
    require(live_allocations.load() == nothrow_baseline, "noexcept wrapper refusal leaks no allocation");

    auto allocation_failures = vector_failure_trials();
    require(hepta_cpp_ctors_live_span_owners() == 0 && hepta_cpp_ctors_live_nothrow_values() == 0, "no fixture objects left live");
    std::cout << "{\"bidirectional_native\":true,\"boost_version\":" << BOOST_VERSION
              << ",\"boost_lib_version\":\"" << BOOST_LIB_VERSION
              << "\",\"boost_nondefault_constructible\":true,\"boost_success_cases\":5,\"boost_domain_failure_cases\":3"
              << ",\"vector_constructor_cases\":8,\"vector_length_rejected\":true,\"pod_span_constructor\":true,\"span_copy_observed\":true"
              << ",\"pointer_negative_controls\":5,\"noexcept_wrapper_allocation_failure\":true,\"allocation_failure_sites\":" << allocation_failures
              << ",\"allocation_recovery_calls\":" << allocation_failures
              << ",\"warm_registry_live_allocation_delta\":0,\"live_fixture_objects\":0,\"output_preserved_on_failure\":true}\n";
}
