#include "bridge.h"
#include "hepta.h"
#include "foreign.hpp"
#include <cstdio>
#include <cstdlib>
#include <limits>
#include <new>
#include <type_traits>

namespace {
std::uint64_t allocation_attempts = 0, allocations = 0, deallocations = 0, reject_at = 0;
void require(bool condition, const char* message) {
    if (!condition) { std::fprintf(stderr, "%s\n", message); std::exit(1); }
}
std::uint64_t live_allocations() { return allocations - deallocations; }
}
// These counters observe C++ ordinary new/delete, not every process allocator.
void* operator new(std::size_t size) {
    ++allocation_attempts;
    if (reject_at && allocation_attempts == reject_at) throw std::bad_alloc();
    if (auto* ptr = std::malloc(size ? size : 1)) { ++allocations; return ptr; }
    throw std::bad_alloc();
}
void operator delete(void* ptr) noexcept { if (ptr) { ++deallocations; std::free(ptr); } }
void operator delete(void* ptr, std::size_t) noexcept { ::operator delete(ptr); }
void* operator new[](std::size_t size) { return ::operator new(size); }
void operator delete[](void* ptr) noexcept { ::operator delete(ptr); }
void operator delete[](void* ptr, std::size_t) noexcept { ::operator delete(ptr); }

// Imported Hepta type names contain module identities. Use the actual emitted
// C prototype to obtain its POD pointee, rather than guessing a matching name.
template<class R, class A, class B, class C>
auto output_pointee(R(*)(A, B, C)) -> std::remove_pointer_t<C>;
using HeptaPair = decltype(output_pointee(&hepta_scoped_pair));

int main() {
    std::uint64_t successful_vectors = 0;
    for (std::size_t count : {0u, 1u, 3u, 8u}) {
        for (auto initial : {std::int64_t{-7}, std::int64_t{5}}) {
            for (auto index : {std::size_t{0}, count}) {
                std::int64_t out = -1;
                auto before = live_allocations();
                require(hepta_scoped_vector(count, initial, 91, index, &out) == 0, "Hepta vector call");
                require(out == scoped_example::native_vector(count, initial, 91, index), "native differential result");
                require(live_allocations() == before, "scoped vector allocation not released");
                ++successful_vectors;
            }
        }
    }

    std::int64_t out = scoped_example::output_sentinel;
    auto before_attempts = allocation_attempts;
    require(hepta_scoped_vector(8, 1, 2, 0, nullptr) == 1, "null output rejected");
    alignas(std::int64_t) unsigned char storage[sizeof(std::int64_t) + 1]{};
    require(hepta_scoped_vector(8, 1, 2, 0, reinterpret_cast<std::int64_t*>(storage + 1)) == 8,
            "misaligned output rejected");
    require(allocation_attempts == before_attempts, "output guards run before construction");
    auto before_live = live_allocations();
    require(hepta_scoped_vector((std::numeric_limits<std::size_t>::max)(), 1, 2, 0, &out) == 3,
            "native length exception translated");
    require(out == scoped_example::output_sentinel && live_allocations() == before_live,
            "constructor rejection preserves output and allocations");
    require(hepta_scoped_vector(8, 1, 2, 999, &out) == 3, "native at exception translated");
    require(out == scoped_example::output_sentinel && live_allocations() == before_live,
            "method rejection destroys vector before returning");

    std::uint64_t probe_paths = 0;
    for (std::uint64_t mode = 0; mode != 4; ++mode) {
        scoped_example::audit = {};
        out = scoped_example::output_sentinel;
        scoped_example::watched_output = &out;
        const auto baseline = live_allocations();
        auto status = hepta_scoped_probe(3, 12, mode, 43, 3, &out);
        scoped_example::watched_output = nullptr;
        const auto& a = scoped_example::audit;
        require(status == (mode == 0 ? 0 : 3), "probe status");
        require(out == (mode == 0 ? 43 : scoped_example::output_sentinel), "probe output preservation");
        require(a.members_constructed == 1 && a.members_destroyed == 1, "subobject RAII including failed ctor");
        require(a.objects_constructed == (mode == 1 ? 0u : 1u) && a.objects_destroyed == a.objects_constructed,
                "exactly one destructor for each fully constructed immovable object");
        require(a.final_calls == ((mode == 0 || mode == 3) ? 1u : 0u), "failed earlier call stops later methods");
        require(a.output_seen_before_publication == a.objects_destroyed, "output published only after destruction");
        require(live_allocations() == baseline, "probe allocation delta");
        ++probe_paths;
    }
    for (std::uint64_t mode : {0u, 2u}) {
        scoped_example::audit = {};
        auto baseline = live_allocations();
        require(hepta_scoped_unit(3, 12, mode, 43) == (mode ? 3 : 0), "Unit scoped status");
        require(scoped_example::audit.objects_destroyed == 1 && live_allocations() == baseline, "Unit scoped cleanup");
    }
    HeptaPair pair{-1, 0};
    require(hepta_scoped_pair(123, 456, &pair) == 0 && pair.first == 123 && pair.second == 456,
            "POD reference copied before destructor changes original");

    // Count complete lifecycle operations with the registry already warmed.
    std::uint64_t handle = 0;
    require(hepta_cpp_scoped_Vector_filled(8, 1, &handle) == 0, "warm handle create");
    require(hepta_cpp_scoped_Vector_destroy(handle) == 0, "warm handle destroy");
    auto start = allocations;
    auto baseline = live_allocations();
    require(scoped_example::native_vector(8, 1, 2, 8) == 2, "direct count baseline");
    auto direct_allocations = allocations - start;
    require(live_allocations() == baseline, "direct allocation balance");
    start = allocations;
    require(hepta_scoped_vector(8, 1, 2, 8, &out) == 0 && out == 2, "scoped count result");
    auto scoped_allocations = allocations - start;
    require(live_allocations() == baseline, "scoped allocation balance");
    start = allocations;
    require(hepta_cpp_scoped_Vector_filled(8, 1, &handle) == 0, "handle count create");
    require(hepta_cpp_scoped_Vector_append(handle, 2) == 0, "handle count append");
    require(hepta_cpp_scoped_Vector_at(handle, 8, &out) == 0 && out == 2, "handle count at");
    require(hepta_cpp_scoped_Vector_destroy(handle) == 0, "handle count destroy");
    auto handle_allocations = allocations - start;
    require(live_allocations() == baseline, "handle allocation balance excluding warmed registry");
    require(direct_allocations > 0 && scoped_allocations == direct_allocations && handle_allocations > scoped_allocations,
            "measured ordinary new cost distinguishes scoped and registry paths");

    for (std::uint64_t site = 1; site <= scoped_allocations; ++site) {
        baseline = live_allocations();
        out = scoped_example::output_sentinel;
        reject_at = allocation_attempts + site;
        auto status = hepta_scoped_vector(8, 1, 2, 8, &out);
        reject_at = 0;
        require(status == 3 && out == scoped_example::output_sentinel, "allocation refusal status/output");
        require(live_allocations() == baseline, "allocation refusal cleanup");
        require(hepta_scoped_vector(8, 1, 2, 8, &out) == 0 && out == 2, "recovery after allocation refusal");
        require(live_allocations() == baseline, "recovery cleanup");
    }
    std::printf("{\"vector_differential_cases\":%llu,\"probe_lifecycle_paths\":%llu,"
                "\"unit_cleanup_paths\":2,\"pod_reference_copy\":true,\"output_guard_cases\":2,"
                "\"allocation_refusal_sites\":%llu,\"allocation_recoveries\":%llu,"
                "\"direct_cpp_new_calls\":%llu,\"scoped_cpp_new_calls\":%llu,\"handle_cpp_new_calls\":%llu,"
                "\"scoped_wrapper_allocation_delta\":0,\"live_cpp_allocation_delta\":0,"
                "\"output_after_destructor\":true,\"foreign_cpp_library_rewritten\":false}\n",
                (unsigned long long)successful_vectors, (unsigned long long)probe_paths,
                (unsigned long long)scoped_allocations, (unsigned long long)scoped_allocations,
                (unsigned long long)direct_allocations, (unsigned long long)scoped_allocations,
                (unsigned long long)handle_allocations);
}
