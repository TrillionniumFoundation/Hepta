/* Compiled as C++ for the original, and C for translated implementations. */
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <inttypes.h>
#include "cases.h"

static volatile bool observed_tracking;
static volatile size_t observed_refuse_at, observed_allocated, observed_freed, observed_refusals, observed_attempts;
static volatile intptr_t observed_live;
static volatile uint64_t observed_trace;
static volatile size_t observed_bytes, observed_peak_bytes, observed_peak_owners;
static void* volatile observed_pointers[8];
static volatile size_t observed_sizes[8];

static uint64_t observe_word(uint64_t state, uint64_t word) {
    for (unsigned i = 0; i < 8; ++i) { state ^= (word >> (i * 8)) & 255; state *= UINT64_C(1099511628211); }
    return state;
}
static void observe_event(uint64_t kind, size_t identity, size_t size) {
    observed_trace = observe_word(observe_word(observe_word(observed_trace, kind), identity), size);
}
static bool refuse_allocation(size_t size) {
    if (!observed_tracking) return false;
    observed_attempts = observed_attempts + 1;
    if (observed_attempts != observed_refuse_at) return false;
    observed_refusals = observed_refusals + 1;
    observe_event(3, observed_attempts, size);
    return true;
}
static void record_allocation(void* pointer, size_t size) {
    if (!observed_tracking || !pointer) return;
    if (observed_allocated >= 8) abort();
    observed_pointers[observed_allocated] = pointer;
    observed_sizes[observed_allocated] = size;
    observed_allocated = observed_allocated + 1;
    observed_live = observed_live + 1;
    observed_bytes = observed_bytes + size;
    if (observed_bytes > observed_peak_bytes) observed_peak_bytes = observed_bytes;
    if ((size_t)observed_live > observed_peak_owners) observed_peak_owners = (size_t)observed_live;
    observe_event(1, observed_allocated, size);
}
static void record_release(void* pointer) {
    if (!observed_tracking || !pointer) return;
    for (size_t i = 0; i < observed_allocated; ++i) {
        if (observed_pointers[i] == pointer) {
            observed_pointers[i] = NULL;
            observed_freed = observed_freed + 1;
            observed_live = observed_live - 1;
            observed_bytes = observed_bytes - observed_sizes[i];
            observe_event(2, i + 1, observed_sizes[i]);
            return;
        }
    }
    abort(); /* Unknown or double release is a native observation failure. */
}
#ifdef __cplusplus
#include <new>
extern "C" uint64_t composed_case(size_t, size_t, uint8_t, size_t, uint32_t, uint32_t) noexcept;
void* operator new[](std::size_t size) {
    if (refuse_allocation(size)) throw std::bad_alloc();
    void* pointer = std::malloc(size);
    if (!pointer) throw std::bad_alloc();
    record_allocation(pointer, size);
    return pointer;
}
void operator delete[](void* pointer) noexcept { record_release(pointer); std::free(pointer); }
void operator delete[](void* pointer, std::size_t) noexcept { ::operator delete[](pointer); }
#else
extern uint64_t composed_case(size_t, size_t, uint8_t, size_t, uint32_t, uint32_t);
void* __real_calloc(size_t, size_t);
void* __real_malloc(size_t);
void __real_free(void*);
void* __wrap_calloc(size_t count, size_t size) {
    if (refuse_allocation(count * size)) return NULL;
    void* pointer = __real_calloc(count, size);
    record_allocation(pointer, count * size);
    return pointer;
}
void* __wrap_malloc(size_t size) {
    if (refuse_allocation(size)) return NULL;
    void* pointer = __real_malloc(size);
    record_allocation(pointer, size);
    return pointer;
}
void __wrap_free(void* pointer) { record_release(pointer); __real_free(pointer); }
#endif

int main(void) {
    uint64_t digest = UINT64_C(14695981039346656037);
    size_t total_allocations = 0, total_frees = 0, total_refusals = 0;
    size_t max_live_bytes = 0, max_live_owners = 0;
    for (size_t i = 0; i < COMPOSED_CASE_COUNT; ++i) {
        const struct ComposedCase* current = &composed_cases[i];
        observed_allocated = 0; observed_freed = 0; observed_refusals = 0; observed_attempts = 0;
        observed_bytes = 0; observed_peak_bytes = 0; observed_peak_owners = 0;
        observed_live = 0; observed_trace = UINT64_C(14695981039346656037);
        for (size_t j = 0; j < 8; ++j) { observed_pointers[j] = NULL; observed_sizes[j] = 0; }
        observed_refuse_at = current->refuse_at; observed_tracking = true;
        uint64_t actual = composed_case(current->left, current->right, current->value, current->index, current->reject, current->early);
        observed_tracking = false;
        if (actual != current->expected) {
            printf("{\"ok\":false,\"failure\":\"value\",\"case\":%zu,\"expected\":%" PRIu64 ",\"actual\":%" PRIu64 "}\n", i, current->expected, actual);
            return 2;
        }
        if (observed_allocated != current->allocated || observed_freed != current->allocated || observed_live != 0 || observed_bytes != 0 ||
            observed_refusals != current->refusals || observed_attempts != current->allocated + current->refusals || observed_trace != current->trace) {
            printf("{\"ok\":false,\"failure\":\"lifecycle\",\"case\":%zu,\"allocated\":%zu,\"freed\":%zu,\"live\":%" PRIdPTR ",\"refusals\":%zu,\"trace\":\"%016" PRIx64 "\",\"expected_trace\":\"%016" PRIx64 "\"}\n",
                   i, observed_allocated, observed_freed, observed_live, observed_refusals, observed_trace, current->trace);
            return 3;
        }
        if (observed_peak_bytes > max_live_bytes) max_live_bytes = observed_peak_bytes;
        if (observed_peak_owners > max_live_owners) max_live_owners = observed_peak_owners;
        total_allocations += observed_allocated; total_frees += observed_freed; total_refusals += observed_refusals;
        digest = observe_word(digest, i); digest = observe_word(digest, actual); digest = observe_word(digest, observed_trace);
        digest = observe_word(digest, observed_allocated); digest = observe_word(digest, observed_freed); digest = observe_word(digest, observed_refusals);
    }
    printf("{\"ok\":true,\"cases\":%zu,\"observations_fnv64\":\"%016" PRIx64 "\",\"allocations\":%zu,\"frees\":%zu,\"refusals\":%zu,\"live\":0,\"max_live_bytes\":%zu,\"max_live_owners\":%zu}\n",
           (size_t)COMPOSED_CASE_COUNT, digest, total_allocations, total_frees, total_refusals, max_live_bytes, max_live_owners);
    return 0;
}
