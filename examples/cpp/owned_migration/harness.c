/* This harness is also compiled as C++ for the original reference. */
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <inttypes.h>
#include "cases.h"

/* Linker wrapping is applied after optimization. Volatile observations keep
 * the optimizer from assuming an ordinary calloc cannot reach this state. */
static volatile bool observed_tracking = false, observed_refuse = false;
static volatile size_t observed_allocated = 0, observed_freed = 0, observed_refusals = 0;
static volatile size_t observed_attempts = 0;
static volatile intptr_t observed_live = 0;

#ifdef __cplusplus
#include <new>
extern "C" uint64_t owned_case(size_t, uint8_t, size_t, uint32_t, uint32_t) noexcept;
void* operator new[](std::size_t size) {
    if (observed_tracking) {
        observed_attempts = observed_attempts + 1;
        if (observed_refuse) { observed_refusals = observed_refusals + 1; throw std::bad_alloc(); }
    }
    void* pointer = std::malloc(size);
    if (!pointer) { throw std::bad_alloc(); }
    if (observed_tracking) { observed_allocated = observed_allocated + 1; observed_live = observed_live + 1; }
    return pointer;
}
void operator delete[](void* pointer) noexcept {
    if (observed_tracking && pointer) { observed_freed = observed_freed + 1; observed_live = observed_live - 1; }
    std::free(pointer);
}
void operator delete[](void* pointer, std::size_t) noexcept { ::operator delete[](pointer); }
#else
extern uint64_t owned_case(size_t, uint8_t, size_t, uint32_t, uint32_t);
void* __real_calloc(size_t, size_t);
void* __real_malloc(size_t);
void __real_free(void*);
void* __wrap_calloc(size_t count, size_t size) {
    if (observed_tracking) {
        observed_attempts = observed_attempts + 1;
        if (observed_refuse) { observed_refusals = observed_refusals + 1; return NULL; }
    }
    void* pointer = __real_calloc(count, size);
    if (observed_tracking && pointer) { observed_allocated = observed_allocated + 1; observed_live = observed_live + 1; }
    return pointer;
}
void* __wrap_malloc(size_t size) {
    if (observed_tracking) {
        observed_attempts = observed_attempts + 1;
        if (observed_refuse) { observed_refusals = observed_refusals + 1; return NULL; }
    }
    void* pointer = __real_malloc(size);
    if (observed_tracking && pointer) { observed_allocated = observed_allocated + 1; observed_live = observed_live + 1; }
    return pointer;
}
void __wrap_free(void* pointer) {
    if (observed_tracking && pointer) { observed_freed = observed_freed + 1; observed_live = observed_live - 1; }
    __real_free(pointer);
}
#endif

static uint64_t observe_word(uint64_t state, uint64_t word) {
    for (unsigned i = 0; i < 8; ++i) {
        state ^= (word >> (i * 8)) & 255;
        state *= UINT64_C(1099511628211);
    }
    return state;
}

int main(void) {
    uint64_t digest = UINT64_C(14695981039346656037);
    size_t total_allocations = 0, total_frees = 0, total_refusals = 0;
    for (size_t i = 0; i < OWNED_CASE_COUNT; ++i) {
        const struct OwnedCase* current = &owned_cases[i];
        observed_allocated = 0;
        observed_freed = 0;
        observed_refusals = 0;
        observed_attempts = 0;
        observed_live = 0;
        observed_refuse = current->refuse != 0;
        observed_tracking = true;
        uint64_t actual = owned_case(current->size, current->value, current->index, current->reject, current->early);
        observed_tracking = false;
        if (actual != current->expected) {
            printf("{\"ok\":false,\"failure\":\"value\",\"case\":%zu,\"expected\":%" PRIu64 ",\"actual\":%" PRIu64 "}\n",
                   i, current->expected, actual);
            return 2;
        }
        if (observed_allocated != current->allocated || observed_freed != current->allocated ||
            observed_live != 0 || observed_refusals != current->refusals ||
            observed_attempts != current->allocated + current->refusals) {
            printf("{\"ok\":false,\"failure\":\"lifecycle\",\"case\":%zu,\"allocated\":%zu,\"freed\":%zu,\"live\":%" PRIdPTR ",\"refusals\":%zu,\"attempts\":%zu}\n",
                   i, observed_allocated, observed_freed, observed_live, observed_refusals, observed_attempts);
            return 3;
        }
        total_allocations += observed_allocated;
        total_frees += observed_freed;
        total_refusals += observed_refusals;
        digest = observe_word(digest, i);
        digest = observe_word(digest, actual);
        digest = observe_word(digest, observed_allocated);
        digest = observe_word(digest, observed_freed);
        digest = observe_word(digest, observed_refusals);
    }
    printf("{\"ok\":true,\"cases\":%zu,\"observations_fnv64\":\"%016" PRIx64 "\",\"allocations\":%zu,\"frees\":%zu,\"refusals\":%zu,\"live\":0}\n",
           (size_t)OWNED_CASE_COUNT, digest, total_allocations, total_frees, total_refusals);
    return 0;
}
