/* Test-only C allocator instrumentation; the upstream parser calls these hooks. */
#include <stddef.h>
#include <stdlib.h>

int ini_fail_next_allocation = 0;
static void* live[64];
static size_t allocation_calls = 0;

void* ini_malloc(size_t size) {
    ++allocation_calls;
    if (ini_fail_next_allocation) { ini_fail_next_allocation = 0; return NULL; }
    void* result = malloc(size);
    if (!result) { return NULL; }
    for (size_t i = 0; i < 64; ++i) {
        if (!live[i]) { live[i] = result; return result; }
    }
    abort();
}

void ini_free(void* pointer) {
    if (!pointer) { return; }
    for (size_t i = 0; i < 64; ++i) {
        if (live[i] == pointer) { live[i] = NULL; free(pointer); return; }
    }
    abort();
}

void* ini_realloc(void* pointer, size_t size) {
    if (!pointer) { return ini_malloc(size); }
    for (size_t i = 0; i < 64; ++i) {
        if (live[i] == pointer) {
            void* result = realloc(pointer, size);
            if (result || size == 0) { live[i] = result; }
            return result;
        }
    }
    abort();
}

size_t ini_live_allocations(void) {
    size_t count = 0;
    for (size_t i = 0; i < 64; ++i) { count += live[i] != NULL; }
    return count;
}

size_t ini_total_allocations(void) { return allocation_calls; }

/* Called only AFTER the original leak observation is printed. This does not
   turn original production cleanup into a passing observation. */
void ini_probe_release_observed_leaks(void) {
    for (size_t i = 0; i < 64; ++i) {
        if (live[i]) { free(live[i]); live[i] = NULL; }
    }
}
