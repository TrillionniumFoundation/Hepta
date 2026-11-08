/* Finite qualification witness for ordinary allocator contracts.
 * This object is linked only into explicitly named test programs. --wrap binds
 * generated calloc/malloc/free references; real allocations still use libc.
 * Exactly one selected call returns NULL. No allocator interposition is installed
 * into a host, service, or unrelated process. Pointer values are never exported.
 */
#include <stdint.h>
#include <stddef.h>
#include <limits.h>

extern void *__real_calloc(size_t, size_t);
extern void *__real_malloc(size_t);
extern void __real_free(void *);

#define MAX_LIVE 16384
#define MAGIC UINT64_C(0x484941434841494e)
struct tracked { void *ptr; uint64_t bytes; uint64_t id; };
static struct tracked live[MAX_LIVE];
static volatile uint64_t *stats;
static volatile uint64_t *events;
static uint64_t event_capacity, failure_index, next_id;

enum {
    ATTEMPTS, CALLOC_CALLS, MALLOC_CALLS, FORCED_FAILURES, ALLOCATIONS, FREES,
    LIVE_ALLOCATIONS, LIVE_BYTES, PEAK_BYTES, FOREIGN_FREES, RECORD_OVERFLOW,
    ZERO_SIZE_CALLS, UNEXPECTED_LIBC_NULL, EVENT_COUNT, FAILURE_INDEX, READY_MAGIC
};

void hia_test_begin(uint64_t selected_failure, volatile uint64_t *counters,
                    volatile uint64_t *event_words, uint64_t capacity) {
    stats = counters;
    events = event_words;
    event_capacity = capacity;
    failure_index = selected_failure;
    next_id = 0;
    for (size_t i = 0; i < 16; ++i) stats[i] = 0;
    for (size_t i = 0; i < MAX_LIVE; ++i) {
        live[i].ptr = NULL; live[i].bytes = 0; live[i].id = 0;
    }
    stats[FAILURE_INDEX] = failure_index;
    stats[READY_MAGIC] = MAGIC;
}

static void event(uint64_t kind, uint64_t bytes, uint64_t id, uint64_t result) {
    uint64_t index = stats[EVENT_COUNT];
    if (index >= event_capacity) {
        ++stats[RECORD_OVERFLOW];
        return;
    }
    events[index * 4] = kind;
    events[index * 4 + 1] = bytes;
    events[index * 4 + 2] = id;
    events[index * 4 + 3] = result;
    stats[EVENT_COUNT] = index + 1;
}

static int fail_this_call(uint64_t kind, uint64_t bytes) {
    ++stats[ATTEMPTS];
    ++stats[kind == 1 ? CALLOC_CALLS : MALLOC_CALLS];
    if (!bytes) ++stats[ZERO_SIZE_CALLS];
    if (failure_index && stats[ATTEMPTS] == failure_index) {
        ++stats[FORCED_FAILURES];
        event(kind, bytes, 0, 0);
        return 1;
    }
    return 0;
}

static void *remember(uint64_t kind, uint64_t bytes, void *ptr) {
    if (!ptr) {
        ++stats[UNEXPECTED_LIBC_NULL];
        event(kind, bytes, 0, 0);
        return NULL;
    }
    uint64_t id = ++next_id;
    for (size_t i = 0; i < MAX_LIVE; ++i) {
        if (!live[i].ptr) {
            live[i].ptr = ptr; live[i].bytes = bytes; live[i].id = id;
            ++stats[ALLOCATIONS]; ++stats[LIVE_ALLOCATIONS];
            stats[LIVE_BYTES] += bytes;
            if (stats[LIVE_BYTES] > stats[PEAK_BYTES])
                stats[PEAK_BYTES] = stats[LIVE_BYTES];
            event(kind, bytes, id, 1);
            return ptr;
        }
    }
    ++stats[RECORD_OVERFLOW];
    /* Outside this witness's declared tracking bound; the parent fails it. */
    event(kind, bytes, id, 1);
    return ptr;
}

void *__wrap_calloc(size_t count, size_t size) {
    if (!stats) return __real_calloc(count, size);
    uint64_t bytes = size && count > SIZE_MAX / size ? UINT64_MAX : count * size;
    if (fail_this_call(1, bytes)) return NULL;
    return remember(1, bytes, __real_calloc(count, size));
}

void *__wrap_malloc(size_t size) {
    if (!stats) return __real_malloc(size);
    if (fail_this_call(2, size)) return NULL;
    return remember(2, size, __real_malloc(size));
}

void __wrap_free(void *ptr) {
    if (!stats) { __real_free(ptr); return; }
    if (!ptr) return;
    for (size_t i = 0; i < MAX_LIVE; ++i) {
        if (live[i].ptr == ptr) {
            uint64_t bytes = live[i].bytes, id = live[i].id;
            live[i].ptr = NULL; live[i].bytes = 0; live[i].id = 0;
            ++stats[FREES]; --stats[LIVE_ALLOCATIONS]; stats[LIVE_BYTES] -= bytes;
            event(3, bytes, id, 1);
            __real_free(ptr);
            return;
        }
    }
    /* Never turn a diagnosed invalid free into an uncontrolled libc operation.
     * Every qualified invocation requires this counter to remain zero. */
    ++stats[FOREIGN_FREES];
    event(3, 0, 0, 0);
}

