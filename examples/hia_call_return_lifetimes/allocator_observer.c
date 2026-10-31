/* Finite native qualification observer, not a production allocator.
 * Linker wrapping observes calls from the generated HIA object. An abort
 * records the exact allocation prefix and then actually raises SIGABRT.
 * Loans are erased by native lowering; these counters do not observe loans.
 */
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <sys/resource.h>

void *__real_malloc(size_t);
void *__real_calloc(size_t, size_t);
void __real_free(void *);
_Noreturn void __real_abort(void);

struct allocation { void *pointer; uint64_t id, bytes; };
struct event { unsigned kind; uint64_t id, bytes; };
static struct allocation live[32];
static struct event events[256];
static size_t event_count;
static uint64_t attempts, refuse_at, allocations, frees, live_bytes, peak_bytes;
static uint64_t null_frees, bad_frees;

static void event(unsigned kind, uint64_t id, uint64_t bytes) {
    if (event_count == sizeof events / sizeof *events) _Exit(67);
    events[event_count++] = (struct event){kind, id, bytes};
}

static void report(const char *status, uint64_t result) {
    printf("{\"status\":\"%s\",\"result\":%llu,\"attempts\":%llu,"
           "\"allocations\":%llu,\"frees\":%llu,\"live_bytes\":%llu,"
           "\"peak_bytes\":%llu,\"null_frees\":%llu,\"bad_frees\":%llu,\"events\":[",
           status, (unsigned long long)result, (unsigned long long)attempts,
           (unsigned long long)allocations, (unsigned long long)frees,
           (unsigned long long)live_bytes, (unsigned long long)peak_bytes,
           (unsigned long long)null_frees, (unsigned long long)bad_frees);
    for (size_t index = 0; index < event_count; index++) {
        struct event item = events[index];
        printf("%s[%u,%llu,%llu]", index ? "," : "", item.kind,
               (unsigned long long)item.id, (unsigned long long)item.bytes);
    }
    puts("]}");
    fflush(stdout);
}

static void *allocate(size_t bytes, bool zero) {
    attempts++;
    event(0, attempts, bytes);
    void *pointer = attempts == refuse_at ? NULL :
        (zero ? __real_calloc(1, bytes) : __real_malloc(bytes));
    if (!pointer) { event(1, attempts, bytes); return NULL; }
    size_t slot;
    for (slot = 0; slot < sizeof live / sizeof *live && live[slot].pointer; slot++);
    if (slot == sizeof live / sizeof *live) _Exit(68);
    live[slot] = (struct allocation){pointer, attempts, bytes};
    allocations++;
    live_bytes += bytes;
    if (live_bytes > peak_bytes) peak_bytes = live_bytes;
    event(2, attempts, bytes);
    return pointer;
}

void *__wrap_malloc(size_t bytes) { return allocate(bytes, false); }
void *__wrap_calloc(size_t count, size_t bytes) {
    if (count && bytes > SIZE_MAX / count) _Exit(69);
    return allocate(count * bytes, true);
}
void __wrap_free(void *pointer) {
    if (!pointer) { null_frees++; event(5, 0, 0); return; }
    size_t slot;
    for (slot = 0; slot < sizeof live / sizeof *live && live[slot].pointer != pointer; slot++);
    if (slot == sizeof live / sizeof *live) { bad_frees++; _Exit(70); }
    struct allocation item = live[slot];
    live[slot] = (struct allocation){NULL, 0, 0};
    live_bytes -= item.bytes;
    frees++;
    event(3, item.id, item.bytes);
    __real_free(pointer);
}

_Noreturn void __wrap_abort(void) {
    event(4, 0, 0);
    report("trapped", 0);
    __real_abort();
}

/* ENTRY_DECLARATION */
int main(int argc, char **argv) {
    struct rlimit zero = {0, 0}, cpu = {2, 2}, memory = {268435456, 268435456};
    if (setrlimit(RLIMIT_CORE, &zero) || setrlimit(RLIMIT_CPU, &cpu) ||
        setrlimit(RLIMIT_AS, &memory)) return 71;
    /* ENTRY_CALL */
    report("returned", result);
    return 0;
}
