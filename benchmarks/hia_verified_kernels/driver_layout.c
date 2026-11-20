/* Fixed-layout extension; the original v6 driver remains a separate control.
 * One arena lower-base phase (0 mod 4096), two exact gaps and both copy orders.
 * --validate-only executes the untimed checks and never reads the clock.
 */
#define _GNU_SOURCE
#include <dlfcn.h>
#include <errno.h>
#include <inttypes.h>
#include <stdint.h>
#include <sched.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <unistd.h>

#define MAX_LENGTH 65536u
#define PAGE_BYTES 4096u
#define ARENA_BYTES 262144u
#define LOWER_OFFSET 4096u
#define FIRST_GAP 131072u
#define SECOND_GAP 131136u

typedef uint64_t (*span_fn)(const uint8_t *, uint64_t, uint64_t);
typedef uint64_t (*copy_fn)(uint8_t *, uint64_t, const uint8_t *, uint64_t, uint64_t);
static volatile uint64_t observed;
static cpu_set_t admitted_affinity;

static int affinity_unchanged(void) {
    cpu_set_t current;
    CPU_ZERO(&current);
    return sched_getaffinity(0, sizeof(current), &current) == 0 && CPU_EQUAL(&current, &admitted_affinity);
}

static uint64_t now(void) {
    struct timespec t;
    if (clock_gettime(CLOCK_MONOTONIC_RAW, &t)) abort();
    return (uint64_t)t.tv_sec * UINT64_C(1000000000) + (uint64_t)t.tv_nsec;
}

static int number(const char *text, uint64_t *result) {
    if (!text[0]) return 0;
    for (const char *p = text; *p; ++p) if (*p < '0' || *p > '9') return 0;
    char *end;
    errno = 0;
    unsigned long long value = strtoull(text, &end, 10);
    if (errno || *end) return 0;
    *result = (uint64_t)value;
    return 1;
}

static void initialize(uint8_t *source, size_t length, int zero) {
    uint64_t state = UINT64_C(0x3c79ac492ba7b653);
    for (size_t i = 0; i < length + 32; ++i) {
        state ^= state >> 12; state ^= state << 25; state ^= state >> 27;
        source[i] = zero ? 0 : (uint8_t)((state * UINT64_C(0x2545f4914f6cdd1d)) >> 56);
    }
}

static int preflight(span_fn rf, copy_fn cf, uint8_t *source,
                     uint8_t *destination, size_t length, int copy, int zero) {
    for (size_t offset = 1; offset <= 16; ++offset) {
        uint64_t expected = zero ? 1 : 0;
        if (!copy && !zero)
            for (size_t j = 0; j < length; ++j) expected += source[offset + j];
        if (copy) memset(destination, 0xa5, length + 32);
        uint64_t actual = copy
            ? cf(destination + offset, length, source + offset, length, length)
            : rf(source + offset, length, length);
        if (actual != (copy ? length : expected)) return 9;
        if (copy) {
            if (memcmp(destination + offset, source + offset, length)) return 10;
            for (size_t j = 0; j < length + 32; ++j)
                if ((j < offset || j >= offset + length) && destination[j] != 0xa5) return 14;
        }
    }
    if (zero && length) {
        const size_t positions[] = {1, 1 + length / 2, length};
        for (size_t j = 0; j < 3; ++j) {
            source[positions[j]] = 255;
            if (rf(source + 1, length, length) != 0) return 12;
            source[positions[j]] = 0;
        }
    }
    return 0;
}

int main(int argc, char **argv) {
    int validation_only = argc == 10 && strcmp(argv[9], "--validate-only") == 0;
    if (argc != 9 && !validation_only) return 2;
    const char *mode = argv[1], *order = argv[8];
    int copy = strcmp(mode, "copy") == 0, zero = strcmp(mode, "zero") == 0;
    int source_high = strcmp(order, "src-high") == 0;
    uint64_t batches, iterations, parsed_length, gap;
    if ((!copy && !zero && strcmp(mode, "sum")) ||
        (!source_high && strcmp(order, "src-low")) ||
        !number(argv[4], &batches) || batches != 21 ||
        !number(argv[5], &iterations) || !iterations ||
        !number(argv[6], &parsed_length) || parsed_length > MAX_LENGTH ||
        !number(argv[7], &gap) || (gap != FIRST_GAP && gap != SECOND_GAP) ||
        (!copy && (source_high || gap != FIRST_GAP)) ||
        sysconf(_SC_PAGESIZE) != PAGE_BYTES) return 3;
    size_t length = (size_t)parsed_length;
    CPU_ZERO(&admitted_affinity);
    if (sched_getaffinity(0, sizeof(admitted_affinity), &admitted_affinity) || CPU_COUNT(&admitted_affinity) != 1) return 16;
    int cpu = 0;
    while (cpu < CPU_SETSIZE && !CPU_ISSET(cpu, &admitted_affinity)) ++cpu;
    void *allocation = NULL;
    if (posix_memalign(&allocation, PAGE_BYTES, ARENA_BYTES)) return 7;
    uint8_t *arena = allocation, *lower = arena + LOWER_OFFSET, *upper = lower + gap;
    uint8_t *source = source_high ? upper : lower;
    uint8_t *destination = source_high ? lower : upper;
    if ((uintptr_t)arena % PAGE_BYTES || (uintptr_t)lower % PAGE_BYTES ||
        upper + MAX_LENGTH + 32 > arena + ARENA_BYTES ||
        gap < MAX_LENGTH + 32) return 15;
    memset(arena, 0x5a, ARENA_BYTES);
    initialize(source, length, zero);

    /* This receipt is emitted before dlopen; the arena is never reallocated. */
    printf("{\"record\":\"layout\",\"schema\":\"hia.kernel-layout.phase0.v1\","
           "\"mode\":\"%s\",\"length\":%zu,\"cpu\":%d,\"arena_base\":%" PRIuPTR
           ",\"arena_bytes\":%u,\"page_bytes\":%u,\"lower_base\":%" PRIuPTR
           ",\"upper_base\":%" PRIuPTR ",\"source_base\":%" PRIuPTR
           ",\"destination_base\":%" PRIuPTR ",\"source_mod64\":%" PRIuPTR
           ",\"destination_mod64\":%" PRIuPTR ",\"source_mod4096\":%" PRIuPTR
           ",\"destination_mod4096\":%" PRIuPTR ",\"gap\":%" PRIu64
           ",\"destination_minus_source\":%" PRId64 ",\"address_order\":\"%s\","
           "\"relative_offsets\":[1,16],\"arena_allocated_before_dlopen\":true,"
           "\"validation_only\":%s}\n",
           mode, length, cpu, (uintptr_t)arena, ARENA_BYTES, PAGE_BYTES, (uintptr_t)lower,
           (uintptr_t)upper, (uintptr_t)source, (uintptr_t)destination,
           (uintptr_t)source % 64, (uintptr_t)destination % 64,
           (uintptr_t)source % PAGE_BYTES, (uintptr_t)destination % PAGE_BYTES,
           gap, (int64_t)(destination - source), order, validation_only ? "true" : "false");
    fflush(stdout);
    void *library = dlopen(argv[2], RTLD_NOW | RTLD_LOCAL);
    if (!library) { fprintf(stderr, "%s\n", dlerror()); return 5; }
    void *address = dlsym(library, argv[3]);
    if (!address) return 6;
    span_fn rf = (span_fn)address;
    copy_fn cf = (copy_fn)address;
    uint64_t timed_expected = UINT64_C(0x123456789abcdef);
    if (copy || zero) timed_expected += iterations * (copy ? length : 1);
    else {
        for (size_t offset = 1; offset <= 16; ++offset) {
            uint64_t total = 0;
            for (size_t j = 0; j < length; ++j) total += source[offset + j];
            timed_expected += total * (iterations / 16 + (offset <= iterations % 16));
        }
    }
    if (validation_only) {
        int error = preflight(rf, cf, source, destination, length, copy, zero);
        if (error) return error;
        if (!affinity_unchanged()) return 16;
        printf("{\"record\":\"validation\",\"ok\":true,\"timed_samples\":0,"
               "\"length\":%zu,\"offsets_checked\":16,\"checksum\":%" PRIu64 "}\n", length, timed_expected);
        free(allocation); dlclose(library);
        return 0;
    }
    for (int batch = -3; batch < 21; ++batch) {
        if (!affinity_unchanged()) return 16;
        int error = preflight(rf, cf, source, destination, length, copy, zero);
        if (error) return error;
        if (copy) memset(destination, 0xa5, length + 32);
        uint64_t value = UINT64_C(0x123456789abcdef);
        uint64_t start = now();
        if (copy) {
            for (uint64_t i = 0; i < iterations; ++i) {
                size_t offset = 1 + (i & 15);
                value += cf(destination + offset, length, source + offset, length, length);
            }
        } else {
            for (uint64_t i = 0; i < iterations; ++i)
                value += rf(source + 1 + (i & 15), length, length);
        }
        uint64_t elapsed = now() - start;
        if (!affinity_unchanged()) return 16;
        observed = value;
        if (value != timed_expected) return 13;
        if (copy) {
            size_t last_offset = 1 + ((iterations - 1) & 15);
            if (length && memcmp(destination + last_offset, source + last_offset, length)) return 11;
            if (destination[0] != 0xa5 || destination[length + 31] != 0xa5) return 14;
        }
        if (batch >= 0) {
            printf("{\"batch\":%d,\"elapsed_ns\":%" PRIu64 ",\"calls\":%" PRIu64
                   ",\"ns_per_call\":%.9f,\"checksum\":%" PRIu64
                   ",\"source_base\":%" PRIuPTR ",\"destination_base\":%" PRIuPTR "}\n",
                   batch, elapsed, iterations, (double)elapsed / (double)iterations, value,
                   (uintptr_t)source, (uintptr_t)destination);
            fflush(stdout);
        }
    }
    free(allocation); dlclose(library);
    return 0;
}
