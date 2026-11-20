/* Indirect-call hot-cache microbenchmarks; every batch and checksum is retained. */
#define _GNU_SOURCE
#include <dlfcn.h>
#include <inttypes.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

typedef uint64_t (*scalar_fn)(uint64_t, uint64_t, uint64_t);
typedef uint64_t (*span_fn)(const uint8_t *, uint64_t, uint64_t);
typedef uint64_t (*copy_fn)(uint8_t *, uint64_t, const uint8_t *, uint64_t, uint64_t);
static volatile uint64_t observed;

static uint64_t now(void) {
    struct timespec t;
    if (clock_gettime(CLOCK_MONOTONIC_RAW, &t)) abort();
    return (uint64_t)t.tv_sec * UINT64_C(1000000000) + (uint64_t)t.tv_nsec;
}

int main(int argc, char **argv) {
    if (argc != 7) return 2;
    const char *mode = argv[1];
    int batches = atoi(argv[4]);
    uint64_t iterations = strtoull(argv[5], NULL, 10);
    size_t length = (size_t)strtoull(argv[6], NULL, 10);
    if (batches != 21 || !iterations || length > (1u << 20)) return 3;
    int scalar = strcmp(mode, "scalar") == 0;
    int copy = strcmp(mode, "copy") == 0;
    int zero = strcmp(mode, "zero") == 0;
    if (!scalar && !copy && !zero && strcmp(mode, "sum") != 0) return 4;
    void *library = dlopen(argv[2], RTLD_NOW | RTLD_LOCAL);
    if (!library) { fprintf(stderr, "%s\n", dlerror()); return 5; }
    void *address = dlsym(library, argv[3]);
    if (!address) return 6;
    scalar_fn sf = (scalar_fn)address;
    span_fn rf = (span_fn)address;
    copy_fn cf = (copy_fn)address;
    uint8_t *source = malloc(length + 32), *destination = malloc(length + 32);
    if (!source || !destination) return 7;
    uint64_t state = UINT64_C(0x3c79ac492ba7b653);
    for (size_t i = 0; i < length + 32; ++i) {
        state ^= state >> 12; state ^= state << 25; state ^= state >> 27;
        source[i] = zero ? 0 : (uint8_t)((state * UINT64_C(0x2545f4914f6cdd1d)) >> 56);
    }
    memset(destination, 0x5a, length + 32);
    uint64_t timed_expected = UINT64_C(0x123456789abcdef);
    if (scalar) {
        for (uint64_t i = 0; i < iterations; ++i)
            timed_expected = timed_expected * UINT64_C(0x9e3779b97f4a7c15) + i;
    } else if (copy || zero) {
        timed_expected += iterations * (copy ? length : 1);
    } else {
        for (size_t offset = 1; offset <= 16; ++offset) {
            uint64_t total = 0;
            for (size_t j = 0; j < length; ++j) total += source[offset+j];
            timed_expected += total * (iterations/16 + (offset <= iterations%16));
        }
    }
    for (int batch = -3; batch < batches; ++batch) {
        uint64_t value = UINT64_C(0x123456789abcdef), expected = value;
        if (scalar) {
            /* Check scalar correctness independently outside the timed region. */
            for (uint64_t i = 0; i < 257; ++i) {
                value = sf(value, UINT64_C(0x9e3779b97f4a7c15), i);
                expected = expected * UINT64_C(0x9e3779b97f4a7c15) + i;
                if (value != expected) return 8;
            }
        } else {
            for (size_t offset = 1; offset <= 16; ++offset) {
                expected = zero ? 1 : 0;
                if (!copy && !zero) for (size_t j = 0; j < length; ++j) expected += source[offset+j];
                uint64_t actual = copy
                    ? cf(destination + offset, length, source + offset, length, length)
                    : rf(source + offset, length, length);
                if (actual != (copy ? length : expected)) return 9;
                if (copy && memcmp(destination + offset, source + offset, length)) return 10;
            }
            if (zero && length) {
                const size_t positions[] = {1, 1 + length/2, length};
                for (size_t j = 0; j < 3; ++j) {
                    source[positions[j]] = 255;
                    if (rf(source + 1, length, length) != 0) return 12;
                    source[positions[j]] = 0;
                }
            }
        }
        if (copy) memset(destination, 0xa5, length + 32);
        value = UINT64_C(0x123456789abcdef);
        uint64_t start = now();
        if (scalar) {
            for (uint64_t i = 0; i < iterations; ++i)
                value = sf(value, UINT64_C(0x9e3779b97f4a7c15), i);
        } else if (copy) {
            for (uint64_t i = 0; i < iterations; ++i) {
                size_t offset = 1 + (i & 15);
                value += cf(destination + offset, length, source + offset, length, length);
            }
        } else {
            for (uint64_t i = 0; i < iterations; ++i)
                value += rf(source + 1 + (i & 15), length, length);
        }
        uint64_t elapsed = now() - start;
        observed = value;
        if (value != timed_expected) return 13;
        if (copy) {
            size_t last_offset = 1 + ((iterations - 1) & 15);
            if (length && memcmp(destination + last_offset, source + last_offset, length)) return 11;
            if (destination[0] != 0xa5 || destination[length + 31] != 0xa5) return 14;
        }
        if (batch >= 0) {
            printf("{\"batch\":%d,\"elapsed_ns\":%" PRIu64 ",\"calls\":%" PRIu64
                   ",\"ns_per_call\":%.9f,\"checksum\":%" PRIu64 "}\n",
                   batch, elapsed, iterations, (double)elapsed / (double)iterations, value);
            fflush(stdout);
        }
    }
    free(source); free(destination); dlclose(library);
    return 0;
}
