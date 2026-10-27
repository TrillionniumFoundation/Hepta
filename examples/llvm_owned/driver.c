#define _POSIX_C_SOURCE 200809L
#include <stdint.h>
#include <inttypes.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <dlfcn.h>
#include <time.h>
#include <sys/resource.h>
typedef uint64_t (*Kernel)(size_t, uint32_t);
static uint64_t nanos(struct timespec value) {
    return (uint64_t)value.tv_sec * UINT64_C(1000000000) + (uint64_t)value.tv_nsec;
}
int main(int argc, char **argv) {
    if (argc != 3) return 11;
    size_t size = 4093;
    unsigned repetitions;
    if (!strcmp(argv[2], "constructor_error")) repetitions = 8388608;
    else if (!strcmp(argv[2], "full_lifecycle") || !strcmp(argv[2], "two_stage")) repetitions = 1048576;
    else return 12;
    void *library = dlopen(argv[1], RTLD_NOW | RTLD_LOCAL);
    if (!library) { fprintf(stderr, "%s\n", dlerror()); return 13; }
    dlerror();
    void *symbol = dlsym(library, argv[2]);
    if (dlerror() || !symbol) return 14;
    Kernel kernel = NULL;
    _Static_assert(sizeof(symbol) == sizeof(kernel), "POSIX function pointer size");
    memcpy(&kernel, &symbol, sizeof(symbol));
    volatile uint64_t warm_sink = 0;
    for (unsigned r = 0; r < 8192; ++r) {
        uint32_t seed = ((r % 64) * 17 + 13) % 97 + 1;
        warm_sink ^= kernel(size, seed);
    }
    struct timespec start, stop, resolution;
    if (clock_getres(CLOCK_MONOTONIC_RAW, &resolution)) return 15;
    if (clock_gettime(CLOCK_MONOTONIC_RAW, &start)) return 16;
    uint64_t checksum = UINT64_C(1469598103934665603);
    for (unsigned r = 0; r < repetitions; ++r) {
        uint32_t seed = ((r % 64) * 17 + 13) % 97 + 1;
        checksum = (checksum ^ kernel(size, seed)) * UINT64_C(1099511628211);
    }
    if (clock_gettime(CLOCK_MONOTONIC_RAW, &stop)) return 17;
    struct rusage usage;
    if (getrusage(RUSAGE_SELF, &usage) || nanos(stop) <= nanos(start)) return 18;
    printf("{\"elapsed_ns\":%" PRIu64 ",\"checksum\":%" PRIu64
           ",\"clock_resolution_ns\":%" PRIu64 ",\"process_peak_rss_kib\":%ld}\n",
           nanos(stop) - nanos(start), checksum, nanos(resolution), usage.ru_maxrss);
    dlclose(library);
    (void)warm_sink;
    return 0;
}
