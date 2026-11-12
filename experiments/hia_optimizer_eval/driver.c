#define _POSIX_C_SOURCE 200809L
#include <dlfcn.h>
#include <inttypes.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/resource.h>
#include <time.h>
#include "workload.h"

typedef uint64_t (*Kernel)(size_t, uint32_t);
static uint64_t now(clockid_t clock) {
    struct timespec value;
    if (clock_gettime(clock, &value)) exit(20);
    return (uint64_t)value.tv_sec * UINT64_C(1000000000) + (uint64_t)value.tv_nsec;
}
int main(int argc, char **argv) {
    if (argc != 4 || (strcmp(argv[3], "train") && strcmp(argv[3], "holdout"))) return 10;
    setbuf(stdout, NULL);
    const int train = !strcmp(argv[3], "train");
    const size_t *sizes = train ? TRAIN_SIZES : HOLDOUT_SIZES;
    const uint32_t *seeds = train ? TRAIN_SEEDS : HOLDOUT_SEEDS;
    const unsigned nsizes = train ? TRAIN_SIZE_COUNT : HOLDOUT_SIZE_COUNT;
    const unsigned nseeds = train ? TRAIN_SEED_COUNT : HOLDOUT_SEED_COUNT;
    void *library = dlopen(argv[1], RTLD_NOW | RTLD_LOCAL);
    if (!library) { fprintf(stderr, "%s\n", dlerror()); return 11; }
    dlerror(); void *symbol = dlsym(library, argv[2]);
    if (dlerror() || !symbol) return 12;
    Kernel kernel = NULL;
    _Static_assert(sizeof(kernel) == sizeof(symbol), "POSIX function pointer size");
    memcpy(&kernel, &symbol, sizeof(kernel));
    volatile uint64_t warm_sink = 0;
    for (unsigned i = 0; i < WARMUP_CALLS; ++i) warm_sink ^= kernel(sizes[i % nsizes], seeds[i % nseeds]);
    const uint64_t start = now(CLOCK_MONOTONIC_RAW), cpu_start = now(CLOCK_PROCESS_CPUTIME_ID);
    uint64_t checksum = UINT64_C(1469598103934665603), batches[BATCHES];
    for (unsigned batch = 0; batch < BATCHES; ++batch) {
        const uint64_t begin = now(CLOCK_MONOTONIC_RAW);
        for (unsigned j = 0; j < CALLS_PER_BATCH; ++j) {
            const unsigned index = batch * CALLS_PER_BATCH + j;
            checksum = (checksum ^ kernel(sizes[index % nsizes], seeds[(index * 5 + 1) % nseeds])) * UINT64_C(1099511628211);
        }
        batches[batch] = now(CLOCK_MONOTONIC_RAW) - begin;
    }
    const uint64_t cpu = now(CLOCK_PROCESS_CPUTIME_ID) - cpu_start, elapsed = now(CLOCK_MONOTONIC_RAW) - start;
    struct rusage usage;
    if (getrusage(RUSAGE_SELF, &usage)) return 13;
    /* ru_maxrss may retain the fork-to-exec high-water mark of the Python
       launcher. VmHWM belongs to this post-exec address space. Keep both. */
    FILE *status = fopen("/proc/self/status", "r");
    if (!status) return 14;
    char line[256]; long peak_rss_kib = 0;
    while (fgets(line, sizeof(line), status)) {
        long value;
        if (sscanf(line, "VmHWM: %ld kB", &value) == 1) peak_rss_kib = value;
    }
    fclose(status);
    if (peak_rss_kib <= 0) return 15;
    printf("{\"elapsed_ns\":%" PRIu64 ",\"checksum\":%" PRIu64 ",\"process_cpu_ns\":%" PRIu64
           ",\"process_peak_rss_kib\":%ld,\"process_ru_maxrss_kib\":%ld,\"voluntary_context_switches\":%ld,\"involuntary_context_switches\":%ld,\"batch_ns\":[",
           elapsed, checksum, cpu, peak_rss_kib, usage.ru_maxrss, usage.ru_nvcsw, usage.ru_nivcsw);
    for (unsigned batch = 0; batch < BATCHES; ++batch) printf("%s%" PRIu64, batch ? "," : "", batches[batch]);
    puts("]}");
    (void)warm_sink;
    dlclose(library);
    return 0;
}
