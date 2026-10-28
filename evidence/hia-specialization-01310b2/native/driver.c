#define _POSIX_C_SOURCE 200809L
#include <dlfcn.h>
#include <inttypes.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <sys/resource.h>
#include <time.h>
typedef uint32_t (*kernel_t)(uint32_t, uint32_t);
struct input { uint32_t x, mask, expected; };
static uint64_t now(clockid_t clock) {
    struct timespec t;
    if (clock_gettime(clock, &t)) exit(81);
    return (uint64_t)t.tv_sec * UINT64_C(1000000000) + (uint64_t)t.tv_nsec;
}
int main(int argc, char **argv) {
    if (argc != 5) return 82;
    uint64_t calls = strtoull(argv[3], NULL, 10), warmup = strtoull(argv[4], NULL, 10);
    if (!calls || calls > UINT64_C(250000000) || warmup > UINT64_C(20000)) return 83;
    FILE *file = fopen(argv[2], "r");
    struct input inputs[64];
    if (!file) return 84;
    for (int n = 0; n != 64; ++n)
        if (fscanf(file, "%" SCNu32 " %" SCNu32 " %" SCNu32,
                   &inputs[n].x, &inputs[n].mask, &inputs[n].expected) != 3) return 85;
    if (fclose(file)) return 86;
    void *library = dlopen(argv[1], RTLD_NOW | RTLD_LOCAL);
    if (!library) { fprintf(stderr, "%s\n", dlerror()); return 87; }
    kernel_t kernel = (kernel_t)dlsym(library, "calculate");
    if (!kernel) return 88;
    for (int n = 0; n != 64; ++n)
        if (kernel(inputs[n].x, inputs[n].mask) != inputs[n].expected) return 89;
    volatile uint64_t warm_checksum = 0;
    for (uint64_t n = 0; n != warmup; ++n)
        warm_checksum += kernel(inputs[n & 63].x, inputs[n & 63].mask);
    (void)warm_checksum;
    struct rusage before, after;
    if (getrusage(RUSAGE_SELF, &before)) return 90;
    uint64_t checksum = 0, cpu = now(CLOCK_PROCESS_CPUTIME_ID), start = now(CLOCK_MONOTONIC);
    for (uint64_t n = 0; n != calls; ++n)
        checksum += kernel(inputs[n & 63].x, inputs[n & 63].mask);
    uint64_t elapsed = now(CLOCK_MONOTONIC) - start, cpu_ns = now(CLOCK_PROCESS_CPUTIME_ID) - cpu;
    if (getrusage(RUSAGE_SELF, &after)) return 91;
    printf("{\"elapsed_ns\":%" PRIu64 ",\"process_cpu_ns\":%" PRIu64
           ",\"iterations\":%" PRIu64 ",\"checksum\":%" PRIu64
           ",\"voluntary_context_switches\":%ld,\"involuntary_context_switches\":%ld"
           ",\"minor_page_faults\":%ld,\"major_page_faults\":%ld}\n",
           elapsed, cpu_ns, calls, checksum, after.ru_nvcsw-before.ru_nvcsw,
           after.ru_nivcsw-before.ru_nivcsw, after.ru_minflt-before.ru_minflt,
           after.ru_majflt-before.ru_majflt);
    if (dlclose(library)) return 92;
    return 0;
}
