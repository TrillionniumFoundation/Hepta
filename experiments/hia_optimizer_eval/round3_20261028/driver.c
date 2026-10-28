#define _GNU_SOURCE
#include <dlfcn.h>
#include <errno.h>
#include <fcntl.h>
#include <inttypes.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/resource.h>
#include <sys/stat.h>
#include <sys/sysmacros.h>
#include <time.h>
#include <unistd.h>
#include "workload.h"

typedef uint64_t (*Kernel)(size_t, uint32_t);

static uint64_t now(clockid_t clock) {
    struct timespec value;
    if (clock_gettime(clock, &value)) exit(20);
    return (uint64_t)value.tv_sec * UINT64_C(1000000000) + (uint64_t)value.tv_nsec;
}

static uint64_t exact_u64(const char *text, uint64_t limit) {
    char *end = NULL;
    errno = 0;
    if (!*text || *text == '-' || *text == '+') exit(21);
    uint64_t value = strtoull(text, &end, 10);
    if (errno || !end || *end || value > limit) exit(21);
    return value;
}

static uint64_t checked_mapping(int fd, void *symbol, const struct stat *file) {
    const int wanted = F_SEAL_SEAL | F_SEAL_SHRINK | F_SEAL_GROW | F_SEAL_WRITE;
    if (fcntl(fd, F_GET_SEALS) != wanted || !S_ISREG(file->st_mode) || file->st_size <= 0) exit(22);
    FILE *maps = fopen("/proc/self/maps", "r");
    if (!maps) exit(23);
    char line[8192], permissions[5];
    unsigned long start, end, offset;
    unsigned device_major, device_minor;
    unsigned long long inode;
    const uintptr_t address = (uintptr_t)symbol;
    unsigned matches = 0;
    uint64_t file_offset = 0;
    while (fgets(line, sizeof(line), maps)) {
        if (sscanf(line, "%lx-%lx %4s %lx %x:%x %llu", &start, &end, permissions,
                   &offset, &device_major, &device_minor, &inode) != 7) continue;
        if (address < start || address >= end) continue;
        if (strcmp(permissions, "r-xp") || device_major != major(file->st_dev) ||
            device_minor != minor(file->st_dev) || inode != (unsigned long long)file->st_ino) exit(24);
        file_offset = (uint64_t)offset + (uint64_t)(address - start);
        if (file_offset >= (uint64_t)file->st_size) exit(25);
        ++matches;
    }
    fclose(maps);
    if (matches != 1) exit(26);
    return file_offset;
}

static void prefix(const struct stat *file, uint64_t offset) {
    printf("{\"mapping_verified\":true,\"image_device\":%" PRIu64
           ",\"image_inode\":%" PRIu64 ",\"image_bytes\":%" PRIu64
           ",\"symbol_file_offset\":%" PRIu64,
           (uint64_t)file->st_dev, (uint64_t)file->st_ino,
           (uint64_t)file->st_size, offset);
}

int main(int argc, char **argv) {
    const struct rlimit no_core = {0, 0};
    if (setrlimit(RLIMIT_CORE, &no_core)) return 27;
    if (argc != 4 && argc != 6) return 10;
    if (strcmp(argv[2], "full_lifecycle") && strcmp(argv[2], "packet_xor")) return 10;
    const int probe = !strcmp(argv[3], "case"), train = !strcmp(argv[3], "train");
    if ((probe && argc != 6) || (!probe && (argc != 4 || (!train && strcmp(argv[3], "holdout"))))) return 10;
    setbuf(stdout, NULL);
    const int fd = (int)exact_u64(argv[1], INT32_MAX);
    struct stat file;
    if (fstat(fd, &file)) return 22;
    const int wanted = F_SEAL_SEAL | F_SEAL_SHRINK | F_SEAL_GROW | F_SEAL_WRITE;
    if (fcntl(fd, F_GET_SEALS) != wanted) return 22;
    char path[64];
    if (snprintf(path, sizeof(path), "/proc/self/fd/%d", fd) <= 0) return 10;
    void *library = dlopen(path, RTLD_NOW | RTLD_LOCAL);
    if (!library) { fprintf(stderr, "%s\n", dlerror()); return 11; }
    dlerror();
    void *symbol = dlsym(library, argv[2]);
    if (dlerror() || !symbol) return 12;
    const uint64_t offset = checked_mapping(fd, symbol, &file);
    Kernel kernel = NULL;
    _Static_assert(sizeof(kernel) == sizeof(symbol), "POSIX function pointer size");
    memcpy(&kernel, &symbol, sizeof(kernel));
    if (probe) {
        const size_t size = (size_t)exact_u64(argv[4], 65536);
        const uint32_t seed = (uint32_t)exact_u64(argv[5], UINT32_MAX);
        const uint64_t actual = kernel(size, seed);
        prefix(&file, offset);
        printf(",\"actual\":%" PRIu64 "}\n", actual);
        dlclose(library);
        return 0;
    }
    const size_t *sizes = train ? TRAIN_SIZES : HOLDOUT_SIZES;
    const uint32_t *seeds = train ? TRAIN_SEEDS : HOLDOUT_SEEDS;
    const unsigned nsizes = train ? TRAIN_SIZE_COUNT : HOLDOUT_SIZE_COUNT;
    const unsigned nseeds = train ? TRAIN_SEED_COUNT : HOLDOUT_SEED_COUNT;
    const uint64_t workload_start = now(CLOCK_MONOTONIC_RAW);
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
    uint64_t requests[REQUEST_TAIL_PROBES], clocks[CLOCK_OVERHEAD_PROBES];
    uint64_t tail_checksum = UINT64_C(1469598103934665603);
    for (unsigned index = 0; index < REQUEST_TAIL_PROBES; ++index) {
        const uint64_t begin = now(CLOCK_MONOTONIC_RAW);
        const uint64_t value = kernel(sizes[(index * 7 + 3) % nsizes], seeds[(index * 3 + 2) % nseeds]);
        requests[index] = now(CLOCK_MONOTONIC_RAW) - begin;
        tail_checksum = (tail_checksum ^ value) * UINT64_C(1099511628211);
    }
    for (unsigned index = 0; index < CLOCK_OVERHEAD_PROBES; ++index) {
        const uint64_t begin = now(CLOCK_MONOTONIC_RAW);
        clocks[index] = now(CLOCK_MONOTONIC_RAW) - begin;
    }
    const uint64_t workload_wall = now(CLOCK_MONOTONIC_RAW) - workload_start;
    struct rusage usage;
    if (getrusage(RUSAGE_SELF, &usage)) return 13;
    FILE *status = fopen("/proc/self/status", "r");
    if (!status) return 14;
    char line[256];
    long peak_rss_kib = 0;
    while (fgets(line, sizeof(line), status)) {
        long value;
        if (sscanf(line, "VmHWM: %ld kB", &value) == 1) peak_rss_kib = value;
    }
    fclose(status);
    if (peak_rss_kib <= 0) return 15;
    prefix(&file, offset);
    printf(",\"elapsed_ns\":%" PRIu64 ",\"checksum\":%" PRIu64 ",\"process_cpu_ns\":%" PRIu64
           ",\"driver_workload_wall_ns\":%" PRIu64 ",\"tail_checksum\":%" PRIu64
           ",\"process_peak_rss_kib\":%ld,\"process_ru_maxrss_kib\":%ld,\"voluntary_context_switches\":%ld,\"involuntary_context_switches\":%ld,\"batch_ns\":[",
           elapsed, checksum, cpu, workload_wall, tail_checksum, peak_rss_kib,
           usage.ru_maxrss, usage.ru_nvcsw, usage.ru_nivcsw);
    for (unsigned index = 0; index < BATCHES; ++index) printf("%s%" PRIu64, index ? "," : "", batches[index]);
    printf("],\"request_ns\":[");
    for (unsigned index = 0; index < REQUEST_TAIL_PROBES; ++index) printf("%s%" PRIu64, index ? "," : "", requests[index]);
    printf("],\"clock_ns\":[");
    for (unsigned index = 0; index < CLOCK_OVERHEAD_PROBES; ++index) printf("%s%" PRIu64, index ? "," : "", clocks[index]);
    puts("]}");
    (void)warm_sink;
    dlclose(library);
    return 0;
}
