#define _POSIX_C_SOURCE 200809L
#include <dlfcn.h>
#include <errno.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/resource.h>
#include <time.h>

typedef unsigned long long (*chunk_fn)(unsigned long, unsigned long long,
                                       unsigned int, unsigned int);
static unsigned long long latency[65536];
static unsigned long long now_ns(void) {
    struct timespec t;
    if (clock_gettime(CLOCK_MONOTONIC, &t)) { perror("clock_gettime"); exit(71); }
    return (unsigned long long)t.tv_sec * 1000000000ULL + (unsigned long long)t.tv_nsec;
}

/* A failed staged load leaves the current handle and function untouched. */
static int stage(const char *path, const char *symbol, void **handle, chunk_fn *fn) {
    void *next = dlopen(path, RTLD_NOW | RTLD_LOCAL);
    if (!next) { return 0; }
    dlerror();
    void *address = dlsym(next, symbol);
    if (dlerror() || !address) { dlclose(next); return 0; }
    chunk_fn replacement;
    _Static_assert(sizeof(replacement) == sizeof(address), "POSIX pointer representation");
    memcpy(&replacement, &address, sizeof(replacement));
    void *old = *handle;
    *handle = next;
    *fn = replacement;
    if (old) { dlclose(old); }
    return 1;
}

int main(int argc, char **argv) {
    if (argc != 5 && argc != 6) {
        fprintf(stderr, "usage: filecheck LIB SYMBOL FILE POLYNOMIAL [STAGED_LIB]\n");
        return 64;
    }
    _Static_assert(sizeof(unsigned long) == 8 && sizeof(unsigned int) == 4, "LP64");
    unsigned long long started = now_ns(), load_begin = now_ns();
    void *handle = NULL;
    chunk_fn fn = NULL;
    if (!stage(argv[1], argv[2], &handle, &fn)) { fprintf(stderr, "initial load failed\n"); return 65; }
    unsigned long long load_ns = now_ns() - load_begin;
    FILE *file = fopen(argv[3], "rb");
    if (!file) { perror("input"); dlclose(handle); return 66; }
    unsigned int polynomial = (unsigned int)strtoul(argv[4], NULL, 0), state = 0xffffffffU;
    unsigned char buffer[4096];
    unsigned long long bytes = 0, calls = 0, read_ns = 0, switch_ns = 0;
    unsigned long batches = 0, switches = 0, refused = 0;
    for (;;) {
        unsigned long long read_begin = now_ns();
        size_t count = fread(buffer, 1, sizeof(buffer), file);
        read_ns += now_ns() - read_begin;
        if (!count) { break; }
        if (batches == 65536) { fprintf(stderr, "latency ledger full\n"); return 67; }
        if (argc == 6 && batches == 8) {
            unsigned long long switch_begin = now_ns();
            if (stage(argv[5], argv[2], &handle, &fn)) { ++switches; } else { ++refused; }
            switch_ns += now_ns() - switch_begin;
        }
        /* Batch latency includes this read, any staged switch, packing and CRC. */
        unsigned long long batch_begin = read_begin;
        for (size_t offset = 0; offset < count; offset += 8) {
            unsigned long take = (unsigned long)((count - offset) < 8 ? count - offset : 8);
            unsigned long long packed = 0;
            for (unsigned long index = 0; index < take; ++index) {
                packed |= (unsigned long long)buffer[offset + index] << (index * 8);
            }
            unsigned long long result = fn(take, packed, state, polynomial);
            if (result >> 32) {
                fprintf(stderr, "chunk refused status=%llu byte=%llu\n", result >> 32, bytes + offset);
                fclose(file); dlclose(handle); return 68;
            }
            state = (unsigned int)result;
            ++calls;
        }
        latency[batches++] = now_ns() - batch_begin;
        bytes += count;
    }
    if (ferror(file)) { perror("read"); fclose(file); dlclose(handle); return 69; }
    fclose(file);
    unsigned long long close_begin = now_ns();
    dlclose(handle);
    unsigned long long close_ns = now_ns() - close_begin, elapsed_ns = now_ns() - started;
    struct rusage usage;
    unsigned long long monitor_begin = now_ns();
    if (getrusage(RUSAGE_SELF, &usage)) { perror("getrusage"); return 70; }
    unsigned long long monitor_ns = now_ns() - monitor_begin;
    printf("{\"checksum\":%u,\"bytes\":%llu,\"calls\":%llu,\"batches\":%lu,"
           "\"elapsed_ns\":%llu,\"load_ns\":%llu,\"read_ns\":%llu,\"close_ns\":%llu,"
           "\"switch_ns\":%llu,\"switches\":%lu,\"refused_switches\":%lu,"
           "\"monitor_ns\":%llu,\"peak_rss_kib\":%ld,\"user_us\":%lld,\"system_us\":%lld,"
           "\"voluntary_switches\":%ld,\"involuntary_switches\":%ld,\"batch_ns\":[",
           state ^ 0xffffffffU, bytes, calls, batches, elapsed_ns, load_ns, read_ns, close_ns,
           switch_ns, switches, refused, monitor_ns, usage.ru_maxrss,
           (long long)usage.ru_utime.tv_sec * 1000000 + usage.ru_utime.tv_usec,
           (long long)usage.ru_stime.tv_sec * 1000000 + usage.ru_stime.tv_usec,
           usage.ru_nvcsw, usage.ru_nivcsw);
    for (unsigned long index = 0; index < batches; ++index) {
        printf("%s%llu", index ? "," : "", latency[index]);
    }
    puts("]}");
    return 0;
}
