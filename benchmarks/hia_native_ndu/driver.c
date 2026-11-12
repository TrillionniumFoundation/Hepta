#define _GNU_SOURCE
#include "metrics.h"
#include <dlfcn.h>
#include <inttypes.h>
#include <link.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/resource.h>
#include <sys/mman.h>
#include <time.h>
#include <unistd.h>

typedef uint64_t (*kernel_t)(size_t, uint32_t);
typedef void (*begin_t)(uint64_t);
typedef void (*end_t)(struct metrics *);
static struct { void *handle; kernel_t run; begin_t begin; end_t end; int invoked; } bank[4];
struct loaded_pages { uintptr_t base; uint64_t mapped, resident, failed; };
static int pages(struct dl_phdr_info *info, size_t unused, void *opaque) {
    (void)unused;
    struct loaded_pages *result = opaque;
    if (info->dlpi_addr != result->base) return 0;
    uintptr_t prior_end = 0;
    uintptr_t page_size = (uintptr_t)sysconf(_SC_PAGESIZE);
    for (unsigned i = 0; i < info->dlpi_phnum; ++i) {
        const ElfW(Phdr) *h = &info->dlpi_phdr[i];
        if (h->p_type != PT_LOAD || !h->p_memsz) continue;
        uintptr_t low = (info->dlpi_addr+h->p_vaddr) & ~(page_size-1);
        uintptr_t high = (info->dlpi_addr+h->p_vaddr+h->p_memsz+page_size-1) & ~(page_size-1);
        if (low < prior_end) low = prior_end;
        if (high <= low) continue;
        if (high-low > 16*1024*1024) return 1;
        for (uintptr_t address = low; address < high; address += page_size) {
            unsigned char present = 0;
            result->mapped += page_size;
            if (mincore((void *)address, page_size, &present)) ++result->failed;
            else if (present & 1) result->resident += page_size;
        }
        if (high > prior_end) prior_end = high;
    }
    return 1;
}
static uint64_t now(clockid_t clock) {
    struct timespec t;
    if (clock_gettime(clock, &t)) exit(71);
    return (uint64_t)t.tv_sec * UINT64_C(1000000000) + (uint64_t)t.tv_nsec;
}
static uint64_t batch(kernel_t fn, size_t n, uint32_t seed, unsigned calls) {
    uint64_t sum = 0;
    for (unsigned i = 0; i < calls; ++i) sum += fn(n, seed + i);
    return sum;
}
static void limits(void) {
    struct rlimit core = {0, 0}, cpu = {30, 30}, mem = {512*1024*1024, 512*1024*1024};
    if (setrlimit(RLIMIT_CORE, &core) || setrlimit(RLIMIT_CPU, &cpu) || setrlimit(RLIMIT_AS, &mem)) exit(72);
}
int main(void) {
    limits();
    setvbuf(stdout, 0, _IOLBF, 0);
    printf("{\"ready\":true,\"pid\":%d}\n", (int)getpid());
    char command[8192], path[4096];
    while (fgets(command, sizeof(command), stdin)) {
        unsigned id = 0, samples = 0, calls = 0, warmup = 0, seed = 0, fail = 0;
        size_t n = 0;
        if (command[0] == 'Q') break;
        if (command[0] == 'L') {
            if (sscanf(command, "L %u %4095s", &id, path) != 2 || id >= 4 || bank[id].handle) return 73;
            uint64_t t = now(CLOCK_MONOTONIC);
            bank[id].handle = dlopen(path, RTLD_NOW | RTLD_LOCAL);
            if (!bank[id].handle) { fprintf(stderr, "%s\n", dlerror()); return 74; }
            bank[id].run = (kernel_t)dlsym(bank[id].handle, "calculate");
            bank[id].begin = (begin_t)dlsym(bank[id].handle, "probe_begin");
            bank[id].end = (end_t)dlsym(bank[id].handle, "probe_end");
            if (!bank[id].run || !bank[id].begin || !bank[id].end) return 75;
            printf("{\"loaded\":%u,\"load_ns\":%" PRIu64 "}\n", id, now(CLOCK_MONOTONIC)-t);
        } else if (command[0] == 'M') {
            if (sscanf(command,"M %u",&id)!=1 || id>=4 || !bank[id].handle) return 81;
            struct link_map *map = 0;
            if (dlinfo(bank[id].handle,RTLD_DI_LINKMAP,&map) || !map) return 82;
            struct loaded_pages result = {(uintptr_t)map->l_addr,0,0,0};
            dl_iterate_phdr(pages,&result);
            printf("{\"status\":\"observed-loader-segments\",\"mapped_bytes\":%" PRIu64 ",\"backing_resident_bytes\":%" PRIu64 ",\"mincore_failed_pages\":%" PRIu64 "}\n",result.mapped,result.resident,result.failed);
        } else if (command[0] == 'R') {
            if (sscanf(command, "R %u %zu %u %u %u %u %u", &id, &n, &seed, &calls, &samples, &warmup, &fail) != 7
                || id >= 4 || !bank[id].handle || n > 65536 || !calls || calls > 1024 || !samples || samples > 64 || warmup > 64 || fail > 1) return 76;
            int first_library_call = !bank[id].invoked;
            bank[id].invoked = 1;
            uint64_t cold_t = now(CLOCK_MONOTONIC);
            uint64_t cold_value = bank[id].run(n, seed);
            uint64_t cold_ns = now(CLOCK_MONOTONIC)-cold_t;
            struct metrics m;
            bank[id].begin(fail);
            uint64_t observed = bank[id].run(n, seed);
            bank[id].end(&m);
            volatile uint64_t warmed = batch(bank[id].run, n, seed, warmup);
            (void)warmed;
            uint64_t total = 0, cpu_start = now(CLOCK_PROCESS_CPUTIME_ID);
            struct rusage before, after;
            if (getrusage(RUSAGE_SELF, &before)) return 77;
            printf("{\"id\":%u,\"n\":%zu,\"seed\":%u,\"calls\":%u,\"samples\":%u,\"observed\":%" PRIu64 ",\"cold_value\":%" PRIu64 ",\"cold_ns\":%" PRIu64 ",\"first_library_call\":%s,\"times_ns\":[", id,n,seed,calls,samples,observed,cold_value,cold_ns,first_library_call?"true":"false");
            uint64_t checksum = 0;
            for (unsigned sample = 0; sample < samples; ++sample) {
                uint64_t t = now(CLOCK_MONOTONIC);
                checksum = batch(bank[id].run,n,seed,calls);
                uint64_t elapsed = now(CLOCK_MONOTONIC)-t;
                total += elapsed;
                printf("%s%" PRIu64, sample?",":"", elapsed);
            }
            if (getrusage(RUSAGE_SELF, &after)) return 78;
            printf("],\"batch_checksum\":%" PRIu64 ",\"elapsed_ns\":%" PRIu64 ",\"cpu_ns\":%" PRIu64 ",\"maxrss_kib\":%ld,\"minor_faults\":%ld,\"major_faults\":%ld,\"voluntary_switches\":%ld,\"involuntary_switches\":%ld,\"metrics\":[",checksum,total,now(CLOCK_PROCESS_CPUTIME_ID)-cpu_start,after.ru_maxrss,after.ru_minflt-before.ru_minflt,after.ru_majflt-before.ru_majflt,after.ru_nvcsw-before.ru_nvcsw,after.ru_nivcsw-before.ru_nivcsw);
            uint64_t values[14];
            memcpy(values, &m, sizeof(m));
            for (unsigned i = 0; i < sizeof(m)/sizeof(uint64_t); ++i) printf("%s%" PRIu64, i?",":"",values[i]);
            printf("]}\n");
        } else return 79;
    }
    for (unsigned i = 0; i < 4; ++i) if (bank[i].handle && dlclose(bank[i].handle)) return 80;
    printf("{\"closed\":true}\n");
    return 0;
}
