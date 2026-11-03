/* Separate diagnostic observer. Never substitutes CPU time for release gates. */
#define _POSIX_C_SOURCE 200809L
#include <dlfcn.h>
#include <errno.h>
#include <inttypes.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <sys/resource.h>
#include <time.h>

typedef uint64_t (*kernel_t)(size_t, uint32_t);
static uint64_t stamp(clockid_t clock) {
    struct timespec t;
    if (clock_gettime(clock, &t)) exit(71);
    return (uint64_t)t.tv_sec * UINT64_C(1000000000) + (uint64_t)t.tv_nsec;
}
static uint64_t resolution(clockid_t clock) {
    struct timespec t;
    if (clock_getres(clock, &t)) exit(72);
    return (uint64_t)t.tv_sec * UINT64_C(1000000000) + (uint64_t)t.tv_nsec;
}
static uint64_t number(const char *text, uint64_t maximum) {
    if (!*text) exit(64);
    for (const char *p=text; *p; ++p) if (*p<'0' || *p>'9') exit(64);
    char *end;
    errno=0;
    unsigned long long value=strtoull(text,&end,10);
    if (errno || *end || value>maximum) exit(64);
    return value;
}
static uint64_t batch(kernel_t fn, size_t n, uint32_t seed, unsigned calls) {
    uint64_t result=0;
    for (unsigned i=0;i<calls;++i) result+=fn(n,seed+i);
    return result;
}
int main(int argc,char **argv) {
    if (argc!=7) return 64;
    size_t n=number(argv[2],1048576);
    uint32_t seed=number(argv[3],UINT32_MAX);
    unsigned calls=number(argv[4],1024), samples=number(argv[5],64), warmup=number(argv[6],64);
    if (!calls || !samples) return 64;
    struct rlimit cpu={30,30}, mem={512*1024*1024,512*1024*1024}, core={0,0};
    if (setrlimit(RLIMIT_CPU,&cpu) || setrlimit(RLIMIT_AS,&mem) || setrlimit(RLIMIT_CORE,&core)) return 65;
    void *handle=dlopen(argv[1],RTLD_NOW|RTLD_LOCAL);
    if (!handle) {fprintf(stderr,"%s\n",dlerror());return 66;}
    kernel_t fn=(kernel_t)dlsym(handle,"calculate");
    if (!fn) return 67;
    volatile uint64_t warmed=batch(fn,n,seed,warmup);(void)warmed;
    uint64_t wall[64],cpu_envelope[64],checksums[64];
    for (unsigned i=0;i<samples;++i) {
        /* CPU interval strictly surrounds the wall interval. Its overhead
         * biases wall-minus-CPU downwards, not toward an apparent off-CPU gap.
         * Both clocks and their own acquisition costs remain trusted. */
        uint64_t c0=stamp(CLOCK_THREAD_CPUTIME_ID);
        uint64_t t0=stamp(CLOCK_MONOTONIC);
        checksums[i]=batch(fn,n,seed,calls);
        uint64_t t1=stamp(CLOCK_MONOTONIC);
        uint64_t c1=stamp(CLOCK_THREAD_CPUTIME_ID);
        if (t1<t0 || c1<c0) return 68;
        wall[i]=t1-t0;cpu_envelope[i]=c1-c0;
    }
    /* No sample printing, allocation or getrusage inside the clock envelope. */
    printf("{\"n\":%zu,\"seed\":%" PRIu32 ",\"calls\":%u,\"samples\":%u,\"warmup\":%u,\"wall_resolution_ns\":%" PRIu64 ",\"cpu_resolution_ns\":%" PRIu64 ",\"observations\":[",n,seed,calls,samples,warmup,resolution(CLOCK_MONOTONIC),resolution(CLOCK_THREAD_CPUTIME_ID));
    for (unsigned i=0;i<samples;++i) printf("%s{\"wall_ns\":%" PRIu64 ",\"cpu_envelope_ns\":%" PRIu64 ",\"checksum\":%" PRIu64 "}",i?",":"",wall[i],cpu_envelope[i],checksums[i]);
    puts("]}");
    if (dlclose(handle)) return 69;
    return 0;
}
