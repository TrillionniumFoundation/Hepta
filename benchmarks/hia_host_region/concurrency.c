#define _POSIX_C_SOURCE 200809L
#include <stddef.h>
#include <stdint.h>
#include <stdatomic.h>
#include <time.h>
#include <sched.h>

/* Reviewed synchronous, no-pointer-escape test rendezvous. Shared atomics
 * synchronize code execution only; data remains behind the HostRegion gate. */
extern int region_sum(const uint8_t *,size_t,uint64_t,uint64_t *);
static _Atomic unsigned gate_open;
static _Atomic unsigned entered;

int region_gate_arm(const uint8_t *p,size_t n,uint64_t argument,uint64_t *out) {
    (void)p;(void)n;(void)argument;
    atomic_store_explicit(&entered,0,memory_order_release);
    atomic_store_explicit(&gate_open,0,memory_order_release);
    *out=0; return 0;
}
int region_gate_count(const uint8_t *p,size_t n,uint64_t argument,uint64_t *out) {
    (void)p;(void)n;(void)argument;
    *out=atomic_load_explicit(&entered,memory_order_acquire); return 0;
}
int region_gate_release(const uint8_t *p,size_t n,uint64_t argument,uint64_t *out) {
    (void)p;(void)n;(void)argument;
    atomic_store_explicit(&gate_open,1,memory_order_release);
    *out=0; return 0;
}
int region_gate_sum(const uint8_t *p,size_t n,uint64_t argument,uint64_t *out) {
    (void)argument;
    struct timespec start,now;
    if(clock_gettime(CLOCK_MONOTONIC,&start)) return 11;
    atomic_fetch_add_explicit(&entered,1,memory_order_acq_rel);
    while(!atomic_load_explicit(&gate_open,memory_order_acquire)) {
        if(clock_gettime(CLOCK_MONOTONIC,&now)) return 11;
        if(now.tv_sec-start.tv_sec>=5) return 12;
        sched_yield();
    }
    return region_sum(p,n,0,out);
}
