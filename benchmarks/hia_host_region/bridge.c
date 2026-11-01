#define _POSIX_C_SOURCE 200809L
#include <stddef.h>
#include <stdint.h>
#include <stdatomic.h>
#include <time.h>

/* Reviewed synchronous no-escape region ABI. These actual HIA scalar exports
 * are linked from independently verified Core through its native backend. */
extern uint64_t hia_region_fold(uint64_t,uint64_t);
extern uint8_t hia_region_byte(uint32_t,size_t);
static _Atomic unsigned active;
static _Atomic unsigned peak;

int region_sum(const uint8_t *p,size_t n,uint64_t argument,uint64_t *out) {
    (void)argument;
    uint64_t value=0;
    for (size_t i=0;i<n;++i) value=hia_region_fold(value,p[i]);
    *out=value;
    return 0;
}
int region_fill(uint8_t *p,size_t n,uint64_t seed,uint64_t *out) {
    for (size_t i=0;i<n;++i) p[i]=hia_region_byte((uint32_t)seed,i);
    return region_sum(p,n,0,out);
}
int region_delayed_sum(const uint8_t *p,size_t n,uint64_t milliseconds,uint64_t *out) {
    if (milliseconds>5000) return 12;
    unsigned now=atomic_fetch_add_explicit(&active,1,memory_order_acq_rel)+1;
    unsigned seen=atomic_load_explicit(&peak,memory_order_relaxed);
    while (seen<now && !atomic_compare_exchange_weak_explicit(&peak,&seen,now,memory_order_relaxed,memory_order_relaxed)) {}
    struct timespec delay={(time_t)(milliseconds/1000),(long)(milliseconds%1000)*1000000};
    while (nanosleep(&delay,&delay)) {}
    int result=region_sum(p,n,0,out);
    atomic_fetch_sub_explicit(&active,1,memory_order_acq_rel);
    return result;
}
int region_peak(const uint8_t *p,size_t n,uint64_t argument,uint64_t *out) {
    (void)p;(void)n;(void)argument;
    *out=atomic_load_explicit(&peak,memory_order_acquire);
    return 0;
}
int region_fail_write(uint8_t *p,size_t n,uint64_t argument,uint64_t *out) {
    (void)argument;
    if (n) p[0]=0xee;
    *out=0;
    return 7;
}
/* This deliberately false read contract is invoked only in a disposable
 * negative-control process. Kernel read permission must fault on this write. */
int region_bad_read(uint8_t *p,size_t n,uint64_t argument,uint64_t *out) {
    (void)argument;
    if (n) p[0]^=1;
    *out=0;
    return 0;
}
