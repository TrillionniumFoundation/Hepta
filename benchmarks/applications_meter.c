#define _POSIX_C_SOURCE 200809L
#include "applications.h"
#include <stdalign.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

/* A single-threaded, fixed-capacity instrumentation table. It never allocates
 * storage of its own. All three implementations use these same entry points.
 * Counts are requested allocation sizes, not allocator usable-size or RSS. */
void *__real_malloc(size_t);
void *__real_calloc(size_t,size_t);
void *__real_realloc(void *,size_t);
void __real_free(void *);
static struct {uintptr_t address;size_t size;} live[64];
static AppAllocationMetrics metrics;
static size_t fail_at;
static int active;

static void broken(const char *message) {
    active=0;fprintf(stderr,"allocation instrumentation failure: %s\n",message);exit(80);
}
void app_measure_begin(size_t fail_nth) {
    if(active || metrics.live_bytes)broken("unreleased allocation at request boundary");
    for(size_t i=0;i<64;i++)if(live[i].address)broken("unreleased allocation identity");
    memset(&metrics,0,sizeof(metrics));fail_at=fail_nth;active=1;
}
AppAllocationMetrics app_measure_end(void) {
    active=0;
    if(metrics.live_bytes)broken("application returned with live allocation");
    for(size_t i=0;i<64;i++)if(live[i].address)broken("application returned with allocation identity");
    return metrics;
}
static int request(size_t size,int kind) {
    if(!active)return 0;
    metrics.attempts++;metrics.attempted_bytes+=size;
    if(kind==0)metrics.malloc_calls++;
    else if(kind==1)metrics.calloc_calls++;
    else metrics.realloc_calls++;
    if(fail_at && metrics.attempts==fail_at){metrics.failures++;return 1;}
    return 0;
}
static void returned(void *pointer,size_t size) {
    if(!active)return;
    if(!pointer){metrics.failures++;return;}
    size_t index=0;
    while(index<64 && live[index].address)index++;
    if(index==64)broken("tracking capacity exhausted");
    live[index].address=(uintptr_t)pointer;live[index].size=size;
    metrics.allocations++;metrics.allocated_bytes+=size;metrics.live_bytes+=size;
    if(metrics.live_bytes>metrics.peak_live_bytes)metrics.peak_live_bytes=metrics.live_bytes;
}
static size_t forget(uintptr_t address,int count_free) {
    for(size_t i=0;i<64;i++)if(live[i].address==address && address){
        size_t size=live[i].size;live[i].address=0;live[i].size=0;
        if(count_free)metrics.frees++;
        metrics.freed_bytes+=size;metrics.live_bytes-=size;return size;
    }
    return 0;
}
void *app_measure_alloc(size_t size,size_t alignment,int zeroed) {
    if(request(size,zeroed?1:0))return NULL;
    void *pointer=NULL;
    if(alignment<=alignof(max_align_t))pointer=zeroed?__real_calloc(1,size):__real_malloc(size);
    else {
        if(posix_memalign(&pointer,alignment,size)!=0)pointer=NULL;
        if(pointer && zeroed)memset(pointer,0,size);
    }
    returned(pointer,size);return pointer;
}
void app_measure_dealloc(void *pointer) {
    if(pointer)forget((uintptr_t)pointer,1);
    __real_free(pointer);
}
void *app_measure_realloc(void *pointer,size_t size,size_t alignment) {
    if(request(size,2))return NULL;
    if(alignment>alignof(max_align_t))broken("unexpected over-aligned reallocation");
    uintptr_t old_address=(uintptr_t)pointer;
    void *result=__real_realloc(pointer,size);
    if(result){forget(old_address,0);returned(result,size);}
    else if(active)metrics.failures++;
    return result;
}
void *__wrap_malloc(size_t size){return app_measure_alloc(size,alignof(max_align_t),0);}
void *__wrap_calloc(size_t count,size_t size){
    if(size && count>SIZE_MAX/size){if(active){metrics.attempts++;metrics.calloc_calls++;metrics.failures++;}return NULL;}
    return app_measure_alloc(count*size,alignof(max_align_t),1);
}
void *__wrap_realloc(void *pointer,size_t size){return app_measure_realloc(pointer,size,alignof(max_align_t));}
void __wrap_free(void *pointer){app_measure_dealloc(pointer);}
