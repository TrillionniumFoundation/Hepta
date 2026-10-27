#ifndef HEPTA_APPLICATION_BENCHMARK_H
#define HEPTA_APPLICATION_BENCHMARK_H
#include <stddef.h>
#include <stdint.h>
typedef struct {
    uint32_t status, reserved;
    uint64_t bytes, records, checksum;
} AppResult;
_Static_assert(sizeof(AppResult)==32,"application ABI size");
_Static_assert(offsetof(AppResult,checksum)==24,"application ABI field offset");
AppResult packet_app(size_t units,uint64_t request);
AppResult transform_app(size_t units,uint64_t request);
typedef struct {
    uint64_t attempts, allocations, frees, failures;
    uint64_t malloc_calls, calloc_calls, realloc_calls;
    uint64_t attempted_bytes, allocated_bytes, freed_bytes, peak_live_bytes, live_bytes;
} AppAllocationMetrics;
void app_measure_begin(size_t fail_nth);
AppAllocationMetrics app_measure_end(void);
void *app_measure_alloc(size_t size,size_t alignment,int zeroed);
void app_measure_dealloc(void *pointer);
void *app_measure_realloc(void *pointer,size_t size,size_t alignment);
#endif
