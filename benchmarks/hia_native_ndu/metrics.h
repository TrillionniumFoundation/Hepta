#ifndef HEPTA_NATIVE_ECONOMICS_METRICS_H
#define HEPTA_NATIVE_ECONOMICS_METRICS_H
#include <stdint.h>
struct metrics {
    uint64_t attempts, allocations, frees, refusals, live;
    uint64_t requested_total, usable_total, peak_requested, peak_usable;
    uint64_t live_requested, live_usable, accounting_errors;
    uint64_t stack_anchor, stack_max_distance;
};
void metrics_begin(uint64_t fail);
void metrics_end(struct metrics *out);
#endif
