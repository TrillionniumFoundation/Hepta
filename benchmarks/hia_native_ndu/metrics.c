#include "metrics.h"
#include <malloc.h>
#include <stddef.h>
#include <stdint.h>
#include <string.h>

void *__real_malloc(size_t);
void *__real_calloc(size_t, size_t);
void *__real_realloc(void *, size_t);
void __real_free(void *);
static struct metrics current;
static uint64_t fail_at;
static int active;
static struct { void *p; size_t requested, usable; } slots[32];

static void stack_sample(void) {
    volatile char point = 0;
    uintptr_t here = (uintptr_t)&point, anchor = (uintptr_t)current.stack_anchor;
    uint64_t distance = here > anchor ? here - anchor : anchor - here;
    if (distance > current.stack_max_distance) current.stack_max_distance = distance;
}
void metrics_begin(uint64_t fail) {
    volatile char point = 0;
    memset(&current, 0, sizeof(current));
    memset(slots, 0, sizeof(slots));
    current.stack_anchor = (uintptr_t)&point;
    fail_at = fail;
    active = 1;
}
void metrics_end(struct metrics *out) { active = 0; *out = current; }
static int refusal(void) {
    if (!active) return 0;
    stack_sample();
    ++current.attempts;
    if (fail_at && current.attempts == fail_at) { ++current.refusals; return 1; }
    return 0;
}
static void record(void *p, size_t requested) {
    if (!active || !p) return;
    size_t usable = malloc_usable_size(p);
    unsigned slot = 0;
    while (slot < 32 && slots[slot].p) ++slot;
    if (slot == 32) { ++current.accounting_errors; return; }
    slots[slot].p = p; slots[slot].requested = requested; slots[slot].usable = usable;
    ++current.allocations; ++current.live;
    current.requested_total += requested; current.usable_total += usable;
    current.live_requested += requested; current.live_usable += usable;
    if (current.live_requested > current.peak_requested) current.peak_requested = current.live_requested;
    if (current.live_usable > current.peak_usable) current.peak_usable = current.live_usable;
}
static void release(void *p) {
    if (!active || !p) return;
    stack_sample();
    unsigned slot = 0;
    while (slot < 32 && slots[slot].p != p) ++slot;
    if (slot == 32) { ++current.accounting_errors; return; }
    ++current.frees; --current.live;
    current.live_requested -= slots[slot].requested;
    current.live_usable -= slots[slot].usable;
    slots[slot].p = 0;
}
void *__wrap_malloc(size_t n) {
    if (refusal()) return 0;
    void *p = __real_malloc(n); record(p, n); return p;
}
void *__wrap_calloc(size_t n, size_t size) {
    if (refusal()) return 0;
    void *p = __real_calloc(n, size); record(p, n * size); return p;
}
void *__wrap_realloc(void *old, size_t n) {
    if (refusal()) return 0;
    unsigned slot = 0;
    if (active && old) {
        while (slot < 32 && slots[slot].p != old) ++slot;
    }
    void *p = __real_realloc(old, n);
    if (active && (p || n == 0)) {
        if (slot < 32 && slots[slot].p) {
            ++current.frees; --current.live;
            current.live_requested -= slots[slot].requested;
            current.live_usable -= slots[slot].usable;
            slots[slot].p = 0;
        }
        record(p, n);
    }
    return p;
}
void __wrap_free(void *p) { release(p); __real_free(p); }
