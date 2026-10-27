/* Untimed allocator observation for the C and LLVM implementations. */
#include <stddef.h>
#include <stdint.h>
#include <stdlib.h>
static volatile size_t attempts, allocations, releases, refusals, reject_attempt;
static volatile intptr_t live;
void *__real_malloc(size_t);
void *__real_calloc(size_t, size_t);
void __real_free(void *);
static int refuse(void) {
    attempts += 1;
    if (reject_attempt && attempts == reject_attempt) { refusals += 1; return 1; }
    return 0;
}
void *__wrap_malloc(size_t size) {
    if (refuse()) return NULL;
    void *p = __real_malloc(size);
    if (p) { allocations += 1; live += 1; }
    return p;
}
void *__wrap_calloc(size_t size, size_t count) {
    if (refuse()) return NULL;
    void *p = __real_calloc(size, count);
    if (p) { allocations += 1; live += 1; }
    return p;
}
void __wrap_free(void *p) {
    if (p) { releases += 1; live -= 1; }
    __real_free(p);
}
void lv_reset(size_t reject) {
    if (live != 0) abort();
    attempts = allocations = releases = refusals = 0; reject_attempt = reject;
}
size_t lv_attempts(void) { return attempts; }
size_t lv_allocations(void) { return allocations; }
size_t lv_releases(void) { return releases; }
size_t lv_refusals(void) { return refusals; }
intptr_t lv_live(void) { return live; }
