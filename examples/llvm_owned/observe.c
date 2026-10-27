#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
void *__real_calloc(size_t, size_t);
void *__real_malloc(size_t);
void __real_free(void *);
static volatile size_t allocations = 0, frees = 0, live = 0, refusals = 0;
static volatile int fail_second = 0;
void *__wrap_calloc(size_t count, size_t size) {
    if (fail_second && ((count == 12281 && size == 1) || (count == 1 && size == 12281))) {
        refusals++; return NULL;
    }
    void *value = __real_calloc(count, size);
    if (value) { allocations++; live++; }
    return value;
}
void *__wrap_malloc(size_t size) {
    if (fail_second && size == 12281) { refusals++; return NULL; }
    void *value = __real_malloc(size);
    if (value) { allocations++; live++; }
    return value;
}
void __wrap_free(void *value) {
    if (value) { frees++; live--; }
    __real_free(value);
}
extern uint64_t two_alloc(size_t, uint32_t);
int main(void) {
    if (two_alloc(3, 0) != 22) return 11;
    if (two_alloc(5, 1) != 2) return 12;
    if (two_alloc(0, 0) != 19) return 13;
    fail_second = 1;
    if (two_alloc(12281, 0) != 1) return 14;
    if (two_alloc((size_t)-1, 0) != 1) return 15;
    printf("{\"allocations\":%zu,\"frees\":%zu,\"live\":%zu,\"refusals\":%zu}\n",
           allocations, frees, live, refusals);
    return allocations != 7 || frees != 7 || live != 0 || refusals != 1;
}
