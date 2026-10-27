#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <sys/resource.h>
#include "cases.h"
extern int32_t local_case(size_t, uint8_t);
extern uint8_t local_bounds(size_t, size_t);
extern void lv_reset(size_t);
extern size_t lv_attempts(void), lv_allocations(void), lv_releases(void), lv_refusals(void);
extern intptr_t lv_live(void);
int main(int argc, char **argv) {
    (void)argv;
    struct rlimit core_limit = {0, 0};
    if (setrlimit(RLIMIT_CORE, &core_limit)) return 91;
    if (argc == 2) {
        lv_reset(0);
        uint8_t value = local_bounds(4, 4);
        printf("unexpected_bounds_result=%u\n", (unsigned)value); return 90;
    }
    for (size_t i = 0; i < sizeof(cases) / sizeof(cases[0]); ++i) {
        const struct Case *c = &cases[i];
        lv_reset(c->reject);
        int32_t result = local_case(c->size, c->mode);
        size_t a = lv_attempts(), n = lv_allocations(), f = lv_releases(), r = lv_refusals();
        intptr_t l = lv_live();
        printf("{\"case\":%zu,\"size\":%zu,\"mode\":%u,\"reject\":%zu,\"result\":%d,"
               "\"attempts\":%zu,\"allocations\":%zu,\"releases\":%zu,\"refusals\":%zu,\"live\":%ld}\n",
               i, c->size, (unsigned)c->mode, c->reject, result, a, n, f, r, (long)l);
        if (result != c->result) return 80;
        if (a != c->attempts || n != c->allocations || f != c->allocations || r != c->refusals || l != 0) return 86;
    }
    return 0;
}
