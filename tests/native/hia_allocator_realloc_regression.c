/* Finite Linux/glibc GNU --wrap instrumentation regression; research only.
 * An independent native executable exercises realloc(NULL, n) while slot 0
 * already holds another allocation and checks exact request/peak accounting.
 */
#include "metrics.h"
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>

void *__real_malloc(size_t);
void __real_free(void *);
void *__wrap_malloc(size_t);
void *__wrap_realloc(void *, size_t);
void __wrap_free(void *);

static int check(const char *case_name, const struct metrics *m,
                 uint64_t attempts, uint64_t allocations, uint64_t frees,
                 uint64_t refusals, uint64_t live, uint64_t peak,
                 uint64_t errors) {
    printf("%s: attempts=%llu allocations=%llu frees=%llu refusals=%llu "
           "live=%llu peak_requested=%llu accounting_errors=%llu\n",
           case_name, (unsigned long long)m->attempts,
           (unsigned long long)m->allocations, (unsigned long long)m->frees,
           (unsigned long long)m->refusals, (unsigned long long)m->live,
           (unsigned long long)m->peak_requested,
           (unsigned long long)m->accounting_errors);
    if (m->attempts != attempts || m->allocations != allocations ||
        m->frees != frees || m->refusals != refusals || m->live != live ||
        m->peak_requested != peak || m->accounting_errors != errors ||
        (live == 0 && m->live_requested != 0) ||
        (live == 0 && m->live_usable != 0)) {
        fprintf(stderr, "%s: native accounting mismatch\n", case_name);
        return 1;
    }
    return 0;
}

static int realloc_null_preserves_existing(void) {
    struct metrics m;
    metrics_begin(0);
    void *existing = __wrap_malloc(24);
    void *added = __wrap_realloc(NULL, 32);
    if (!existing || !added) return 2;
    __wrap_free(added);
    __wrap_free(existing);
    metrics_end(&m);
    return check("realloc_null_slot0", &m, 2, 2, 2, 0, 0, 56, 0);
}

static int realloc_null_failure_keeps_existing(void) {
    struct metrics m;
    metrics_begin(2);
    void *existing = __wrap_malloc(24);
    void *refused = __wrap_realloc(NULL, 32);
    if (!existing || refused) return 2;
    __wrap_free(existing);
    metrics_end(&m);
    return check("realloc_null_refusal", &m, 2, 1, 1, 1, 0, 24, 0);
}

static int realloc_known_growth(void) {
    struct metrics m;
    metrics_begin(0);
    void *old = __wrap_malloc(24);
    if (!old) return 2;
    void *grown = __wrap_realloc(old, 48);
    if (!grown) return 2;
    __wrap_free(grown);
    metrics_end(&m);
    return check("realloc_owned_growth", &m, 2, 2, 2, 0, 0, 48, 0);
}

static int realloc_known_failure(void) {
    struct metrics m;
    metrics_begin(2);
    void *old = __wrap_malloc(24);
    if (!old) return 2;
    void *refused = __wrap_realloc(old, 48);
    if (refused) return 2;
    __wrap_free(old);
    metrics_end(&m);
    return check("realloc_owned_refusal", &m, 2, 1, 1, 1, 0, 24, 0);
}

static int unknown_origin_is_observable(void) {
    struct metrics m;
    metrics_begin(0);
    void *tracked = __wrap_malloc(24);
    void *foreign = __real_malloc(8);
    if (!tracked || !foreign) return 2;
    void *grown = __wrap_realloc(foreign, 32);
    if (!grown) return 2;
    /* Foreign-owned output cannot be accounted as a valid complete lifetime. */
    __real_free(grown);
    __wrap_free(tracked);
    metrics_end(&m);
    if (m.accounting_errors != 1 || m.frees != 1 || m.peak_requested != 56) {
        fprintf(stderr, "foreign realloc source was silently accepted or unrelated slot reused\n");
        return 1;
    }
    puts("foreign_realloc_origin: accounting_errors=1 (measurement denied)");
    return 0;
}

int main(void) {
    int failed = 0;
    failed |= realloc_null_preserves_existing();
    failed |= realloc_null_failure_keeps_existing();
    failed |= realloc_known_growth();
    failed |= realloc_known_failure();
    failed |= unknown_origin_is_observable();
    if (failed) return 1;
    puts("PASS: 5/5 real GNU-linker-wrapped allocator probes, zero skipped");
    return 0;
}
