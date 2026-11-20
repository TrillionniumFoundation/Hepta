/* Release C baselines. They have the same signatures and valid-input workload. */
#include <stdint.h>
#include <stdlib.h>
#include <string.h>

__attribute__((noinline)) uint64_t reference_madd(uint64_t a, uint64_t b, uint64_t c) {
    return a*b+c;
}
static void range(const void *p, uint64_t extent, uint64_t n) {
    if (n > extent || (n && (!p || (uintptr_t)p + n < (uintptr_t)p))) abort();
}
__attribute__((noinline)) uint64_t reference_sum(const uint8_t *p, uint64_t extent, uint64_t n) {
    range(p, extent, n);
    uint64_t result = 0;
    for (uint64_t i = 0; i < n; ++i) result += p[i];
    return result;
}
__attribute__((noinline)) uint64_t reference_zero(const uint8_t *p, uint64_t extent, uint64_t n) {
    range(p, extent, n);
    uint8_t result = 0;
    for (uint64_t i = 0; i < n; ++i) result |= p[i];
    return result == 0;
}
__attribute__((noinline)) uint64_t reference_copy(uint8_t *d, uint64_t de, const uint8_t *s, uint64_t se, uint64_t n) {
    range(d, de, n); range(s, se, n);
    if (n && (uintptr_t)d < (uintptr_t)s+n && (uintptr_t)s < (uintptr_t)d+n) abort();
    if (n) memcpy(d,s,n);
    return n;
}
