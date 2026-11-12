#include <stddef.h>
#include <stdint.h>
#include <stdlib.h>

uint64_t calculate(size_t n, uint32_t seed) {
    if (n == 0) return 0;
    uint8_t *bytes = calloc(n, 1);
    if (!bytes) return 1001;
    for (size_t i = 0; i < n; ++i) bytes[i] = (uint8_t)((uint32_t)i + seed);
    uint64_t total = 0;
    for (size_t i = 0; i < n; ++i) total += bytes[i];
    free(bytes);
    return total;
}
