#include <stddef.h>
#include <stdint.h>
#include <stdlib.h>

uint64_t full_lifecycle(size_t size, uint32_t seed) {
    if (!size) return 0;
    uint8_t *bytes = (uint8_t *)calloc(size, 1);
    if (!bytes) return 1001;
    for (size_t i = 0; i < size; ++i) bytes[i] = (uint8_t)((uint32_t)i + seed);
    uint64_t total = 0;
    for (size_t i = 0; i < size; ++i) total += bytes[i];
    free(bytes);
    return total;
}

uint64_t packet_xor(size_t size, uint32_t seed) {
    if (!size) return 0;
    uint8_t *first = (uint8_t *)calloc(size, 1);
    if (!first) return 1001;
    for (size_t i = 0; i < size; ++i)
        first[i] = (uint8_t)((uint32_t)i * UINT32_C(13) + seed);
    uint8_t *second = (uint8_t *)calloc(size, 1);
    if (!second) { free(first); return 1001; }
    for (size_t i = 0; i < size; ++i)
        second[i] = first[i] ^ (uint8_t)((uint32_t)i + (seed ^ UINT32_C(90)));
    uint64_t total = 0;
    for (size_t i = 0; i < size; ++i) total += second[i];
    free(second); free(first);
    return total;
}
