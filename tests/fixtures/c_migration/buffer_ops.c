/* Authored conformance module for local control flow, direct calls and buffers.
 * The separate native/ directory is the frozen pre-existing repository module.
 */
#include <stdint.h>
#include <stddef.h>

static uint32_t mix_byte(uint32_t value) {
    return value * 1664525u + 1013904223u;
}

uint32_t sum_bytes(const uint8_t *data, size_t count) {
    uint32_t total = 0u;
    size_t i = 0;
    while (i < count) {
        total += data[i];
        ++i;
    }
    return total;
}

uint32_t mutate_bytes(uint8_t *data, size_t count, uint8_t seed) {
    uint32_t total = 0u;
    for (size_t i = 0; i < count; ++i) {
        data[i] = (uint8_t)(mix_byte((uint32_t)data[i] + seed) >> 24);
        total += data[i];
    }
    return total;
}
