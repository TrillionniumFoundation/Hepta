/* Authored conformance module: independent multi-owner migration workload.
 * This is not a third-party production-library coverage claim. */
#include "paired_bytes.h"
#include <stdlib.h>

uint64_t hia_seed_byte(uint64_t index, unsigned char seed) {
    return (index + seed) % 251;
}

uint64_t hia_paired_bytes(size_t left_size, size_t right_size,
                          unsigned char seed, unsigned int early) {
    if (left_size == 0 || right_size == 0) return 0;
    unsigned char *left = (unsigned char *)calloc(left_size, 1);
    if (!left) return 1001;
    unsigned char *right = (unsigned char *)calloc(right_size, 1);
    if (!right) {
        free(left);
        return 1002;
    }
    for (size_t i = 0; i < left_size; ++i) {
        left[i] = (unsigned char)hia_seed_byte(i, seed);
    }
    for (size_t j = 0; j < right_size; ++j) {
        right[j] = (unsigned char)(hia_seed_byte(j, seed) ^ 90);
    }
    if (early != 0) {
        free(right);
        free(left);
        return 2000;
    }
    uint64_t total = 0;
    for (size_t i = 0; i < left_size; ++i) total += left[i];
    for (size_t j = 0; j < right_size; ++j) total += right[j];
    free(right);
    free(left);
    return total;
}
