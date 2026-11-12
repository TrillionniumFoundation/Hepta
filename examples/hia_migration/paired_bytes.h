#ifndef HEPTA_HIA_PAIRED_BYTES_H
#define HEPTA_HIA_PAIRED_BYTES_H
#include <stddef.h>
#include <stdint.h>

uint64_t hia_seed_byte(uint64_t index, unsigned char seed);
uint64_t hia_paired_bytes(size_t left_size, size_t right_size,
                          unsigned char seed, unsigned int early);
#endif
