#ifndef HEPTA_RING_MATRIX_CLIENT_H
#define HEPTA_RING_MATRIX_CLIENT_H
#include "ringbuffer.h"

/* Authored client API, separate from the unchanged upstream ring module. */
size_t ring_transfer(ring_buffer_t *buffer, const char *input,
                     size_t input_len, char *output, size_t output_len);
#endif
