#include "client.h"

#ifndef HEPTA_RING_OUTPUT_MASK
#define HEPTA_RING_OUTPUT_MASK 0
#endif

size_t ring_transfer(ring_buffer_t *buffer, const char *input,
                     size_t input_len, char *output, size_t output_len) {
    ring_buffer_queue_arr(buffer, input, input_len);
    size_t received = ring_buffer_dequeue_arr(buffer, output, output_len);
    for (size_t i = 0; i < received; ++i) {
        output[i] = (char)(output[i] ^ HEPTA_RING_OUTPUT_MASK);
    }
    return received;
}
