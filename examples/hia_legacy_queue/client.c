/* Authored integration client; the three upstream files are unchanged. */
#include <stdlib.h>
#include <stdint.h>
#include "ring/ringbuffer.h"
#include "compare/platform/string.h"
#include "compare/platform/strings.h"
#include "checksum.h"

unsigned long long legacy_checksum_chunk(size_t count, unsigned long long packed,
                                         unsigned int state, unsigned int polynomial) {
    if (count == 0) return state;
    if (count > 8) return 4294967296ULL;
    unsigned char *storage = calloc(16, 1);
    if (!storage) return 8589934592ULL;
    unsigned char *input = calloc(8, 1);
    if (!input) { free(storage); return 8589934592ULL; }
    unsigned char *output = calloc(8, 1);
    if (!output) { free(input); free(storage); return 8589934592ULL; }
    for (size_t i = 0; i < count; ++i) input[i] = (unsigned char)(packed >> (i * 8));
    ring_buffer_t ring;
    ring_buffer_init(&ring, (char *)storage, 16);
    if (ring_buffer_is_empty(&ring) != 1) abort();
    ring_buffer_queue_arr(&ring, (char *)input, count);
    if (ring_buffer_num_items(&ring) != count || ring_buffer_is_full(&ring) != 0) abort();
    if (ring_buffer_peek(&ring, (char *)output, 0) != 1 || output[0] != input[0]) abort();
    if (ring_buffer_dequeue_arr(&ring, (char *)output, count) != count) abort();
    if (memcmp(input, output, count) != 0 || bcmp(input, output, count) != 0) abort();
    unsigned int value = state;
    for (size_t i = 0; i < count; ++i) value = checksum_byte(value, output[i], polynomial);
    ring_buffer_queue(&ring, (char)input[0]);
    if (ring_buffer_dequeue(&ring, (char *)output) != 1 || output[0] != input[0]) abort();
    if (ring_buffer_is_empty(&ring) != 1) abort();
    free(output); free(input); free(storage);
    return value;
}
