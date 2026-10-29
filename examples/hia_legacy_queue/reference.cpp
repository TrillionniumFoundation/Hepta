// RAII client with the same original C component bodies and allocation policy.
#include <cstdlib>
#include <memory>
#include "ring/ringbuffer.h"
extern "C" {
#include "compare/platform/string.h"
#include "compare/platform/strings.h"
#include "checksum.h"
}
using Bytes = std::unique_ptr<unsigned char, decltype(&std::free)>;
extern "C" unsigned long long legacy_checksum_chunk(size_t count, unsigned long long packed,
                                                    unsigned int state, unsigned int polynomial) {
    if (!count) return state;
    if (count > 8) return 4294967296ULL;
    Bytes storage(static_cast<unsigned char *>(std::calloc(16, 1)), &std::free);
    if (!storage) return 8589934592ULL;
    Bytes input(static_cast<unsigned char *>(std::calloc(8, 1)), &std::free);
    if (!input) return 8589934592ULL;
    Bytes output(static_cast<unsigned char *>(std::calloc(8, 1)), &std::free);
    if (!output) return 8589934592ULL;
    for (size_t i=0; i<count; ++i) input.get()[i]=static_cast<unsigned char>(packed>>(i*8));
    ring_buffer_t ring;
    ring_buffer_init(&ring, reinterpret_cast<char *>(storage.get()), 16);
    if (ring_buffer_is_empty(&ring) != 1) std::abort();
    ring_buffer_queue_arr(&ring, reinterpret_cast<char *>(input.get()), count);
    if (ring_buffer_num_items(&ring) != count || ring_buffer_is_full(&ring) != 0) std::abort();
    if (ring_buffer_peek(&ring, reinterpret_cast<char *>(output.get()), 0) != 1 || output.get()[0] != input.get()[0]) std::abort();
    if (ring_buffer_dequeue_arr(&ring, reinterpret_cast<char *>(output.get()), count) != count) std::abort();
    if (memcmp(input.get(), output.get(), count) != 0 || bcmp(input.get(), output.get(), count) != 0) std::abort();
    unsigned int value=state;
    for (size_t i=0; i<count; ++i) value=checksum_byte(value, output.get()[i], polynomial);
    ring_buffer_queue(&ring, static_cast<char>(input.get()[0]));
    if (ring_buffer_dequeue(&ring, reinterpret_cast<char *>(output.get())) != 1 || output.get()[0] != input.get()[0]) std::abort();
    if (ring_buffer_is_empty(&ring) != 1) std::abort();
    return value;
}
