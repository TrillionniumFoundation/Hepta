#include <memory>
#include <new>
#include "checksum.h"

// Independent RAII baseline with the same algorithm and byte layout.
extern "C" unsigned long long checksum_chunk(size_t count,
    unsigned long long packed, unsigned int state, unsigned int polynomial) {
    if (count == 0) { return state; }
    if (count > 8) { return 4294967296ULL; }
    std::unique_ptr<unsigned char[]> bytes(new (std::nothrow) unsigned char[count]{});
    if (!bytes) { return 8589934592ULL; }
    for (unsigned long index = 0; index < count; ++index) {
        bytes[index] = static_cast<unsigned char>(packed >> (index * 8UL));
    }
    unsigned int value = state;
    for (unsigned long index = 0; index < count; ++index) {
        value = checksum_byte(value, bytes[index], polynomial);
    }
    return value;
}
