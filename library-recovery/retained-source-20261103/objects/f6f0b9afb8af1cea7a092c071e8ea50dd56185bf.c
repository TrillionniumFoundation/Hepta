#include "checksum.h"
unsigned long long checksum_chunk_v2(size_t count, unsigned long long packed,
                                    unsigned int state, unsigned int algorithm) {
    if (algorithm == 1) { return checksum_chunk(count, packed, state, 0xedb88320U); }
    if (algorithm == 2) { return checksum_chunk(count, packed, state, 0x82f63b78U); }
    return 12884901888ULL;
}
