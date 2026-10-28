#include <stdlib.h>
#include "checksum.h"

unsigned long long checksum_chunk(size_t count, unsigned long long packed,
                                  unsigned int state, unsigned int polynomial) {
    if (count == 0) { return (unsigned long long)state; }
    if (count > 8) { return 4294967296ULL; }
    unsigned char *bytes = calloc(count, 1);
    if (!bytes) { return 8589934592ULL; }
    for (size_t index = 0; index < count; ++index) {
        bytes[index] = (unsigned char)(packed >> (index * 8UL));
    }
    unsigned int value = state;
    for (size_t index = 0; index < count; ++index) {
        value = checksum_byte(value, bytes[index], polynomial);
    }
    free(bytes);
    return (unsigned long long)value;
}
