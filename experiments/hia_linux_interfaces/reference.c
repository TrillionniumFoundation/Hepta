#include <stdint.h>
#include <stddef.h>
#include <stdlib.h>

/* Independent host qualification reference. This source MUST NOT be linked
 * in the Hepta artifact cohort. It is not a generated Hepta implementation. */
uint64_t worker_checksum(size_t count, uint32_t seed) {
    if (!count) return 0;
    unsigned char *bytes = calloc(1, count);
    if (!bytes) return 1001;
    for (size_t index = 0; index < count; ++index)
        bytes[index] = (unsigned char)((uint32_t)index + seed);
    uint64_t result = 0;
    for (size_t index = 0; index < count; ++index) result += bytes[index];
    free(bytes);
    return result;
}
