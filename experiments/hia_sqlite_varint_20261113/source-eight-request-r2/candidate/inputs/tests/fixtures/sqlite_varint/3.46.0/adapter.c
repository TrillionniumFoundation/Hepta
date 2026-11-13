/* Authored mechanical oracle ABI; codec.inc is unmodified upstream C. */
#include <assert.h>
#include <stdint.h>
typedef uint8_t u8;
typedef uint32_t u32;
typedef uint64_t u64;
#define SQLITE_NOINLINE
#include "codec.inc"
unsigned hia_reference_get(const unsigned char *input, uint64_t *value) {
    return sqlite3GetVarint(input, value);
}
unsigned hia_reference_put(unsigned char *output, uint64_t value) {
    return (unsigned)sqlite3PutVarint(output, value);
}
