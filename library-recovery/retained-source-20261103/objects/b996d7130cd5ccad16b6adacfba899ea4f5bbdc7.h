#ifndef HEPTA_FILECHECK_CHECKSUM_H
#define HEPTA_FILECHECK_CHECKSUM_H
#include <stddef.h>
#ifdef __cplusplus
extern "C" {
#endif
/* LP64 scalar C ABI. Bytes are packed least-significant byte first. */
unsigned int checksum_byte(unsigned int state, unsigned char byte,
                           unsigned int polynomial);
/* Low 32 bits: updated state. High bits: 1 invalid count, 2 allocation failure. */
unsigned long long checksum_chunk(size_t count, unsigned long long packed,
                                  unsigned int state, unsigned int polynomial);

/* Additive C API v2; the original entry remains available. */
unsigned long long checksum_chunk_v2(size_t count, unsigned long long packed,
    unsigned int state, unsigned int algorithm);
#ifdef __cplusplus
}
#endif
#endif
