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
#ifdef __cplusplus
}
#endif
#endif
