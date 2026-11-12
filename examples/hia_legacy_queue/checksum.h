#ifndef HIA_LEGACY_CHECKSUM_H
#define HIA_LEGACY_CHECKSUM_H
#ifdef __cplusplus
extern "C" {
#endif
unsigned int checksum_byte(unsigned int state, unsigned char byte, unsigned int polynomial);
#ifdef __cplusplus
}
#endif
#endif
