#include "checksum.h"

unsigned int checksum_byte(unsigned int state, unsigned char byte,
                           unsigned int polynomial) {
    unsigned int value = state ^ (unsigned int)byte;
    for (unsigned int bit = 0; bit < 8; ++bit) {
        if ((value & 1U) != 0) {
            value = (value >> 1U) ^ polynomial;
        } else {
            value = value >> 1U;
        }
    }
    return value;
}
