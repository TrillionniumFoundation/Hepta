#include "model.h"

unsigned int matrix_word(unsigned int value, unsigned int salt) {
    for (int index = 0; index < PROJECT_ROUNDS; index = index + 1) {
        value = value * 33u + salt + (unsigned int)index;
    }
    return value + PROJECT_BIAS;
}

unsigned long long matrix_cross(unsigned int value, unsigned long long salt) {
    return (unsigned long long)matrix_word(value, 7u) ^ matrix_wide(salt, 11ull);
}
