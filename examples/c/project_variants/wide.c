#include "model.h"

unsigned long long matrix_wide(unsigned long long value, unsigned long long salt) {
    for (int index = 0; index < PROJECT_ROUNDS; index = index + 1) {
        value = value * 33ull + salt + (unsigned long long)index;
    }
    return value + (unsigned long long)PROJECT_BIAS;
}
