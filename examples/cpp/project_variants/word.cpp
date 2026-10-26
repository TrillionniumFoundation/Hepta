#include "model.hpp"

extern "C" unsigned int matrix_word(unsigned int value, unsigned int salt) noexcept {
    return matrix_mix<unsigned int, PROJECT_ROUNDS>(value, salt);
}

extern "C" unsigned long long matrix_cross(unsigned int value, unsigned long long salt) noexcept {
    return static_cast<unsigned long long>(matrix_word(value, 7u)) ^ matrix_wide(salt, 11ull);
}
