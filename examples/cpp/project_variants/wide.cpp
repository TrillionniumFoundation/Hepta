#include "model.hpp"

extern "C" unsigned long long matrix_wide(unsigned long long value, unsigned long long salt) noexcept {
    return matrix_mix<unsigned long long, PROJECT_ROUNDS>(value, salt);
}
