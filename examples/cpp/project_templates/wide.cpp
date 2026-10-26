#include "generic.hpp"

namespace arithmetic {
unsigned long long adjust(unsigned long long value) noexcept {
    return value + static_cast<unsigned long long>(PROJECT_BIAS);
}
}

extern "C" unsigned long long wide(unsigned long long value, unsigned long long salt) noexcept {
    return arithmetic::adjust(arithmetic::mix<unsigned long long, 5>(value, salt));
}

extern "C" long long wide_clamp(long long value, long long low, long long high) noexcept {
    return arithmetic::clamp<long long>(value, low, high);
}

extern "C" unsigned long long cross_unit(unsigned int value, unsigned long long salt) noexcept {
    return static_cast<unsigned long long>(word(value, 7u)) ^ wide(salt, 11ull);
}
