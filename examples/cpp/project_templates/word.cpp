#include "generic.hpp"

namespace arithmetic {
unsigned int adjust(unsigned int value) noexcept {
    return value + static_cast<unsigned int>(PROJECT_BIAS);
}
}

extern "C" unsigned int word(unsigned int value, unsigned int salt) noexcept {
    return arithmetic::adjust(arithmetic::mix<unsigned int, 3>(value, salt));
}

extern "C" int signed_clamp(int value, int low, int high) noexcept {
    return arithmetic::clamp<int>(value, low, high);
}

extern "C" int signed_step(int value) noexcept {
    return value + 1;
}

extern "C" bool positive(unsigned int value) noexcept {
    return value != 0u;
}
