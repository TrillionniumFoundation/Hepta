#ifndef HEPTA_PROJECT_TEMPLATE_GENERIC_HPP
#define HEPTA_PROJECT_TEMPLATE_GENERIC_HPP
#ifndef PROJECT_BIAS
#error "The captured build must define PROJECT_BIAS"
#endif

namespace arithmetic {
template<class T, unsigned int Count>
T mix(T value, T salt) noexcept {
    T result = value;
    for (unsigned int i = 0; i < Count; ++i) {
        result = result * static_cast<T>(33) + salt + static_cast<T>(i);
    }
    return result;
}

template<class T>
T clamp(T value, T low, T high) noexcept {
    if (value < low) return low;
    if (value > high) return high;
    return value;
}

unsigned int adjust(unsigned int value) noexcept;
unsigned long long adjust(unsigned long long value) noexcept;
}

extern "C" unsigned int word(unsigned int value, unsigned int salt) noexcept;
extern "C" unsigned long long wide(unsigned long long value, unsigned long long salt) noexcept;
extern "C" int signed_clamp(int value, int low, int high) noexcept;
extern "C" long long wide_clamp(long long value, long long low, long long high) noexcept;
extern "C" unsigned long long cross_unit(unsigned int value, unsigned long long salt) noexcept;
extern "C" int signed_step(int value) noexcept;
extern "C" bool positive(unsigned int value) noexcept;
#endif
