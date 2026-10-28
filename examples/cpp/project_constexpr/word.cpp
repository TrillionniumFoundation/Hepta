#include "branches.hpp"

extern "C" unsigned runtime_step(unsigned value) noexcept {
    return scalar_step(value);
}

extern "C" unsigned narrow0(unsigned value) noexcept {
    return adjust<unsigned, 0>(value);
}
extern "C" unsigned narrow1(unsigned value) noexcept {
    return adjust<unsigned, 1>(value);
}
extern "C" unsigned scope0(unsigned value) noexcept {
    return scoped<0>(value);
}
extern "C" unsigned scope1(unsigned value) noexcept {
    return scoped<1>(value);
}
extern "C" unsigned discard_object(unsigned value) noexcept {
    return scalar_only(value);
}
