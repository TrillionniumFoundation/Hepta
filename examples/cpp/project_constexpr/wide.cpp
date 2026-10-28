#include "branches.hpp"

extern "C" unsigned long wide0(unsigned long value) noexcept {
    return adjust<unsigned long, 0>(value);
}
extern "C" unsigned long wide1(unsigned long value) noexcept {
    return adjust<unsigned long, 1>(value);
}
// Exercise the same complete template pattern and same instance in two TUs.
extern "C" unsigned repeated_narrow(unsigned value) noexcept {
    return adjust<unsigned, 0>(value);
}
