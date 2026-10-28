#include <cstddef>
#include <cstdint>
#include "owners.h"
extern "C" std::uint64_t composed_case(std::size_t left, std::size_t right, std::uint8_t value,
    std::size_t index, std::uint32_t reject, std::uint32_t early) noexcept {
    return run_pair(left, right, value, index, reject, early);
}
