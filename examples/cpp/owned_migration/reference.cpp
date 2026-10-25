#include <cstddef>
#include <cstdint>
#include "owned_bytes.cpp"

extern "C" std::uint64_t owned_case(std::size_t size, std::uint8_t value, std::size_t index,
                                   std::uint32_t reject, std::uint32_t early) noexcept {
    return run_owned(size, value, index, reject != 0, early != 0);
}
