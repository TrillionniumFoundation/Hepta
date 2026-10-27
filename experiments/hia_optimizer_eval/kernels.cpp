#include <cstddef>
#include <cstdint>
#include <new>
#include <stdexcept>
#include <vector>

extern "C" std::uint64_t full_lifecycle(std::size_t size, std::uint32_t seed) {
    try {
        std::vector<std::uint8_t> bytes(size, 0);
        for (std::size_t i = 0; i < size; ++i) bytes[i] = static_cast<std::uint8_t>(static_cast<std::uint32_t>(i) + seed);
        std::uint64_t total = 0;
        for (const auto byte : bytes) total += byte;
        return total;
    } catch (const std::bad_alloc &) { return 1001; }
      catch (const std::length_error &) { return 1001; }
}

extern "C" std::uint64_t packet_xor(std::size_t size, std::uint32_t seed) {
    try {
        std::vector<std::uint8_t> first(size, 0);
        for (std::size_t i = 0; i < size; ++i)
            first[i] = static_cast<std::uint8_t>(static_cast<std::uint32_t>(i) * UINT32_C(13) + seed);
        std::vector<std::uint8_t> second(size, 0);
        for (std::size_t i = 0; i < size; ++i)
            second[i] = first[i] ^ static_cast<std::uint8_t>(static_cast<std::uint32_t>(i) + (seed ^ UINT32_C(90)));
        std::uint64_t total = 0;
        for (const auto byte : second) total += byte;
        return total;
    } catch (const std::bad_alloc &) { return 1001; }
      catch (const std::length_error &) { return 1001; }
}
