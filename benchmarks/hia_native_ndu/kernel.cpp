#include <cstddef>
#include <cstdint>
#include <cstdlib>
#include <memory>

extern "C" std::uint64_t calculate(std::size_t n, std::uint32_t seed) noexcept {
    if (n == 0) return 0;
    std::unique_ptr<std::uint8_t, decltype(&std::free)> bytes(
        static_cast<std::uint8_t *>(std::calloc(n, 1)), &std::free);
    if (!bytes) return 1001;
    for (std::size_t i = 0; i < n; ++i)
        bytes.get()[i] = static_cast<std::uint8_t>(static_cast<std::uint32_t>(i) + seed);
    std::uint64_t total = 0;
    for (std::size_t i = 0; i < n; ++i) total += bytes.get()[i];
    return total;
}
