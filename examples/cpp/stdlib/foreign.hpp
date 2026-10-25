#pragma once
#include <cstddef>
#include <cstdint>
#include <span>
#include <string>
#include <vector>

namespace hepta_example {
struct Pair { std::int64_t first; std::int64_t second; };
std::uint64_t mix(std::uint64_t value) noexcept;
Pair swap_pair(Pair value) noexcept;
std::int64_t sum(std::span<const std::int64_t> values) noexcept;
void add(std::span<std::int64_t> values, std::int64_t delta);
std::size_t text_size(std::span<const std::uint8_t> text);
std::uint64_t native_vector_size(const std::vector<std::int64_t>& values) noexcept;

// Concrete C++ template instantiation remains in this C++ compiler. Hepta
// sees an ordinary, fully checked scalar C ABI, not a std::vector layout.
template<typename T> T twice(T value) noexcept { return value + value; }
}
