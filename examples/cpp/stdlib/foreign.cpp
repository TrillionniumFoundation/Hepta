#include "foreign.hpp"
#include <stdexcept>

namespace hepta_example {
std::uint64_t mix(std::uint64_t value) noexcept {
    return (value ^ UINT64_C(0x9e3779b97f4a7c15)) * UINT64_C(0xbf58476d1ce4e5b9);
}
Pair swap_pair(Pair value) noexcept { return {value.second, value.first}; }
std::int64_t sum(std::span<const std::int64_t> values) noexcept {
    std::int64_t result = 0;
    for (auto value : values) result += value;
    return result;
}
void add(std::span<std::int64_t> values, std::int64_t delta) {
    for (auto& value : values) {
        value += delta;
        if (delta == -999) throw std::runtime_error("intentional partial mutation");
    }
}
std::size_t text_size(std::span<const std::uint8_t> text) {
    // This actually constructs a standard-library string, including embedded
    // NUL bytes. Its allocation stays entirely in the C++ module.
    if (text.empty()) return std::string{}.size();
    std::string value(reinterpret_cast<const char*>(text.data()), text.size());
    return value.size();
}
std::uint64_t native_vector_size(const std::vector<std::int64_t>& values) noexcept {
    return static_cast<std::uint64_t>(values.size());
}
}
