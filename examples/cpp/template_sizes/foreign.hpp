#pragma once
#include <array>
#include <cstddef>
#include <cstdint>
#include <stdexcept>

namespace sized_example {
template<std::size_t N>
std::uint32_t add_size(std::uint32_t value) noexcept {
    return value + static_cast<std::uint32_t>(N);
}

// Observable lifecycle witness around the same standard-library storage.
// The bridge does not infer these counters, allocation rules or non-retention.
struct Member {
    static inline std::uint32_t live = 0;
    Member() noexcept { ++live; }
    ~Member() noexcept { --live; }
};

template<class T, std::size_t N>
struct CountedArray {
    static inline std::uint32_t destroyed = 0;
    Member member;
    std::array<T, N> storage{};
    explicit CountedArray(std::uint32_t reject) {
        if (reject) throw std::runtime_error("rejected after member initialization");
    }
    ~CountedArray() noexcept { ++destroyed; }
    void fill(const T& value) { storage.fill(value); }
    const T& at(std::size_t index) const { return storage.at(index); }
};
}
