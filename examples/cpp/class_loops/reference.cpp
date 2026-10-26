#include "mixer.cpp"
#include <cstdint>

// A reference-only symbol lets qualification detect accidental linkage of
// this C++ translation unit into either migrated implementation.
extern "C" std::uint32_t original_cpp_mixer_marker() { return 0x435050u; }

extern "C" std::uint32_t mixer_trace(std::uint32_t seed, std::uint32_t first_count,
                                      std::uint32_t second_count) {
    Mixer state(seed);
    const Mixer snapshot = state;
    auto first = state.advance(first_count);
    auto checksum = state.checksum(second_count);
    auto drained = state.drain(second_count);
    auto second = state.advance(second_count);
    return first ^ checksum ^ drained ^ second ^ snapshot.shadowed(first_count);
}

extern "C" std::uint32_t mixer_read_guard(std::uint32_t seed, std::uint32_t count) {
    Mixer state(seed);
    auto checksum = state.checksum(count);
    auto shadowed = state.shadowed(count);
    (void)checksum;
    (void)shadowed;
    return state.advance(0);
}
