#include "scalar_state.cpp"

extern "C" unsigned int word_trace(unsigned int initial, unsigned int step,
                                   unsigned int reset, unsigned int last) noexcept {
    ScalarState state(initial, 0ULL, 0, 0LL);
    const auto snapshot = state;
    auto first = state.add_word(step);
    state.set_word(reset);
    auto final = state.add_word(last);
    return first ^ final ^ snapshot.word_value();
}

extern "C" unsigned long long wide_trace(unsigned long long initial, unsigned long long first,
                                         unsigned long long second) noexcept {
    ScalarState state(0U, initial, 0, 0LL);
    const auto snapshot = state;
    auto a = state.mix(first);
    auto b = state.mix(second);
    return a ^ b ^ snapshot.wide_value();
}

extern "C" int balance_trace(int initial, int lower, int upper) noexcept {
    ScalarState state(0U, 0ULL, initial, 0LL);
    state.clamp_balance(lower, upper);
    return state.balance_value();
}

extern "C" long long position_trace(long long initial, long long next) noexcept {
    ScalarState state(0U, 0ULL, 0, initial);
    state.replace_position(next);
    return state.position_value();
}

extern "C" int state_guard(unsigned int word, unsigned long long wide, int balance, long long position,
                            unsigned int step, unsigned long long mix, int lower, int upper,
                            long long next) noexcept {
    ScalarState state(word, wide, balance, position);
    auto new_word = state.add_word(step);
    if (state.word_value() != new_word || state.wide_value() != wide ||
        state.balance_value() != balance || state.position_value() != position) return 1;
    auto new_wide = state.mix(mix);
    if (state.word_value() != new_word || state.wide_value() != new_wide ||
        state.balance_value() != balance || state.position_value() != position) return 2;
    auto new_balance = state.clamp_balance(lower, upper);
    if (state.word_value() != new_word || state.wide_value() != new_wide ||
        state.balance_value() != new_balance || state.position_value() != position) return 3;
    auto new_position = state.replace_position(next);
    if (state.word_value() != new_word || state.wide_value() != new_wide ||
        state.balance_value() != new_balance || state.position_value() != new_position) return 4;
    return 0;
}
