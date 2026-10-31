#include "callback.hpp"

// Authored callback with branch-local values and nested conditional cleanup.
void GslCallback::operator()() noexcept {
    const unsigned long long parity = tag & 1ULL;
    if (parity == 0ULL || state->trace == 0ULL) {
        state->trace = state->trace + tag;
    } else {
        const unsigned long long next = state->trace ^ tag;
        if (next > state->trace) {
            state->trace = next;
        } else {
            state->trace = state->trace * 37ULL + tag;
        }
    }
    state->calls = state->calls + 1ULL;
}
