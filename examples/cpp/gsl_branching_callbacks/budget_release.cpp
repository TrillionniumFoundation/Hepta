#include "callback.hpp"

// Authored integration callback; the final_action implementation is real GSL.
// trace is a finite budget ledger, not an OS allocator or file descriptor.
void GslCallback::operator()() noexcept {
    const unsigned long long before = state->trace;
    if (tag <= before) {
        state->trace = before - tag;
        state->calls = state->calls + 1ULL;
    } else {
        state->trace = before;
        state->calls = state->calls + 2ULL;
    }
}
