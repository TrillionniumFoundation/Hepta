#include "callback.hpp"

void GslCallback::operator()() noexcept {
    state->trace = state->trace * 31ULL + tag;
    state->calls = state->calls + 1ULL;
}
