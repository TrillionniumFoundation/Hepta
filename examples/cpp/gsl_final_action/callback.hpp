#pragma once

// Authored closed callback contract; not part of Microsoft GSL.
struct GslState {
    unsigned long long trace;
    unsigned long long calls;
};
struct GslCallback {
    GslState* state;
    unsigned long long tag;
    void operator()() noexcept;
};
