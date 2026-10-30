#include "original.hpp"
#include <utility>

extern "C" std::uint64_t original_case(std::uint64_t seed,
    std::uint64_t tag, std::uint32_t mode, std::uint32_t field) noexcept {
    GslState state{seed, 0};
    unsigned long long status = 0;
    try {
        if (mode == 7) throw 1007ULL;
        auto owner = gsl::finally(GslCallback{&state, tag});
        if (mode == 6) throw 1006ULL;
        if (mode == 4) status = 1004;
        else status = gsl_consume(static_cast<GslGuard&&>(owner), &state, mode);
    } catch (unsigned long long code) {
        status = code;
    }
    if (field == 0) return state.trace;
    if (field == 1) return state.calls;
    return status;
}
