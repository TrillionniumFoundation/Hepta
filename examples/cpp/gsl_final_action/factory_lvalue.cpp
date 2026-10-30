#include "selected_gsl.hpp"
#include "callback.hpp"
#include <type_traits>
#include <cstdint>

// A real upgrade boundary: v3.1.0 retains an lvalue-reference template argument
// and fails to construct it from std::move(f); v4.0.0 strips cv/reference types.
extern "C" std::uint64_t original_factory_case(std::uint64_t seed,
        std::uint64_t tag, std::uint32_t, std::uint32_t field) noexcept {
    GslState state{seed, 0};
    GslCallback callback{&state, tag};
    {
        auto action = gsl::finally(callback);
        static_assert(std::is_same<decltype(action),
                                  gsl::final_action<GslCallback>>::value);
    }
    if (field == 0) return state.trace;
    if (field == 1) return state.calls;
    return 0;
}
#ifndef HEPTA_FACTORY_LIBRARY
int main() {
    return original_factory_case(7, 3, 0, 0) == 220 &&
           original_factory_case(7, 3, 0, 1) == 1 ? 0 : 1;
}
#endif
