#include "selected_gsl.hpp"
#include "callback.hpp"
#include <type_traits>
#include <cstdint>

// Both releases accept a const lvalue, but instantiate different real bodies:
// GSL 3.1 copies its separate const F& parameter directly; GSL 4.0 forwards
// const F& and removes cv/reference qualifiers from the owner type.
extern "C" std::uint64_t original_const_factory_case(std::uint64_t seed,
        std::uint64_t tag, std::uint32_t, std::uint32_t field) noexcept {
    GslState state{seed, 0};
    const GslCallback callback{&state, tag};
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
    return original_const_factory_case(7, 3, 0, 0) == 220 &&
           original_const_factory_case(7, 3, 0, 1) == 1 ? 0 : 1;
}
#endif
