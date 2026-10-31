#include "selected_gsl.hpp"
#include "callback.hpp"
#include <climits>
#include <type_traits>
#include <utility>

using GslGuard = gsl::final_action<GslCallback>;
static_assert(CHAR_BIT == 8 && sizeof(unsigned long long) == 8);
static_assert(std::is_aggregate<GslCallback>::value);
static_assert(std::is_aggregate<GslState>::value);
static_assert(std::is_trivially_copy_constructible<GslCallback>::value);
static_assert(std::is_trivially_move_constructible<GslCallback>::value);
static_assert(std::is_trivially_destructible<GslCallback>::value);
static_assert(std::is_standard_layout<GslCallback>::value);
static_assert(std::is_same<decltype(&GslCallback::operator()),
                          void (GslCallback::*)() noexcept>::value);
static_assert(!std::is_copy_constructible<GslGuard>::value);
static_assert(!std::is_copy_assignable<GslGuard>::value);
static_assert(!std::is_move_assignable<GslGuard>::value);
static_assert(std::is_nothrow_move_constructible<GslGuard>::value);
static_assert(std::is_nothrow_destructible<GslGuard>::value);

// This instantiates all three upstream implementation bodies. Its source is
// a compiler probe and is not counted as an upstream implementation.
void gsl_capture(GslState* state, unsigned long long tag) noexcept {
    GslGuard first(GslCallback{state, tag});
    GslGuard second(static_cast<GslGuard&&>(first));
}
void gsl_factory_capture(GslState* state, unsigned long long tag) noexcept {
    auto guard = gsl::finally(GslCallback{state, tag});
}
void gsl_const_lvalue_factory_capture(GslState* state, unsigned long long tag) noexcept {
    const GslCallback callback{state, tag};
    auto guard = gsl::finally(callback);
}
#if HEPTA_GSL_LVALUE
void gsl_lvalue_factory_capture(GslState* state, unsigned long long tag) noexcept {
    GslCallback callback{state, tag};
    auto guard = gsl::finally(callback);
}
#endif
