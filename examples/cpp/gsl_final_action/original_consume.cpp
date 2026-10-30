#include "original.hpp"
#include <utility>

unsigned long long gsl_consume(GslGuard owner, GslState* state,
                               unsigned int mode) {
    if (mode == 1) return 2001;
    if (mode == 2) throw 2002ULL;
    if (mode == 3) {
        GslGuard moved(static_cast<GslGuard&&>(owner));
        return 2003;
    }
    if (mode == 5) {
        auto nested = gsl::finally(GslCallback{state, 9});
        return 2005;
    }
    return 0;
}
