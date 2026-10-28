#include "owners.h"
extern "C" unsigned long long composed_case(unsigned long left, unsigned long right, unsigned char value,
    unsigned long index, unsigned int reject, unsigned int early) noexcept {
    return run_pair(left, right, value, index, reject, early);
}
