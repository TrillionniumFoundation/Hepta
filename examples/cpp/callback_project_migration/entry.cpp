#include "owners.h"
unsigned long long read_pair(const PairedBytes& borrowed, unsigned long index, bool reject) noexcept {
    if (reject) { return 4001; }
    return borrowed.score(index);
}
unsigned long long run_pair(unsigned long left, unsigned long right, unsigned char value,
                            unsigned long index, unsigned int reject, unsigned int early) noexcept {
    try {
        PairedBytes first(left, right, reject);
        first.prepare(value);
        if (early == 1) { return 2001; }
        PairedBytes second(static_cast<PairedBytes&&>(first));
        return consume_pair(static_cast<PairedBytes&&>(second), read_pair, index, early);
    } catch (int code) { return 1000 + static_cast<unsigned long long>(code); }
      catch (...) { return 1001; }
}
