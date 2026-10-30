#include "owners.h"
unsigned long long consume_pair(PairedBytes owned,
    unsigned long long (*callback)(const PairedBytes&, unsigned long, bool) noexcept,
    unsigned long index, unsigned int early) noexcept {
    if (early == 2) { return 2002; }
    if (index >= owned.limit()) { return 2003; }
    PairedBytes final_owner(static_cast<PairedBytes&&>(owned));
    return callback(final_owner, index, early == 3);
}
