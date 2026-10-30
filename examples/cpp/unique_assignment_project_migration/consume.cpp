#include "owners.h"
unsigned long long consume_pair(PairedBytes owned, unsigned long index, unsigned int early) noexcept {
    owned = static_cast<PairedBytes&&>(owned);
    if (early == 2) { return 2002; }
    if (index >= owned.limit()) { return 2003; }
    PairedBytes final_owner(static_cast<PairedBytes&&>(owned));
    return final_owner.score(index);
}
