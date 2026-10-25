#include "bridge.h"
int main(void) {
    if (hepta_cxx_native_add(7, 4) != 11) return 1;
    if (hepta_cxx_native_add(-7, 4) != -3) return 2;
    if (hepta_cxx_native_square(12) != 144) return 3;
    return 0;
}
