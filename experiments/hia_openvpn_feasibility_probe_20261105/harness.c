#include <stddef.h>
#include <stdint.h>
#include <stdio.h>

extern uint32_t probe_opcode(const uint8_t *data, size_t count);
extern uint32_t probe_host_call(uint32_t value);
uint32_t host_mask(uint32_t value) { return value & UINT32_C(7); }

int main(void) {
    if (probe_opcode(NULL, 0) != 256) return 1;
    for (unsigned i = 0; i < 256; ++i) {
        uint8_t header = (uint8_t)i;
        if (probe_opcode(&header, 1) != i >> 3) return 2;
        if (probe_host_call(i) != (i & 7)) return 3;
    }
    puts("513 finite byte-boundary and bidirectional-C-call observations passed");
    return 0;
}
