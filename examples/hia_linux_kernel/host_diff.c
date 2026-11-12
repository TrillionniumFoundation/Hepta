// SPDX-License-Identifier: GPL-2.0
// A common actual-object differential driver. Neither external body is here.
#include <stdint.h>
#include <stdio.h>

extern unsigned int hia_sw_hweight32(unsigned int);
extern unsigned int __sw_hweight32(unsigned int);
static volatile uint32_t seed = UINT32_C(0x6a09e667);

static unsigned int oracle(uint32_t value)
{
    unsigned int result = 0;
    for (unsigned int i = 0; i != 32; ++i)
        result += (value >> i) & 1u;
    return result;
}

int main(void)
{
    uint64_t calls = 0, failures = 0, digest = UINT64_C(1469598103934665603);
    uint32_t state = seed;
    for (uint32_t i = 0; i < 135168; ++i) {
        uint32_t value;
        if (i < 65536) value = i;
        else if (i < 131072) value = ~(i - 65536);
        else {
            state ^= state << 13; state ^= state >> 17; state ^= state << 5;
            value = state;
        }
        unsigned int expected = oracle(value);
        unsigned int actual = hia_sw_hweight32(value);
        unsigned int original = __sw_hweight32(value);
        failures += actual != expected || original != expected;
        digest = (digest ^ value ^ ((uint64_t)actual << 32)) * UINT64_C(1099511628211);
        ++calls;
    }
    printf("HIA_LINUX_NATIVE_DIFF {\"cases\":%llu,\"failures\":%llu,\"result_digest\":\"%016llx\"}\n",
           (unsigned long long)calls, (unsigned long long)failures, (unsigned long long)digest);
    return failures ? 1 : 0;
}
