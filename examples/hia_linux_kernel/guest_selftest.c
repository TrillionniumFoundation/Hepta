// SPDX-License-Identifier: GPL-2.0
// Identical driver in control and hybrid. HIA implements no test/oracle state.
#include <linux/init.h>
#include <linux/kernel.h>
#include <linux/bitops.h>
#include <linux/compiler.h>
#include <linux/errno.h>
#include <linux/types.h>
#include <asm/cpufeature.h>
#include "hia_component_identity.h"

extern unsigned int hia_hweight_abi_probe(unsigned int);
static unsigned int hia_test_seed = 0x6a09e667u;

static noinline unsigned int independent_weight(u32 value)
{
    unsigned int result = 0;
    unsigned int bit;
    for (bit = 0; bit < 32; ++bit)
        result += (value >> bit) & 1u;
    return result;
}

static int __init hia_component_selftest(void)
{
    u32 state = READ_ONCE(hia_test_seed);
    u64 digest = 1469598103934665603ULL;
    unsigned long direct_calls = 0, natural_calls = 0, failures = 0, abi_calls = 0;
    unsigned int i;
    for (i = 0; i < 135168; ++i) {
        u32 value;
        unsigned int expected, direct, natural;
        if (i < 65536) value = i;
        else if (i < 131072) value = ~(i - 65536);
        else {
            state ^= state << 13; state ^= state >> 17; state ^= state << 5;
            value = state;
        }
        expected = independent_weight(value);
        direct = __sw_hweight32(value);
        ++direct_calls;
        natural = hweight32(value);
        ++natural_calls;
        failures += direct != expected || natural != expected;
        digest = (digest ^ value ^ ((u64)direct << 32)) * 1099511628211ULL;
    }
    for (i = 0; i < 32; ++i) {
        state ^= state << 13; state ^= state >> 17; state ^= state << 5;
        failures += hia_hweight_abi_probe(state) != 0;
        ++abi_calls;
    }
    pr_info("HIA_LINUX_COMPONENT_TEST {\"arm\":\"%s\",\"core_sha256\":\"%s\",\"object_sha256\":\"%s\",\"direct_calls\":%lu,\"natural_calls\":%lu,\"abi_calls\":%lu,\"popcnt\":%u,\"failures\":%lu,\"result_digest\":\"%016llx\"}\n",
            HIA_COMPONENT_ARM, HIA_COMPONENT_CORE_SHA256, HIA_COMPONENT_OBJECT_SHA256,
            direct_calls, natural_calls, abi_calls, !!boot_cpu_has(X86_FEATURE_POPCNT), failures,
            (unsigned long long)digest);
    return failures ? -EINVAL : 0;
}
late_initcall(hia_component_selftest);
