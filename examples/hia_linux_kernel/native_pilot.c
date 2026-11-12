/* SPDX-License-Identifier: GPL-2.0 */
#define _GNU_SOURCE
#include <errno.h>
#include <inttypes.h>
#include <sched.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

extern unsigned __sw_hweight32(unsigned);
extern unsigned hia_bridge_hweight32(unsigned);
extern unsigned hia_sw_hweight32(unsigned);
extern unsigned hardware_popcnt(unsigned);
extern unsigned stock_abi_probe(unsigned);
extern unsigned hybrid_abi_probe(unsigned);
typedef unsigned (*weight_fn)(unsigned);
static weight_fn const functions[] = {
    __sw_hweight32, hia_bridge_hweight32, hia_sw_hweight32, hardware_popcnt
};
static uint32_t inputs[135168];
static volatile uint64_t final_sink;

static uint64_t clock_ns(clockid_t which)
{
    struct timespec value;
    if (clock_gettime(which, &value) != 0) { perror("clock_gettime"); exit(2); }
    return (uint64_t)value.tv_sec * UINT64_C(1000000000) + value.tv_nsec;
}

static unsigned oracle(uint32_t value)
{
    unsigned result = 0;
    for (unsigned i = 0; i != 32; ++i) result += (value >> i) & 1u;
    return result;
}

static unsigned parse_unsigned(const char *value, unsigned limit)
{
    char *end;
    errno = 0;
    unsigned long parsed = strtoul(value, &end, 10);
    if (errno || !*value || *end || parsed > limit) exit(2);
    return (unsigned)parsed;
}

int main(int argc, char **argv)
{
    if (argc != 4) return 2;
    unsigned arm = parse_unsigned(argv[1], 3), cycles = parse_unsigned(argv[2], 1024);
    unsigned cpu = parse_unsigned(argv[3], CPU_SETSIZE - 1);
    if (!cycles) return 2;
    cpu_set_t cpus;
    CPU_ZERO(&cpus); CPU_SET(cpu, &cpus);
    if (sched_setaffinity(0, sizeof(cpus), &cpus)) { perror("sched_setaffinity"); return 2; }
    __builtin_cpu_init();
    int has_popcnt = !!__builtin_cpu_supports("popcnt");
    if (arm == 3 && !has_popcnt) {
        puts("{\"status\":\"NOT_RUN_UNSUPPORTED_CPU\",\"arm\":3}");
        return 77;
    }
    uint32_t state = UINT32_C(0x6a09e667);
    uint64_t failures = 0, expected_sum = 0, comparisons = 0;
    uint64_t digest = UINT64_C(1469598103934665603);
    for (unsigned i = 0; i < 135168; ++i) {
        uint32_t value;
        if (i < 65536) value = i;
        else if (i < 131072) value = ~(i - 65536);
        else {
            state ^= state << 13; state ^= state >> 17; state ^= state << 5;
            value = state;
        }
        inputs[i] = value;
        unsigned expected = oracle(value);
        expected_sum += expected;
        digest = (digest ^ value ^ ((uint64_t)expected << 32)) * UINT64_C(1099511628211);
        for (unsigned target = 0; target < (has_popcnt ? 4u : 3u); ++target) {
            failures += functions[target](value) != expected;
            ++comparisons;
        }
    }
    for (unsigned i = 0; i < 32; ++i) {
        failures += stock_abi_probe(UINT32_C(1) << i) != 0;
        failures += hybrid_abi_probe(UINT32_C(1) << i) != 0;
    }
    if (failures) {
        printf("{\"status\":\"FAIL\",\"failures\":%" PRIu64 "}\n", failures);
        return 1;
    }
    weight_fn function = functions[arm];
    uint64_t sum = 0;
    uint64_t wall_start = clock_ns(CLOCK_MONOTONIC_RAW);
    uint64_t cpu_start = clock_ns(CLOCK_PROCESS_CPUTIME_ID);
    for (unsigned cycle = 0; cycle < cycles; ++cycle)
        for (unsigned i = 0; i < 135168; ++i) sum += function(inputs[i]);
    uint64_t cpu_ns = clock_ns(CLOCK_PROCESS_CPUTIME_ID) - cpu_start;
    uint64_t wall_ns = clock_ns(CLOCK_MONOTONIC_RAW) - wall_start;
    final_sink = sum;
    if (sum != expected_sum * cycles) return 1;
    printf("{\"status\":\"PASS\",\"arm\":%u,\"cases\":135168,\"cycles\":%u,"
           "\"calls\":%" PRIu64 ",\"comparisons\":%" PRIu64 ",\"abi_checks\":64,"
           "\"failures\":0,\"sum\":%" PRIu64 ",\"input_digest\":\"%016" PRIx64 "\","
           "\"wall_ns\":%" PRIu64 ",\"cpu_ns\":%" PRIu64 ",\"cpu\":%d,\"has_popcnt\":%s}\n",
           arm, cycles, UINT64_C(135168) * cycles, comparisons, sum, digest,
           wall_ns, cpu_ns, sched_getcpu(), has_popcnt ? "true" : "false");
    return 0;
}
