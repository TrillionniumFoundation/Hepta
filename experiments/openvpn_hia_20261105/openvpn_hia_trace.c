/* SPDX-License-Identifier: GPL-2.0-only
 * Diagnostic-only instrumentation. Do not use this object for timings.
 * Link second-level --wrap=ovpn_hia_packet_id_* against the actual HIA exports.
 * No payload, state bytes, keys, or pointer addresses are logged.
 */
#include <inttypes.h>
#include <stdint.h>
#include <stdio.h>
#include <stdatomic.h>

static _Atomic uint64_t counts[4];
static _Atomic uint64_t abi_failures;

extern uint64_t __real_ovpn_hia_packet_id_read(const uint8_t *, uint64_t, uint8_t *, uint64_t, uint32_t);
extern uint64_t __real_ovpn_hia_packet_id_write(uint8_t *, uint64_t, uint8_t *, uint64_t, int64_t, uint32_t, uint32_t);
extern uint64_t __real_ovpn_hia_packet_id_read_epoch(const uint8_t *, uint64_t, uint8_t *, uint64_t);
extern uint64_t __real_ovpn_hia_packet_id_write_epoch(uint8_t *, uint64_t, uint8_t *, uint64_t, int64_t, uint16_t);

static uint64_t observed(unsigned kind, uint64_t result)
{
    atomic_fetch_add_explicit(&counts[kind], 1, memory_order_relaxed);
    if (result >> 32) { atomic_fetch_add_explicit(&abi_failures, 1, memory_order_relaxed); }
    return result;
}

uint64_t __wrap_ovpn_hia_packet_id_read(const uint8_t *p, uint64_t n, uint8_t *s, uint64_t sn, uint32_t l)
{ return observed(0, __real_ovpn_hia_packet_id_read(p, n, s, sn, l)); }
uint64_t __wrap_ovpn_hia_packet_id_write(uint8_t *p, uint64_t n, uint8_t *s, uint64_t sn, int64_t now, uint32_t l, uint32_t pre)
{ return observed(1, __real_ovpn_hia_packet_id_write(p, n, s, sn, now, l, pre)); }
uint64_t __wrap_ovpn_hia_packet_id_read_epoch(const uint8_t *p, uint64_t n, uint8_t *s, uint64_t sn)
{ return observed(2, __real_ovpn_hia_packet_id_read_epoch(p, n, s, sn)); }
uint64_t __wrap_ovpn_hia_packet_id_write_epoch(uint8_t *p, uint64_t n, uint8_t *s, uint64_t sn, int64_t now, uint16_t epoch)
{ return observed(3, __real_ovpn_hia_packet_id_write_epoch(p, n, s, sn, now, epoch)); }

__attribute__((destructor)) static void report(void)
{
    fprintf(stderr, "OPENVPN_HIA_CALLS read=%" PRIu64 " write=%" PRIu64
            " read_epoch=%" PRIu64 " write_epoch=%" PRIu64 " abi_failures=%" PRIu64 "\n",
            atomic_load_explicit(&counts[0], memory_order_relaxed),
            atomic_load_explicit(&counts[1], memory_order_relaxed),
            atomic_load_explicit(&counts[2], memory_order_relaxed),
            atomic_load_explicit(&counts[3], memory_order_relaxed),
            atomic_load_explicit(&abi_failures, memory_order_relaxed));
}
