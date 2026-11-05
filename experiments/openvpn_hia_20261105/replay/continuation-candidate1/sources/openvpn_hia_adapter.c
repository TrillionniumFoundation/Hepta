/* SPDX-License-Identifier: GPL-2.0-only
 * Derived from OpenVPN 2.7.8 packet-ID semantics, upstream commit
 * dc1f569087135894ac2703aeabd7a960ee9452d4.
 */
#include "config.h"
#include "syshead.h"
#include "openvpn_hia_adapter.h"

#if !defined(__x86_64__) || __BYTE_ORDER__ != __ORDER_LITTLE_ENDIAN__
#error "The experimental OpenVPN state adapter is frozen to Linux x86-64 little endian"
#endif
_Static_assert(sizeof(time_t) == 8, "LP64 signed 64-bit time_t is required");
_Static_assert(sizeof(void *) == 8, "64-bit pointers are required");

extern uint64_t ovpn_hia_packet_id_read(const uint8_t *, uint64_t, uint8_t *, uint64_t, uint32_t);
extern uint64_t ovpn_hia_packet_id_write(uint8_t *, uint64_t, uint8_t *, uint64_t, int64_t, uint32_t, uint32_t);
extern uint64_t ovpn_hia_packet_id_read_epoch(const uint8_t *, uint64_t, uint8_t *, uint64_t);
extern uint64_t ovpn_hia_packet_id_write_epoch(uint8_t *, uint64_t, uint8_t *, uint64_t, int64_t, uint16_t);

/* Caller objects must be live and initialized. Numeric range checks establish
 * non-overlap, not liveness. Check object addresses before reading any fields;
 * reading the buffer descriptor is then necessary to inspect its wire range.
 * Rejected arguments leave the complete application state untouched. */
static bool
hia_range(const void *p, uint64_t n, uintptr_t *end)
{
    if ((n && !p) || n > UINTPTR_MAX - (uintptr_t)p) { return false; }
    *end = (uintptr_t)p + n;
    return true;
}

static bool
hia_overlap(const void *a, uintptr_t ae, const void *b, uintptr_t be)
{
    return (uintptr_t)a < be && (uintptr_t)b < ae;
}

static bool
hia_objects(const void *p, size_t psize, size_t palign, const struct buffer *b)
{
    uintptr_t pe, be, we;
    if (!hia_range(p, psize, &pe) || !hia_range(b, sizeof(*b), &be)
        || (uintptr_t)p % palign || (uintptr_t)b % _Alignof(struct buffer)
        || hia_overlap(p, pe, b, be)) { return false; }
    if (b->capacity < 0 || b->capacity > 65536 || b->offset < 0 || b->len < 0
        || b->offset > b->capacity || b->len > b->capacity - b->offset
        || !hia_range(b->data, (uint64_t)b->capacity, &we)) { return false; }
    if (b->capacity && (hia_overlap(p, pe, b->data, we)
                       || hia_overlap(b, be, b->data, we))) { return false; }
    return true;
}

static bool
hia_result(uint64_t result)
{
    return (result >> 32) == 0 && (uint32_t)result == 1;
}

bool
hia_packet_id_read(struct packet_id_net *p, struct buffer *b, bool long_form)
{
    if (!hia_objects(p, sizeof(*p), _Alignof(struct packet_id_net), b)) { return false; }
    /* Upstream initializes the receiver; its incoming fields may be indeterminate. */
    uint64_t state[4] = {0, 0, (uint64_t)b->offset, (uint64_t)b->len};
    uint64_t result = ovpn_hia_packet_id_read(b->data, (uint64_t)b->capacity,
                                             (uint8_t *)state, sizeof(state), (uint32_t)long_form);
    if (result >> 32 || (uint32_t)result > 1) { return false; }
    p->id = state[0]; p->time = (time_t)state[1];
    b->offset = (int)state[2]; b->len = (int)state[3];
    return hia_result(result);
}

bool
hia_packet_id_write(struct packet_id_send *p, struct buffer *b, bool long_form, bool prepend)
{
    if (!hia_objects(p, sizeof(*p), _Alignof(struct packet_id_send), b)) { return false; }
    uint64_t state[4] = {p->id, (uint64_t)p->time, (uint64_t)b->offset, (uint64_t)b->len};
    uint64_t result = ovpn_hia_packet_id_write(b->data, (uint64_t)b->capacity,
                                              (uint8_t *)state, sizeof(state), (int64_t)now,
                                              (uint32_t)long_form, (uint32_t)prepend);
    if (result >> 32 || (uint32_t)result > 1) { return false; }
    p->id = state[0]; p->time = (time_t)state[1];
    b->offset = (int)state[2]; b->len = (int)state[3];
    return hia_result(result);
}

uint16_t
hia_packet_id_read_epoch(struct packet_id_net *p, struct buffer *b)
{
    if (!hia_objects(p, sizeof(*p), _Alignof(struct packet_id_net), b)) { return 0; }
    const int input_len = b->len;
    uint64_t state[4] = {0, 0, (uint64_t)b->offset, (uint64_t)b->len};
    uint64_t result = ovpn_hia_packet_id_read_epoch(b->data, (uint64_t)b->capacity,
                                                   (uint8_t *)state, sizeof(state));
    if (result >> 32 || (uint32_t)result > UINT16_MAX) { return 0; }
    /* Upstream never accesses time; truncated reads also leave id untouched.
     * A valid zero epoch still consumes eight bytes and updates the ID. */
    if (input_len >= 8) { p->id = state[0]; }
    b->offset = (int)state[2]; b->len = (int)state[3];
    return (uint16_t)result;
}

bool
hia_packet_id_write_epoch(struct packet_id_send *p, uint16_t epoch, struct buffer *b)
{
    if (!hia_objects(p, sizeof(*p), _Alignof(struct packet_id_send), b)) { return false; }
    uint64_t state[4] = {p->id, (uint64_t)p->time, (uint64_t)b->offset, (uint64_t)b->len};
    uint64_t result = ovpn_hia_packet_id_write_epoch(b->data, (uint64_t)b->capacity,
                                                    (uint8_t *)state, sizeof(state),
                                                    (int64_t)now, epoch);
    if (result >> 32 || (uint32_t)result > 1) { return false; }
    p->id = state[0]; p->time = (time_t)state[1];
    b->offset = (int)state[2]; b->len = (int)state[3];
    return hia_result(result);
}

/* GNU/LLVM ELF link --wrap redirects normal application call sites. */
bool __wrap_packet_id_read(struct packet_id_net *p, struct buffer *b, bool l)
{ return hia_packet_id_read(p, b, l); }
bool __wrap_packet_id_write(struct packet_id_send *p, struct buffer *b, bool l, bool prepend)
{ return hia_packet_id_write(p, b, l, prepend); }
uint16_t __wrap_packet_id_read_epoch(struct packet_id_net *p, struct buffer *b)
{ return hia_packet_id_read_epoch(p, b); }
bool __wrap_packet_id_write_epoch(struct packet_id_send *p, uint16_t epoch, struct buffer *b)
{ return hia_packet_id_write_epoch(p, epoch, b); }
