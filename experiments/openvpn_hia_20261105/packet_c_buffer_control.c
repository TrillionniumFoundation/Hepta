/* SPDX-License-Identifier: GPL-2.0-only
 * Derived from OpenVPN 2.7.8 packet-ID semantics, upstream commit
 * dc1f569087135894ac2703aeabd7a960ee9452d4.
 */
/* Same admitted byte-range/state ABI, delegating algorithms to the UNMODIFIED
 * upstream packet_id.c. This control exposes the cost of metadata marshaling
 * and admission separately from the normal raw OpenVPN C function. */
#include "config.h"
#include "syshead.h"
#include "packet_id.h"
#include <stdint.h>
#include <string.h>
#define INVALID_STATE UINT64_C(0xfffe0001)
static uint64_t admit(const uint8_t *wire, uint64_t n, uint8_t *state, uint64_t sn)
{
    const uint8_t *p[2] = {wire,state};
    uint64_t size[2] = {n,sn};
    uintptr_t end[2];
    for (int i=0;i<2;++i) {
        if (size[i] > 65536) { return UINT64_C(1)<<32; }
        if (size[i] && !p[i]) { return UINT64_C(2)<<32; }
        if (size[i] > UINTPTR_MAX-(uintptr_t)p[i]) { return UINT64_C(3)<<32; }
        end[i]=(uintptr_t)p[i]+size[i];
    }
    if (n && sn && end[0]>(uintptr_t)state && end[1]>(uintptr_t)wire) {
        return UINT64_C(4)<<32;
    }
    return 0;
}
static bool metadata(const uint64_t s[4], uint64_t n)
{ return s[2]<=n && s[3]<=n-s[2]; }
uint64_t c_buffer_packet_id_read(const uint8_t *wire, uint64_t n, uint8_t *state, uint64_t sn, uint32_t l)
{
    uint64_t error=admit(wire,n,state,sn), s[4];
    if (error) { return error; }
    if (sn!=32 || l>1) { return INVALID_STATE; }
    memcpy(s,state,32);
    if (!metadata(s,n)) { return INVALID_STATE; }
    struct packet_id_net p={.id=s[0],.time=(time_t)s[1]};
    struct buffer b={.capacity=(int)n,.offset=(int)s[2],.len=(int)s[3],.data=(uint8_t *)wire};
    bool ok=packet_id_read(&p,&b,l);
    s[0]=p.id; s[1]=(uint64_t)p.time; s[2]=(uint64_t)b.offset; s[3]=(uint64_t)b.len;
    memcpy(state,s,32); return ok;
}
uint64_t c_buffer_packet_id_write(uint8_t *wire, uint64_t n, uint8_t *state, uint64_t sn, int64_t clock_value, uint32_t l, uint32_t prepend)
{
    uint64_t error=admit(wire,n,state,sn), s[4];
    if (error) { return error; }
    if (sn!=32 || l>1 || prepend>1) { return INVALID_STATE; }
    memcpy(s,state,32);
    if (!metadata(s,n)) { return INVALID_STATE; }
    struct packet_id_send p={.id=s[0],.time=(time_t)s[1]};
    struct buffer b={.capacity=(int)n,.offset=(int)s[2],.len=(int)s[3],.data=wire};
    now=(time_t)clock_value;
    bool ok=packet_id_write(&p,&b,l,prepend);
    s[0]=p.id; s[1]=(uint64_t)p.time; s[2]=(uint64_t)b.offset; s[3]=(uint64_t)b.len;
    memcpy(state,s,32); return ok;
}
uint64_t c_buffer_packet_id_read_epoch(const uint8_t *wire, uint64_t n, uint8_t *state, uint64_t sn)
{
    uint64_t error=admit(wire,n,state,sn), s[4];
    if (error) { return error; }
    if (sn!=32) { return INVALID_STATE; }
    memcpy(s,state,32);
    if (!metadata(s,n)) { return INVALID_STATE; }
    struct packet_id_net p={.id=s[0],.time=(time_t)s[1]};
    struct buffer b={.capacity=(int)n,.offset=(int)s[2],.len=(int)s[3],.data=(uint8_t *)wire};
    uint16_t ep=packet_id_read_epoch(&p,&b);
    s[0]=p.id; s[1]=(uint64_t)p.time; s[2]=(uint64_t)b.offset; s[3]=(uint64_t)b.len;
    memcpy(state,s,32); return ep;
}
uint64_t c_buffer_packet_id_write_epoch(uint8_t *wire, uint64_t n, uint8_t *state, uint64_t sn, int64_t clock_value, uint16_t epoch)
{
    uint64_t error=admit(wire,n,state,sn), s[4];
    if (error) { return error; }
    if (sn!=32) { return INVALID_STATE; }
    memcpy(s,state,32);
    if (!metadata(s,n)) { return INVALID_STATE; }
    struct packet_id_send p={.id=s[0],.time=(time_t)s[1]};
    struct buffer b={.capacity=(int)n,.offset=(int)s[2],.len=(int)s[3],.data=wire};
    now=(time_t)clock_value;
    bool ok=packet_id_write_epoch(&p,epoch,&b);
    s[0]=p.id; s[1]=(uint64_t)p.time; s[2]=(uint64_t)b.offset; s[3]=(uint64_t)b.len;
    memcpy(state,s,32); return ok;
}
