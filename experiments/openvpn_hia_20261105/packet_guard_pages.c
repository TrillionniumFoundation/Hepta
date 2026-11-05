/* SPDX-License-Identifier: GPL-2.0-only
 * OpenVPN 2.7.8 semantics: dc1f569087135894ac2703aeabd7a960ee9452d4.
 * Exact live ranges end immediately before a PROT_NONE page; both reads and
 * writes are checked against full unmodified upstream through its C control.
 */
#define _GNU_SOURCE
#include <stdint.h>
#include <stddef.h>
#include <sys/mman.h>
#include <unistd.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <inttypes.h>
#include <time.h>
time_t now, now_usec;
#define DECLARE(prefix) \
extern uint64_t prefix##_packet_id_read(const uint8_t *, uint64_t, uint8_t *, uint64_t, uint32_t); \
extern uint64_t prefix##_packet_id_write(uint8_t *, uint64_t, uint8_t *, uint64_t, int64_t, uint32_t, uint32_t); \
extern uint64_t prefix##_packet_id_read_epoch(const uint8_t *, uint64_t, uint8_t *, uint64_t); \
extern uint64_t prefix##_packet_id_write_epoch(uint8_t *, uint64_t, uint8_t *, uint64_t, int64_t, uint16_t)
DECLARE(ovpn_hia); DECLARE(c_buffer);
static uint8_t *region(size_t page)
{
    uint8_t *p=mmap(NULL,page*2,PROT_READ|PROT_WRITE,MAP_PRIVATE|MAP_ANONYMOUS,-1,0);
    if (p==MAP_FAILED || mprotect(p+page,page,PROT_NONE)) { perror("guard pages"); exit(2); }
    return p;
}
int main(void)
{
    size_t page=(size_t)sysconf(_SC_PAGESIZE);
    uint64_t checked=0;
    for (int cap=0;cap<=16;++cap) {
        uint8_t *wa=region(page), *wb=region(page), *sa=region(page), *sb=region(page);
        uint8_t *ca=wa+page-cap,*ha=wb+page-cap,*cs=sa+page-32,*hs=sb+page-32;
        for (int off=0;off<=cap;++off) for (int len=0;len<=cap-off;++len)
          for (int mode=0;mode<4;++mode) for (int flags=0;flags<4;++flags) {
            for (int i=0;i<cap;++i) { ca[i]=ha[i]=(uint8_t)(i*13+cap); }
            uint64_t initial[4]={UINT32_MAX,41,(uint64_t)off,(uint64_t)len};
            memcpy(cs,initial,32); memcpy(hs,initial,32);
            uint64_t cr,hr;
            if(mode==0) {
                cr=c_buffer_packet_id_read(ca,cap,cs,32,flags&1);
                hr=ovpn_hia_packet_id_read(ha,cap,hs,32,flags&1);
            } else if(mode==1) {
                cr=c_buffer_packet_id_write(ca,cap,cs,32,42,flags&1,flags>>1);
                hr=ovpn_hia_packet_id_write(ha,cap,hs,32,42,flags&1,flags>>1);
            } else if(mode==2) {
                cr=c_buffer_packet_id_read_epoch(ca,cap,cs,32);
                hr=ovpn_hia_packet_id_read_epoch(ha,cap,hs,32);
            } else {
                cr=c_buffer_packet_id_write_epoch(ca,cap,cs,32,42,65535);
                hr=ovpn_hia_packet_id_write_epoch(ha,cap,hs,32,42,65535);
            }
            if (cr!=hr || memcmp(cs,hs,32) || memcmp(ca,ha,(size_t)cap)) {
                fprintf(stderr,"guard mismatch cap=%d off=%d len=%d mode=%d flags=%d\n",cap,off,len,mode,flags);
                return 1;
            }
            ++checked;
        }
        /* Ownership is released by the caller only, after every native call. */
        munmap(wa,page*2); munmap(wb,page*2); munmap(sa,page*2); munmap(sb,page*2);
    }
    printf("{\"kind\":\"guard_pages\",\"cases\":%" PRIu64 ",\"failures\":0}\n",checked);
    return 0;
}
