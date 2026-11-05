/* SPDX-License-Identifier: GPL-2.0-only
 * OpenVPN 2.7.8 semantics: dc1f569087135894ac2703aeabd7a960ee9452d4.
 * Contract-level rejection/effect checks, plus caller-owned release checks.
 */
#include "config.h"
#include "syshead.h"
#include "openvpn_hia_adapter.h"
#include <stddef.h>
#include <stdio.h>
#include <inttypes.h>
time_t now, now_usec;
#define DECLARE(prefix) \
extern uint64_t prefix##_packet_id_read(const uint8_t *, uint64_t, uint8_t *, uint64_t, uint32_t); \
extern uint64_t prefix##_packet_id_write(uint8_t *, uint64_t, uint8_t *, uint64_t, int64_t, uint32_t, uint32_t); \
extern uint64_t prefix##_packet_id_read_epoch(const uint8_t *, uint64_t, uint8_t *, uint64_t); \
extern uint64_t prefix##_packet_id_write_epoch(uint8_t *, uint64_t, uint8_t *, uint64_t, int64_t, uint16_t)
DECLARE(ovpn_hia); DECLARE(c_buffer);
static volatile unsigned frees;
extern void __real_free(void *);
void __wrap_free(void *p) { ++frees; __real_free(p); }
static uint64_t raw(int which, int mode, uint8_t *w, uint64_t n, uint8_t *s,
                    uint64_t sn, uint32_t l, uint32_t prepend)
{
    if (mode==0) return which ? ovpn_hia_packet_id_read(w,n,s,sn,l) : c_buffer_packet_id_read(w,n,s,sn,l);
    if (mode==1) return which ? ovpn_hia_packet_id_write(w,n,s,sn,43,l,prepend) : c_buffer_packet_id_write(w,n,s,sn,43,l,prepend);
    if (mode==2) return which ? ovpn_hia_packet_id_read_epoch(w,n,s,sn) : c_buffer_packet_id_read_epoch(w,n,s,sn);
    return which ? ovpn_hia_packet_id_write_epoch(w,n,s,sn,43,33) : c_buffer_packet_id_write_epoch(w,n,s,sn,43,33);
}
static unsigned raw_checks(void)
{
    unsigned checked=0;
    for (int mode=0;mode<4;++mode) for (int test=0;test<22;++test) {
        if ((test==14 && mode>=2) || (test==15 && mode!=1)) continue;
        uint8_t memory[2][512], original[512];
        uint64_t result[2], expected=UINT64_C(0xfffe0001);
        bool unchanged=true;
        for (int which=0;which<2;++which) {
            memset(memory[which],0xa7,sizeof(memory[which]));
            uint8_t *w=memory[which]+64,*s=memory[which]+256;
            uint64_t n=64,sn=32,init[4]={17,42,0,16};
            uint32_t l=1,prepend=0;
            if(test==0) {n=65537; expected=UINT64_C(1)<<32;}
            if(test==1) {w=NULL; expected=UINT64_C(2)<<32;}
            if(test==2) {w=(uint8_t *)(UINTPTR_MAX-3); n=8; expected=UINT64_C(3)<<32;}
            if(test==3) {sn=65537; expected=UINT64_C(1)<<32;}
            if(test==4) {s=NULL; expected=UINT64_C(2)<<32;}
            if(test==5) {s=(uint8_t *)(UINTPTR_MAX-3); expected=UINT64_C(3)<<32;}
            if(test==6) {s=w; expected=UINT64_C(4)<<32;}
            if(test==7) {s=w+56; expected=UINT64_C(4)<<32;}
            if(test==8) {w=s+24; expected=UINT64_C(4)<<32;}
            if(test==9) sn=0;
            if(test==10) sn=31;
            if(test==11) sn=33;
            if(test==12) init[2]=65;
            if(test==13) {init[2]=1;init[3]=64;}
            if(test==14) l=2;
            if(test==15) prepend=2;
            if(test==16) init[2]=UINT64_MAX;
            if(test==17) init[3]=UINT64_MAX;
            if(test==18) {w=NULL;n=0;init[2]=init[3]=0;unchanged=false;}
            if(test==19) {n=0;w=s;init[2]=init[3]=0;unchanged=false;}
            if(test==20) {n=32;s=w+32;unchanged=false;}
            if(test==21) {n=32;w=s+32;unchanged=false;}
            /* Only the numeric-wrap/null probes point outside live storage;
             * they must reject before dereference. All aliases are live. */
            if(s && test!=5) memcpy(s,init,sizeof(init));
            if(which==0) memcpy(original,memory[which],sizeof(original));
            result[which]=raw(which,mode,w,n,s,sn,l,prepend);
        }
        if(result[0]!=result[1] || memcmp(memory[0],memory[1],512)
           || (unchanged && (result[0]!=expected || memcmp(memory[0],original,512)))) {
            fprintf(stderr,"admission mode=%d test=%d result=%" PRIu64 "/%" PRIu64 " expected=%" PRIu64 "\n",mode,test,result[0],result[1],expected);
            exit(1);
        }
        ++checked;
    }
    return checked;
}
static uint64_t adapted(int mode, void *p, struct buffer *b)
{
    if(mode==0) return hia_packet_id_read(p,b,true);
    if(mode==1) return hia_packet_id_write(p,b,true,false);
    if(mode==2) return hia_packet_id_read_epoch(p,b);
    return hia_packet_id_write_epoch(p,33,b);
}
static unsigned adapter_checks(void)
{
    unsigned checked=0;
    for(int mode=0;mode<4;++mode) for(int test=0;test<20;++test) {
        union { max_align_t align; uint8_t bytes[256]; } storage;
        memset(&storage,0xa7,sizeof(storage));
        struct packet_id_send *p=(void *)(storage.bytes+64);
        struct buffer *b=(void *)(storage.bytes+128);
        p->id=17;p->time=42;
        *b=(struct buffer){.capacity=32,.offset=0,.len=16,.data=storage.bytes+16};
        if(test==0) b->data=(void *)p;
        if(test==1) {b->data=storage.bytes+56;b->capacity=16;}
        if(test==2) b->data=(void *)b;
        if(test==3) {b->data=storage.bytes+144;b->capacity=16;}
        if(test==4) p=(void *)b;
        if(test==5) p=(void *)(storage.bytes+136);
        if(test==6) b->data=NULL;
        if(test==7) b->capacity=65537;
        if(test==8) b->data=(uint8_t *)(UINTPTR_MAX-3);
        if(test==9) p=(void *)(UINTPTR_MAX-7);
        if(test==10) b=(void *)(UINTPTR_MAX-7);
        if(test==11) p=NULL;
        if(test==12) b=NULL;
        if(test==13) p=(void *)(storage.bytes+65);
        if(test==14) b=(void *)(storage.bytes+129);
        if(test==15) b->capacity=-1;
        if(test==16) b->offset=-1;
        if(test==17) b->len=-1;
        if(test==18) b->offset=33;
        if(test==19) {b->offset=31;b->len=2;}
        uint8_t before[sizeof(storage)]; memcpy(before,&storage,sizeof(storage));
        now=43;
        if(adapted(mode,p,b)!=0 || memcmp(before,&storage,sizeof(storage))) {
            fprintf(stderr,"adapter rejection changed state mode=%d test=%d\n",mode,test);exit(1);
        }
        ++checked;
    }
    return checked;
}
static void ownership_check(void)
{
    uint8_t *w=malloc(128), *s=malloc(32);
    if(!w || !s) {fputs("malloc failed\n",stderr);exit(2);}
    memset(w,0,128);
    unsigned before=frees;
    for(int mode=0;mode<4;++mode) {
        uint64_t initial[4]={17,42,0,16};memcpy(s,initial,32);
        (void)raw(1,mode,w,128,s,32,1,0);
    }
    if(frees!=before) {fputs("HIA freed caller storage\n",stderr);exit(1);}
    free(w);free(s);
    if(frees!=before+2) {fputs("caller release count wrong\n",stderr);exit(1);}
}
static unsigned receiver_check(void)
{
    uint8_t wire[8]={0,0,0,1,0,0,0,2};
    unsigned checks=0;
    /* The original C API permits write-only uninitialized receiver objects. */
    struct packet_id_net receiver;
    struct buffer b={.capacity=8,.offset=0,.len=8,.data=wire};
    if(!hia_packet_id_read(&receiver,&b,true) || receiver.id!=1 || receiver.time!=2) exit(1);
    ++checks;
    struct packet_id_net epoch_receiver;
    b.offset=0;b.len=8;
    if(hia_packet_id_read_epoch(&epoch_receiver,&b)!=0 || epoch_receiver.id!=UINT64_C(0x100000002)) exit(1);
    ++checks; /* Never read the uninitialized epoch_receiver.time. */
    for(int len=0;len<=8;++len) {
        receiver.id=UINT64_C(0xd1d2d3d4d5d6d7d8);receiver.time=(time_t)INT64_MIN;
        b.offset=0;b.len=len;
        uint16_t got=hia_packet_id_read_epoch(&receiver,&b);
        if(got!=0 || receiver.time!=(time_t)INT64_MIN
           || receiver.id!=(len<8 ? UINT64_C(0xd1d2d3d4d5d6d7d8) : UINT64_C(0x100000002))
           || b.offset!=(len<8 ? 0 : 8) || b.len!=(len<8 ? len : 0)) exit(1);
        ++checks;
    }
    return checks;
}
int main(void)
{
    unsigned raw=raw_checks(), adapter=adapter_checks(), receivers=receiver_check();
    ownership_check();
    printf("{\"kind\":\"admission\",\"raw_cases\":%u,\"adapter_cases\":%u,\"receiver_cases\":%u,\"hia_frees\":0,\"caller_frees\":2,\"failures\":0}\n",raw,adapter,receivers);
    return 0;
}
