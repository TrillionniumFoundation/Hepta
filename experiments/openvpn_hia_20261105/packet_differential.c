/* SPDX-License-Identifier: GPL-2.0-only
 * Derived from OpenVPN 2.7.8 packet-ID semantics, upstream commit
 * dc1f569087135894ac2703aeabd7a960ee9452d4.
 */
/* Compare the unmodified upstream packet_id.c against genuine HIA LLVM.
 * The compiler/linker receives the same -O3 settings for both kernels.
 * Every admitted call compares return value, packet-ID fields, full buffer
 * metadata and every byte of guarded storage, including partial failures.
 */
#include "config.h"
#include "syshead.h"
#include "packet_id.h"
#include "openvpn_hia_adapter.h"
#include <stdio.h>
#include <inttypes.h>
#include <time.h>

/* The standalone codec oracle has no wall clock reads; both implementations
 * consume this identical frozen input for each call. */
time_t now;
time_t now_usec;


#define DECLARE_BUFFER_API(prefix) \
extern uint64_t prefix##_packet_id_read(const uint8_t *, uint64_t, uint8_t *, uint64_t, uint32_t); \
extern uint64_t prefix##_packet_id_write(uint8_t *, uint64_t, uint8_t *, uint64_t, int64_t, uint32_t, uint32_t); \
extern uint64_t prefix##_packet_id_read_epoch(const uint8_t *, uint64_t, uint8_t *, uint64_t); \
extern uint64_t prefix##_packet_id_write_epoch(uint8_t *, uint64_t, uint8_t *, uint64_t, int64_t, uint16_t)
DECLARE_BUFFER_API(ovpn_hia);
DECLARE_BUFFER_API(c_buffer);

static uint64_t rng_state = UINT64_C(0x20261105a83f29b1);
static uint64_t observations, failures, success_calls, partial_failures;
static volatile uint64_t sink;

static uint64_t next64(void)
{
    uint64_t x = rng_state;
    x ^= x << 13; x ^= x >> 7; x ^= x << 17;
    return rng_state = x;
}

static void compare_case(int mode, int cap, int off, int len, uint64_t id,
                         int64_t stamp, int64_t clock_value, int long_form,
                         int prepend, uint16_t epoch)
{
    uint8_t left[164], right[164], original[164];
    for (size_t i = 0; i < sizeof(left); ++i) { left[i] = (uint8_t)next64(); }
    memcpy(right, left, sizeof(left));
    memcpy(original, left, sizeof(left));
    /* +17 deliberately supplies unaligned byte ranges with both-side canaries. */
    struct buffer cbuf = {.capacity=cap, .offset=off, .len=len, .data=left+17};
    struct buffer hbuf = {.capacity=cap, .offset=off, .len=len, .data=right+17};
    struct packet_id_net cr = {.id=id, .time=(time_t)stamp}, hr = cr;
    struct packet_id_send cw = {.id=id, .time=(time_t)stamp}, hw = cw;
    now = (time_t)clock_value;
    uint32_t cresult, hresult;
    if (mode == 0) {
        cresult=packet_id_read(&cr,&cbuf,long_form);
        hresult=hia_packet_id_read(&hr,&hbuf,long_form);
    } else if (mode == 1) {
        cresult=packet_id_write(&cw,&cbuf,long_form,prepend);
        hresult=hia_packet_id_write(&hw,&hbuf,long_form,prepend);
    } else if (mode == 2) {
        cresult=packet_id_read_epoch(&cr,&cbuf);
        hresult=hia_packet_id_read_epoch(&hr,&hbuf);
    } else {
        cresult=packet_id_write_epoch(&cw,epoch,&cbuf);
        hresult=hia_packet_id_write_epoch(&hw,epoch,&hbuf);
    }
    uint8_t abi_left[164], abi_right[164];
    /* Repeat from the identical ORIGINAL storage and metadata for direct ABI. */
    memcpy(abi_left, original, sizeof(abi_left));
    memcpy(abi_right,abi_left,sizeof(abi_left));
    uint64_t cs[4]={id,(uint64_t)stamp,(uint64_t)off,(uint64_t)len}, hs[4];
    memcpy(hs,cs,sizeof(cs));
    uint64_t ca,ha;
    if (mode == 0) {
        ca=c_buffer_packet_id_read(abi_left+17,cap,(uint8_t *)cs,32,long_form);
        ha=ovpn_hia_packet_id_read(abi_right+17,cap,(uint8_t *)hs,32,long_form);
    } else if (mode == 1) {
        ca=c_buffer_packet_id_write(abi_left+17,cap,(uint8_t *)cs,32,clock_value,long_form,prepend);
        ha=ovpn_hia_packet_id_write(abi_right+17,cap,(uint8_t *)hs,32,clock_value,long_form,prepend);
    } else if (mode == 2) {
        ca=c_buffer_packet_id_read_epoch(abi_left+17,cap,(uint8_t *)cs,32);
        ha=ovpn_hia_packet_id_read_epoch(abi_right+17,cap,(uint8_t *)hs,32);
    } else {
        ca=c_buffer_packet_id_write_epoch(abi_left+17,cap,(uint8_t *)cs,32,clock_value,epoch);
        ha=ovpn_hia_packet_id_write_epoch(abi_right+17,cap,(uint8_t *)hs,32,clock_value,epoch);
    }
    if (ca!=ha || memcmp(cs,hs,sizeof(cs)) || memcmp(abi_left,abi_right,sizeof(abi_left))) {
        ++failures;
        if (failures <= 20) { fprintf(stderr,"DIRECT_ABI_DIFF mode=%d case=%" PRIu64 "\n",mode,observations); }
    }
    ++observations;
    success_calls += cresult != 0;
    partial_failures += cresult == 0 && (cbuf.offset != off || cbuf.len != len
        || cw.id != id || cw.time != stamp || cr.id != id || cr.time != stamp);
    if (cresult != hresult || cr.id != hr.id || cr.time != hr.time
        || cw.id != hw.id || cw.time != hw.time || cbuf.offset != hbuf.offset
        || cbuf.len != hbuf.len || cbuf.capacity != hbuf.capacity
        || cbuf.data != left+17 || hbuf.data != right+17
        || memcmp(left,right,sizeof(left))) {
        ++failures;
        if (failures <= 20) {
            fprintf(stderr,"DIFF mode=%d cap=%d off=%d len=%d id=%" PRIu64
                    " stamp=%" PRId64 " now=%" PRId64 " long=%d prepend=%d epoch=%u"
                    " result=%u/%u send_id=%" PRIu64 "/%" PRIu64
                    " send_time=%" PRId64 "/%" PRId64
                    " recv_id=%" PRIu64 "/%" PRIu64
                    " recv_time=%" PRId64 "/%" PRId64
                    " off=%d/%d len=%d/%d\n",
                    mode,cap,off,len,id,stamp,clock_value,long_form,prepend,epoch,
                    cresult,hresult,cw.id,hw.id,(int64_t)cw.time,(int64_t)hw.time,
                    cr.id,hr.id,(int64_t)cr.time,(int64_t)hr.time,cbuf.offset,hbuf.offset,cbuf.len,hbuf.len);
        }
    }
}

static uint64_t nanos(void)
{
    struct timespec t;
    if (clock_gettime(CLOCK_MONOTONIC, &t)) { perror("clock_gettime"); exit(3); }
    return (uint64_t)t.tv_sec*UINT64_C(1000000000)+(uint64_t)t.tv_nsec;
}

static uint64_t benchmark(int which, int mode, unsigned rounds)
{
    uint8_t bytes[128] = {0};
    struct buffer b = {.capacity=128,.offset=16,.len=16,.data=bytes};
    struct packet_id_send p = {.id=0,.time=42};
    struct packet_id_net r = {.id=0,.time=0};
    now=43;
    const uint64_t start=nanos();
    for (unsigned i=0;i<rounds;++i) {
        b.offset=16; b.len=16;
        if (mode == 0) {
            sink += which ? hia_packet_id_write(&p,&b,true,false) : packet_id_write(&p,&b,true,false);
            sink ^= bytes[35];
        } else if (mode == 1) {
            sink += which ? hia_packet_id_read(&r,&b,true) : packet_id_read(&r,&b,true);
            sink ^= r.id + bytes[16];
        } else if (mode == 2) {
            sink += which ? hia_packet_id_write_epoch(&p,33,&b) : packet_id_write_epoch(&p,33,&b);
            sink ^= bytes[39];
        } else {
            sink += which ? hia_packet_id_read_epoch(&r,&b) : packet_id_read_epoch(&r,&b);
            sink ^= r.id + bytes[16];
        }
    }
    return nanos()-start;
}


static uint64_t benchmark_buffer(int which, int mode, unsigned rounds)
{
    uint8_t bytes[128]={0};
    uint64_t state[4]={0,(mode==0 || mode==2) ? 42 : 0,16,16};
    now=43;
    const uint64_t start=nanos();
    for (unsigned i=0;i<rounds;++i) {
        state[2]=16; state[3]=16;
        if (mode==0) {
            sink += which ? ovpn_hia_packet_id_write(bytes,128,(uint8_t *)state,32,43,1,0)
                          : c_buffer_packet_id_write(bytes,128,(uint8_t *)state,32,43,1,0);
            sink ^= bytes[35];
        } else if (mode==1) {
            sink += which ? ovpn_hia_packet_id_read(bytes,128,(uint8_t *)state,32,1)
                          : c_buffer_packet_id_read(bytes,128,(uint8_t *)state,32,1);
            sink ^= state[0] + bytes[16];
        } else if (mode==2) {
            sink += which ? ovpn_hia_packet_id_write_epoch(bytes,128,(uint8_t *)state,32,43,33)
                          : c_buffer_packet_id_write_epoch(bytes,128,(uint8_t *)state,32,43,33);
            sink ^= bytes[39];
        } else {
            sink += which ? ovpn_hia_packet_id_read_epoch(bytes,128,(uint8_t *)state,32)
                          : c_buffer_packet_id_read_epoch(bytes,128,(uint8_t *)state,32);
            sink ^= state[0] + bytes[16];
        }
    }
    return nanos()-start;
}

int main(int argc, char **argv)
{
    const uint64_t ids[] = {0,1,255,UINT32_MAX-1,UINT32_MAX,(UINT64_C(1)<<32),
                            (UINT64_C(1)<<48)-2,(UINT64_C(1)<<48)-1,
                            (UINT64_C(1)<<48),UINT64_MAX};
    const int64_t times[] = {0,1,-1,42,INT32_MAX,UINT32_MAX,INT64_MIN,INT64_MAX};
    for (int cap=0;cap<=20;++cap) for (int off=0;off<=cap;++off)
      for (int len=0;len<=cap-off;++len) for (int mode=0;mode<4;++mode)
        for (int flags=0;flags<4;++flags)
          compare_case(mode,cap,off,len,ids[(cap+off+len)%10],
                       times[(cap+len)%8],times[(off+len+1)%8],flags&1,flags>>1,
                       (uint16_t)(cap*233+off));
    for (unsigned i=0;i<200000;++i) {
        int cap=(int)(next64()%129), off=(int)(next64()%(cap+1));
        int len=(int)(next64()%(cap-off+1));
        uint64_t id=(i%3) ? ids[next64()%10] : next64();
        int64_t stamp=(i%3) ? times[next64()%8] : (int64_t)next64();
        int64_t clock_value=(i%3) ? times[next64()%8] : (int64_t)next64();
        compare_case((int)(i%4),cap,off,len,id,stamp,clock_value,
                     (int)(next64()&1),(int)(next64()&1),(uint16_t)next64());
    }
    printf("{\"kind\":\"differential\",\"observations\":%" PRIu64
           ",\"comparisons\":%" PRIu64 ",\"failures\":%" PRIu64 ",\"success_calls\":%" PRIu64
           ",\"partial_failures\":%" PRIu64 "}\n",
           observations,observations*2,failures,success_calls,partial_failures);
    if (failures) { return 1; }
    if (argc>1 && !strcmp(argv[1],"--benchmark")) {
        /* Six predetermined orders; 18 samples use every order three times.
         * C buffer-control is observed separately, never inferred by subtracting
         * different harness timings. Original earlier observations are archived. */
        static const int orders[6][3]={{0,1,2},{0,2,1},{1,0,2},{1,2,0},{2,0,1},{2,1,0}};
        const unsigned rounds=1000000;
        for (int mode=0;mode<4;++mode) {
            (void)benchmark(0,mode,10000); (void)benchmark_buffer(1,mode,10000);
            (void)benchmark(1,mode,10000); (void)benchmark_buffer(0,mode,10000);
          for (int sample=0;sample<18;++sample) {
            uint64_t ns[3], c_buffer_ns;
            if (!(sample&1)) { c_buffer_ns=benchmark_buffer(0,mode,rounds); }
            for (int index=0;index<3;++index) {
                int arm=orders[sample%6][index];
                ns[arm]=arm==0 ? benchmark(0,mode,rounds)
                       : arm==1 ? benchmark_buffer(1,mode,rounds)
                       : benchmark(1,mode,rounds);
            }
            if (sample&1) { c_buffer_ns=benchmark_buffer(0,mode,rounds); }
            printf("{\"kind\":\"benchmark\",\"mode\":%d,\"sample\":%d,"
                   "\"order\":[%d,%d,%d],\"calls\":%u,\"c_ns\":%" PRIu64
                   ",\"hia_raw_ns\":%" PRIu64 ",\"hia_adapter_ns\":%" PRIu64
                   ",\"c_buffer_ns\":%" PRIu64 "}\n",mode,sample,
                   orders[sample%6][0],orders[sample%6][1],orders[sample%6][2],
                   rounds,ns[0],ns[1],ns[2],c_buffer_ns);
          }
        }
    }
    return 0;
}
