/* SPDX-License-Identifier: GPL-2.0-only
 * OpenVPN 2.7.8 codec workload: dc1f569087135894ac2703aeabd7a960ee9452d4.
 * Same bytes, state, reset, sink and batch size as packet_differential.c.
 * Only namespaces and a predeclared balanced six-arm schedule are new.
 */
#include "config.h"
#include "syshead.h"
#include "packet_id.h"
#include <inttypes.h>
#include <time.h>
time_t now, now_usec;
static volatile uint64_t sink;
#define DECLARE_APP(prefix) \
extern bool prefix##_packet_id_read(struct packet_id_net *, struct buffer *, bool); \
extern bool prefix##_packet_id_write(struct packet_id_send *, struct buffer *, bool, bool); \
extern uint16_t prefix##_packet_id_read_epoch(struct packet_id_net *, struct buffer *); \
extern bool prefix##_packet_id_write_epoch(struct packet_id_send *, uint16_t, struct buffer *)
DECLARE_APP(hia_old); DECLARE_APP(hia_new);
#define DECLARE_RAW(prefix) \
extern uint64_t prefix##_packet_id_read(const uint8_t *, uint64_t, uint8_t *, uint64_t, uint32_t); \
extern uint64_t prefix##_packet_id_write(uint8_t *, uint64_t, uint8_t *, uint64_t, int64_t, uint32_t, uint32_t); \
extern uint64_t prefix##_packet_id_read_epoch(const uint8_t *, uint64_t, uint8_t *, uint64_t); \
extern uint64_t prefix##_packet_id_write_epoch(uint8_t *, uint64_t, uint8_t *, uint64_t, int64_t, uint16_t)
DECLARE_RAW(c_buffer); DECLARE_RAW(ovpn_hia_old); DECLARE_RAW(ovpn_hia_new);
static uint64_t nanos(void)
{
    struct timespec t;
    if(clock_gettime(CLOCK_MONOTONIC,&t)) {perror("clock_gettime");exit(3);}
    return (uint64_t)t.tv_sec*UINT64_C(1000000000)+(uint64_t)t.tv_nsec;
}
/* noinline affects only the batch driver, identically for every arm. The actual
 * kernel objects have their original/compiler-defined optimization attributes.
 * Kernel calls inside each loop are direct, without per-call function pointers. */
#define APP_BENCH(NAME,READ,WRITE,READ_EPOCH,WRITE_EPOCH) \
__attribute__((noinline)) static uint64_t NAME(int mode,unsigned rounds) \
{ \
    uint8_t bytes[128]={0}; \
    struct buffer b={.capacity=128,.offset=16,.len=16,.data=bytes}; \
    struct packet_id_send p={.id=0,.time=42}; \
    struct packet_id_net r={.id=0,.time=0}; \
    now=43; \
    const uint64_t start=nanos(); \
    for(unsigned i=0;i<rounds;++i) { \
        b.offset=16;b.len=16; \
        if(mode==0) {sink+=WRITE(&p,&b,true,false);sink^=bytes[35];} \
        else if(mode==1) {sink+=READ(&r,&b,true);sink^=r.id+bytes[16];} \
        else if(mode==2) {sink+=WRITE_EPOCH(&p,33,&b);sink^=bytes[39];} \
        else {sink+=READ_EPOCH(&r,&b);sink^=r.id+bytes[16];} \
    } \
    return nanos()-start; \
}
APP_BENCH(bench_original,packet_id_read,packet_id_write,packet_id_read_epoch,packet_id_write_epoch)
APP_BENCH(bench_old_adapter,hia_old_packet_id_read,hia_old_packet_id_write,hia_old_packet_id_read_epoch,hia_old_packet_id_write_epoch)
APP_BENCH(bench_new_adapter,hia_new_packet_id_read,hia_new_packet_id_write,hia_new_packet_id_read_epoch,hia_new_packet_id_write_epoch)
#define RAW_BENCH(NAME,PREFIX) \
__attribute__((noinline)) static uint64_t NAME(int mode,unsigned rounds) \
{ \
    uint8_t bytes[128]={0}; \
    uint64_t state[4]={0,(mode==0 || mode==2)?42:0,16,16}; \
    now=43; \
    const uint64_t start=nanos(); \
    for(unsigned i=0;i<rounds;++i) { \
        state[2]=16;state[3]=16; \
        if(mode==0) {sink+=PREFIX##_packet_id_write(bytes,128,(uint8_t *)state,32,43,1,0);sink^=bytes[35];} \
        else if(mode==1) {sink+=PREFIX##_packet_id_read(bytes,128,(uint8_t *)state,32,1);sink^=state[0]+bytes[16];} \
        else if(mode==2) {sink+=PREFIX##_packet_id_write_epoch(bytes,128,(uint8_t *)state,32,43,33);sink^=bytes[39];} \
        else {sink+=PREFIX##_packet_id_read_epoch(bytes,128,(uint8_t *)state,32);sink^=state[0]+bytes[16];} \
    } \
    return nanos()-start; \
}
RAW_BENCH(bench_c_buffer,c_buffer)
RAW_BENCH(bench_old_raw,ovpn_hia_old)
RAW_BENCH(bench_new_raw,ovpn_hia_new)
int main(void)
{
    uint64_t (*const arms[6])(int,unsigned)={bench_original,bench_c_buffer,bench_old_raw,bench_new_raw,bench_old_adapter,bench_new_adapter};
    static const int base[6]={0,1,5,2,4,3};
    const unsigned rounds=1000000,warmup=10000;
    puts("{\"kind\":\"plan\",\"arms\":[\"original_c\",\"c_buffer_control\",\"old_hia_raw\",\"new_hia_raw\",\"old_hia_adapter\",\"new_hia_adapter\"],\"calls\":1000000,\"warmup_calls\":10000,\"samples_per_mode_arm\":18,\"order\":\"Williams6 base 0,1,5,2,4,3; modulo6 rotation; repeat3\"}");
    for(int mode=0;mode<4;++mode) {
        for(int arm=0;arm<6;++arm) {sink=0;(void)arms[arm](mode,warmup);}
        for(int sample=0;sample<18;++sample) {
            uint64_t ns[6],sums[6];int order[6];
            for(int pos=0;pos<6;++pos) {
                int arm=(base[pos]+sample%6)%6;order[pos]=arm;sink=0;
                ns[arm]=arms[arm](mode,rounds);sums[arm]=sink;
            }
            bool same=true;for(int arm=1;arm<6;++arm) if(sums[arm]!=sums[0]) same=false;
            printf("{\"kind\":\"paired_benchmark\",\"mode\":%d,\"sample\":%d,\"calls\":%u,"
                   "\"order\":[%d,%d,%d,%d,%d,%d],\"ns\":[%" PRIu64 ",%" PRIu64 ",%" PRIu64 ",%" PRIu64 ",%" PRIu64 ",%" PRIu64 "],"
                   "\"sinks\":[%" PRIu64 ",%" PRIu64 ",%" PRIu64 ",%" PRIu64 ",%" PRIu64 ",%" PRIu64 ",%" PRIu64 "],\"equal_sinks\":%s}\n",
                   mode,sample,rounds,order[0],order[1],order[2],order[3],order[4],order[5],
                   ns[0],ns[1],ns[2],ns[3],ns[4],ns[5],sums[0],sums[1],sums[2],sums[3],sums[4],sums[5],same?"true":"false");
            if(!same) {fputs("arm observation mismatch; all results retained\n",stderr);return 1;}
        }
    }
    return 0;
}
