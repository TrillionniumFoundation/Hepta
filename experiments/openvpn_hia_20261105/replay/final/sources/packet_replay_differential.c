/* SPDX-License-Identifier: GPL-2.0-only
 * Replay integration oracle for the OpenVPN 2.7.8 HIA packet-ID experiment.
 *
 * Two independent receive states use UNMODIFIED upstream packet_id_init,
 * packet_id_test, packet_id_add, packet_id_reap and packet_id_free. Only the
 * decoder differs (upstream C versus the experimental HIA object+adapter).
 * This does NOT implement replay protection in HIA, authenticate packets,
 * exercise TLS, or execute crypto epoch key selection/rekey management.
 *
 * The only standalone support shims are debug logging/assert/OOM reporting.
 * Actual upstream buffer.c and otime.c provide their original support code.
 */
#include "config.h"
#include "syshead.h"
#include "packet_id.h"
#include "openvpn_hia_adapter.h"
#include <inttypes.h>
#include <stdarg.h>
#include <stdio.h>

/* The configured application owns these diagnostics in its error module.
 * Standalone tests keep debug disabled, write real messages if requested,
 * and abort on every assertion/OOM rather than fabricating success. */
msglvl_t x_debug_level = 0;
bool dont_mute(msglvl_t flags) { (void)flags; return true; }
void x_msg(msglvl_t flags, const char *format, ...)
{
    va_list args;
    va_start(args, format); vfprintf(stderr, format, args); va_end(args);
    fputc('\n', stderr);
    if (flags & M_FATAL) { exit(90); }
}
void assert_failed(const char *file, int line, const char *condition)
{
    fprintf(stderr, "upstream assertion %s:%d %s\n", file, line, condition ? condition : "");
    abort();
}
void out_of_memory(void) { fputs("upstream out of memory\n", stderr); abort(); }

static uint64_t observations, comparisons, failures, decode_failures;
static uint64_t accepted, rejected, reject_stat_changes, reaps, list_bytes_compared;
static uint64_t rng = UINT64_C(0x52504c595f484941);
static uint64_t random64(void)
{
    uint64_t x=rng;
    x ^= x<<13; x ^= x>>7; x ^= x<<17;
    return rng=x;
}

static bool same_state(const struct packet_id *a, const struct packet_id *b,
                       unsigned format, int window, const char *action, const char *stage)
{
    const struct packet_id_rec *x=&a->rec, *y=&b->rec;
    bool ok = a->send.id==b->send.id && a->send.time==b->send.time
        && x->last_reap==y->last_reap && x->time==y->time && x->id==y->id
        && x->seq_backtrack==y->seq_backtrack && x->time_backtrack==y->time_backtrack
        && x->max_backtrack_stat==y->max_backtrack_stat && x->initialized==y->initialized
        && x->unit==y->unit && (x->name==y->name || (x->name && y->name && !strcmp(x->name,y->name)))
        && ((x->seq_list==NULL)==(y->seq_list==NULL));
    if (x->seq_list && y->seq_list) {
        const struct seq_list *u=x->seq_list, *v=y->seq_list;
        ok = ok && u->x_head==v->x_head && u->x_size==v->x_size
             && u->x_cap==v->x_cap && u->x_sizeof==v->x_sizeof;
        if (u->x_cap==v->x_cap && u->x_cap>=0 && u->x_cap<=MAX_SEQ_BACKTRACK) {
            size_t n=(size_t)u->x_cap*sizeof(u->x_list[0]);
            /* Includes unused slots, beyond the logical circular-list size. */
            ok = ok && memcmp(u->x_list,v->x_list,n)==0;
            list_bytes_compared += n;
        } else { ok=false; }
    }
    ++comparisons;
    if (!ok) {
        ++failures;
        if (failures<=16) { fprintf(stderr,"REPLAY_STATE_DIFF format=%u window=%d action=%s stage=%s\n",format,window,action,stage); }
    }
    return ok;
}

static void put_be(uint8_t *p, uint64_t value, unsigned bytes)
{
    for (unsigned i=0;i<bytes;++i) { p[i]=(uint8_t)(value >> (8*(bytes-1-i))); }
}

static void one(struct packet_id *c, struct packet_id *h, unsigned format, int window,
                const char *action, uint64_t id, uint32_t stamp, time_t local_now,
                unsigned wire_length, uint16_t epoch, int expected, bool trace)
{
    uint8_t cb[64], hb[64];
    for (size_t i=0;i<sizeof(cb);++i) { cb[i]=(uint8_t)random64(); }
    /* Network bytes are independent, explicit BE fixtures, not codec output. */
    if (format==2) { put_be(cb+12, ((uint64_t)epoch<<48)|(id&PACKET_ID_MASK), 8); }
    else { put_be(cb+12,id,4); put_be(cb+16,stamp,4); }
    memcpy(hb,cb,sizeof(cb));
    struct buffer cbuf={.capacity=48,.offset=7,.len=(int)wire_length,.data=cb+5};
    struct buffer hbuf={.capacity=48,.offset=7,.len=(int)wire_length,.data=hb+5};
    struct packet_id_net cp={.id=UINT64_C(0xfedcba9876543210),.time=0}, hp=cp;
    now=local_now;
    unsigned cr,hr;
    if (format==2) { cr=packet_id_read_epoch(&cp,&cbuf); hr=hia_packet_id_read_epoch(&hp,&hbuf); }
    else { cr=packet_id_read(&cp,&cbuf,format==1); hr=hia_packet_id_read(&hp,&hbuf,format==1); }
    bool decoded=cr!=0;
    bool equal=cr==hr && cp.id==hp.id && cp.time==hp.time
        && cbuf.capacity==hbuf.capacity && cbuf.offset==hbuf.offset && cbuf.len==hbuf.len
        && cbuf.data==cb+5 && hbuf.data==hb+5 && !memcmp(cb,hb,sizeof(cb));
    ++observations;
    if (!equal) {
        ++failures;
        if (failures<=16) { fprintf(stderr,"REPLAY_DECODE_DIFF format=%u action=%s\n",format,action); }
    }
    same_state(c,h,format,window,action,"after-decode");
    bool ct=false,ht=false;
    if (decoded && hr) {
        time_t previous_reap=c->rec.last_reap;
        packet_id_reap_test(&c->rec); packet_id_reap_test(&h->rec);
        reaps += c->rec.last_reap!=previous_reap;
        same_state(c,h,format,window,action,"after-reap");
        uint64_t old_stat=c->rec.max_backtrack_stat;
        ct=packet_id_test(&c->rec,&cp); ht=packet_id_test(&h->rec,&hp);
        reject_stat_changes += !ct && c->rec.max_backtrack_stat!=old_stat;
        /* Rejections can mutate max_backtrack_stat: compare BEFORE branching. */
        same_state(c,h,format,window,action,"after-test-including-rejection");
        if (ct!=ht) { ++failures; }
        if (ct) { packet_id_add(&c->rec,&cp); ++accepted; } else { ++rejected; }
        if (ht) { packet_id_add(&h->rec,&hp); }
        same_state(c,h,format,window,action,"after-add-or-reject");
    } else { ++decode_failures; }
    if (expected>=0 && (int)(decoded && ct)!=expected) {
        ++failures;
        fprintf(stderr,"REPLAY_EXPECTATION format=%u action=%s expected=%d actual=%d\n",
                format,action,expected,decoded&&ct);
    }
    if (trace) {
        printf("{\"kind\":\"replay_case\",\"format\":%u,\"window\":%d,\"action\":\"%s\","
               "\"decoded\":%s,\"accepted\":%s,\"id\":%" PRIu64 ",\"time\":%" PRId64
               ",\"last_reap\":%" PRId64 ",\"max_backtrack_stat\":%" PRIu64 "}\n",
               format,window,action,decoded?"true":"false",ct?"true":"false",c->rec.id,
               (int64_t)c->rec.time,(int64_t)c->rec.last_reap,c->rec.max_backtrack_stat);
    }
}

struct scenario { const char *name; uint64_t id; uint32_t stamp; time_t clock; int expected; };
static const struct scenario cases[] = {
    {"first",1,100,1000,1}, {"gap",3,100,1001,1},
    {"within-window",2,100,1002,1}, {"duplicate",2,100,1003,0},
    {"zero-id",0,100,1004,0}, {"advance",8,100,1005,1},
    {"out-of-order",4,100,1006,1}, {"expired-unseen-gap",5,100,1012,0},
    {"large-jump",30,100,1013,1}, {"outside-window",1,100,1014,0},
    {"remote-time-backtrack",1,99,1015,0}, {"new-timestamp-series",1,101,1016,1},
    {"after-new-series",2,101,1017,1}, {"local-clock-backtrack",3,101,900,1},
    {"old-timestamp-series",30,100,901,0}, {"clock-catches-up",4,101,1025,1},
    {"duplicate-after-clock",3,101,1026,0}, {"maximum-u32-id",UINT32_MAX,102,1030,1},
    {"before-maximum-u32-id",UINT32_MAX-1,102,1031,1}, {"duplicate-maximum-id",UINT32_MAX,102,1032,0}
};

static void run_stream(unsigned format, int window, int time_window)
{
    struct packet_id c,h;
    packet_id_init(&c,window,time_window,"replay-oracle",7);
    packet_id_init(&h,window,time_window,"replay-oracle",7);
    same_state(&c,&h,format,window,"init","init");
    unsigned full=format?8:4;
    for (size_t i=0;i<sizeof(cases)/sizeof(cases[0]);++i) {
        const struct scenario *s=&cases[i];
        int expected=(format==1 && window==8 && time_window==5)?s->expected:-1;
        one(&c,&h,format,window,s->name,s->id,s->stamp,s->clock,full,42,expected,
            format==1 && window==8 && time_window==5);
    }
    for (unsigned len=0;len<full;++len) {
        one(&c,&h,format,window,"truncated",29,102,1033,len,42,0,false);
    }
    if (format==2) {
        one(&c,&h,format,window,"invalid-zero-crypto-epoch",1,0,1034,8,0,0,true);
        one(&c,&h,format,window,"maximum-u48-id",PACKET_ID_MASK,0,1035,8,42,-1,true);
        one(&c,&h,format,window,"duplicate-u48-id",PACKET_ID_MASK,0,1036,8,42,0,true);
    }
    unsigned random_cases=window==MAX_SEQ_BACKTRACK?64:5000;
    for (unsigned i=0;i<random_cases;++i) {
        uint64_t r=random64(), id;
        switch(i%6) {
        case 0: id=c.rec.id+(r%5)+1; break;
        case 1: id=c.rec.id; break;
        case 2: id=c.rec.id>(r%80)?c.rec.id-(r%80):1; break;
        case 3: id=0; break;
        case 4: id=r%100000; break;
        default: id=1; break;
        }
        uint32_t stamp=100+(i/200);
        if (i%7==0 && stamp>0) { --stamp; }
        time_t clock=1100+(i/4);
        if (i%97==0) { clock-=200; }
        unsigned len=(i%31==0)?(unsigned)(r%full):full;
        one(&c,&h,format,window,"deterministic-random",id,stamp,clock,len,42,-1,false);
    }
    /* Real final reap, including the TCP/no-window no-list path. */
    now=4000;
    packet_id_reap(&c.rec); packet_id_reap(&h.rec);
    same_state(&c,&h,format,window,"final-reap","explicit-reap");
    packet_id_free(&c); packet_id_free(&h);
    same_state(&c,&h,format,window,"free","all-fields-cleared");
}

int main(void)
{
    const int windows[]={0,1,8,64,MAX_SEQ_BACKTRACK};
    for (unsigned format=0;format<3;++format) {
        for (size_t i=0;i<sizeof(windows)/sizeof(windows[0]);++i) {
            run_stream(format,windows[i],windows[i]?5:0);
        }
    }
    /* Expiry-disabled and maximum configured expiry-bound controls. */
    run_stream(1,8,0); run_stream(1,8,MAX_TIME_BACKTRACK);
    if (!reject_stat_changes || !decode_failures || !accepted || !rejected || !reaps) { ++failures; }
    printf("{\"kind\":\"replay_summary\",\"observations\":%" PRIu64 ",\"state_comparisons\":%" PRIu64
           ",\"accepted\":%" PRIu64 ",\"rejected\":%" PRIu64 ",\"decode_failures\":%" PRIu64
           ",\"rejected_calls_changing_max_backtrack_stat\":%" PRIu64 ",\"reaps\":%" PRIu64
           ",\"ring_bytes_compared\":%" PRIu64 ",\"failures\":%" PRIu64
           ",\"replay_implementation\":\"unmodified OpenVPN C on both sides\","
           "\"hia_replay_implementation\":false,\"authentication_tested\":false,"
           "\"crypto_epoch_key_management_tested\":false}\n",
           observations,comparisons,accepted,rejected,decode_failures,reject_stat_changes,reaps,
           list_bytes_compared,failures);
    return failures?1:0;
}
