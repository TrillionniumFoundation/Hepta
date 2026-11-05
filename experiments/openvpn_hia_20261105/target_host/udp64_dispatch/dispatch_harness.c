/* GPL-2.0-only. Offline dispatch experiment; not an OpenVPN implementation. */
#include <assert.h>
#include <stdbool.h>
#include <stdio.h>
#include <string.h>

/* Exact values from OpenVPN's pinned src/openvpn/event.h. */
#define SOCKET_READ 1
#define SOCKET_WRITE 2
#define TUN_READ 4
#define TUN_WRITE 8
#define MANAGEMENT_READ 64
#define MANAGEMENT_WRITE 128
#define DCO_READ 1024
#define ENABLE_MANAGEMENT 1
#define ASSERT assert
#define IS_SIG(c) ((c)->signal)

struct link_socket { int unused; };
struct tuntap { int dco; };
struct context {
    struct { struct tuntap *tuntap; } c1;
    struct {
        unsigned int event_set_status;
        bool prefer_tun_read;
        bool to_link, to_tun;
    } c2;
    bool signal;
};
static int management_value;
static int *management = &management_value;
enum action { NONE, LINK_WRITE, TUN_WRITE_ACTION, LINK_READ, TUN_READ_ACTION, DCO };
static enum action selected;
static unsigned int calls, processed, managed;
static unsigned int link_reads, tun_reads, link_writes, tun_writes;
static void choose(enum action a) { selected = a; ++calls; }
static void management_io(int *m) { assert(m == management); ++managed; }
static void process_outgoing_link(struct context *c, struct link_socket *s) {
    (void)s; choose(LINK_WRITE); ++link_writes; c->c2.to_link = false;
}
static void process_outgoing_tun(struct context *c, struct link_socket *s) {
    (void)s; choose(TUN_WRITE_ACTION); ++tun_writes; c->c2.to_tun = false;
}
static void read_incoming_link(struct context *c, struct link_socket *s) {
    (void)c; (void)s; choose(LINK_READ); ++link_reads;
}
static void process_incoming_link(struct context *c, struct link_socket *s) {
    (void)s; ++processed; c->c2.to_tun = true;
}
static void read_incoming_tun(struct context *c) {
    (void)c; choose(TUN_READ_ACTION); ++tun_reads;
}
static void process_incoming_tun(struct context *c, struct link_socket *s) {
    (void)s; ++processed; c->c2.to_link = true;
}
static void dco_read_and_process(int *dco) { (void)dco; choose(DCO); }

#ifdef CANDIDATE
#include "candidate_process_io.c"
#else
#include "upstream_process_io.c"
#endif

static void reset_counters(void) {
    selected = NONE; calls = processed = managed = 0;
    link_reads = tun_reads = link_writes = tun_writes = 0;
}

static unsigned int exhaustive(void) {
    const unsigned int bits[] = {SOCKET_READ, SOCKET_WRITE, TUN_READ, TUN_WRITE,
                                 MANAGEMENT_READ, MANAGEMENT_WRITE, DCO_READ};
    unsigned int checked = 0;
    struct tuntap tt = {0};
    struct link_socket sock = {0};
    for (unsigned int mask = 0; mask < 128; ++mask) {
        unsigned int status = 0;
        for (unsigned int b = 0; b < 7; ++b) if (mask & (1u << b)) status |= bits[b];
        for (unsigned int turn = 0; turn < 2; ++turn) {
            for (unsigned int sig = 0; sig < 2; ++sig) {
                struct context c = {.c1 = {&tt}, .c2 = {status, turn != 0, false, false}, .signal = sig != 0};
                enum action want = NONE;
                if (status & SOCKET_WRITE) want = LINK_WRITE;
                else if (status & TUN_WRITE) want = TUN_WRITE_ACTION;
#ifdef CANDIDATE
                else if ((status & TUN_READ) && (!(status & SOCKET_READ) || turn)) want = TUN_READ_ACTION;
#endif
                else if (status & SOCKET_READ) want = LINK_READ;
                else if (status & TUN_READ) want = TUN_READ_ACTION;
                else if ((status & DCO_READ) && !sig) want = DCO;
                reset_counters();
                process_io(&c, &sock);
                assert(selected == want);
                assert(calls == (unsigned int)(want != NONE));
                assert(managed == (unsigned int)((status & (MANAGEMENT_READ | MANAGEMENT_WRITE)) != 0));
                assert(processed == (unsigned int)(!sig && (want == LINK_READ || want == TUN_READ_ACTION)));
                assert(c.c2.event_set_status == status);
#ifdef CANDIDATE
                bool expected_turn = want == LINK_READ ? true : want == TUN_READ_ACTION ? false : turn != 0;
                assert(c.c2.prefer_tun_read == expected_turn);
#else
                assert(c.c2.prefer_tun_read == (turn != 0));
#endif
                ++checked;
            }
        }
    }
    return checked;
}

static void isolated_contexts(void) {
    struct tuntap tt = {0}; struct link_socket sock = {0};
    struct context a = {.c1 = {&tt}, .c2 = {SOCKET_READ | TUN_READ, false, false, false}};
    struct context b = a;
    reset_counters();
    process_io(&a, &sock); assert(selected == LINK_READ);
    process_io(&b, &sock); assert(selected == LINK_READ);
    process_io(&a, &sock);
#ifdef CANDIDATE
    assert(selected == TUN_READ_ACTION);
#else
    assert(selected == LINK_READ);
#endif
    /* A newly zeroed context begins with the original socket preference. */
    a = (struct context){.c1 = {&tt}, .c2 = {SOCKET_READ | TUN_READ, false, false, false}};
    process_io(&a, &sock); assert(selected == LINK_READ);
}

int main(int argc, char **argv) {
    unsigned int checked = exhaustive();
    isolated_contexts();
    reset_counters();
    struct tuntap tt = {0}; struct link_socket sock = {0};
    struct context c = {.c1 = {&tt}};
    /* Model both inputs continuously readable. Pending output suppresses
     * its corresponding input, matching p2p_iow_flags/multi_io_process_flags.
     * All output is writable. No OS, socket, crypto or actual buffer exists. */
    for (unsigned int i = 0; i < 10000; ++i) {
        c.c2.event_set_status = (c.c2.to_link ? SOCKET_WRITE : TUN_READ)
                               | (c.c2.to_tun ? TUN_WRITE : SOCKET_READ);
        process_io(&c, &sock);
    }
    bool fair = link_reads == 2500 && tun_reads == 2500
                && link_writes == 2500 && tun_writes == 2500;
    printf("{\"dispatch_controls\":%u,\"iterations\":10000,\"socket_reads\":%u,"
           "\"tun_reads\":%u,\"socket_writes\":%u,\"tun_writes\":%u,\"fair_model\":%s}\n",
           checked, link_reads, tun_reads, link_writes, tun_writes, fair ? "true" : "false");
    if (argc == 2 && strcmp(argv[1], "--require-fair") == 0 && !fair) return 23;
    return 0;
}
