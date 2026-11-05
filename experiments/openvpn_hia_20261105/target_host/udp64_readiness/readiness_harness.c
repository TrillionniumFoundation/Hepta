/* GPL-2.0-only. Controlled local I/O; not an OpenVPN application or tunnel. */
#include "upstream/event.c"
#include "upstream/iow_flags.h"

#define TARGET_LINUX 1
#define ENABLE_MANAGEMENT 1
#define MODE_SERVER 1
#include "upstream/init_constant.h"
#define TO_LINK_FRAG(c) false
#define IS_SIG(c) ((c)->sig->signal_received != 0)

enum { LINK = 0, TUN = 1, PACKET_SIZE = 64, PREFILL = 64, PREFIX = 96 };
enum action { NO_ACTION, READ_LINK, WRITE_TUN, READ_TUN, WRITE_LINK };
struct buffer { int len; unsigned char *data; };
struct link_socket { int fd; struct event_arg ev_arg; unsigned int rwflags_debug; };
struct tuntap { int fd, dco; unsigned int rwflags_debug; };
struct signal_info { int signal_received; };
struct context {
    struct { int mode, shaper; } options;
    struct { struct tuntap *tuntap; } c1;
    struct {
        struct buffer buf, to_tun, to_link;
        struct timeval timeval;
        struct event_set *event_set;
        int event_set_max, shaper;
        bool event_set_owned, prefer_tun_read;
        unsigned int event_set_status;
        struct link_socket **link_sockets;
    } c2;
    struct signal_info *sig;
    struct signal_info owned_signal;
    struct tuntap tt;
    struct link_socket sock;
    struct link_socket *sock_array[1];
    int peer[2];
    unsigned int sent[2], read[2], delivered[2], writes[2];
    unsigned char storage[2][PACKET_SIZE];
    enum action action;
};

/* UDP/userspace adapters below the preserved event-registration functions. */
static bool stream_buf_read_setup(struct link_socket *s) { (void)s; return true; }
static int socket_event_handle(struct link_socket *s) { return s->fd; }
static bool tuntap_defined(struct tuntap *tt) { return tt && tt->fd >= 0; }
static bool tuntap_is_dco_win(struct tuntap *tt) { (void)tt; return false; }
static int tun_event_handle(struct tuntap *tt) { return tt->fd; }
#include "upstream/socket_set.c"
#include "upstream/tun_set.c"

/* No TLS, actual DCO, shaping, residual TCP, management, signal or timer work. */
static void *management;
static int shaper_delay(int *s) { (void)s; abort(); }
static void shaper_soonest_event(struct timeval *tv, int delay) { (void)tv; (void)delay; abort(); }
static bool sockets_read_residual(struct context *c) { (void)c; return false; }
static void dco_event_set(int *dco, struct event_set *es, void *arg) {
    (void)es; (void)arg; assert(*dco == 0);
}
static void management_socket_set(void *m, struct event_set *es, void *arg, void *p) {
    (void)m; (void)es; (void)arg; (void)p; abort();
}
static void management_io(void *m) { (void)m; abort(); }
static void dco_read_and_process(int *dco) { (void)dco; abort(); }
static void check_status(int status, const char *label, void *a, void *b) {
    (void)label; (void)a; (void)b; assert(status >= 0);
}
static void update_time(void) {}
static void get_signal(int *sig) { (void)sig; abort(); }
#include "upstream/p2p_iow_flags.c"
#include "upstream/do_event_set_init.c"
#include "upstream/wait_functions.c"

static void encode(unsigned char *bytes, unsigned int direction, unsigned int sequence) {
    for (unsigned int i = 0; i < PACKET_SIZE; ++i)
        bytes[i] = (unsigned char)((sequence * 17u + i * 11u + direction * 83u) & 255u);
    bytes[0] = 0x48; bytes[1] = (unsigned char)direction;
    bytes[2] = (unsigned char)sequence; bytes[3] = (unsigned char)(sequence >> 8);
}
static void verify(const unsigned char *bytes, unsigned int direction, unsigned int sequence) {
    assert(bytes[0] == 0x48 && bytes[1] == direction);
    assert(bytes[2] == (sequence & 255u) && bytes[3] == ((sequence >> 8) & 255u));
    /* Independent byte expectations; do not call the producer's encoder. */
    for (unsigned int i = 4; i < PACKET_SIZE; ++i)
        assert(bytes[i] == (unsigned char)(17u * sequence + 11u * i + 83u * direction));
}
static void offer(struct context *c, unsigned int direction, unsigned int count) {
    for (unsigned int i = 0; i < count; ++i) {
        unsigned char bytes[PACKET_SIZE]; encode(bytes, direction, c->sent[direction]);
        assert(send(c->peer[direction], bytes, sizeof(bytes), MSG_NOSIGNAL) == PACKET_SIZE);
        ++c->sent[direction];
    }
}
static void initialize(struct context *c) {
    memset(c, 0, sizeof(*c));
    int fd[2];
    assert(socketpair(AF_UNIX, SOCK_DGRAM | SOCK_NONBLOCK | SOCK_CLOEXEC, 0, fd) == 0);
    c->sock.fd = fd[0]; c->peer[LINK] = fd[1];
    assert(socketpair(AF_UNIX, SOCK_DGRAM | SOCK_NONBLOCK | SOCK_CLOEXEC, 0, fd) == 0);
    c->tt.fd = fd[0]; c->peer[TUN] = fd[1];
    c->sock.ev_arg.type = EVENT_ARG_LINK_SOCKET;
    c->sock.ev_arg.u.sock = &c->sock;
    c->sock_array[0] = &c->sock; c->c2.link_sockets = c->sock_array;
    c->c1.tuntap = &c->tt; c->sig = &c->owned_signal;
    do_event_set_init(c, false);
    assert(c->c2.event_set_owned && c->c2.event_set_max == BASE_N_EVENTS);
    /* Verify the actual factory branch, not the compile-time EPOLL capability. */
    assert(c->c2.event_set->func.wait == po_wait);
    assert(((struct po_set *)c->c2.event_set)->fast);
}
static void destroy(struct context *c) {
    event_free(c->c2.event_set);
    assert(close(c->sock.fd) == 0 && close(c->tt.fd) == 0);
    assert(close(c->peer[LINK]) == 0 && close(c->peer[TUN]) == 0);
}
static void read_input(struct context *c, unsigned int direction) {
    assert((direction == LINK ? c->c2.to_tun.len : c->c2.to_link.len) == 0);
    int fd = direction == LINK ? c->sock.fd : c->tt.fd;
    ssize_t got = recv(fd, c->storage[direction], PACKET_SIZE, MSG_TRUNC);
    assert(got == PACKET_SIZE);
    verify(c->storage[direction], direction, c->read[direction]++);
    c->c2.buf = (struct buffer){PACKET_SIZE, c->storage[direction]};
    c->action = direction == LINK ? READ_LINK : READ_TUN;
}
static void read_incoming_link(struct context *c, struct link_socket *s) { assert(s == &c->sock); read_input(c, LINK); }
static void read_incoming_tun(struct context *c) { read_input(c, TUN); }
static void process_incoming_link(struct context *c, struct link_socket *s) {
    assert(s == &c->sock && c->c2.to_tun.len == 0); c->c2.to_tun = c->c2.buf;
}
static void process_incoming_tun(struct context *c, struct link_socket *s) {
    assert(s == &c->sock && c->c2.to_link.len == 0); c->c2.to_link = c->c2.buf;
}
static void write_output(struct context *c, unsigned int direction) {
    struct buffer *buf = direction == LINK ? &c->c2.to_tun : &c->c2.to_link;
    int fd = direction == LINK ? c->tt.fd : c->sock.fd;
    assert(buf->len == PACKET_SIZE && buf->data == c->storage[direction]);
    verify(buf->data, direction, c->writes[direction]);
    assert(send(fd, buf->data, buf->len, MSG_NOSIGNAL) == PACKET_SIZE);
    ++c->writes[direction]; buf->len = 0;
    c->action = direction == LINK ? WRITE_TUN : WRITE_LINK;
}
static void process_outgoing_tun(struct context *c, struct link_socket *s) { assert(s == &c->sock); write_output(c, LINK); }
static void process_outgoing_link(struct context *c, struct link_socket *s) { assert(s == &c->sock); write_output(c, TUN); }

#ifndef DISPATCH_SOURCE
#error Specify the immutable original or candidate dispatcher explicitly.
#endif
#include DISPATCH_SOURCE

static void drain_sinks(struct context *c) {
    for (unsigned int direction = 0; direction < 2; ++direction) {
        unsigned char bytes[PACKET_SIZE]; ssize_t got;
        int fd = c->peer[direction == LINK ? TUN : LINK];
        while ((got = recv(fd, bytes, sizeof(bytes), MSG_TRUNC)) >= 0) {
            assert(got == PACKET_SIZE);
            verify(bytes, direction, c->delivered[direction]++);
        }
        assert(errno == EAGAIN || errno == EWOULDBLOCK);
    }
}
static unsigned int step(struct context *c) {
    c->c2.timeval = (struct timeval){0, 0}; c->action = NO_ACTION;
    io_wait(c, p2p_iow_flags(c));
    unsigned int observed = c->c2.event_set_status;
    assert(observed != ES_ERROR && !IS_SIG(c));
    if (observed != ES_TIMEOUT) process_io(c, &c->sock);
    assert(c->c2.event_set_status == observed);
    drain_sinks(c);
    return observed;
}
static void finish(struct context *c) {
    unsigned int budget = 4u * (c->sent[LINK] + c->sent[TUN]) + 4u;
    while (c->delivered[LINK] != c->sent[LINK] || c->delivered[TUN] != c->sent[TUN]) {
        assert(budget-- > 0); assert(step(c) != ES_TIMEOUT);
    }
    for (unsigned int d = 0; d < 2; ++d)
        assert(c->sent[d] == c->read[d] && c->sent[d] == c->writes[d]);
    assert(c->c2.to_link.len == 0 && c->c2.to_tun.len == 0);
    assert(step(c) == ES_TIMEOUT);
}
static int dual(bool require_fair) {
    struct context c; initialize(&c); offer(&c, LINK, PREFILL); offer(&c, TUN, PREFILL);
    unsigned int statuses[PREFIX], actions[PREFIX], dual_readiness = 0;
    for (unsigned int i = 0; i < PREFIX; ++i) {
        statuses[i] = step(&c); actions[i] = c.action;
        if ((statuses[i] & (SOCKET_READ | TUN_READ)) == (SOCKET_READ | TUN_READ)) ++dual_readiness;
    }
    assert(dual_readiness == PREFIX / 2);
    unsigned int read_link = c.read[LINK], read_tun = c.read[TUN];
    unsigned int out_link = c.delivered[LINK], out_tun = c.delivered[TUN];
    bool fair = read_link == PREFIX / 4 && read_tun == PREFIX / 4;
    finish(&c);
    printf("{\"scenario\":\"dual\",\"backend\":\"poll-fast\",\"prefill_each\":%u,\"prefix_dispatches\":%u,"
           "\"dual_readiness_turns\":%u,\"prefix_link_reads\":%u,\"prefix_tun_reads\":%u,"
           "\"prefix_link_deliveries\":%u,\"prefix_tun_deliveries\":%u,"
           "\"final_link_deliveries\":%u,\"final_tun_deliveries\":%u,\"fair_prefix\":%s,\"statuses\":[",
           PREFILL, PREFIX, dual_readiness, read_link, read_tun, out_link, out_tun,
           c.delivered[LINK], c.delivered[TUN], fair ? "true" : "false");
    for (unsigned int i = 0; i < PREFIX; ++i) printf("%s%u", i ? "," : "", statuses[i]);
    printf("],\"actions\":[");
    for (unsigned int i = 0; i < PREFIX; ++i) printf("%s%u", i ? "," : "", actions[i]);
    puts("]}"); destroy(&c);
    return require_fair && !fair ? 23 : 0;
}
static void single(unsigned int direction) {
    struct context c; initialize(&c); offer(&c, direction, PREFILL); finish(&c);
    printf("{\"scenario\":\"single\",\"direction\":%u,\"delivered\":%u}\n", direction, c.delivered[direction]);
    destroy(&c);
}
static void empty(void) {
    struct context c; initialize(&c); assert(step(&c) == ES_TIMEOUT);
    assert(c.action == NO_ACTION); puts("{\"scenario\":\"empty\",\"timeout\":true}"); destroy(&c);
}
static void pending(void) {
    struct context c; initialize(&c);
    for (unsigned int d = 0; d < 2; ++d) { encode(c.storage[d], d, 0); c.sent[d] = c.read[d] = 1; }
    c.c2.to_link = (struct buffer){PACKET_SIZE, c.storage[TUN]};
    c.c2.to_tun = (struct buffer){PACKET_SIZE, c.storage[LINK]};
    assert(step(&c) == (SOCKET_WRITE | TUN_WRITE)); assert(c.action == WRITE_LINK);
    assert(c.c2.to_tun.len == PACKET_SIZE && c.c2.to_link.len == 0);
    assert(step(&c) == TUN_WRITE); assert(c.action == WRITE_TUN);
    finish(&c); puts("{\"scenario\":\"pending\",\"socket_write_first\":true}"); destroy(&c);
}
static void backpressure(void) {
    struct context c; initialize(&c);
    unsigned char blocker[PACKET_SIZE]; memset(blocker, 0xa5, sizeof(blocker));
    unsigned int blocked = 0;
    while (send(c.sock.fd, blocker, sizeof(blocker), MSG_NOSIGNAL) == PACKET_SIZE) assert(++blocked < 4096);
    assert(blocked > 0 && (errno == EAGAIN || errno == EWOULDBLOCK));
    encode(c.storage[TUN], TUN, 0); c.sent[TUN] = c.read[TUN] = 1;
    c.c2.to_link = (struct buffer){PACKET_SIZE, c.storage[TUN]};
    offer(&c, TUN, 1); /* Sequence 1 remains actually queued while input is suppressed. */
    c.c2.timeval = (struct timeval){0, 0}; io_wait(&c, p2p_iow_flags(&c));
    assert(c.c2.event_set_status == ES_TIMEOUT);
    verify(c.c2.to_link.data, TUN, 0); assert(c.c2.to_link.len == PACKET_SIZE && c.read[TUN] == 1);
    for (unsigned int i = 0; i < blocked; ++i) {
        unsigned char got[PACKET_SIZE]; assert(recv(c.peer[LINK], got, sizeof(got), MSG_TRUNC) == PACKET_SIZE);
        for (unsigned int j = 0; j < PACKET_SIZE; ++j) assert(got[j] == 0xa5);
    }
    assert(step(&c) == SOCKET_WRITE); assert(c.action == WRITE_LINK);
    assert(step(&c) == TUN_READ); assert(c.action == READ_TUN);
    finish(&c); printf("{\"scenario\":\"backpressure\",\"blocked_datagrams\":%u,\"delivered\":2}\n", blocked);
    destroy(&c);
}
static void isolation(void) {
    struct context a, b; initialize(&a); initialize(&b);
    offer(&a, LINK, 2); offer(&a, TUN, 2); offer(&b, LINK, 2); offer(&b, TUN, 2);
    assert(step(&a) == (SOCKET_READ | TUN_READ)); assert(a.action == READ_LINK);
    assert(step(&b) == (SOCKET_READ | TUN_READ)); assert(b.action == READ_LINK);
    assert(step(&a) == (TUN_READ | TUN_WRITE)); assert(a.action == WRITE_TUN);
    assert(step(&a) == (SOCKET_READ | TUN_READ));
    unsigned int second_read = a.action;
    finish(&a); finish(&b); destroy(&a); destroy(&b);
    initialize(&a); offer(&a, LINK, 1); offer(&a, TUN, 1);
    assert(step(&a) == (SOCKET_READ | TUN_READ)); assert(a.action == READ_LINK);
    finish(&a); destroy(&a);
    printf("{\"scenario\":\"isolation\",\"second_read\":%u,\"reset_first_read\":1}\n", second_read);
}
int main(int argc, char **argv) {
    assert(argc == 2 || argc == 3);
    bool require_fair = argc == 3 && strcmp(argv[2], "--require-fair") == 0;
    if (strcmp(argv[1], "dual") == 0) return dual(require_fair);
    if (strcmp(argv[1], "link") == 0) single(LINK);
    else if (strcmp(argv[1], "tun") == 0) single(TUN);
    else if (strcmp(argv[1], "empty") == 0) empty();
    else if (strcmp(argv[1], "pending") == 0) pending();
    else if (strcmp(argv[1], "backpressure") == 0) backpressure();
    else if (strcmp(argv[1], "isolation") == 0) isolation();
    else abort();
    return 0;
}
