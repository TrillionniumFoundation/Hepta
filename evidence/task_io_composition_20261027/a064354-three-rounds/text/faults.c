#define _POSIX_C_SOURCE 200809L
#include <errno.h>
#include <fcntl.h>
#include <poll.h>
#include <sched.h>
#include <stdatomic.h>
#include <stdint.h>
#include <sys/socket.h>

/* Qualification-only syscall controls. None is linked into source examples. */
static _Atomic unsigned poll_entries;
static _Atomic unsigned poll_failures;
static _Atomic unsigned pair_failures;
static _Atomic int pause_poll;

unsigned hepta_task_io_poll_entries(void) { return atomic_load(&poll_entries); }
void hepta_task_io_fail_poll(void) { atomic_store(&poll_failures, 1); }
void hepta_task_io_fail_pair(void) { atomic_store(&pair_failures, 1); }
void hepta_task_io_pause_poll(int enabled) { atomic_store(&pause_poll, enabled); }
int hepta_task_io_fd_open(int fd) {
    if (fcntl(fd, F_GETFD) >= 0) return 1;
    return errno == EBADF ? 0 : -1;
}
int __real_poll(struct pollfd *, nfds_t, int);
int __wrap_poll(struct pollfd *fds, nfds_t count, int timeout) {
    atomic_fetch_add(&poll_entries, 1);
    while (atomic_load(&pause_poll)) sched_yield();
    if (atomic_exchange(&poll_failures, 0)) { errno=EIO; return -1; }
    return __real_poll(fds, count, timeout);
}
int __real_socketpair(int, int, int, int[2]);
int __wrap_socketpair(int domain, int type, int protocol, int sockets[2]) {
    if (atomic_exchange(&pair_failures, 0)) { errno=EMFILE; return -1; }
    return __real_socketpair(domain, type, protocol, sockets);
}
