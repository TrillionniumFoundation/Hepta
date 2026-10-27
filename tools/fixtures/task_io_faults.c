#define _POSIX_C_SOURCE 200809L
#include <errno.h>
#include <fcntl.h>
#include <poll.h>
#include <sched.h>
#include <stdatomic.h>
#include <stdarg.h>
#include <stdint.h>
#include <sys/ioctl.h>
#include <sys/socket.h>

/* Qualification-only syscall controls. None is linked into source examples. */
static _Atomic unsigned poll_entries;
static _Atomic unsigned poll_failures;
static _Atomic unsigned pair_failures;
static _Atomic unsigned nonblocking_countdown;
static _Atomic unsigned nonblocking_failures;
static _Atomic int last_pair[2];
static _Atomic int pause_poll;

unsigned hepta_task_io_poll_entries(void) { return atomic_load(&poll_entries); }
void hepta_task_io_fail_poll(void) { atomic_store(&poll_failures, 1); }
void hepta_task_io_fail_pair(void) { atomic_store(&pair_failures, 1); }
void hepta_task_io_fail_nonblocking(unsigned ordinal) { atomic_store(&nonblocking_countdown, ordinal); }
unsigned hepta_task_io_nonblocking_failures(void) { return atomic_load(&nonblocking_failures); }
int hepta_task_io_last_pair_fd(unsigned index) { return index < 2 ? atomic_load(&last_pair[index]) : -1; }
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
    int result=__real_socketpair(domain, type, protocol, sockets);
    if (result==0) { atomic_store(&last_pair[0], sockets[0]); atomic_store(&last_pair[1], sockets[1]); }
    return result;
}
int __real_ioctl(int, unsigned long, ...);
int __wrap_ioctl(int fd, unsigned long request, ...) {
    /* Only this fixed Linux profile's FIONBIO pointer ABI is admitted by the
       qualification shim. An unexpected ioctl fails instead of inventing a
       variadic argument type. These hooks never enter source-example builds. */
    if (request!=FIONBIO) { errno=EINVAL; return -1; }
    va_list args;
    va_start(args, request);
    int *argument=va_arg(args, int *);
    va_end(args);
    unsigned remaining=atomic_load(&nonblocking_countdown);
    while (remaining && !atomic_compare_exchange_weak(&nonblocking_countdown, &remaining, remaining-1)) {}
    if (remaining==1) { atomic_fetch_add(&nonblocking_failures, 1); errno=EIO; return -1; }
    return __real_ioctl(fd, request, argument);
}
