#define _POSIX_C_SOURCE 200809L
#include <errno.h>
#include <stddef.h>
#include <stdint.h>
#include <stdatomic.h>
#include <poll.h>
#include <sys/resource.h>
#include <time.h>
#include <fcntl.h>

static unsigned interruptions;
static unsigned interruption_delay_ms;
static unsigned fail_poll;
static uint64_t blocked_ns;
static uint64_t real_polls;
static int final_timeout;
static struct rlimit saved_limit;
static int limit_saved;

static uint64_t clock_ns(clockid_t clock) {
    struct timespec value;
    if (clock_gettime(clock,&value)!=0) return 0;
    return (uint64_t)value.tv_sec*UINT64_C(1000000000)+(uint64_t)value.tv_nsec;
}
uint64_t hepta_io_test_cpu_ns(void) { return clock_ns(CLOCK_THREAD_CPUTIME_ID); }
uint64_t hepta_io_test_blocked_ns(void) { return blocked_ns; }
uint64_t hepta_io_test_real_polls(void) { return real_polls; }
int hepta_io_test_final_timeout(void) { return final_timeout; }
void hepta_io_test_reset(void) { blocked_ns=0;real_polls=0;final_timeout=-1;interruptions=0;fail_poll=0; }
void hepta_io_test_interrupt(unsigned count,unsigned delay_ms) { interruptions=count;interruption_delay_ms=delay_ms; }
void hepta_io_test_fail_poll(void) { fail_poll=1; }

int __real_poll(struct pollfd *,nfds_t,int);
int __wrap_poll(struct pollfd *fds,nfds_t count,int timeout) {
    if (interruptions) {
        --interruptions;
        struct timespec delay={.tv_sec=(time_t)(interruption_delay_ms/1000),.tv_nsec=(long)(interruption_delay_ms%1000)*1000000L};
        while (nanosleep(&delay,&delay)!=0 && errno==EINTR) {}
        errno=EINTR;return -1;
    }
    if (fail_poll) {fail_poll=0;errno=EIO;return -1;}
    final_timeout=timeout;
    uint64_t before=clock_ns(CLOCK_MONOTONIC);
    int result=__real_poll(fds,count,timeout);
    int saved_errno=errno;
    uint64_t after=clock_ns(CLOCK_MONOTONIC);
    if (after>=before) blocked_ns+=after-before;
    ++real_polls;
    errno=saved_errno;
    return result;
}
// These change only this short-lived qualification process's soft fd limit.
// No emulated socket error is substituted: the next socketpair reaches Linux.
int hepta_io_test_exhaust_fds(void) {
    if (getrlimit(RLIMIT_NOFILE,&saved_limit)!=0) return -1;
    struct rlimit limited=saved_limit;limited.rlim_cur=0;
    if (setrlimit(RLIMIT_NOFILE,&limited)!=0) return -1;
    limit_saved=1;return 0;
}
int hepta_io_test_restore_fds(void) {
    if (!limit_saved) return -1;
    int result=setrlimit(RLIMIT_NOFILE,&saved_limit);limit_saved=0;return result;
}
size_t hepta_io_test_pollfd_size(void) {return sizeof(struct pollfd);}
size_t hepta_io_test_pollfd_align(void) {return _Alignof(struct pollfd);}
size_t hepta_io_test_pollfd_events(void) {return offsetof(struct pollfd,events);}
size_t hepta_io_test_pollfd_revents(void) {return offsetof(struct pollfd,revents);}
size_t hepta_io_test_nfds_size(void) {return sizeof(nfds_t);}
int hepta_io_test_fd_open(int fd) {
    if (fcntl(fd,F_GETFD)>=0) return 1;
    return errno==EBADF ? 0 : -1;
}
// A fixture peer can block on readiness without touching the reactor-thread
// instrumentation above. It remains nonblocking for the actual read syscall.
int hepta_io_test_wait_readable(int fd) {
    struct pollfd waiting={.fd=fd,.events=POLLIN,.revents=0};
    int result;
    do {result=__real_poll(&waiting,1,2000);} while (result<0 && errno==EINTR);
    return result;
}
