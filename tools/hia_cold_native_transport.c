/* Explicit Linux x86-64 mechanical dispatcher for a HIA-owned child lifetime.
 *
 * R3 is an explicit opt-in native transport with an optional visible CPython
 * resource owner. It does not install a default replacement.
 * All business sequencing is selected by the pinned HIA policy. This file
 * supplies one named OS operation per command, immutable byte operands, actual
 * observations, and an emergency owner cleanup if the policy ABI is lost.
 *
 * fork's child arm is a fixed async-signal-safe exec adapter: stdio dup, cwd,
 * restore_signals, close_fds/pass_fds, execve, and an errno/stage pipe. It does
 * not interpret the target or enter Python. It creates no extra process group.
 */
#define _GNU_SOURCE 1
#include "hia_cold_native_transport.h"
#include <errno.h>
#include <fcntl.h>
#include <limits.h>
#include <poll.h>
#include <signal.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/syscall.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <time.h>
#include <unistd.h>

#if !defined(__linux__) || !defined(__x86_64__)
#error "The explicit native transport profile is Linux x86-64 only"
#endif
_Static_assert(sizeof(void *) == 8 && sizeof(uint64_t) == 8, "LP64 required");

#define HCT_REQUEST_MAGIC UINT64_C(3688501220647785288)
#define HCT_REPLY_MAGIC   UINT64_C(3688501229237719880)
#define HCT_STATE_MAGIC   UINT64_C(3688501233549464392)
#define HCT_CANARY        UINT64_C(10177645963941345917)
#define HCT_REQUEST_BYTES 128
#define HCT_REPLY_BYTES 64
#define HCT_STATE_BYTES 256
#define HCT_FDS 9
#define HCT_PIPE_BYTES 4096
#define HCT_READ_BYTES 32768
#define HCT_MAX_TIMEOUT UINT64_C(9223372036854775807)

extern char **environ;

struct capture {
    unsigned char *data;
    size_t size, capacity, reads;
};
struct guarded_state {
    uint64_t before;
    unsigned char bytes[HCT_STATE_BYTES];
    uint64_t after;
};
struct session {
    const struct hia_cold_config *config;
    struct hia_cold_result *result;
    struct hia_cold_event *trace;
    size_t trace_capacity;
    int fd[HCT_FDS];
    pid_t pid;
    int reaped, owner_lost, status, exec_confirmed;
    unsigned char exec_error[8];
    size_t exec_error_bytes;
    struct capture output[2];
    char executable_path[64];
    char **argv;
    uint64_t seq, last_action, last_argument;
    uint64_t issued_close_mask;
    uint64_t pre_signal_sequence;
    pid_t pre_signal_pid;
    uint64_t wait_clock_ns;
    unsigned wait_clock_observed;
    uint64_t value0, value1;
    unsigned error;
    struct guarded_state state;
};

static uint64_t get64(const unsigned char *p) {
    uint64_t value;
    memcpy(&value, p, sizeof value);
    return value;
}
static void put64(unsigned char *p, uint64_t value) {
    memcpy(p, &value, sizeof value);
}
static uint64_t owned_mask(const struct session *s) {
    uint64_t value = 0;
    for (unsigned i = 0; i != HCT_FDS; ++i)
        if (s->fd[i] >= 0) value |= UINT64_C(1) << i;
    return value;
}
static struct hia_cold_snapshot snapshot(const struct session *s) {
    return (struct hia_cold_snapshot){
        s->fd, s->pid, (unsigned)s->reaped, (unsigned)s->owner_lost, s->status,
        get64(s->state.bytes+40),get64(s->state.bytes+96),
        get64(s->state.bytes+104),get64(s->state.bytes+112),
        (unsigned)get64(s->state.bytes+152),(unsigned)get64(s->state.bytes+184),
        get64(s->state.bytes+232)==2,s->issued_close_mask,
        s->output[0].data,s->output[1].data,s->output[0].size,s->output[1].size,
        s->output[0].reads,s->output[1].reads,
        s->result->start_ns,s->wait_clock_ns,s->wait_clock_observed
    };
}
static void block_enter(struct session *s) {
    if(s->config->host) s->config->host->block_enter(s->config->host->context);
}
static void block_leave(struct session *s) {
    if(s->config->host) s->config->host->block_leave(s->config->host->context);
}
static unsigned actual_errno(void) {
    return errno > 0 ? (unsigned)errno : (unsigned)EIO;
}
static int timestamp(uint64_t *value) {
    struct timespec t;
    if (clock_gettime(CLOCK_MONOTONIC, &t) != 0) return -1;
    if (t.tv_sec < 0 || (uint64_t)t.tv_sec > UINT64_MAX / UINT64_C(1000000000)) {
        errno = EOVERFLOW;
        return -1;
    }
    uint64_t seconds = (uint64_t)t.tv_sec * UINT64_C(1000000000);
    if (seconds > UINT64_MAX - (uint64_t)t.tv_nsec) {
        errno = EOVERFLOW;
        return -1;
    }
    *value = seconds + (uint64_t)t.tv_nsec;
    return 0;
}
static int returncode(int status) {
    if (WIFEXITED(status)) return WEXITSTATUS(status);
    if (WIFSIGNALED(status)) return -WTERMSIG(status);
    return INT_MIN; /* A stopped/continued status is never a completed child. */
}
static int reserve_read(struct capture *p) {
    if (p->size > SIZE_MAX - HCT_READ_BYTES) { errno = EOVERFLOW; return -1; }
    size_t needed = p->size + HCT_READ_BYTES;
    if (needed <= p->capacity) return 0;
    size_t capacity = p->capacity ? p->capacity : HCT_READ_BYTES;
    while (capacity < needed) {
        if (capacity > SIZE_MAX / 2) { capacity = needed; break; }
        capacity *= 2;
    }
    void *next = realloc(p->data, capacity);
    if (next == NULL) return -1;
    p->data = next;
    p->capacity = capacity;
    return 0;
}
static void record_cleanup_error(struct session *s, unsigned error, unsigned action) {
    if (s->result->cleanup_errno == 0) {
        s->result->cleanup_errno = error;
        s->result->cleanup_stage = action;
    }
}
static void close_slot(struct session *s, unsigned slot) {
    int fd=s->fd[slot], retired=1;
    const struct hia_cold_host *host=s->config->host;
    if(host){
        struct hia_cold_snapshot facts=snapshot(s);
        s->error=host->close(host->context,slot,fd,&retired,&facts);
    }else{
        /* Linux raw close retires the number on EINTR; never retry that number. */
        if(close(fd)!=0)s->error=actual_errno();
    }
    if(retired)s->fd[slot]=-1;
    if(s->error)record_cleanup_error(s,s->error,HCT_CLOSE);
    else s->value0=0;
}
static _Noreturn void child_error(int descriptor, unsigned stage, unsigned error) {
    uint32_t words[2] = { error, stage };
    const unsigned char *p = (const unsigned char *)words;
    size_t at = 0;
    while (at < sizeof words) {
        ssize_t count = write(descriptor, p + at, sizeof words - at);
        if (count < 0 && errno == EINTR) continue;
        if (count <= 0) break;
        at += (size_t)count;
    }
    _exit(255);
}
static _Noreturn void child_exec(struct session *s) {
    const struct hia_cold_config *c = s->config;
    int report = s->fd[8];
    if (dup2(s->fd[1], STDIN_FILENO) < 0
            || dup2(s->fd[4], STDOUT_FILENO) < 0
            || dup2(s->fd[6], STDERR_FILENO) < 0)
        child_error(report, 1, actual_errno());
    if (chdir(c->cwd) != 0) child_error(report, 2, actual_errno());

    struct sigaction action;
    memset(&action, 0, sizeof action);
    action.sa_handler = SIG_DFL;
    sigemptyset(&action.sa_mask);
    if (sigaction(SIGPIPE, &action, NULL) != 0)
        child_error(report, 3, actual_errno());
#ifdef SIGXFZ
    if (sigaction(SIGXFZ, &action, NULL) != 0)
        child_error(report, 3, actual_errno());
#endif
#ifdef SIGXFSZ
    if (sigaction(SIGXFSZ, &action, NULL) != 0)
        child_error(report, 3, actual_errno());
#endif

    /* All parent-created descriptors are >=3 under the explicit entry profile.
       Keep the exact executable and outer-owned descriptors, plus the CLOEXEC
       error writer until exec. No /proc scan, descriptor renumbering or cache. */
    unsigned keep[4];
    size_t n = 0;
    keep[n++] = (unsigned)s->fd[0];
    for (size_t i = 0; i < c->pass_fd_count; ++i)
        keep[n++] = (unsigned)c->pass_fds[i];
    keep[n++] = (unsigned)report;
    for (size_t i = 1; i < n; ++i) {
        unsigned value = keep[i];
        size_t j = i;
        while (j && keep[j - 1] > value) { keep[j] = keep[j - 1]; --j; }
        keep[j] = value;
    }
    unsigned begin = 3;
    for (size_t i = 0; i < n; ++i) {
        if (keep[i] < begin) continue;
        if (begin < keep[i] && syscall(SYS_close_range, begin, keep[i] - 1, 0) != 0)
            child_error(report, 4, actual_errno());
        begin = keep[i] + 1;
    }
    if (syscall(SYS_close_range, begin, UINT_MAX, 0) != 0)
        child_error(report, 4, actual_errno());

    for (size_t i = 0; i + 1 < n; ++i) {
        /* The sorted array does not identify the error fd by position. */
        if (keep[i] == (unsigned)report) continue;
        int flags = fcntl((int)keep[i], F_GETFD);
        if (flags < 0 || fcntl((int)keep[i], F_SETFD, flags & ~FD_CLOEXEC) != 0)
            child_error(report, 5, actual_errno());
    }
    /* Include the last sorted retained fd unless it is the error writer. */
    if (n && keep[n - 1] != (unsigned)report) {
        int flags = fcntl((int)keep[n - 1], F_GETFD);
        if (flags < 0 || fcntl((int)keep[n - 1], F_SETFD, flags & ~FD_CLOEXEC) != 0)
            child_error(report, 5, actual_errno());
    }

    char *flat_environment[] = {
        (char *)"PATH=/usr/bin:/bin", (char *)"LANG=C.UTF-8",
        (char *)"LC_ALL=C.UTF-8", (char *)"TZ=UTC", NULL
    };
    execve(s->executable_path, s->argv,
           c->linked_environment ? environ : (c->environment ? c->environment : flat_environment));
    child_error(report, 6, actual_errno());
}
static int prepare_arguments(struct session *s) {
    const struct hia_cold_config *c = s->config;
    if (c->argument_count > SIZE_MAX / sizeof(char *) - 2) {
        errno = EOVERFLOW; return -1;
    }
    s->argv = calloc(c->argument_count + 2, sizeof(char *));
    if (s->argv == NULL) return -1;
    int size = snprintf(s->executable_path, sizeof s->executable_path,
                        "/proc/self/fd/%d", s->fd[0]);
    if (size < 0 || (size_t)size >= sizeof s->executable_path) {
        errno = EOVERFLOW; return -1;
    }
    s->argv[0] = s->executable_path;
    for (size_t i = 0; i < c->argument_count; ++i)
        s->argv[i + 1] = (char *)c->arguments[i];
    return 0;
}
static int valid_entry(const struct hia_cold_config *c) {
    if (c == NULL || (!c->host && c->cwd == NULL) || c->nonce == 0
            || c->linked_environment > 1 || c->pass_fd_count > 2
            || c->timeout_ns > HCT_MAX_TIMEOUT
            || (c->executable_bytes && c->executable == NULL)
            || (c->input_bytes && c->input == NULL)
            || c->executable_bytes > (size_t)SSIZE_MAX
            || c->input_bytes > (size_t)SSIZE_MAX
            || (c->argument_count && c->arguments == NULL)
            || (c->pass_fd_count && c->pass_fds == NULL)) return 0;
    if(c->host && (!c->host->before||!c->host->perform||!c->host->close
            ||!c->host->error||!c->host->handoff
            ||!c->host->block_enter||!c->host->block_leave||!c->host->wrap))return 0;
    for (int fd = 0; fd < 3; ++fd) if (fcntl(fd, F_GETFD) < 0) return 0;
    for (size_t i = 0; i < c->argument_count; ++i)
        if (c->arguments[i] == NULL) return 0;
    for (size_t i = 0; i < c->pass_fd_count; ++i) {
        if (c->pass_fds[i] < 3 || fcntl(c->pass_fds[i], F_GETFD) < 0) return 0;
        for (size_t j = 0; j < i; ++j)
            if (c->pass_fds[i] == c->pass_fds[j]) return 0;
    }
    struct sigaction action;
    if (sigaction(SIGPIPE, NULL, &action) != 0 || action.sa_handler != SIG_IGN) return 0;
    if (sigaction(SIGCHLD, NULL, &action) != 0
            || action.sa_handler == SIG_IGN || (action.sa_flags & SA_NOCLDWAIT)) return 0;
    return 1;
}
static int poll_milliseconds(uint64_t ns) {
    uint64_t ms = ns / UINT64_C(1000000) + (ns % UINT64_C(1000000) != 0);
    return ms > INT_MAX ? INT_MAX : (int)ms;
}

/* A rejection-only projection checker. It never issues an action, chooses an
 * alternative, performs an OS operation or advances the session. The HIA call
 * remains the sole producer of the next command. The prior workspace and this
 * actual completed-operation receipt bind every mutable tracking field.
 */
static void projected_failure(unsigned char state[HCT_STATE_BYTES], int *cleanup,
                              uint64_t mode, uint64_t error, uint64_t stage) {
    put64(state + 248, get64(state + 40));
    put64(state + 96, mode); put64(state + 104, error); put64(state + 112, stage);
    if (error == HCT_PY_KEYBOARD) put64(state + 208, 2);
    else if (error == HCT_PY_EXCEPTION) put64(state + 208, 1);
    *cleanup = 1;
}
static int close_projection(uint64_t phase, uint64_t action, uint64_t arg,
                            uint64_t amount, uint64_t auxiliary, unsigned slot) {
    return phase == 53 && action == HCT_CLOSE && arg == slot
        && !amount && !auxiliary;
}
static int handback_projection(const struct session *s, const unsigned char *state,
                              uint64_t phase, uint64_t action, uint64_t arg,
                              uint64_t amount, uint64_t auxiliary) {
    uint64_t mask = owned_mask(s), claims = get64(state + 216);
    /* state already includes the issued close bit; inspect the actual prior
       issued mask to distinguish a new outer-finally close from a repeated one. */
    if ((mask & 1) && !(s->issued_close_mask & 1))
        return close_projection(phase, action, arg, amount, auxiliary, 0);
    int live = s->pid && !s->reaped && !s->owner_lost;
    if (mask || live)
        return get64(state + 72) == 1 && get64(state + 96) != HCT_RETURNED
            && s->config->host && phase == 98 && action == HCT_HOST_HANDOFF
            && arg == get64(state + 96) && amount == mask
            && auxiliary == (s->pid > 0 ? (uint64_t)s->pid : 0)
            && claims == s->issued_close_mask;
    return phase == 99 && action == HCT_FINISH
        && arg == get64(state + 96) && amount == get64(state + 104)
        && auxiliary == get64(state + 112)
        && arg <= HCT_CUSTODY_LOST && arg != HCT_POLICY_LOST
        && amount <= UINT_MAX && auxiliary <= UINT_MAX
        && (!s->owner_lost || arg == HCT_CUSTODY_LOST)
        && (arg != HCT_RETURNED || (s->exec_confirmed && s->reaped));
}
static int cleanup_projection(const struct session *s, const unsigned char *state,
                              uint64_t phase, uint64_t action, uint64_t arg,
                              uint64_t amount, uint64_t auxiliary) {
    uint64_t mask = owned_mask(s), remaining = mask & ~s->issued_close_mask;
    uint64_t mode = get64(state + 96);
    int live = s->pid && !s->reaped && !s->owner_lost;
    if (get64(state + 152) == 0 && (get64(state + 72) == 1 || mode == HCT_EXEC_ERROR)) {
        if (get64(state + 160))
            return handback_projection(s,state,phase,action,arg,amount,auxiliary);
        if (get64(state + 248) == 5 && get64(state + 136) < 3) {
            for (unsigned slot = 1; slot < 7; ++slot)
                if (remaining & (UINT64_C(1) << slot))
                    return close_projection(phase,action,arg,amount,auxiliary,slot);
            return handback_projection(s,state,phase,action,arg,amount,auxiliary);
        }
        if (remaining & 256) return close_projection(phase,action,arg,amount,auxiliary,8);
        if (remaining & 128) return close_projection(phase,action,arg,amount,auxiliary,7);
        if (live && mode == HCT_EXEC_ERROR)
            return phase == 52 && action == HCT_WAIT_BLOCK && !arg && !amount && !auxiliary;
        static const unsigned startup_slots[] = {2,3,5,1,4,6};
        for (size_t at=0; at<sizeof startup_slots/sizeof startup_slots[0]; ++at)
            if (remaining & (UINT64_C(1) << startup_slots[at]))
                return close_projection(phase,action,arg,amount,auxiliary,startup_slots[at]);
        return handback_projection(s,state,phase,action,arg,amount,auxiliary);
    }
    if (get64(state + 72) == 1 && get64(state + 160))
        return handback_projection(s,state,phase,action,arg,amount,auxiliary);
    if (live) {
        if (get64(state + 208) == 2 && get64(state + 184) == 1 && !get64(state + 232))
            return phase == 55 && action == HCT_CLOCK && !arg && !amount && !auxiliary;
        if (!get64(state + 192))
            return phase == 54 && action == HCT_WAIT_NOHANG && !arg && !amount && !auxiliary;
        if (!get64(state + 200))
            return phase == 51 && action == HCT_KILL && !arg && !amount && !auxiliary;
        if (mode == HCT_SYSTEM_ERROR && get64(state + 152) == 1) {
            static const unsigned close_slots[] = {3,5,2};
            for (size_t at=0; at<3; ++at)
                if (remaining & (UINT64_C(1) << close_slots[at]))
                    return close_projection(phase,action,arg,amount,auxiliary,close_slots[at]);
            if (get64(state + 208) == 2 && get64(state + 232) == 2)
                return handback_projection(s,state,phase,action,arg,amount,auxiliary);
        }
        return phase == 52 && action == HCT_WAIT_BLOCK && !arg && !amount && !auxiliary;
    }
    if (get64(state + 152) == 1) {
        static const unsigned close_slots[] = {3,5,2};
        for (size_t at=0; at<3; ++at)
            if (remaining & (UINT64_C(1) << close_slots[at]))
                return close_projection(phase,action,arg,amount,auxiliary,close_slots[at]);
    }
    for (int slot=HCT_FDS-1; slot>=0; --slot)
        if (remaining & (UINT64_C(1) << slot))
            return close_projection(phase,action,arg,amount,auxiliary,(unsigned)slot);
    return handback_projection(s,state,phase,action,arg,amount,auxiliary);
}
static int issued_projection(const struct session *s,
                             const unsigned char request[HCT_REQUEST_BYTES],
                             const unsigned char prior[HCT_STATE_BYTES],
                             const unsigned char reply[HCT_REPLY_BYTES]) {
    const struct hia_cold_config *c = s->config;
    const unsigned char *state = s->state.bytes;
    uint64_t action=get64(reply+24), arg=get64(reply+32);
    uint64_t amount=get64(reply+40), auxiliary=get64(reply+48);
    uint64_t phase=get64(state+40), mask=owned_mask(s);
    unsigned char expected[HCT_STATE_BYTES];
    memcpy(expected,prior,sizeof expected);
    if (get64(request+16)!=s->seq || get64(request+24)!=s->last_action
        || get64(request+32)!=s->last_argument || get64(request+40)!=s->error
        || get64(request+48)!=s->value0 || get64(request+56)!=s->value1
        || get64(request+64)!=(uint64_t)s->owner_lost
        || get64(request+72)!=c->executable_bytes || get64(request+80)!=c->input_bytes
        || get64(request+88)!=c->timeout_ns || get64(request+96)!=mask
        || get64(request+104)!=(s->pid>0?(uint64_t)s->pid:0)
        || get64(request+112)!=(uint64_t)s->reaped) return 0;
    if (get64(state)!=HCT_STATE_MAGIC || get64(state+8)!=c->nonce
        || get64(state+16)!=s->seq+1 || get64(state+24)!=action || get64(state+32)!=arg)
        return 0;
    if (!s->seq) {
        for(size_t at=0;at<sizeof expected;++at) if(prior[at])return 0;
        if(s->last_action||s->last_argument||s->error||s->value0||s->value1
            ||s->pid||s->reaped||s->owner_lost||mask||s->argv||s->issued_close_mask
            ||action!=HCT_MEMFD||phase!=1||arg||amount||auxiliary)return 0;
        put64(expected,HCT_STATE_MAGIC);put64(expected+8,c->nonce);
        put64(expected+16,1);put64(expected+24,HCT_MEMFD);
        put64(expected+40,1);put64(expected+168,UINT64_C(500000));
        return !memcmp(state,expected,sizeof expected);
    }
    uint64_t acknowledged_claims=get64(prior+216);
    if(s->last_action==HCT_HOST_WRAP){
        if(s->value1 || s->value0>3 || s->value0==2
            ||(s->value0&&!s->error)
            ||(s->last_argument!=2&&s->last_argument!=3&&s->last_argument!=5))return 0;
        if(s->value0){
            uint64_t bit=UINT64_C(1)<<s->last_argument;
            if((s->value0==3&&(mask&bit))||(s->value0==1&&!(mask&bit)))return 0;
            acknowledged_claims|=bit;
            put64(expected+216,acknowledged_claims);
        }
    }
    if(get64(prior)!=HCT_STATE_MAGIC||get64(prior+8)!=c->nonce
        ||get64(prior+16)!=s->seq||get64(prior+24)!=s->last_action
        ||get64(prior+32)!=s->last_argument||acknowledged_claims!=s->issued_close_mask)
        return 0;
    uint64_t previous=get64(prior+40), value=s->value0;
    unsigned error=s->error;
    if(!((previous>=1&&previous<=29)||(previous>=51&&previous<=58)))return 0;
    int cleanup=previous>=51, direct=0;
    int retry=error==EINTR&&(previous==2||previous==8||previous==13
        ||previous==15||previous==16||previous==17||previous==18||previous==21);
    if(!cleanup&&error&&!retry&&!(previous==15&&error==EPIPE)
        &&!(previous==7&&get64(prior+128)>0))
        projected_failure(expected,&cleanup,HCT_SYSTEM_ERROR,error,s->last_action);
    if(previous==1&&!error){
        if(!(mask&1)||s->fd[0]<0||value!=(uint64_t)s->fd[0])return 0;
    }
    if(previous==2&&!error){
        uint64_t offset=get64(prior+48);
        if(offset>c->executable_bytes||value>c->executable_bytes-offset)return 0;
        if(!value)projected_failure(expected,&cleanup,HCT_SYSTEM_ERROR,EIO,HCT_IMAGE_WRITE);
        else put64(expected+48,offset+value);
    }
    if(previous==4&&!error&&(value&15)!=15)
        projected_failure(expected,&cleanup,HCT_SYSTEM_ERROR,EIO,HCT_SEAL_GET);
    if(previous==22&&!error){
        if(value!=(uint64_t)(c->host!=NULL)||s->value1)return 0;
        put64(expected+72,value);put64(expected+136,0);
    }
    if(previous==5&&!error){
        uint64_t index=get64(prior+136);
        if(index>=4)return 0;
        if(index<3)put64(expected+136,index+1);
    }
    if(previous==6&&!error){
        if(!value||value!=(uint64_t)s->pid||s->reaped)return 0;
        put64(expected+80,value);put64(expected+128,0);
    }
    if(previous==7&&(get64(prior+128)>0||!error)){
        if(error){
            put64(expected+96,HCT_SYSTEM_ERROR);put64(expected+104,error);
            put64(expected+112,HCT_CLOSE);put64(expected+248,7);
        }
        uint64_t cursor=get64(prior+128);
        if(cursor>=4)return 0;
        put64(expected+128,cursor+1);
        if(cursor+1==4&&get64(expected+96))cleanup=1;
    }
    if(previous==8&&!error){
        uint64_t count=get64(prior+144);
        if(count>8||value>8-count)return 0;
        count+=value;put64(expected+144,count);
        if(!value&&count==8){
            uint64_t child_error=s->value1&UINT64_C(4294967295);
            uint64_t child_stage=s->value1>>32;
            if(!child_error||child_stage<1||child_stage>6)
                projected_failure(expected,&cleanup,HCT_SYSTEM_ERROR,EPROTO,HCT_EXEC_READ);
            else{
                put64(expected+96,HCT_EXEC_ERROR);put64(expected+104,child_error);
                put64(expected+112,child_stage);put64(expected+248,8);
            }
        }else if(!value&&count)
            projected_failure(expected,&cleanup,HCT_SYSTEM_ERROR,EPROTO,HCT_EXEC_READ);
    }
    if(previous==9&&!error&&get64(expected+96))cleanup=1;
    if(previous==28&&!error)put64(expected+152,1);
    if(previous==10&&!error){
        if(value>UINT64_MAX-c->timeout_ns)
            projected_failure(expected,&cleanup,HCT_SYSTEM_ERROR,EOVERFLOW,HCT_CLOCK);
        else{put64(expected+64,value+c->timeout_ns);put64(expected+184,1);}
    }
    if(previous==12&&!error&&(mask&44)&&value>=get64(prior+64))
        projected_failure(expected,&cleanup,HCT_TIMEOUT_IO,0,HCT_POLL);
    if(previous==13&&!error){if(value>7)return 0;put64(expected+120,value);}
    if(previous==14&&!error&&value>get64(prior+64))
        projected_failure(expected,&cleanup,HCT_TIMEOUT_IO,0,HCT_POLL);
    if(previous==15&&!error){
        uint64_t offset=get64(prior+56),count=c->input_bytes-offset;
        if(offset>=c->input_bytes)return 0;
        if(count>HCT_PIPE_BYTES)count=HCT_PIPE_BYTES;
        if(value>count)return 0;
        put64(expected+56,offset+value);
    }
    if((previous==16||previous==17)&&!error&&value>HCT_READ_BYTES)return 0;
    if(previous==18&&!error&&value){
        if(value!=(uint64_t)s->pid||value!=get64(prior+80)||!s->reaped)return 0;
        put64(expected+88,s->value1);cleanup=1;
    }
    if(previous==19&&!error){
        uint64_t deadline=get64(prior+64),delay=get64(prior+168);
        if(value>=deadline)projected_failure(expected,&cleanup,HCT_TIMEOUT_WAIT,0,HCT_WAIT_NOHANG);
        else{
            if(!delay||delay>UINT64_C(50000000))return 0;
            delay*=2;if(delay>UINT64_C(50000000))delay=UINT64_C(50000000);
            if(delay>deadline-value)delay=deadline-value;
            put64(expected+168,delay);put64(expected+176,value+delay);
        }
    }
    if(previous==51){
        put64(expected+200,1);
        if(error&&error!=ESRCH){
            put64(expected+96,HCT_SYSTEM_ERROR);put64(expected+104,error);
            put64(expected+112,HCT_KILL);put64(expected+208,1);
        }
    }
    if(previous==52||previous==54){
        if(error==EINTR)direct=1;
        else if(error){
            if(error==ECHILD&&s->owner_lost){
                put64(expected+96,HCT_CUSTODY_LOST);put64(expected+104,error);
                put64(expected+112,previous==52?HCT_WAIT_BLOCK:HCT_WAIT_NOHANG);
            }else{
                if(get64(prior+72)!=1)return 0;
                put64(expected+96,HCT_SYSTEM_ERROR);put64(expected+104,error);
                put64(expected+112,previous==52?HCT_WAIT_BLOCK:HCT_WAIT_NOHANG);
                put64(expected+160,1);
            }
        }else if(previous==52||value){
            if(value!=(uint64_t)s->pid||!s->reaped)return 0;
            put64(expected+88,s->value1);
        }
        if(previous==54&&error!=EINTR)put64(expected+192,1);
    }
    if(previous==53&&error){
        uint64_t slot=s->last_argument;
        int suppress=!get64(prior+152)&&error<4096&&slot!=0&&slot!=7&&slot!=8;
        if(!suppress){
            put64(expected+96,HCT_SYSTEM_ERROR);put64(expected+104,error);put64(expected+112,HCT_CLOSE);
            if(get64(prior+72)==1&&(!get64(prior+152)||slot==3||slot==5))
                put64(expected+160,1);
        }
    }
    if(previous>=55&&previous<=58){
        if(error==EINTR&&(previous==56||previous==58))direct=1;
        else if(error){
            put64(expected+96,HCT_SYSTEM_ERROR);put64(expected+104,error);
            put64(expected+112,s->last_action);put64(expected+208,1);put64(expected+232,2);
        }else if(previous==55){
            if(value>UINT64_MAX-UINT64_C(250000000))return 0;
            uint64_t bound=get64(prior+64);
            if(value+UINT64_C(250000000)<bound)bound=value+UINT64_C(250000000);
            put64(expected+224,bound);put64(expected+232,500000);direct=1;
        }else if(previous==56){
            if(value){
                if(value!=(uint64_t)s->pid||!s->reaped)return 0;
                put64(expected+88,s->value1);put64(expected+232,2);
            }else direct=1;
        }else if(previous==57){
            if(value>=get64(prior+224))put64(expected+232,2);
            else{
                uint64_t delay=get64(prior+232)*2;
                if(delay>UINT64_C(50000000))delay=UINT64_C(50000000);
                if(delay>get64(prior+224)-value)delay=get64(prior+224)-value;
                put64(expected+232,delay);put64(expected+240,value+delay);direct=1;
            }
        }else direct=1;
    }
    if(cleanup&&!direct&&s->owner_lost){
        put64(expected+96,HCT_CUSTODY_LOST);
        if(!get64(expected+104)){put64(expected+104,ECHILD);put64(expected+112,HCT_WAIT_BLOCK);}
    }
    int ready=!cleanup&&((previous==14&&!error)
        ||(previous==15&&!error&&get64(expected+56)<c->input_bytes)
        ||((previous==16||previous==17)&&!error&&value)||(previous==20&&!error));
    uint64_t ready_phase=0;
    if(ready){
        uint64_t bits=get64(expected+120);if(bits>7)return 0;
        if(bits&1){put64(expected+120,bits&6);ready_phase=15;}
        else if(bits&2){put64(expected+120,bits&5);ready_phase=16;}
        else if(bits&4){put64(expected+120,bits&3);ready_phase=17;}
        else ready_phase=12;
        if(phase!=ready_phase)return 0;
    }
    put64(expected+16,s->seq+1);put64(expected+24,action);
    put64(expected+32,arg);put64(expected+40,phase);
    if(action==HCT_CLOSE){
        if(arg>=HCT_FDS||(s->issued_close_mask&(UINT64_C(1)<<arg)))return 0;
        put64(expected+216,s->issued_close_mask|(UINT64_C(1)<<arg));
    }
    if(get64(expected+80)!=(s->pid>0?(uint64_t)s->pid:0)
        ||get64(expected+88)!=(uint64_t)(unsigned)s->status
        ||get64(expected+144)!=s->exec_error_bytes
        ||memcmp(state,expected,sizeof expected))return 0;
    if(cleanup){
        if(direct){
            if(previous==52)return phase==52&&action==HCT_WAIT_BLOCK&&!arg&&!amount&&!auxiliary;
            if(previous==54||previous==56)
                return error==EINTR
                    ?phase==previous&&action==HCT_WAIT_NOHANG&&!arg&&!amount&&!auxiliary
                    :phase==57&&action==HCT_CLOCK&&!arg&&!amount&&!auxiliary;
            if(previous==55||previous==58){
                if(previous==58&&error==EINTR)
                    return phase==58&&action==HCT_SLEEP&&!arg&&!auxiliary&&amount==get64(state+240);
                return phase==56&&action==HCT_WAIT_NOHANG&&!arg&&!amount&&!auxiliary;
            }
            return previous==57&&phase==58&&action==HCT_SLEEP&&!arg&&!auxiliary
                &&amount==get64(state+240);
        }
        return cleanup_projection(s,expected,phase,action,arg,amount,auxiliary);
    }
    if(phase>=50||s->owner_lost)return 0;
    /* A remembered startup close/exec error is deliberately carried through
       the remaining ExitStack closes / error-reader finally, before cleanup. */
    if(get64(state+96)&&!(phase==7||phase==9))return 0;
    switch(action){
    case HCT_IMAGE_WRITE:
        return phase==2&&(previous==1||previous==2)&&(!error||(previous==2&&error==EINTR))
            &&mask==1&&!s->pid&&!arg&&!auxiliary&&amount==get64(state+48)&&amount<c->executable_bytes;
    case HCT_SEAL_ADD:
        return phase==3&&(previous==1||previous==2)&&!error&&mask==1&&!s->pid
            &&!arg&&!amount&&!auxiliary&&get64(state+48)==c->executable_bytes;
    case HCT_SEAL_GET:
        return phase==4&&previous==3&&!error&&mask==1&&!s->pid&&!arg&&!amount&&!auxiliary;
    case HCT_HOST_INIT:
        return phase==22&&previous==4&&!error&&mask==1&&!s->pid&&!arg&&!amount&&!auxiliary;
    case HCT_PIPE:
        return phase==5&&!error&&!s->pid&&arg==get64(state+136)&&arg<4
            &&mask==((UINT64_C(1)<<(1+2*arg))-1)&&!amount&&!auxiliary
            &&((previous==22&&arg==0)||(previous==5&&arg<3)||(previous==26&&arg==3));
    case HCT_HOST_WRAP:
        return !error&&mask==127&&!s->pid&&!amount&&!auxiliary
            &&((phase==23&&previous==5&&arg==2)||(phase==24&&previous==23&&arg==3)
                ||(phase==25&&previous==24&&arg==5));
    case HCT_HOST_AUDIT:
        return phase==26&&previous==25&&!error&&mask==127&&!s->pid&&!arg&&!amount&&!auxiliary;
    case HCT_HOST_PREPARE:
        return phase==27&&previous==5&&!error&&mask==511&&!s->pid&&!s->argv&&!arg&&!amount&&!auxiliary;
    case HCT_FORK_EXEC:
        return phase==6&&previous==27&&!error&&mask==511&&!s->pid&&s->argv&&!arg&&!amount&&!auxiliary;
    case HCT_CLOSE:
        if(amount||auxiliary||arg>=HCT_FDS||s->fd[arg]<0)return 0;
        if(phase==7){
            static const unsigned slots[4]={8,6,4,1};
            static const uint64_t masks[4]={511,255,191,175};
            uint64_t cursor=get64(state+128);
            return (previous==6||previous==7)&&cursor<4&&arg==slots[cursor]
                &&mask==masks[cursor]&&(!error||cursor>1)&&s->pid&&!s->reaped;
        }
        if(phase==9)return previous==8&&!error&&!value&&mask==173&&arg==7&&s->pid&&!s->reaped
            &&((!s->exec_error_bytes&&s->exec_confirmed)||s->exec_error_bytes==8);
        if(phase==11)return previous==29&&!error&&!c->input_bytes&&get64(state+184)==1&&mask==45&&arg==2;
        if(phase!=20)return 0;
        if(arg==2)return previous==15&&(error==EPIPE||(!error&&get64(state+56)==c->input_bytes));
        return !error&&!value&&((arg==3&&previous==16)||(arg==5&&previous==17));
    case HCT_EXEC_READ:
        return phase==8&&!arg&&!amount&&!auxiliary&&mask==173&&s->pid&&!s->reaped&&!s->exec_confirmed
            &&((previous==7&&!error&&get64(state+128)==4)
                ||(previous==8&&(error==EINTR||(!error&&value))));
    case HCT_HOST_ENTER:
        return phase==28&&previous==9&&!error&&mask==45&&s->exec_confirmed&&!arg&&!amount&&!auxiliary;
    case HCT_HOST_FLUSH:
        return phase==29&&previous==10&&!error&&mask==45&&get64(state+184)==1&&!arg&&!amount&&!auxiliary;
    case HCT_CLOCK:
        if(arg||amount||auxiliary||!s->exec_confirmed||!s->pid||s->reaped)return 0;
        if(phase==10)return previous==28&&!error&&!get64(state+184);
        if(get64(state+184)!=1)return 0;
        if(phase==12)return(previous==29&&!error&&c->input_bytes)||(previous==11&&!error)
            ||(previous==13&&error==EINTR)||(ready&&ready_phase==12);
        if(phase==14)return previous==13&&!error;
        return phase==19&&previous==18&&!error&&!value;
    case HCT_POLL:
        return phase==13&&previous==12&&!error&&!arg&&!auxiliary&&s->exec_confirmed&&!s->reaped
            &&(mask&44)&&get64(state+184)==1&&value<get64(state+64)&&amount==get64(state+64)-value;
    case HCT_STDIN_WRITE:{
        uint64_t offset=get64(state+56),count=c->input_bytes-offset;
        if(phase!=15||arg||s->fd[2]<0||offset>=c->input_bytes||amount!=offset||get64(state+184)!=1)return 0;
        if(count>HCT_PIPE_BYTES)count=HCT_PIPE_BYTES;
        return auxiliary==count&&((ready&&ready_phase==15)||(previous==15&&error==EINTR));}
    case HCT_STDOUT_READ:
        return phase==16&&!arg&&!amount&&!auxiliary&&s->fd[3]>=0&&get64(state+184)==1
            &&((ready&&ready_phase==16)||(previous==16&&error==EINTR));
    case HCT_STDERR_READ:
        return phase==17&&!arg&&!amount&&!auxiliary&&s->fd[5]>=0&&get64(state+184)==1
            &&((ready&&ready_phase==17)||(previous==17&&error==EINTR));
    case HCT_WAIT_NOHANG:
        return phase==18&&!arg&&!amount&&!auxiliary&&s->pid&&!s->reaped&&!(mask&44)&&get64(state+184)==1
            &&((previous==12&&!error)||(previous==18&&error==EINTR)||(previous==21&&!error));
    case HCT_SLEEP:
        return phase==21&&!arg&&!auxiliary&&s->pid&&!s->reaped&&!(mask&44)&&get64(state+184)==1
            &&amount==get64(state+176)&&((previous==19&&!error&&value<get64(state+64))
                ||(previous==21&&error==EINTR));
    default:return 0;
    }
}
static int mechanical(struct session *s, uint64_t action, uint64_t arg,
                      uint64_t amount, uint64_t auxiliary) {
    const struct hia_cold_config *c = s->config;
    s->value0 = s->value1 = 0;
    s->error = 0;
    switch (action) {
    case HCT_HOST_INIT:
    case HCT_HOST_WRAP:
    case HCT_HOST_AUDIT:
    case HCT_HOST_PREPARE:
    case HCT_HOST_ENTER:
    case HCT_HOST_FLUSH: {
        if(amount||auxiliary||(action!=HCT_HOST_WRAP&&arg)
            ||(action==HCT_HOST_WRAP&&arg!=2&&arg!=3&&arg!=5))return -1;
        if(c->host){
            struct hia_cold_snapshot facts=snapshot(s);
            if(action==HCT_HOST_WRAP){
                unsigned ownership=0;
                int descriptor=s->fd[arg];
                if(descriptor<0)return -1;
                s->error=c->host->wrap(c->host->context,(unsigned)arg,descriptor,&ownership,&facts);
                if(ownership>3||ownership==2||(ownership&&!s->error))return -1;
                s->value0=ownership;
                if(ownership&1)s->issued_close_mask|=UINT64_C(1)<<arg;
                if(ownership&2)s->fd[arg]=-1;
            }else s->error=c->host->perform(c->host->context,(unsigned)action,(unsigned)arg,&facts);
        }
        if(!s->error&&action==HCT_HOST_INIT)s->value0=c->host!=NULL;
        if(!s->error&&action==HCT_HOST_PREPARE){
            if(!c->cwd||(c->argument_count&&!c->arguments)
                ||(c->pass_fd_count&&!c->pass_fds)||c->pass_fd_count>2)return -1;
            for(size_t at=0;at<c->argument_count;++at)if(!c->arguments[at])return -1;
            for(size_t at=0;at<c->pass_fd_count;++at){
                if(c->pass_fds[at]<3)return -1;
                for(size_t other=0;other<at;++other)
                    if(c->pass_fds[at]==c->pass_fds[other])return -1;
            }
            if(prepare_arguments(s)!=0)s->error=actual_errno();
        }
        break;
    }
    case HCT_MEMFD: {
        if (arg || amount || auxiliary || s->fd[0] >= 0) return -1;
        int fd = (int)syscall(SYS_memfd_create,
            c->linked_environment ? "hia-linked-native-observer" : "hia-native-observer", 2);
        if (fd < 0) s->error = actual_errno();
        else { s->fd[0] = fd; s->value0 = (uint64_t)fd; }
        break;
    }
    case HCT_IMAGE_WRITE: {
        if (arg || auxiliary || s->fd[0] < 0 || amount >= c->executable_bytes) return -1;
        ssize_t count = write(s->fd[0], c->executable + amount, c->executable_bytes - amount);
        if (count < 0) s->error = actual_errno(); else s->value0 = (uint64_t)count;
        break;
    }
    case HCT_SEAL_ADD:
    case HCT_SEAL_GET: {
        if (arg || amount || auxiliary || s->fd[0] < 0) return -1;
        int value = fcntl(s->fd[0], action == HCT_SEAL_ADD ? F_ADD_SEALS : F_GET_SEALS,
                          action == HCT_SEAL_ADD ? 15 : 0);
        if (value < 0) s->error = actual_errno(); else s->value0 = (uint64_t)value;
        break;
    }
    case HCT_PIPE: {
        if (arg >= 4 || amount || auxiliary) return -1;
        unsigned slot = 1 + 2 * (unsigned)arg;
        if (s->fd[slot] >= 0 || s->fd[slot + 1] >= 0) return -1;
        int pair[2];
        if (pipe2(pair, O_CLOEXEC) != 0) s->error = actual_errno();
        else { s->fd[slot] = pair[0]; s->fd[slot + 1] = pair[1]; }
        break;
    }
    case HCT_FORK_EXEC: {
        if (arg || amount || auxiliary || owned_mask(s) != 511
                || s->pid || !s->argv) return -1;
        pid_t pid = fork();
        if (pid < 0) s->error = actual_errno();
        else if (pid == 0) child_exec(s);
        else { s->pid = pid; s->value0 = (uint64_t)pid; }
        break;
    }
    case HCT_CLOSE:
        if (arg >= HCT_FDS || amount || auxiliary || s->fd[arg] < 0) return -1;
        close_slot(s, (unsigned)arg);
        break;
    case HCT_EXEC_READ: {
        if (arg || amount || auxiliary || s->fd[7] < 0 || !s->pid || s->reaped) return -1;
        unsigned char extra;
        void *at = s->exec_error_bytes < 8 ? s->exec_error + s->exec_error_bytes : &extra;
        size_t room = s->exec_error_bytes < 8 ? 8 - s->exec_error_bytes : 1;
        ssize_t count = read(s->fd[7], at, room);
        if (count < 0) s->error = actual_errno();
        else if (count > 0 && s->exec_error_bytes == 8) s->error = EPROTO;
        else {
            s->value0 = (uint64_t)count;
            s->exec_error_bytes += (size_t)count;
            if (s->exec_error_bytes == 8) s->value1 = get64(s->exec_error);
            if (count == 0 && s->exec_error_bytes == 0) s->exec_confirmed = 1;
        }
        break;
    }
    case HCT_CLOCK: {
        if (arg || amount || auxiliary || !s->exec_confirmed) return -1;
        if (timestamp(&s->value0) != 0) s->error = actual_errno();
        else if (s->result->start_ns == 0) s->result->start_ns = s->value0;
        break;
    }
    case HCT_POLL: {
        if (arg || auxiliary || !s->exec_confirmed || s->reaped) return -1;
        struct pollfd descriptors[3];
        unsigned bits[3];
        nfds_t count = 0;
        if (s->fd[2] >= 0) { descriptors[count] = (struct pollfd){s->fd[2], POLLOUT, 0}; bits[count++] = 1; }
        if (s->fd[3] >= 0) { descriptors[count] = (struct pollfd){s->fd[3], POLLIN, 0}; bits[count++] = 2; }
        if (s->fd[5] >= 0) { descriptors[count] = (struct pollfd){s->fd[5], POLLIN, 0}; bits[count++] = 4; }
        if (!count) return -1;
        int value = poll(descriptors, count, poll_milliseconds(amount));
        if (value < 0) s->error = actual_errno();
        else for (nfds_t i = 0; i < count; ++i)
            if (descriptors[i].revents) s->value0 |= bits[i];
        break;
    }
    case HCT_STDIN_WRITE: {
        if (arg || s->fd[2] < 0 || amount >= c->input_bytes
                || auxiliary == 0 || auxiliary > HCT_PIPE_BYTES
                || auxiliary > c->input_bytes - amount) return -1;
        ssize_t count = write(s->fd[2], c->input + amount, (size_t)auxiliary);
        if (count < 0) s->error = actual_errno(); else s->value0 = (uint64_t)count;
        break;
    }
    case HCT_STDOUT_READ:
    case HCT_STDERR_READ: {
        unsigned which = action == HCT_STDOUT_READ ? 0 : 1;
        unsigned slot = which == 0 ? 3 : 5;
        if (arg || amount || auxiliary || s->fd[slot] < 0) return -1;
        struct capture *p = &s->output[which];
        /* Allocate before the syscall; failure must not consume pipe bytes. */
        if (reserve_read(p) != 0) { s->error = actual_errno(); break; }
        ssize_t count = read(s->fd[slot], p->data + p->size, HCT_READ_BYTES);
        if (count < 0) s->error = actual_errno();
        else { ++p->reads; p->size += (size_t)count; s->value0 = (uint64_t)count; }
        break;
    }
    case HCT_WAIT_NOHANG:
    case HCT_WAIT_BLOCK: {
        if (arg || amount || auxiliary || !s->pid || s->reaped || s->owner_lost) return -1;
        int status = 0;
        pid_t pid = waitpid(s->pid, &status, action == HCT_WAIT_NOHANG ? WNOHANG : 0);
        if (pid < 0) {
            s->error = actual_errno();
            if (errno == ECHILD) s->owner_lost = 1;
            /* EINTR is an actual transient receipt, not a terminal cleanup
               exception. A host pending-signal exception is captured later. */
            if (action == HCT_WAIT_BLOCK && s->error != EINTR)
                record_cleanup_error(s, s->error, HCT_WAIT_BLOCK);
        } else if (pid == 0 && action == HCT_WAIT_NOHANG
                && get64(s->state.bytes + 40) == 54) {
            s->pre_signal_sequence = s->seq;
            s->pre_signal_pid = s->pid;
        } else if (pid > 0) {
            if (pid != s->pid || returncode(status) == INT_MIN) return -1;
            s->reaped = 1; s->status = status;
            s->value0 = (uint64_t)pid; s->value1 = (uint64_t)(unsigned)status;
        }
        break;
    }
    case HCT_KILL:
        if (arg || amount || auxiliary || !s->pid || s->reaped || s->owner_lost
                || s->pre_signal_pid != s->pid
                || s->pre_signal_sequence == UINT64_MAX
                || s->pre_signal_sequence + 1 != s->seq) return -1;
        s->pre_signal_sequence = 0; s->pre_signal_pid = 0;
        if (kill(s->pid, SIGKILL) != 0) {
            s->error = actual_errno();
            if (s->error != ESRCH) record_cleanup_error(s, s->error, HCT_KILL);
        }
        break;
    case HCT_SLEEP: {
        if (arg || auxiliary || !s->exec_confirmed || s->reaped) return -1;
        struct timespec deadline = {
            (time_t)(amount / UINT64_C(1000000000)),
            (long)(amount % UINT64_C(1000000000))
        };
        int error = clock_nanosleep(CLOCK_MONOTONIC, TIMER_ABSTIME, &deadline, NULL);
        if (error != 0) s->error = (unsigned)error;
        break;
    }
    default:
        return -1;
    }
    return 0;
}
static void emergency_cleanup(struct session *s) {
    /* Failed-owner cleanup never supplies a successful HIA receipt. Observe
       the real waitable child before any signal. This does not erase the
       documented race with a waiter that violates the single-owner profile. */
    if (s->pid && !s->reaped && !s->owner_lost) {
        int may_signal = 0;
        for (;;) {
            int status = 0;
            pid_t pid = waitpid(s->pid, &status, WNOHANG);
            if (pid < 0 && errno == EINTR) continue;
            if (pid == 0) may_signal = 1;
            else if (pid == s->pid && returncode(status) != INT_MIN) {
                s->status = status; s->reaped = 1;
            } else if (pid < 0 && errno == ECHILD) {
                s->owner_lost = 1;
                record_cleanup_error(s, ECHILD, HCT_WAIT_NOHANG);
            } else {
                record_cleanup_error(s, pid < 0 ? actual_errno() : EPROTO, HCT_WAIT_NOHANG);
            }
            break;
        }
        if (may_signal) {
            if (kill(s->pid, SIGKILL) != 0 && errno != ESRCH)
                record_cleanup_error(s, actual_errno(), HCT_KILL);
            for (;;) {
                int status = 0;
                pid_t pid = waitpid(s->pid, &status, 0);
                if (pid < 0 && errno == EINTR) continue;
                if (pid == s->pid && returncode(status) != INT_MIN) {
                    s->status = status; s->reaped = 1;
                } else if (pid < 0 && errno == ECHILD) {
                    s->owner_lost = 1;
                    record_cleanup_error(s, ECHILD, HCT_WAIT_BLOCK);
                } else {
                    record_cleanup_error(s, pid < 0 ? actual_errno() : EPROTO, HCT_WAIT_BLOCK);
                }
                break;
            }
        }
    }
    for (int slot = HCT_FDS - 1; slot >= 0; --slot)
        if (s->fd[slot] >= 0 && !(s->issued_close_mask & (UINT64_C(1)<<slot))) {
            s->issued_close_mask |= UINT64_C(1)<<slot;
            close_slot(s, (unsigned)slot);
        }
    if(s->config->host && (owned_mask(s)||(s->pid&&!s->reaped&&!s->owner_lost))){
        struct hia_cold_snapshot facts=snapshot(s);
        if(s->config->host->handoff(s->config->host->context,&facts)==0){
            s->result->handed_off=1;
            s->result->handoff_fd_mask=owned_mask(s);
            s->result->handoff_pid=s->pid&&!s->reaped&&!s->owner_lost?s->pid:0;
        }
    }
}
static void request_bytes(struct session *s, unsigned char request[HCT_REQUEST_BYTES]) {
    memset(request, 0, HCT_REQUEST_BYTES);
    put64(request + 0, HCT_REQUEST_MAGIC);
    put64(request + 8, s->config->nonce);
    put64(request + 16, s->seq);
    put64(request + 24, s->last_action);
    put64(request + 32, s->last_argument);
    put64(request + 40, s->error);
    put64(request + 48, s->value0);
    put64(request + 56, s->value1);
    put64(request + 64, s->owner_lost);
    put64(request + 72, s->config->executable_bytes);
    put64(request + 80, s->config->input_bytes);
    put64(request + 88, s->config->timeout_ns);
    put64(request + 96, owned_mask(s));
    put64(request + 104, s->pid > 0 ? (uint64_t)s->pid : 0);
    put64(request + 112, s->reaped);
    put64(request + 120, HCT_CANARY);
}
static void append_event(struct session *s, uint64_t action, uint64_t arg,
                         uint64_t amount, uint64_t auxiliary) {
    size_t at = (size_t)(s->seq - 1);
    if (at >= s->trace_capacity) {
        if (s->trace != NULL) s->result->trace_overflow = 1;
        return;
    }
    if (s->trace != NULL)
        s->trace[at] = (struct hia_cold_event){
            s->seq, action, arg, amount, auxiliary, s->value0, s->value1,
            owned_mask(s), s->pid, s->error, (unsigned)s->reaped
        };
}
int hia_cold_transport_run(hia_cold_policy policy,
                          const struct hia_cold_config *config,
                          struct hia_cold_result *result,
                          struct hia_cold_event *trace, size_t trace_capacity) {
    if (result == NULL) { errno = EINVAL; return -1; }
    memset(result, 0, sizeof *result);
    for(unsigned slot=0;slot<HCT_FDS;++slot)result->remaining_fds[slot]=-1;
    result->returncode = INT_MIN;
    if (policy == NULL || !valid_entry(config) || (trace_capacity && trace == NULL)) {
        result->outcome = HCT_SYSTEM_ERROR;
        result->primary_errno = EINVAL;
        errno = EINVAL;
        return -1;
    }
    struct session s;
    memset(&s, 0, sizeof s);
    s.config = config; s.result = result; s.trace = trace; s.trace_capacity = trace_capacity;
    for (unsigned i = 0; i != HCT_FDS; ++i) s.fd[i] = -1;
    s.state.before = s.state.after = HCT_CANARY;
    result->nonce = config->nonce;
    int complete = 0;
    for (;;) {
        unsigned char request[HCT_REQUEST_BYTES], preserved[HCT_REQUEST_BYTES];
        unsigned char prior[HCT_STATE_BYTES];
        struct { uint64_t before; unsigned char bytes[HCT_REPLY_BYTES]; uint64_t after; } reply;
        request_bytes(&s, request);
        memcpy(preserved, request, sizeof request);
        memcpy(prior, s.state.bytes, sizeof prior);
        reply.before = reply.after = HCT_CANARY;
        memset(reply.bytes, 0xa5, sizeof reply.bytes);
        uint64_t returned = policy(request, sizeof request, reply.bytes, sizeof reply.bytes,
                                   s.state.bytes, sizeof s.state.bytes);
        if (returned != HCT_REPLY_BYTES || memcmp(request, preserved, sizeof request) != 0
                || reply.before != HCT_CANARY || reply.after != HCT_CANARY
                || s.state.before != HCT_CANARY || s.state.after != HCT_CANARY
                || get64(reply.bytes) != HCT_REPLY_MAGIC
                || get64(reply.bytes + 8) != config->nonce
                || s.seq == UINT64_MAX || get64(reply.bytes + 16) != s.seq + 1) break;
        uint64_t seal = HCT_CANARY;
        for (unsigned i = 0; i != 7; ++i) seal ^= get64(reply.bytes + 8 * i);
        if (get64(reply.bytes + 56) != seal
                || !issued_projection(&s, preserved, prior, reply.bytes)) break;
        uint64_t action = get64(reply.bytes + 24), arg = get64(reply.bytes + 32);
        uint64_t amount = get64(reply.bytes + 40), auxiliary = get64(reply.bytes + 48);
        if(action==HCT_WAIT_NOHANG&&get64(s.state.bytes+40)==18&&get64(prior+40)==12){
            /* issued_projection has already bound this issue to the actual
               successful CLOCK receipt after the last IO slot retired. */
            if(s.wait_clock_observed||get64(preserved+24)!=HCT_CLOCK
               ||get64(preserved+40)!=0||get64(prior+184)!=1)break;
            s.wait_clock_ns=get64(preserved+48);
            s.wait_clock_observed=1;
        }
        ++s.seq;
        s.last_action = action; s.last_argument = arg;
        if(action==HCT_CLOSE)s.issued_close_mask|=UINT64_C(1)<<arg;
        if(action==HCT_HOST_HANDOFF){
            if(!config->host||arg==HCT_RETURNED||arg>HCT_CUSTODY_LOST
                ||amount!=owned_mask(&s)||auxiliary!=(s.pid>0?(uint64_t)s.pid:0))break;
            struct hia_cold_snapshot facts=snapshot(&s);
            if(config->host->handoff(config->host->context,&facts)!=0)break;
            result->outcome=(unsigned)arg;
            result->primary_errno=(unsigned)get64(s.state.bytes+104);
            result->primary_stage=(unsigned)get64(s.state.bytes+112);
            result->policy_complete=1;result->handed_off=1;
            result->handoff_fd_mask=owned_mask(&s);
            result->handoff_pid=s.pid&&!s.reaped&&!s.owner_lost?s.pid:0;
            complete=2;
            s.error=0;s.value0=s.value1=0;
            append_event(&s,action,arg,amount,auxiliary);
            break;
        }
        if (action == HCT_FINISH) {
            if (owned_mask(&s) != 0 || arg > HCT_CUSTODY_LOST
                    || (s.pid && !s.reaped && !s.owner_lost)
                    || (s.owner_lost && arg != HCT_CUSTODY_LOST)
                    || (arg == HCT_RETURNED && (!s.exec_confirmed || !s.reaped))
                    || amount > UINT_MAX || auxiliary > UINT_MAX) break;
            result->outcome = (unsigned)arg;
            result->primary_errno = (unsigned)amount;
            result->primary_stage = (unsigned)auxiliary;
            result->policy_complete = 1;
            complete = arg != HCT_CUSTODY_LOST;
            s.error = 0; s.value0 = s.value1 = 0;
            append_event(&s, action, arg, amount, auxiliary);
            break;
        }
        unsigned before_error=0;
        if(config->host){
            struct hia_cold_snapshot facts=snapshot(&s);
            before_error=config->host->before(config->host->context,(unsigned)action,(unsigned)arg,&facts);
        }
        if(before_error){s.error=before_error;s.value0=s.value1=0;}
        else {
            int unlocked=action<HCT_FINISH&&action!=HCT_CLOSE
                &&action!=HCT_FORK_EXEC&&action!=HCT_CLOCK;
            if(unlocked)block_enter(&s);
            int performed=mechanical(&s,action,arg,amount,auxiliary);
            if(unlocked)block_leave(&s);
            if(performed!=0)break;
            if(config->host&&s.error){
                struct hia_cold_snapshot facts=snapshot(&s);
                s.error=config->host->error(config->host->context,(unsigned)action,(unsigned)arg,s.error,&facts);
            }
        }
        append_event(&s, action, arg, amount, auxiliary);
    }
    if (!result->policy_complete) {
        result->outcome = HCT_POLICY_LOST;
        result->primary_errno = EPROTO;
        result->primary_stage = (unsigned)s.last_action;
        emergency_cleanup(&s);
    }
    result->action_count = s.seq;
    result->child_pid = s.pid;
    result->spawned = s.pid != 0;
    result->exec_confirmed = (unsigned)s.exec_confirmed;
    result->reaped = (unsigned)s.reaped;
    result->owner_lost = (unsigned)s.owner_lost;
    result->wait_status = s.status;
    result->returncode = s.reaped ? returncode(s.status) : INT_MIN;
    result->final_fd_mask = owned_mask(&s);
    /* These are actual still-owned slots, not a zero-resource assertion. The
       visible hosted Session adopts unwrapped residuals without callbacks
       immediately on return, even if every fallible handoff was rejected. */
    for(unsigned slot=0;slot<HCT_FDS;++slot)result->remaining_fds[slot]=s.fd[slot];
    if (timestamp(&result->end_ns) != 0) {
        record_cleanup_error(&s, actual_errno(), HCT_CLOCK);
        complete = 0;
    }
    result->stdout_bytes = s.output[0].data; result->stdout_size = s.output[0].size;
    result->stdout_reads = s.output[0].reads;
    result->stderr_bytes = s.output[1].data; result->stderr_size = s.output[1].size;
    result->stderr_reads = s.output[1].reads;
    free(s.argv);
    return complete == 2 ? 1 : complete ? 0 : -1;
}
void hia_cold_transport_release(struct hia_cold_result *result) {
    if (result == NULL) return;
    free(result->stdout_bytes); free(result->stderr_bytes);
    result->stdout_bytes = result->stderr_bytes = NULL;
    result->stdout_size = result->stderr_size = 0;
}
