/* Linux x86-64, explicit native transport prototype.
 * R3 adds an explicit, separately qualified hosted-owner capability.
 * No default Python selector is installed by this file.
 * The caller pins the HIA policy image and keeps every input alive for this call.
 */
#ifndef HIA_COLD_NATIVE_TRANSPORT_H
#define HIA_COLD_NATIVE_TRANSPORT_H
#include <stddef.h>
#include <stdint.h>
#ifdef __cplusplus
extern "C" {
#endif

typedef uint64_t (*hia_cold_policy)(
    const void *, uint64_t, void *, uint64_t, void *, uint64_t);

enum hia_cold_action {
    HCT_MEMFD = 1, HCT_IMAGE_WRITE = 2, HCT_SEAL_ADD = 3,
    HCT_SEAL_GET = 4, HCT_PIPE = 5, HCT_FORK_EXEC = 6,
    HCT_CLOSE = 7, HCT_EXEC_READ = 8, HCT_CLOCK = 9,
    HCT_POLL = 10, HCT_STDIN_WRITE = 11, HCT_STDOUT_READ = 12,
    HCT_STDERR_READ = 13, HCT_WAIT_NOHANG = 14, HCT_KILL = 15,
    HCT_WAIT_BLOCK = 16, HCT_SLEEP = 17, HCT_FINISH = 18,
    HCT_HOST_INIT = 19, HCT_HOST_WRAP = 20, HCT_HOST_AUDIT = 21,
    HCT_HOST_PREPARE = 22, HCT_HOST_ENTER = 23, HCT_HOST_HANDOFF = 24,
    HCT_HOST_FLUSH = 25
};

enum hia_cold_outcome {
    HCT_RETURNED = 0, HCT_TIMEOUT_IO = 1, HCT_SYSTEM_ERROR = 2,
    HCT_EXEC_ERROR = 3, HCT_TIMEOUT_WAIT = 4, HCT_POLICY_LOST = 5,
    HCT_CUSTODY_LOST = 6
};

/* A callback error is a real Python exception retained by the visible owner.
 * It is not an errno and never supplies a successful operation receipt. */
#define HCT_PY_EXCEPTION UINT32_C(1073741825)
#define HCT_PY_KEYBOARD UINT32_C(1073741826)

struct hia_cold_snapshot {
    const int *fds;                 /* Nine actual private descriptor slots. */
    int64_t pid;
    unsigned reaped, owner_lost;
    int wait_status;
    uint64_t phase, outcome, error, stage;
    unsigned context_entered, clock_started, keyboard_wait_done;
    uint64_t issued_close_mask;
    const unsigned char *stdout_bytes, *stderr_bytes;
    size_t stdout_size, stderr_size, stdout_reads, stderr_reads;
    /* Same already-observed native clock receipts; no extra clock read.
       wait_clock_observed is set only at the validated normal IO->wait edge. */
    uint64_t clock_start_ns, wait_clock_ns;
    unsigned wait_clock_observed;
};

/* The explicit CPython bridge supplies these mechanical, individually named
 * capabilities. No callback chooses the next policy action or calls an old
 * whole run/Popen.__init__/communicate method. The owner is GC-visible. */
struct hia_cold_host {
    void *context;
    unsigned (*before)(void *, unsigned, unsigned,
                       const struct hia_cold_snapshot *);
    unsigned (*perform)(void *, unsigned, unsigned,
                        const struct hia_cold_snapshot *);
    unsigned (*close)(void *, unsigned, int, int *,
                      const struct hia_cold_snapshot *);
    unsigned (*error)(void *, unsigned, unsigned, unsigned,
                      const struct hia_cold_snapshot *);
    /* Failure adopts nothing. Success must follow a complete validation pass
       and an allocation/callback-free commit of the actual remaining owners. */
    int (*handoff)(void *, const struct hia_cold_snapshot *);
    void (*block_enter)(void *); /* Release the GIL only around raw OS effects. */
    void (*block_leave)(void *); /* Reacquire before any callback. */
    /* Exact FileIO -> Buffered ownership receipt for the issued slot only.
       Bit 0: its constructor-error close was issued once. Bit 1: the actual
       canonical raw owner's closed state confirmed retirement. Only 0/1/3
       are valid; nonzero requires an actual callback error. */
    unsigned (*wrap)(void *, unsigned, int, unsigned *,
                     const struct hia_cold_snapshot *);
};
struct hia_cold_config {
    const unsigned char *executable;
    size_t executable_bytes;
    const unsigned char *input;
    size_t input_bytes;
    const char *cwd;
    const char *const *arguments; /* Excludes argv[0]; no shell. */
    size_t argument_count;
    const int *pass_fds;          /* Outer-owned output and/or snapshot only. */
    size_t pass_fd_count;         /* 0..2; never closed by the parent bridge. */
    uint64_t timeout_ns;          /* 20e9 normally; .1s is 100000000. */
    uint64_t nonce;               /* Nonzero, independently bound by caller. */
    unsigned linked_environment; /* 0 = original flat four-key env, 1 = inherit. */
    const struct hia_cold_host *host; /* NULL = raw profile; non-NULL = explicit hosted bridge. */
    char *const *environment; /* Explicit flat host environment after its actual audit hook. */
};

struct hia_cold_event {
    uint64_t ordinal, action, argument, amount, auxiliary;
    uint64_t value0, value1, fd_mask;
    int64_t child_pid;
    uint32_t error_number, child_reaped;
};

struct hia_cold_result {
    uint64_t nonce, action_count;
    unsigned outcome;
    unsigned primary_errno, primary_stage;
    unsigned cleanup_errno, cleanup_stage;
    int64_t child_pid;
    int wait_status, returncode;
    unsigned spawned, exec_confirmed, reaped, owner_lost;
    unsigned policy_complete, trace_overflow;
    unsigned handed_off; /* Real remaining resources accepted by the visible host owner. */
    uint64_t handoff_fd_mask;
    int64_t handoff_pid;
    uint64_t start_ns, end_ns;
    uint64_t final_fd_mask;
    int remaining_fds[9]; /* Exact terminal private slots, including failed handoff. */
    unsigned char *stdout_bytes, *stderr_bytes;
    size_t stdout_size, stderr_size;
    size_t stdout_reads, stderr_reads; /* Include a genuine EOF read. */
};

/* Preconditions of this NEW explicit native profile:
 * Linux x86-64; standard descriptors 0/1/2 are open; SIGPIPE is ignored;
 * exact immutable byte/string inputs; valid caller-owned pass_fds >= 3;
 * one owner of this child (no independent SIGCHLD waiter).
 *
 * Result 0 means a complete native protocol, NOT successful child execution,
 * cold qualification, or compatibility with Python exception/reflection APIs.
 * Result 1 means a real exception-owner handoff with explicitly nonzero/live
 * resources where present. It is not zero-resource completion or qualification.
 * Result -1 means protocol/custody loss or invalid entry; inspect every field.
 *
 * No child, pipe, memfd or code image is reused across requests. The timeout
 * starts only after successful exec-error EOF. No stdout/stderr is read after
 * selection of timeout/error cleanup. A failed close is never blindly retried.
 */
int hia_cold_transport_run(hia_cold_policy policy,
                          const struct hia_cold_config *config,
                          struct hia_cold_result *result,
                          struct hia_cold_event *trace, size_t trace_capacity);

/* Frees only the returned byte allocations. Never kills, waits or closes fds. */
void hia_cold_transport_release(struct hia_cold_result *result);

#ifdef __cplusplus
}
#endif
#endif
