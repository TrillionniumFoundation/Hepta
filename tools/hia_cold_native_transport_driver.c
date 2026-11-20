/* Standalone diagnostic harness for the new explicit raw native profile.
 * The reusable library runs in-process. This probe is a separate test process,
 * NOT a production per-invocation extra supervisor and NOT a qualification.
 */
#define _GNU_SOURCE 1
#include "hia_cold_native_transport.h"
#include <errno.h>
#include <fcntl.h>
#include <inttypes.h>
#include <limits.h>
#include <signal.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>
#include <sys/stat.h>
#include <unistd.h>

struct bytes { unsigned char *data; size_t count; };
static int read_all(const char *path, struct bytes *out) {
    int fd = open(path, O_RDONLY | O_CLOEXEC);
    if (fd < 0) return -1;
    size_t used = 0, size = 0;
    unsigned char *data = NULL;
    for (;;) {
        if (size - used < 32768) {
            if (size > SIZE_MAX - 32768) { errno = EOVERFLOW; goto bad; }
            size += 32768;
            void *next = realloc(data, size);
            if (!next) goto bad;
            data = next;
        }
        ssize_t n = read(fd, data + used, size - used);
        if (n < 0 && errno == EINTR) continue;
        if (n < 0) goto bad;
        if (!n) break;
        used += (size_t)n;
    }
    if (close(fd) != 0) { free(data); return -1; }
    out->data = data; out->count = used;
    return 0;
bad: {
    int error = errno;
    close(fd); free(data); errno = error; return -1;
}}
static int save_at(int dir, const char *name, const void *data, size_t bytes) {
    int fd = openat(dir, name, O_WRONLY | O_CREAT | O_EXCL | O_CLOEXEC, 0600);
    if (fd < 0) return -1;
    size_t at = 0;
    while (at < bytes) {
        ssize_t n = write(fd, (const unsigned char *)data + at, bytes - at);
        if (n < 0 && errno == EINTR) continue;
        if (n <= 0) {
            int error = n < 0 ? errno : EIO;
            close(fd); errno = error; return -1;
        }
        at += (size_t)n;
    }
    return close(fd);
}
static int number(const char *text, uint64_t *out) {
    if (!text || !*text || *text == '+' || *text == '-') return -1;
    errno = 0; char *end = NULL;
    unsigned long long value = strtoull(text, &end, 10);
    if (errno || !end || *end) return -1;
    *out = (uint64_t)value;
    return 0;
}
static void p64(unsigned char *at, uint64_t value) { memcpy(at, &value, 8); }

int main(int argc, char **argv) {
    /* POLICY TARGET REQUEST CWD ENV(0|1) TIMEOUT_NS NONCE OUTDIR
       [--pass-fd FD] [--pass-fd FD] [-- ARG ...] */
    if (argc < 9) return 64;
    uint64_t environment, timeout, nonce;
    if (number(argv[5], &environment) || environment > 1
            || number(argv[6], &timeout) || number(argv[7], &nonce) || !nonce) return 64;
    int borrowed[2]; size_t borrowed_count = 0; int at = 9;
    while (at < argc && strcmp(argv[at], "--pass-fd") == 0) {
        uint64_t descriptor;
        if (borrowed_count == 2 || at + 1 >= argc || number(argv[at + 1], &descriptor)
                || descriptor < 3 || descriptor > INT_MAX) return 64;
        borrowed[borrowed_count++] = (int)descriptor; at += 2;
    }
    if (at < argc) {
        if (strcmp(argv[at], "--") != 0) return 64;
        ++at;
    }
    struct bytes policy = {0}, target = {0}, input = {0};
    if (read_all(argv[1], &policy) || read_all(argv[2], &target)
            || read_all(argv[3], &input) || !policy.count) return 65;
    void *mapping = mmap(NULL, policy.count, PROT_READ | PROT_WRITE,
                         MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    if (mapping == MAP_FAILED) return 66;
    memcpy(mapping, policy.data, policy.count);
    if (mprotect(mapping, policy.count, PROT_READ | PROT_EXEC) != 0) return 66;
    free(policy.data); policy.data = NULL;
    hia_cold_policy entry;
    _Static_assert(sizeof entry == sizeof mapping, "SysV pointer representation");
    memcpy(&entry, &mapping, sizeof entry);

    /* This diagnostic process establishes its explicit signal precondition.
       The reusable library does not mutate the caller's signal dispositions. */
    struct sigaction ignored;
    memset(&ignored, 0, sizeof ignored);
    sigemptyset(&ignored.sa_mask);
    ignored.sa_handler = SIG_IGN;
    if (sigaction(SIGPIPE, &ignored, NULL) != 0) return 67;
    struct sigaction children;
    memset(&children, 0, sizeof children);
    sigemptyset(&children.sa_mask);
    children.sa_handler = SIG_DFL;
    if (sigaction(SIGCHLD, &children, NULL) != 0) return 67;

    const size_t trace_capacity = 65536;
    struct hia_cold_event *trace = calloc(trace_capacity, sizeof *trace);
    if (!trace) return 68;
    struct hia_cold_config config = {
        target.data, target.count, input.data, input.count, argv[4],
        (const char *const *)(argv + at), (size_t)(argc - at),
        borrowed, borrowed_count, timeout, nonce, (unsigned)environment, NULL, NULL
    };
    struct hia_cold_result result;
    int rc = hia_cold_transport_run(entry, &config, &result, trace, trace_capacity);

    /* Receipt I/O is outside the target lifetime, so the target cannot inherit
       an evidence-directory fd. Raw target output is never printed or trimmed. */
    int dir = open(argv[8], O_RDONLY | O_DIRECTORY | O_CLOEXEC);
    if (dir < 0) return 69;
    if (save_at(dir, "stdout.bin", result.stdout_bytes, result.stdout_size)
            || save_at(dir, "stderr.bin", result.stderr_bytes, result.stderr_size)) return 69;
    size_t trace_count = result.action_count < trace_capacity
        ? (size_t)result.action_count : trace_capacity;
    if (save_at(dir, "events.bin", trace, trace_count * sizeof *trace)) return 69;
    unsigned char receipt[256] = {0};
    memcpy(receipt, "HCTPROB1", 8);
    uint64_t fields[25] = {
        1, nonce, (uint64_t)(int64_t)rc, result.outcome,
        result.primary_errno, result.primary_stage, result.cleanup_errno,
        result.cleanup_stage, (uint64_t)result.child_pid,
        (uint64_t)(int64_t)result.returncode, (uint64_t)(unsigned)result.wait_status,
        result.spawned, result.exec_confirmed, result.reaped, result.owner_lost,
        result.policy_complete, result.trace_overflow, result.action_count,
        result.final_fd_mask, result.start_ns, result.end_ns,
        result.stdout_size, result.stderr_size, result.stdout_reads, result.stderr_reads
    };
    for (size_t i = 0; i != 25; ++i) p64(receipt + 8 + 8 * i, fields[i]);
    p64(receipt + 208, sizeof(struct hia_cold_event));
    p64(receipt + 216, trace_count);
    p64(receipt + 224, target.count);
    p64(receipt + 232, input.count);
    p64(receipt + 240, policy.count);
    p64(receipt + 248, UINT64_C(10177645963941345917));
    if (save_at(dir, "receipt.bin", receipt, sizeof receipt) || close(dir) != 0) return 69;
    hia_cold_transport_release(&result);
    free(trace); free(target.data); free(input.data);
    if (munmap(mapping, policy.count) != 0) return 70;
    /* A complete nonzero/trapped target is a valid raw result. It is not PASS.
       Overflow/lost protocol is never a complete diagnostic record. */
    return rc == 0 && !result.trace_overflow ? 0 : 1;
}
