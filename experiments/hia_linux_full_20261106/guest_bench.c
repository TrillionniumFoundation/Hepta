/* Finite, guarded PID1 system-workload collector for disposable QEMU guests.
 * It measures this guest/workload only; it is not a Linux selftest suite.
 */
#define _GNU_SOURCE
#include <arpa/inet.h>
#include <ctype.h>
#include <errno.h>
#include <fcntl.h>
#include <inttypes.h>
#include <limits.h>
#include <net/if.h>
#include <netinet/tcp.h>
#include <sched.h>
#include <signal.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/ioctl.h>
#include <sys/mman.h>
#include <sys/mount.h>
#include <sys/reboot.h>
#include <sys/resource.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/syscall.h>
#include <sys/types.h>
#include <sys/utsname.h>
#include <sys/wait.h>
#include <time.h>
#include <unistd.h>

#define PREFIX "HIA_LINUX_BENCH "
#define MIN_ITERATIONS 64U
#define MAX_ITERATIONS 8192U
#define WARMUPS 2U
#define MEASURED 5U
#define STAGES 4U
#define DEADLINE_SECONDS 180U
#define PAGE_BYTES 4096U
#define FILE_BYTES 4096U
#define HASH_OFFSET UINT64_C(14695981039346656037)
#define HASH_PRIME UINT64_C(1099511628211)
#define PIPE_CHANNEL UINT64_C(0x504950455f524551)
#define UNIX_CHANNEL UINT64_C(0x554e49585f524551)
#define TCP_CHANNEL UINT64_C(0x5443505f52455131)

static const char *const stage_names[STAGES] = {
    "syscall_process_pipe", "anonymous_memory", "tmpfs_files", "unix_tcp"
};
static const char *const operation_units[STAGES] = {
    "pipe_request_response_cycles", "pages_initialized_and_verified",
    "file_lifecycles", "socket_request_response_cycles"
};
static uint32_t seed = UINT32_C(20261106), iterations = 1024;
static char run_id[25], expected_release[65];
static volatile sig_atomic_t vm_verified;
static int bench_directory = -1, selected_stage = -1;
static void *expected_fault_address;
static const char *failure_reason = "unspecified";
static int failure_errno;
static unsigned emitted_samples, successful_samples, completed_stages;
static unsigned char file_template[FILE_BYTES];
static uint16_t page_values[MAX_ITERATIONS];
static char deadline_record[768];
static size_t deadline_record_size;

static unsigned selected_stage_count(void) { return selected_stage < 0 ? STAGES : 1U; }
static unsigned expected_sample_count(void) { return selected_stage_count() * (WARMUPS + MEASURED); }
static const char *selection_name(void) { return selected_stage < 0 ? "all" : stage_names[selected_stage]; }
static int wants_stage(unsigned stage) { return selected_stage < 0 || (unsigned)selected_stage == stage; }

static uint64_t mix64(uint64_t value)
{
    value ^= value >> 30;
    value *= UINT64_C(0xbf58476d1ce4e5b9);
    value ^= value >> 27;
    value *= UINT64_C(0x94d049bb133111eb);
    return value ^ (value >> 31);
}

static uint64_t fold(uint64_t hash, uint64_t value)
{
    return (hash ^ value) * HASH_PRIME;
}

static uint64_t request_value(uint64_t channel, uint32_t index)
{
    return mix64(((uint64_t)seed << 32) ^ index ^ channel);
}

static uint64_t response_value(uint64_t request, unsigned rotation, uint64_t mask)
{
    return ((request << rotation) | (request >> (64U - rotation))) ^ mask;
}

static uint64_t pipe_reply(uint64_t request)
{
    return response_value(request, 17, UINT64_C(0x9e3779b97f4a7c15));
}

static uint64_t unix_reply(uint64_t request)
{
    return response_value(request, 23, UINT64_C(0xd6e8feb86659fd93));
}

static uint64_t tcp_reply(uint64_t request)
{
    return response_value(request, 31, UINT64_C(0xa0761d6478bd642f));
}

static int fail(const char *reason)
{
    failure_reason = reason;
    failure_errno = errno;
    return 0;
}

static void json_string(const char *value)
{
    putchar('"');
    for (const unsigned char *p = (const unsigned char *)value; *p; ++p) {
        if (*p == '"' || *p == '\\') {
            putchar('\\');
            putchar(*p);
        } else if (*p >= 0x20 && *p <= 0x7e) {
            putchar(*p);
        } else {
            printf("\\u%04x", (unsigned)*p);
        }
    }
    putchar('"');
}

static void emit_error(const char *reason, int error)
{
    printf(PREFIX "{\"event\":\"error\",\"run_id\":");
    if (*run_id) json_string(run_id); else fputs("null", stdout);
    fputs(",\"status\":\"FAIL\",\"reason\":", stdout);
    json_string(reason);
    printf(",\"errno\":%d}\n", error);
}

static void emit_summary(int ok, int aborted)
{
    printf(PREFIX "{\"event\":\"summary\",\"run_id\":");
    if (*run_id) json_string(run_id); else fputs("null", stdout);
    printf(",\"status\":\"%s\",\"selection\":\"%s\",\"aborted\":%s,\"expected_samples\":%u,"
           "\"emitted_samples\":%u,\"successful_samples\":%u,"
           "\"completed_stages\":%u,\"warmups_per_stage\":%u,"
           "\"measured_per_stage\":%u,\"shutdown_required\":true}\n",
           ok ? "PASS" : "FAIL", selection_name(), aborted ? "true" : "false",
           expected_sample_count(), emitted_samples, successful_samples,
           completed_stages, WARMUPS, MEASURED);
}

static _Noreturn void power_off(void)
{
    sync();
    errno = 0;
    int result = reboot(RB_POWER_OFF);
    emit_error("poweroff_returned", result ? errno : EPROTO);
    emit_summary(0, 1);
    _exit(125);
}

static void alarm_handler(int number)
{
    (void)number;
    if (deadline_record_size)
        (void)write(STDOUT_FILENO, deadline_record, deadline_record_size);
    if (vm_verified) (void)reboot(RB_POWER_OFF);
    _exit(124);
}

static int transfer(int fd, void *buffer, size_t bytes, int writing)
{
    size_t done = 0;
    while (done < bytes) {
        ssize_t count = writing ? write(fd, (char *)buffer + done, bytes - done)
                                : read(fd, (char *)buffer + done, bytes - done);
        if (count < 0 && errno == EINTR) continue;
        if (count <= 0) {
            if (count == 0) errno = EIO;
            return 0;
        }
        done += (size_t)count;
    }
    return 1;
}

static void close_fd(int *fd)
{
    if (*fd >= 0) {
        (void)close(*fd);
        *fd = -1;
    }
}

static void discard_child(pid_t *child)
{
    if (*child > 0) {
        (void)kill(*child, SIGKILL);
        while (waitpid(*child, NULL, 0) < 0 && errno == EINTR) {}
        *child = -1;
    }
}

static int finish_child(pid_t *child, int expected_signal)
{
    int status = 0;
    pid_t result;
    do { result = waitpid(*child, &status, 0); } while (result < 0 && errno == EINTR);
    if (result != *child) return fail("waitpid");
    *child = -1;
    if (expected_signal < 0) {
        if (!WIFEXITED(status) || WEXITSTATUS(status) != -expected_signal) {
            errno = EPROTO; return fail("child_expected_fault_handler");
        }
    } else if (expected_signal) {
        if (!WIFSIGNALED(status) || WTERMSIG(status) != expected_signal) {
            errno = EPROTO;
            return fail("child_expected_signal");
        }
    } else if (!WIFEXITED(status) || WEXITSTATUS(status) != 0) {
        errno = ECHILD;
        return fail("child_status");
    }
    return 1;
}

static int read_text(const char *path, char *buffer, size_t capacity)
{
    int fd = open(path, O_RDONLY | O_CLOEXEC);
    if (fd < 0) return 0;
    size_t used = 0;
    while (used + 1 < capacity) {
        ssize_t count = read(fd, buffer + used, capacity - used - 1);
        if (count < 0 && errno == EINTR) continue;
        if (count < 0) { close(fd); return 0; }
        if (!count) break;
        used += (size_t)count;
    }
    char extra;
    ssize_t more;
    do { more = read(fd, &extra, 1); } while (more < 0 && errno == EINTR);
    close(fd);
    if (more != 0) { errno = EOVERFLOW; return 0; }
    buffer[used] = '\0';
    while (used && isspace((unsigned char)buffer[used - 1])) buffer[--used] = '\0';
    return 1;
}

static int decimal_u32(const char *text, uint32_t *value)
{
    if (!*text) return 0;
    uint32_t result = 0;
    for (const unsigned char *p = (const unsigned char *)text; *p; ++p) {
        if (*p < '0' || *p > '9') return 0;
        uint32_t digit = *p - '0';
        if (result > (UINT32_MAX - digit) / 10U) return 0;
        result = result * 10U + digit;
    }
    *value = result;
    return 1;
}

static int parse_cmdline(void)
{
    char line[4096], *state = NULL;
    unsigned seen = 0;
    if (!read_text("/proc/cmdline", line, sizeof(line))) return fail("read_cmdline");
    for (char *token = strtok_r(line, " \t\r\n", &state); token;
         token = strtok_r(NULL, " \t\r\n", &state)) {
        if (strncmp(token, "hia_", 4)) continue;
        char *equal = strchr(token, '=');
        if (!equal) { errno = EINVAL; return fail("malformed_hia_argument"); }
        *equal++ = '\0';
        unsigned bit = 0;
        if (!strcmp(token, "hia_bench")) {
            bit = 1U;
            if (strcmp(equal, "1")) { errno = EINVAL; return fail("hia_bench_must_equal_one"); }
        } else if (!strcmp(token, "hia_seed")) {
            bit = 2U;
            if (!decimal_u32(equal, &seed)) { errno = EINVAL; return fail("invalid_seed"); }
        } else if (!strcmp(token, "hia_iterations")) {
            bit = 4U;
            if (!decimal_u32(equal, &iterations) || iterations < MIN_ITERATIONS ||
                iterations > MAX_ITERATIONS) { errno = EINVAL; return fail("invalid_iterations"); }
        } else if (!strcmp(token, "hia_run_id")) {
            bit = 8U;
            if (strlen(equal) != 24) { errno = EINVAL; return fail("invalid_run_id"); }
            for (const char *p = equal; *p; ++p)
                if (!((*p >= '0' && *p <= '9') || (*p >= 'a' && *p <= 'f'))) {
                    errno = EINVAL; return fail("invalid_run_id");
                }
            memcpy(run_id, equal, sizeof(run_id));
        } else if (!strcmp(token, "hia_phase")) {
            bit = 32U;
            if (!strcmp(equal, "all")) selected_stage = -1;
            else {
                selected_stage = -2;
                for (unsigned stage = 0; stage < STAGES; ++stage)
                    if (!strcmp(equal, stage_names[stage])) selected_stage = (int)stage;
                if (selected_stage == -2) { errno = EINVAL; return fail("invalid_phase"); }
            }
        } else if (!strcmp(token, "hia_expected_release")) {
            bit = 16U;
            size_t length = strlen(equal);
            if (!length || length >= sizeof(expected_release)) {
                errno = EINVAL; return fail("invalid_expected_release");
            }
            for (const unsigned char *p = (const unsigned char *)equal; *p; ++p)
                if (!(isalnum(*p) || strchr("._+-", *p))) {
                    errno = EINVAL; return fail("invalid_expected_release");
                }
            memcpy(expected_release, equal, length + 1);
        } else {
            errno = EINVAL; return fail("unknown_hia_argument");
        }
        if (seen & bit) { errno = EINVAL; return fail("duplicate_hia_argument"); }
        seen |= bit;
    }
    if ((seen & 25U) != 25U) { errno = EINVAL; return fail("missing_required_arguments"); }
    return 1;
}

static int vm_identity(char *vendor, size_t vendor_size, char *product, size_t product_size)
{
    if (!read_text("/sys/class/dmi/id/sys_vendor", vendor, vendor_size) ||
        !read_text("/sys/class/dmi/id/product_name", product, product_size))
        return fail("read_dmi");
    if (!(strcasestr(vendor, "qemu") || strcasestr(vendor, "bochs") ||
          strcasestr(product, "qemu") || strcasestr(product, "bochs"))) {
        errno = EPERM;
        return fail("dmi_not_qemu_or_bochs");
    }
    vm_verified = 1;
    return 1;
}

static int loopback_up(void)
{
    int fd = socket(AF_INET, SOCK_DGRAM | SOCK_CLOEXEC, 0);
    if (fd < 0) return fail("loopback_control_socket");
    struct ifreq request;
    memset(&request, 0, sizeof(request));
    memcpy(request.ifr_name, "lo", 3);
    int ok = ioctl(fd, SIOCGIFFLAGS, &request) == 0;
    if (ok) {
        request.ifr_flags |= IFF_UP;
        ok = ioctl(fd, SIOCSIFFLAGS, &request) == 0;
    }
    int saved = errno;
    close(fd);
    errno = saved;
    return ok ? 1 : fail("loopback_up");
}

static int socket_options(int fd, int tcp)
{
    struct timeval timeout = {5, 0};
    int one = 1;
    if (setsockopt(fd, SOL_SOCKET, SO_RCVTIMEO, &timeout, sizeof(timeout)) ||
        setsockopt(fd, SOL_SOCKET, SO_SNDTIMEO, &timeout, sizeof(timeout)) ||
        (tcp && setsockopt(fd, IPPROTO_TCP, TCP_NODELAY, &one, sizeof(one))))
        return 0;
    return 1;
}

static int stage_pipe(uint64_t *checksum)
{
    int request[2] = {-1, -1}, reply[2] = {-1, -1}, ok = 0;
    pid_t child = -1;
    uint64_t hash = HASH_OFFSET;
    if (pipe2(request, O_CLOEXEC) || pipe2(reply, O_CLOEXEC)) {
        fail("pipe2"); goto done;
    }
    child = fork();
    if (child < 0) { fail("pipe_fork"); goto done; }
    if (child == 0) {
        close(request[1]); close(reply[0]);
        for (uint32_t i = 0; i < iterations; ++i) {
            uint64_t value = 0;
            if (!transfer(request[0], &value, sizeof(value), 0) ||
                value != request_value(PIPE_CHANNEL, i)) _exit(41);
            value = pipe_reply(value);
            if (!transfer(reply[1], &value, sizeof(value), 1)) _exit(42);
        }
        close(request[0]); close(reply[1]); _exit(0);
    }
    close_fd(&request[0]); close_fd(&reply[1]);
    for (uint32_t i = 0; i < iterations; ++i) {
        if (syscall(SYS_getpid) != 1 || syscall(SYS_gettid) != 1) {
            errno = EPROTO; fail("explicit_syscall_identity"); goto done;
        }
        uint64_t value = request_value(PIPE_CHANNEL, i), received = 0;
        if (!transfer(request[1], &value, sizeof(value), 1) ||
            !transfer(reply[0], &received, sizeof(received), 0)) {
            fail("pipe_transfer"); goto done;
        }
        if (received != pipe_reply(value)) { errno = EILSEQ; fail("pipe_payload"); goto done; }
        hash = fold(hash, received);
    }
    close_fd(&request[1]); close_fd(&reply[0]);
    if (!finish_child(&child, 0)) goto done;
    *checksum = hash; ok = 1;
done:
    close_fd(&request[0]); close_fd(&request[1]);
    close_fd(&reply[0]); close_fd(&reply[1]);
    discard_child(&child);
    return ok;
}

static void expected_fault_handler(int signal_number, siginfo_t *info, void *context)
{
    (void)context;
    _exit(signal_number == SIGSEGV && info && info->si_code == SEGV_ACCERR &&
          info->si_addr == expected_fault_address ? 73 : 74);
}

static int stage_memory(uint64_t *checksum)
{
    size_t length = (size_t)iterations * PAGE_BYTES;
    unsigned char *memory = mmap(NULL, length, PROT_READ | PROT_WRITE,
                                 MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    if (memory == MAP_FAILED) return fail("anonymous_mmap");
    int ok = 0;
    pid_t child = -1;
    uint64_t hash = HASH_OFFSET;
    if (madvise(memory, length, MADV_NOHUGEPAGE)) { fail("madvise_nohugepage"); goto done; }
    for (uint32_t i = 0; i < iterations; ++i) {
        memory[(size_t)i * PAGE_BYTES] = (unsigned char)page_values[i];
        memory[(size_t)i * PAGE_BYTES + PAGE_BYTES - 1] = (unsigned char)(page_values[i] >> 8);
    }
    if (mprotect(memory, length, PROT_READ)) { fail("mprotect_readonly"); goto done; }
    for (uint32_t i = 0; i < iterations; ++i) {
        size_t offset = (size_t)i * PAGE_BYTES;
        uint16_t value = (uint16_t)memory[offset] |
                         (uint16_t)((uint16_t)memory[offset + PAGE_BYTES - 1] << 8);
        if (value != page_values[i] || memory[offset + 1] || memory[offset + PAGE_BYTES - 2]) {
            errno = EILSEQ; fail("anonymous_page_contents"); goto done;
        }
        hash = fold(hash, value);
    }
    child = fork();
    if (child < 0) { fail("mprotect_fork"); goto done; }
    if (child == 0) {
        struct sigaction action;
        memset(&action, 0, sizeof(action));
        action.sa_sigaction = expected_fault_handler;
        action.sa_flags = SA_SIGINFO;
        sigemptyset(&action.sa_mask);
        expected_fault_address = memory;
        if (sigaction(SIGSEGV, &action, NULL)) _exit(75);
        volatile unsigned char *forbidden = memory;
        forbidden[0] ^= 1U;
        _exit(43);
    }
    if (!finish_child(&child, -73)) goto done;
    if (mprotect(memory, length, PROT_READ | PROT_WRITE)) {
        fail("mprotect_readwrite"); goto done;
    }
    for (uint32_t i = 0; i < iterations; ++i) {
        size_t offset = (size_t)i * PAGE_BYTES;
        memory[offset] ^= 0x5aU;
        memory[offset + PAGE_BYTES - 1] ^= 0xa5U;
        uint16_t value = (uint16_t)memory[offset] |
                         (uint16_t)((uint16_t)memory[offset + PAGE_BYTES - 1] << 8);
        if (value != (uint16_t)(page_values[i] ^ UINT16_C(0xa55a))) {
            errno = EILSEQ; fail("writable_page_contents"); goto done;
        }
        hash = fold(hash, value);
    }
    *checksum = hash; ok = 1;
done:
    discard_child(&child);
    if (munmap(memory, length) && ok) ok = fail("anonymous_munmap");
    return ok;
}

static uint64_t file_tag(uint32_t index)
{
    return request_value(UINT64_C(0x46494c455f544147), index);
}

static int stage_files(uint64_t *checksum)
{
    unsigned char written[FILE_BYTES], received[FILE_BYTES];
    uint64_t hash = HASH_OFFSET;
    memcpy(written, file_template, sizeof(written));
    for (uint32_t i = 0; i < iterations; ++i) {
        char name[32];
        int length = snprintf(name, sizeof(name), "file-%08" PRIu32, i);
        if (length <= 0 || (size_t)length >= sizeof(name)) { errno = EOVERFLOW; return fail("file_name"); }
        uint64_t first = file_tag(i), last = first ^ UINT64_C(0xd6e8feb86659fd93);
        memcpy(written, &first, sizeof(first));
        memcpy(written + FILE_BYTES - sizeof(last), &last, sizeof(last));
        int fd = openat(bench_directory, name, O_RDWR | O_CREAT | O_EXCL | O_CLOEXEC, 0600);
        if (fd < 0) return fail("file_create");
        int ok = 0;
        struct stat info;
        unsigned char extra = 0;
        if (!transfer(fd, written, sizeof(written), 1)) fail("file_write");
        else if (lseek(fd, 0, SEEK_SET) != 0) fail("file_seek");
        else if (!transfer(fd, received, sizeof(received), 0)) fail("file_read");
        else if (read(fd, &extra, 1) != 0) { errno = EILSEQ; fail("file_eof"); }
        else if (fstat(fd, &info)) fail("file_stat");
        else if (info.st_size != FILE_BYTES) { errno = EILSEQ; fail("file_size"); }
        else if (memcmp(written, received, sizeof(written))) { errno = EILSEQ; fail("file_contents"); }
        else ok = 1;
        if (close(fd) && ok) ok = fail("file_close");
        if (unlinkat(bench_directory, name, 0) && ok) ok = fail("file_unlink");
        if (!ok) return 0;
        errno = 0;
        if (fstatat(bench_directory, name, &info, AT_SYMLINK_NOFOLLOW) != -1 || errno != ENOENT) {
            errno = EILSEQ; return fail("file_deletion");
        }
        memcpy(&first, received, sizeof(first));
        memcpy(&last, received + FILE_BYTES - sizeof(last), sizeof(last));
        hash = fold(fold(hash, first), last);
    }
    *checksum = hash;
    return 1;
}

static int stage_sockets(uint64_t *checksum)
{
    int pair[2] = {-1, -1}, listener = -1, client = -1, ok = 0;
    pid_t child = -1;
    uint64_t hash = HASH_OFFSET;
    struct sockaddr_in address;
    memset(&address, 0, sizeof(address));
    address.sin_family = AF_INET;
    address.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
    if (socketpair(AF_UNIX, SOCK_STREAM | SOCK_CLOEXEC, 0, pair)) { fail("socketpair"); goto done; }
    if (!socket_options(pair[0], 0) || !socket_options(pair[1], 0)) { fail("unix_socket_options"); goto done; }
    listener = socket(AF_INET, SOCK_STREAM | SOCK_CLOEXEC, 0);
    if (listener < 0 || !socket_options(listener, 0)) { fail("listener_socket"); goto done; }
    if (bind(listener, (struct sockaddr *)&address, sizeof(address)) || listen(listener, 1)) {
        fail("loopback_bind_listen"); goto done;
    }
    socklen_t address_size = sizeof(address);
    if (getsockname(listener, (struct sockaddr *)&address, &address_size) ||
        address_size != sizeof(address) || !address.sin_port) { fail("listener_address"); goto done; }
    child = fork();
    if (child < 0) { fail("socket_fork"); goto done; }
    if (child == 0) {
        close(pair[0]);
        int peer = accept4(listener, NULL, NULL, SOCK_CLOEXEC);
        close(listener);
        if (peer < 0 || !socket_options(peer, 1)) _exit(44);
        for (uint32_t i = 0; i < iterations; ++i) {
            uint64_t value = 0;
            if (!transfer(pair[1], &value, sizeof(value), 0) ||
                value != request_value(UNIX_CHANNEL, i)) _exit(45);
            value = unix_reply(value);
            if (!transfer(pair[1], &value, sizeof(value), 1)) _exit(46);
            if (!transfer(peer, &value, sizeof(value), 0) ||
                value != request_value(TCP_CHANNEL, i)) _exit(47);
            value = tcp_reply(value);
            if (!transfer(peer, &value, sizeof(value), 1)) _exit(48);
        }
        close(peer); close(pair[1]); _exit(0);
    }
    close_fd(&pair[1]); close_fd(&listener);
    client = socket(AF_INET, SOCK_STREAM | SOCK_CLOEXEC, 0);
    if (client < 0 || !socket_options(client, 1) ||
        connect(client, (struct sockaddr *)&address, sizeof(address))) {
        fail("loopback_connect"); goto done;
    }
    for (uint32_t i = 0; i < iterations; ++i) {
        uint64_t request = request_value(UNIX_CHANNEL, i), reply = 0;
        if (!transfer(pair[0], &request, sizeof(request), 1) ||
            !transfer(pair[0], &reply, sizeof(reply), 0)) { fail("unix_transfer"); goto done; }
        if (reply != unix_reply(request)) { errno = EILSEQ; fail("unix_payload"); goto done; }
        hash = fold(hash, reply);
        request = request_value(TCP_CHANNEL, i);
        if (!transfer(client, &request, sizeof(request), 1) ||
            !transfer(client, &reply, sizeof(reply), 0)) { fail("tcp_transfer"); goto done; }
        if (reply != tcp_reply(request)) { errno = EILSEQ; fail("tcp_payload"); goto done; }
        hash = fold(hash, reply);
    }
    close_fd(&pair[0]); close_fd(&client);
    if (!finish_child(&child, 0)) goto done;
    *checksum = hash; ok = 1;
done:
    close_fd(&pair[0]); close_fd(&pair[1]); close_fd(&listener); close_fd(&client);
    discard_child(&child);
    return ok;
}

static uint64_t expected_checksum(unsigned stage)
{
    uint64_t hash = HASH_OFFSET;
    for (uint32_t i = 0; i < iterations; ++i) {
        if (stage == 0) hash = fold(hash, pipe_reply(request_value(PIPE_CHANNEL, i)));
        else if (stage == 1) hash = fold(hash, page_values[i]);
        else if (stage == 2) {
            uint64_t first = file_tag(i);
            hash = fold(fold(hash, first), first ^ UINT64_C(0xd6e8feb86659fd93));
        } else {
            hash = fold(hash, unix_reply(request_value(UNIX_CHANNEL, i)));
            hash = fold(hash, tcp_reply(request_value(TCP_CHANNEL, i)));
        }
    }
    if (stage == 1)
        for (uint32_t i = 0; i < iterations; ++i)
            hash = fold(hash, (uint16_t)(page_values[i] ^ UINT16_C(0xa55a)));
    return hash;
}

static uint64_t timeval_ns(struct timeval value)
{
    return (uint64_t)value.tv_sec * UINT64_C(1000000000) +
           (uint64_t)value.tv_usec * UINT64_C(1000);
}

static uint64_t timespec_ns(struct timespec value)
{
    return (uint64_t)value.tv_sec * UINT64_C(1000000000) + (uint64_t)value.tv_nsec;
}

static int usage_monotonic(const struct rusage *before, const struct rusage *after)
{
    return timeval_ns(after->ru_utime) >= timeval_ns(before->ru_utime) &&
           timeval_ns(after->ru_stime) >= timeval_ns(before->ru_stime) &&
           after->ru_minflt >= before->ru_minflt && after->ru_majflt >= before->ru_majflt &&
           after->ru_inblock >= before->ru_inblock && after->ru_oublock >= before->ru_oublock &&
           after->ru_nvcsw >= before->ru_nvcsw && after->ru_nivcsw >= before->ru_nivcsw;
}

static void usage_json(const struct rusage *before, const struct rusage *after)
{
    printf("{\"user_ns\":%" PRIu64 ",\"system_ns\":%" PRIu64
           ",\"minor_faults\":%ld,\"major_faults\":%ld,\"input_blocks\":%ld,"
           "\"output_blocks\":%ld,\"voluntary_switches\":%ld,\"involuntary_switches\":%ld,"
           "\"maxrss_before_kib\":%ld,\"maxrss_after_kib\":%ld}",
           timeval_ns(after->ru_utime) - timeval_ns(before->ru_utime),
           timeval_ns(after->ru_stime) - timeval_ns(before->ru_stime),
           after->ru_minflt - before->ru_minflt, after->ru_majflt - before->ru_majflt,
           after->ru_inblock - before->ru_inblock, after->ru_oublock - before->ru_oublock,
           after->ru_nvcsw - before->ru_nvcsw, after->ru_nivcsw - before->ru_nivcsw,
           before->ru_maxrss, after->ru_maxrss);
}

static int sample(unsigned stage, int warmup, unsigned index, uint64_t expected)
{
    struct rusage self_before, child_before, self_after, child_after;
    struct timespec before, after;
    uint64_t checksum = 0;
    int (*const functions[STAGES])(uint64_t *) = {
        stage_pipe, stage_memory, stage_files, stage_sockets
    };
    errno = 0;
    if (getrusage(RUSAGE_SELF, &self_before) || getrusage(RUSAGE_CHILDREN, &child_before) ||
        clock_gettime(CLOCK_MONOTONIC_RAW, &before)) return fail("sample_begin_clock_usage");
    int ok = functions[stage](&checksum);
    if (clock_gettime(CLOCK_MONOTONIC_RAW, &after) || getrusage(RUSAGE_SELF, &self_after) ||
        getrusage(RUSAGE_CHILDREN, &child_after)) return fail("sample_end_clock_usage");
    if (timespec_ns(after) <= timespec_ns(before) ||
        !usage_monotonic(&self_before, &self_after) || !usage_monotonic(&child_before, &child_after)) {
        errno = EPROTO; return fail("nonmonotonic_sample");
    }
    if (ok && checksum != expected) { errno = EILSEQ; ok = fail("sample_checksum"); }
    printf(PREFIX "{\"event\":\"sample\",\"run_id\":\"%s\",\"sequence\":%u,"
           "\"stage\":\"%s\",\"warmup\":%s,\"sample_index\":%u,"
           "\"operation_count\":%" PRIu64 ",\"operation_unit\":\"%s\","
           "\"duration_ns\":%" PRIu64 ",\"checksum\":\"%016" PRIx64
           "\",\"expected_checksum\":\"%016" PRIx64 "\",\"correctness\":%s,"
           "\"errno\":%d,\"reason\":",
           run_id, emitted_samples, stage_names[stage], warmup ? "true" : "false", index,
           (uint64_t)iterations * (stage == 3 ? 2U : 1U), operation_units[stage],
           timespec_ns(after) - timespec_ns(before), checksum, expected, ok ? "true" : "false",
           ok ? 0 : failure_errno);
    json_string(ok ? "ok" : failure_reason);
    fputs(",\"self_rusage_delta\":", stdout); usage_json(&self_before, &self_after);
    fputs(",\"children_rusage_delta\":", stdout); usage_json(&child_before, &child_after);
    fputs("}\n", stdout);
    ++emitted_samples;
    if (ok) ++successful_samples;
    return ok;
}

int main(void)
{
    /* No guest administration or benchmark action is allowed in a host process. */
    if (getpid() != 1) return 77;
    setvbuf(stdout, NULL, _IONBF, 0);
    if (mount("proc", "/proc", "proc", MS_NOSUID | MS_NODEV | MS_NOEXEC, NULL) ||
        mount("sysfs", "/sys", "sysfs", MS_NOSUID | MS_NODEV | MS_NOEXEC, NULL)) {
        emit_error("guard_mounts", errno); emit_summary(0, 1); return 77;
    }
    char vendor[256], product[256];
    if (!vm_identity(vendor, sizeof(vendor), product, sizeof(product))) {
        emit_error(failure_reason, failure_errno); emit_summary(0, 1); return 77;
    }
    if (!parse_cmdline()) {
        emit_error(failure_reason, failure_errno); emit_summary(0, 1); power_off();
    }
    int written = snprintf(deadline_record, sizeof(deadline_record),
        PREFIX "{\"event\":\"error\",\"run_id\":\"%s\",\"status\":\"FAIL\",\"reason\":\"deadline\",\"errno\":0}\n"
        PREFIX "{\"event\":\"summary\",\"run_id\":\"%s\",\"status\":\"FAIL\",\"selection\":\"%s\",\"aborted\":true,"
        "\"expected_samples\":%u,\"emitted_samples\":null,\"successful_samples\":null,"
        "\"completed_stages\":null,\"warmups_per_stage\":2,\"measured_per_stage\":5,\"shutdown_required\":true}\n",
        run_id, run_id, selection_name(), expected_sample_count());
    if (written <= 0 || (size_t)written >= sizeof(deadline_record)) {
        emit_error("deadline_record", EOVERFLOW); emit_summary(0, 1); power_off();
    }
    deadline_record_size = (size_t)written;
    struct sigaction action;
    memset(&action, 0, sizeof(action));
    action.sa_handler = alarm_handler;
    sigemptyset(&action.sa_mask);
    if (sigaction(SIGALRM, &action, NULL) || signal(SIGPIPE, SIG_IGN) == SIG_ERR) {
        emit_error("signal_setup", errno); emit_summary(0, 1); power_off();
    }
    alarm(DEADLINE_SECONDS);
    struct utsname identity;
    struct rlimit core = {0, 0};
    cpu_set_t cpus;
    CPU_ZERO(&cpus); CPU_SET(0, &cpus);
    if (uname(&identity) || strcmp(identity.release, expected_release) ||
        strcmp(identity.machine, "x86_64") || sysconf(_SC_PAGESIZE) != PAGE_BYTES ||
        setrlimit(RLIMIT_CORE, &core) || sched_setaffinity(0, sizeof(cpus), &cpus)) {
        emit_error("kernel_identity_or_fixed_setup", errno); emit_summary(0, 1); power_off();
    }
    if (wants_stage(2)) {
        if (mount("tmpfs", "/tmp", "tmpfs", MS_NOSUID | MS_NODEV | MS_NOEXEC, "size=64m,mode=0700") ||
            mkdir("/tmp/hia-bench", 0700)) {
            emit_error("tmpfs_setup", errno); emit_summary(0, 1); power_off();
        }
        bench_directory = open("/tmp/hia-bench", O_RDONLY | O_DIRECTORY | O_CLOEXEC);
        if (bench_directory < 0) { emit_error("benchmark_directory", errno); emit_summary(0, 1); power_off(); }
        for (size_t i = 0; i < sizeof(file_template); ++i)
            file_template[i] = (unsigned char)mix64((uint64_t)seed + i);
    }
    if (wants_stage(3) && !loopback_up()) {
        emit_error(failure_reason, failure_errno); emit_summary(0, 1); power_off();
    }
    if (wants_stage(1))
        for (uint32_t i = 0; i < iterations; ++i)
            page_values[i] = (uint16_t)request_value(UINT64_C(0x504147455f544147), i);
    printf(PREFIX "{\"event\":\"begin\",\"protocol\":\"hepta.hia.linux.system-benchmark.v1\","
           "\"run_id\":\"%s\",\"pid\":1,\"seed\":%" PRIu32 ",\"iterations\":%" PRIu32
           ",\"release\":\"%s\",\"machine\":\"%s\",\"clock\":\"CLOCK_MONOTONIC_RAW\","
           "\"cpu_affinity\":[0],\"online_cpus\":%ld,\"page_bytes\":%u,\"file_bytes\":%u,"
           "\"deadline_seconds\":%u,\"selection\":\"%s\",\"stage_count\":%u,\"defined_stage_count\":4,\"warmups_per_stage\":%u,"
           "\"measured_per_stage\":%u,\"expected_samples\":%u,\"dmi_vendor\":",
           run_id, seed, iterations, identity.release, identity.machine, sysconf(_SC_NPROCESSORS_ONLN),
           PAGE_BYTES, FILE_BYTES, DEADLINE_SECONDS, selection_name(), selected_stage_count(), WARMUPS, MEASURED,
           expected_sample_count());
    json_string(vendor); fputs(",\"dmi_product\":", stdout); json_string(product); fputs("}\n", stdout);
    for (unsigned stage = 0; stage < STAGES; ++stage) {
        if (!wants_stage(stage)) continue;
        uint64_t expected = expected_checksum(stage);
        for (unsigned i = 0; i < WARMUPS + MEASURED; ++i) {
            int warmup = i < WARMUPS;
            if (!sample(stage, warmup, warmup ? i : i - WARMUPS, expected)) {
                emit_error(failure_reason, failure_errno); emit_summary(0, 1); power_off();
            }
        }
        ++completed_stages;
    }
    if (bench_directory >= 0 && (close(bench_directory) || rmdir("/tmp/hia-bench"))) {
        emit_error("final_cleanup", errno); emit_summary(0, 1); power_off();
    }
    emit_summary(successful_samples == expected_sample_count(), 0);
    power_off();
}
