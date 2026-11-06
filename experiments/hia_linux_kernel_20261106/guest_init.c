/* Finite PID1 OS smoke for a disposable QEMU guest; not Linux selftests. */
#define _GNU_SOURCE
#include <arpa/inet.h>
#include <errno.h>
#include <fcntl.h>
#include <net/if.h>
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
#include <sys/types.h>
#include <sys/utsname.h>
#include <sys/wait.h>
#include <unistd.h>

static char run_id[80];
static char expected_release[128];
static unsigned passed, failed;

static int transfer(int fd, void *buffer, size_t size, int writing) {
    size_t done = 0;
    while (done < size) {
        ssize_t count = writing ? write(fd, (char *)buffer + done, size - done)
                                : read(fd, (char *)buffer + done, size - done);
        if (count < 0 && errno == EINTR) continue;
        if (count <= 0) return 0;
        done += (size_t)count;
    }
    return 1;
}

static int child_exit(pid_t pid, int expected) {
    int status = 0;
    return waitpid(pid, &status, 0) == pid && WIFEXITED(status)
           && WEXITSTATUS(status) == expected;
}

static void result(const char *id, int ok) {
    int saved_errno = errno;
    if (ok) ++passed; else ++failed;
    printf("HIA_LINUX_SMOKE {\"event\":\"check\",\"run_id\":\"%s\","
           "\"id\":\"%s\",\"passed\":%s,\"errno\":%d}\n",
           run_id, id, ok ? "true" : "false", ok ? 0 : saved_errno);
}

static void timeout_handler(int signum) {
    static const char line[] = "HIA_LINUX_SMOKE {\"event\":\"abort\",\"reason\":\"guest_timeout\"}\n";
    (void)signum;
    (void)write(STDOUT_FILENO, line, sizeof(line) - 1);
    reboot(RB_POWER_OFF);
    _exit(125);
}

static int cmdline_value(const char *key, char *value, size_t capacity) {
    char line[4096];
    FILE *stream = fopen("/proc/cmdline", "r");
    if (!stream) return 0;
    int ok = fgets(line, sizeof(line), stream) != NULL;
    fclose(stream);
    if (!ok) return 0;
    for (char *token = strtok(line, " \r\n"); token; token = strtok(NULL, " \r\n")) {
        size_t length = strlen(key);
        if (strncmp(token, key, length) || token[length] != '=') continue;
        const char *source = token + length + 1;
        if (!*source || strlen(source) >= capacity) return 0;
        for (const char *c = source; *c; ++c)
            if (!((*c >= 'a' && *c <= 'z') || (*c >= 'A' && *c <= 'Z') ||
                  (*c >= '0' && *c <= '9') || strchr("._+-", *c))) return 0;
        strcpy(value, source);
        return 1;
    }
    return 0;
}

static int kernel_identity(void) {
    struct utsname identity;
    return uname(&identity) == 0 && !strcmp(identity.release, expected_release)
           && !strcmp(identity.machine, "x86_64");
}

static int process_test(void) {
    pid_t child = fork();
    if (child == 0) {
        execl("/init", "/init", "--exec-child", (char *)NULL);
        _exit(126);
    }
    return child > 0 && child_exit(child, 37);
}

static int pipe_test(void) {
    int fds[2];
    unsigned char payload[257], received[257];
    for (size_t i = 0; i < sizeof(payload); ++i) payload[i] = (unsigned char)(i * 19 + 7);
    if (pipe2(fds, O_CLOEXEC)) return 0;
    pid_t child = fork();
    if (child == 0) {
        close(fds[0]);
        _exit(transfer(fds[1], payload, sizeof(payload), 1) ? 0 : 1);
    }
    close(fds[1]);
    int ok = child > 0 && transfer(fds[0], received, sizeof(received), 0);
    close(fds[0]);
    int child_ok = child > 0 && child_exit(child, 0);
    return ok && child_ok && !memcmp(payload, received, sizeof(payload));
}

static int memory_test(void) {
    long page = sysconf(_SC_PAGESIZE);
    if (page <= 0) return 0;
    size_t length = (size_t)page * 3;
    unsigned char *p = mmap(NULL, length, PROT_READ | PROT_WRITE,
                            MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    if (p == MAP_FAILED) return 0;
    for (size_t i = 0; i < length; ++i) p[i] = (unsigned char)(i * 17 + 3);
    int ok = 1;
    for (size_t i = 0; i < length; ++i)
        if (p[i] != (unsigned char)(i * 17 + 3)) ok = 0;
    if (munmap(p, length)) ok = 0;
    return ok;
}

static int protection_test(void) {
    long page = sysconf(_SC_PAGESIZE);
    if (page <= 0) return 0;
    volatile unsigned char *p = mmap(NULL, (size_t)page * 2, PROT_READ | PROT_WRITE,
                                     MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    if (p == MAP_FAILED) return 0;
    p[0] = 11;
    if (mprotect((void *)(p + page), (size_t)page, PROT_NONE)) {
        munmap((void *)p, (size_t)page * 2);
        return 0;
    }
    pid_t child = fork();
    if (child == 0) {
        struct rlimit limit = {0, 0};
        setrlimit(RLIMIT_CORE, &limit);
        unsigned char value = p[page];
        _exit(value == 255 ? 4 : 5);
    }
    int status = 0;
    int ok = child > 0 && waitpid(child, &status, 0) == child
             && WIFSIGNALED(status) && WTERMSIG(status) == SIGSEGV && p[0] == 11;
    if (munmap((void *)p, (size_t)page * 2)) ok = 0;
    return ok;
}

static int file_test(void) {
    unsigned char payload[513], received[513];
    for (size_t i = 0; i < sizeof(payload); ++i) payload[i] = (unsigned char)(i * 13 + 5);
    int fd = open("/tmp/smoke-before", O_WRONLY | O_CREAT | O_EXCL | O_CLOEXEC, 0600);
    if (fd < 0) return 0;
    int ok = transfer(fd, payload, sizeof(payload), 1);
    if (close(fd)) ok = 0;
    if (rename("/tmp/smoke-before", "/tmp/smoke-after")) return 0;
    if (access("/tmp/smoke-before", F_OK) == 0 || errno != ENOENT) ok = 0;
    fd = open("/tmp/smoke-after", O_RDONLY | O_CLOEXEC);
    if (fd < 0) return 0;
    struct stat info;
    if (fstat(fd, &info) || info.st_size != (off_t)sizeof(payload)) ok = 0;
    if (!transfer(fd, received, sizeof(received), 0) || memcmp(payload, received, sizeof(payload))) ok = 0;
    if (close(fd) || unlink("/tmp/smoke-after")) ok = 0;
    if (access("/tmp/smoke-after", F_OK) == 0 || errno != ENOENT) ok = 0;
    return ok;
}

static int socketpair_test(void) {
    int fds[2];
    uint64_t message = UINT64_C(0x6da4982f0b5173c9), received = 0;
    if (socketpair(AF_UNIX, SOCK_STREAM | SOCK_CLOEXEC, 0, fds)) return 0;
    pid_t child = fork();
    if (child == 0) {
        close(fds[0]);
        _exit(transfer(fds[1], &message, sizeof(message), 1) ? 0 : 1);
    }
    close(fds[1]);
    int ok = child > 0 && transfer(fds[0], &received, sizeof(received), 0);
    close(fds[0]);
    int child_ok = child > 0 && child_exit(child, 0);
    return ok && child_ok && received == message;
}

static int loopback_test(void) {
    int listener = socket(AF_INET, SOCK_STREAM | SOCK_CLOEXEC, 0);
    if (listener < 0) return 0;
    struct timeval timeout = {10, 0};
    setsockopt(listener, SOL_SOCKET, SO_RCVTIMEO, &timeout, sizeof(timeout));
    struct ifreq request = {0};
    strcpy(request.ifr_name, "lo");
    if (ioctl(listener, SIOCGIFFLAGS, &request)) return 0;
    request.ifr_flags |= IFF_UP;
    if (ioctl(listener, SIOCSIFFLAGS, &request)) return 0;
    struct sockaddr_in address = {.sin_family = AF_INET, .sin_addr.s_addr = htonl(INADDR_LOOPBACK)};
    if (bind(listener, (struct sockaddr *)&address, sizeof(address)) || listen(listener, 1)) return 0;
    socklen_t size = sizeof(address);
    if (getsockname(listener, (struct sockaddr *)&address, &size)) return 0;
    pid_t child = fork();
    uint64_t send_value = UINT64_C(0x13a547bc9e0268df), receive_value = 0;
    if (child == 0) {
        close(listener);
        int fd = socket(AF_INET, SOCK_STREAM | SOCK_CLOEXEC, 0);
        if (fd < 0) _exit(1);
        setsockopt(fd, SOL_SOCKET, SO_RCVTIMEO, &timeout, sizeof(timeout));
        setsockopt(fd, SOL_SOCKET, SO_SNDTIMEO, &timeout, sizeof(timeout));
        int ok = !connect(fd, (struct sockaddr *)&address, sizeof(address))
                 && transfer(fd, &send_value, sizeof(send_value), 1)
                 && transfer(fd, &receive_value, sizeof(receive_value), 0)
                 && receive_value == (send_value ^ UINT64_MAX);
        close(fd);
        _exit(ok ? 0 : 2);
    }
    int fd = accept4(listener, NULL, NULL, SOCK_CLOEXEC);
    close(listener);
    int ok = child > 0 && fd >= 0;
    if (fd >= 0) {
        setsockopt(fd, SOL_SOCKET, SO_RCVTIMEO, &timeout, sizeof(timeout));
        setsockopt(fd, SOL_SOCKET, SO_SNDTIMEO, &timeout, sizeof(timeout));
        if (!transfer(fd, &receive_value, sizeof(receive_value), 0) || receive_value != send_value) ok = 0;
        receive_value ^= UINT64_MAX;
        if (!transfer(fd, &receive_value, sizeof(receive_value), 1)) ok = 0;
        close(fd);
    }
    int child_ok = child > 0 && child_exit(child, 0);
    return ok && child_ok;
}

int main(int argc, char **argv) {
    if (argc == 2 && !strcmp(argv[1], "--exec-child")) return 37;
    /* Never run the guest administration path as a normal host process. */
    if (getpid() != 1) return 64;
    setvbuf(stdout, NULL, _IONBF, 0);
    signal(SIGALRM, timeout_handler);
    alarm(60);
    int proc_ok = mount("proc", "/proc", "proc", 0, NULL) == 0;
    int proc_errno = errno;
    if (!proc_ok || !cmdline_value("hia_run_id", run_id, sizeof(run_id))
                 || !cmdline_value("hia_kernel_release", expected_release, sizeof(expected_release))) {
        printf("HIA_LINUX_SMOKE {\"event\":\"abort\",\"reason\":\"missing_boot_identity\"}\n");
        reboot(RB_POWER_OFF);
        return 125;
    }
    printf("HIA_LINUX_SMOKE {\"event\":\"begin\",\"run_id\":\"%s\",\"pid\":%ld}\n", run_id, (long)getpid());
    errno = 0; result("pid1", getpid() == 1);
    errno = proc_errno; result("mount_proc", proc_ok);
    errno = 0; result("mount_sysfs", mount("sysfs", "/sys", "sysfs", 0, NULL) == 0);
    errno = 0; result("mount_devtmpfs", mount("devtmpfs", "/dev", "devtmpfs", 0, "mode=0755") == 0);
    errno = 0; result("mount_tmpfs", mount("tmpfs", "/tmp", "tmpfs", MS_NOSUID | MS_NODEV, "size=16m") == 0);
    errno = 0; result("kernel_identity", kernel_identity());
    errno = 0; result("cpu_count", sysconf(_SC_NPROCESSORS_ONLN) == 2);
    errno = 0; result("fork_exec_wait", process_test());
    errno = 0; result("pipe_roundtrip", pipe_test());
    errno = 0; result("mmap_pages", memory_test());
    errno = 0; result("mprotect_fault", protection_test());
    errno = 0; result("file_lifecycle", file_test());
    errno = 0; result("unix_socketpair", socketpair_test());
    errno = 0; result("loopback_tcp", loopback_test());
    alarm(0);
    printf("HIA_LINUX_SMOKE {\"event\":\"complete\",\"run_id\":\"%s\",\"total\":%u,\"passed\":%u,\"failed\":%u}\n",
           run_id, passed + failed, passed, failed);
    printf("HIA_LINUX_SMOKE {\"event\":\"shutdown\",\"run_id\":\"%s\",\"operation\":\"poweroff\"}\n", run_id);
    sync();
    reboot(RB_POWER_OFF);
    printf("HIA_LINUX_SMOKE {\"event\":\"abort\",\"reason\":\"poweroff_returned\"}\n");
    return 125;
}
