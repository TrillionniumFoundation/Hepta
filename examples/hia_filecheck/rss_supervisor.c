#define _GNU_SOURCE
#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <sys/resource.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <unistd.h>

struct memory_floor { long vm_hwm_kib, vm_rss_kib, self_ru_maxrss_kib; };

static struct memory_floor floor_now(void) {
    struct memory_floor result = {-1, -1, -1};
    FILE *file = fopen("/proc/self/status", "r");
    if (!file) { perror("self status"); exit(71); }
    char line[256];
    while (fgets(line, sizeof(line), file)) {
        long value;
        if (sscanf(line, "VmHWM: %ld kB", &value) == 1) { result.vm_hwm_kib = value; }
        if (sscanf(line, "VmRSS: %ld kB", &value) == 1) { result.vm_rss_kib = value; }
    }
    fclose(file);
    struct rusage usage;
    if (getrusage(RUSAGE_SELF, &usage)) { perror("self rusage"); exit(72); }
    result.self_ru_maxrss_kib = usage.ru_maxrss;
    if (result.vm_hwm_kib < 0 || result.vm_rss_kib < 0) { exit(73); }
    return result;
}

static void write_all(int fd, const void *data, size_t bytes) {
    const char *cursor = data;
    while (bytes) {
        ssize_t count = write(fd, cursor, bytes);
        if (count < 0 && errno == EINTR) { continue; }
        if (count <= 0) { _exit(74); }
        cursor += count;
        bytes -= (size_t)count;
    }
}

int main(int argc, char **argv) {
    if (argc < 3) {
        fprintf(stderr, "usage: rss_supervisor RECEIPT PROGRAM [ARGS...]\n");
        return 64;
    }
    int output = open(argv[1], O_WRONLY | O_CREAT | O_EXCL | O_CLOEXEC, 0600);
    if (output < 0) { perror("new receipt"); return 65; }
    struct memory_floor supervisor = floor_now(), child = {-1, -1, -1};
    int channel[2];
    if (pipe2(channel, O_CLOEXEC)) { perror("pipe"); return 66; }
    pid_t pid = fork();
    if (pid < 0) { perror("fork"); return 67; }
    if (!pid) {
        close(channel[0]);
        struct memory_floor before_exec = floor_now();
        write_all(channel[1], &before_exec, sizeof(before_exec));
        close(channel[1]);
        execv(argv[2], &argv[2]);
        perror("execv");
        _exit(127);
    }
    close(channel[1]);
    size_t remaining = sizeof(child);
    char *cursor = (char *)&child;
    while (remaining) {
        ssize_t count = read(channel[0], cursor, remaining);
        if (count < 0 && errno == EINTR) { continue; }
        if (count <= 0) { break; }
        cursor += count;
        remaining -= (size_t)count;
    }
    close(channel[0]);
    int status = 0;
    struct rusage usage;
    while (wait4(pid, &status, 0, &usage) < 0) {
        if (errno == EINTR) { continue; }
        perror("wait4"); return 68;
    }
    if (remaining) { fprintf(stderr, "missing child pre-exec floor\n"); return 69; }
    int exit_code = WIFEXITED(status) ? WEXITSTATUS(status) : -1;
    int signal_number = WIFSIGNALED(status) ? WTERMSIG(status) : 0;
    dprintf(output,
        "{\"supervisor_vm_hwm_kib\":%ld,\"supervisor_vm_rss_kib\":%ld,"
        "\"supervisor_self_ru_maxrss_kib\":%ld,\"child_preexec_vm_hwm_kib\":%ld,"
        "\"child_preexec_vm_rss_kib\":%ld,\"child_preexec_self_ru_maxrss_kib\":%ld,"
        "\"child_wait4_ru_maxrss_kib\":%ld,\"child_exit_code\":%d,\"child_signal\":%d}\n",
        supervisor.vm_hwm_kib, supervisor.vm_rss_kib, supervisor.self_ru_maxrss_kib,
        child.vm_hwm_kib, child.vm_rss_kib, child.self_ru_maxrss_kib,
        usage.ru_maxrss, exit_code, signal_number);
    if (close(output)) { perror("close receipt"); return 70; }
    return exit_code == 0 && signal_number == 0 ? 0 : 1;
}
