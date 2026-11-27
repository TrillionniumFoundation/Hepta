/* Qualification workload: validate the retained physical entry independently. */
#define _POSIX_C_SOURCE 200809L
#include <errno.h>
#include <fcntl.h>
#include <inttypes.h>
#include <limits.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>

static int number(const char *text, uintmax_t *out) {
    char *end;
    if (!text || !*text || *text == '-') return 0;
    errno = 0;
    *out = strtoumax(text, &end, 10);
    return !errno && !*end;
}

static int output(const char *data) {
    size_t left = strlen(data);
    while (left) {
        ssize_t size = write(STDOUT_FILENO, data, left);
        if (size < 0 && errno == EINTR) continue;
        if (size <= 0) return 0;
        data += size;
        left -= (size_t)size;
    }
    return 1;
}

int main(int argc, char **argv) {
    uintmax_t descriptor, device, inode;
    struct stat info;
    unsigned char header[7];
    const char *selected = getenv("HIA_EXPECTED_ARGV0");
    if (!selected || strcmp(argv[0], selected)) return 94;
    if (argc != 3 || !number(argv[1], &device) || !number(argv[2], &inode) ||
        !number(getenv("HEPTA_RUNTIME_WORKER_ENTRY_FD"), &descriptor) || descriptor > INT_MAX)
        return 91;
    int fd = (int)descriptor;
    int flags = fcntl(fd, F_GETFD);
    if (flags < 0 || (flags & FD_CLOEXEC) || fstat(fd, &info) || !S_ISREG(info.st_mode) ||
        (uintmax_t)info.st_dev != device || (uintmax_t)info.st_ino != inode ||
        pread(fd, header, sizeof(header), 0) != (ssize_t)sizeof(header) ||
        memcmp(header, "\177ELF\002\001\001", sizeof(header)))
        return 92;
    return output("argv0-ok\nentry-anchor-ok\n") ? 0 : 93;
}
