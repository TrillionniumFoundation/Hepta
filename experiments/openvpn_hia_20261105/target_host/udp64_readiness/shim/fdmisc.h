static inline void set_cloexec(int fd) {
    int flags = fcntl(fd, F_GETFD);
    assert(flags >= 0 && fcntl(fd, F_SETFD, flags | FD_CLOEXEC) == 0);
}
