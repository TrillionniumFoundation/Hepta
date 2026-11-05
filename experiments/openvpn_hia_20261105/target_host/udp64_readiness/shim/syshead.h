/* Controlled-I/O compatibility definitions; not OpenVPN's platform layer. */
#ifndef CONTROLLED_SYSHEAD_H
#define CONTROLLED_SYSHEAD_H
#define _GNU_SOURCE 1
#include <assert.h>
#include <errno.h>
#include <fcntl.h>
#include <inttypes.h>
#include <poll.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/select.h>
#include <sys/socket.h>
#include <sys/time.h>
#include <unistd.h>
#define HAVE_POLL_H 1
#define HAVE_EPOLL_CREATE 1
#define HAVE_SYS_EPOLL_H 1
#include "../upstream/platform_flags.h"
#define ASSERT assert
#define CLEAR(x) memset(&(x), 0, sizeof(x))
#define SIZE(x) (sizeof(x) / sizeof((x)[0]))
#define openvpn_fd_set(fd, set) FD_SET((fd), (set))
#endif
