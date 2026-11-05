#if defined(HAVE_POLL_H) || !defined(_WIN32)
#define POLL 1
#else
#define POLL 0
#endif

/*
 * Is epoll available on this platform?
 */
#if defined(HAVE_EPOLL_CREATE) && defined(HAVE_SYS_EPOLL_H)
#define EPOLL 1
#else
#define EPOLL 0
#endif
