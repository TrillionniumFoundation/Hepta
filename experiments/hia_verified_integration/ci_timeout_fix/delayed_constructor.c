#include <errno.h>
#include <fcntl.h>
#include <time.h>
#include <unistd.h>
__attribute__((constructor)) static void delayed_constructor(void) {
  struct timespec delay = {3, 500000000};
  while (nanosleep(&delay, &delay) != 0 && errno == EINTR) {}
  int fd = open("/tmp/hepta-constructor-timeout-sn4l0bs0/forbidden_constructor_marker", O_CREAT|O_EXCL|O_WRONLY, 0600);
  if (fd >= 0) close(fd);
}
int healthy(void) { return 7; }
