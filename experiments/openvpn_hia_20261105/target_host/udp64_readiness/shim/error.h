/* Any upstream event error fails this bounded experiment immediately. */
#define M_WARN 1
#define M_ERRNO 2
#define M_ERR 4
#define D_EVENT_WAIT 8
#define D_EVENT_ERRORS 16
#define D_LINK_ERRORS 32
#define ptr_format "%p"
#define ptr_type void *
#define dmsg(...) ((void)0)
#define msg(level, ...) do { (void)(level); fprintf(stderr, __VA_ARGS__); fputc('\n', stderr); abort(); } while (0)
