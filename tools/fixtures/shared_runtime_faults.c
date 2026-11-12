/* Qualification-only injection at the real pthread_create boundary.
 * The production runtime is unmodified. Other calls use the native routine. */
#include <errno.h>
#include <pthread.h>
#include <stdatomic.h>

static _Atomic int refuse_next;
void hepta_refuse_next_pthread_create(void) { atomic_store(&refuse_next, 1); }
extern int __real_pthread_create(pthread_t *, const pthread_attr_t *,
                                 void *(*)(void *), void *);
int __wrap_pthread_create(pthread_t *thread, const pthread_attr_t *attributes,
                          void *(*entry)(void *), void *argument) {
    if (atomic_exchange(&refuse_next, 0)) return EAGAIN;
    return __real_pthread_create(thread, attributes, entry, argument);
}
