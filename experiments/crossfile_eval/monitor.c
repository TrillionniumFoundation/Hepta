#include <pthread.h>
#include <stdint.h>
#include <stdatomic.h>
static _Atomic uint64_t started, joined;
int __real_pthread_create(pthread_t *, const pthread_attr_t *, void *(*)(void *), void *);
int __real_pthread_join(pthread_t, void **);
int __wrap_pthread_create(pthread_t *t, const pthread_attr_t *a, void *(*f)(void *), void *p) {
    int result = __real_pthread_create(t, a, f, p);
    if (result == 0) atomic_fetch_add(&started, 1);
    return result;
}
int __wrap_pthread_join(pthread_t t, void **p) {
    int result = __real_pthread_join(t, p);
    if (result == 0) atomic_fetch_add(&joined, 1);
    return result;
}
void cf_threads_reset(void) { atomic_store(&started, 0); atomic_store(&joined, 0); }
uint64_t cf_threads(void) { return atomic_load(&started); }
uint64_t cf_joins(void) { return atomic_load(&joined); }
