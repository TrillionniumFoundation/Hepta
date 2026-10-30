/* Authored observation harness. Only calls while the entry is active count. */
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>

extern int strncmp_probe(size_t, uint64_t, uint64_t);
extern void *__real_malloc(size_t);
extern void *__real_calloc(size_t, size_t);
extern void __real_free(void *);
static unsigned attempts, allocations, frees, live, fail_at;
static int active;

void *__wrap_malloc(size_t size)
{
    if (active && ++attempts == fail_at) return NULL;
    void *value = __real_malloc(size);
    if (active && value) { ++allocations; ++live; }
    return value;
}

void *__wrap_calloc(size_t count, size_t size)
{
    if (active && ++attempts == fail_at) return NULL;
    void *value = __real_calloc(count, size);
    if (active && value) { ++allocations; ++live; }
    return value;
}

void __wrap_free(void *value)
{
    if (active && value) { ++frees; --live; }
    __real_free(value);
}

int main(int argc, char **argv)
{
    if (argc != 5) return 2;
    size_t n = (size_t)strtoull(argv[1], NULL, 10);
    uint64_t left = strtoull(argv[2], NULL, 10);
    uint64_t right = strtoull(argv[3], NULL, 10);
    fail_at = (unsigned)strtoul(argv[4], NULL, 10);
    active = 1;
    int result = strncmp_probe(n, left, right);
    active = 0;
    printf("{\"result\":%d,\"attempts\":%u,\"allocations\":%u,"
           "\"frees\":%u,\"live\":%u}\n", result, attempts, allocations, frees, live);
    return 0;
}
