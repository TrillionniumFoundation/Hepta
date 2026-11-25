/* Independent host-only observer. No target C runtime or privileged host action. */
#define _GNU_SOURCE
#include <assert.h>
#include <inttypes.h>
#include <pthread.h>
#include <signal.h>
#include <stdatomic.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <sys/mman.h>
#include <sys/wait.h>
#include <unistd.h>

#ifdef HIA_TEST_FENCE
extern uint64_t f0(uint64_t);
int main(int argc, char **argv) {
    assert(argc == 2 && strcmp(argv[1], "fence") == 0);
    const uint64_t inputs[] = {0, 1, UINT64_C(0xfeed0123456789ab), UINT64_MAX};
    for (size_t i = 0; i < sizeof inputs / sizeof inputs[0]; ++i)
        assert(f0(inputs[i]) == inputs[i]);
    puts("{\"mode\":\"fence\",\"status\":\"PASS\",\"native_calls\":4}");
    return 0;
}
#else
extern uint64_t f0(uint64_t, uint64_t, uint64_t);
enum { THREADS = 4, PER_THREAD = 4096, TOTAL = THREADS * PER_THREAD };
static _Alignas(8) _Atomic uint64_t counter;
static pthread_barrier_t start;
static uint64_t seen[THREADS][PER_THREAD];
static uint64_t failures[THREADS];

static uint64_t cas(void *p, uint64_t expected, uint64_t replacement) {
    return f0((uint64_t)(uintptr_t)p, expected, replacement);
}

static void *worker(void *arg) {
    size_t n = (size_t)(uintptr_t)arg;
    int rc = pthread_barrier_wait(&start);
    assert(rc == 0 || rc == PTHREAD_BARRIER_SERIAL_THREAD);
    for (size_t i = 0; i < PER_THREAD; ++i) {
        uint64_t before = atomic_load_explicit(&counter, memory_order_seq_cst);
        for (;;) {
            assert(before < TOTAL);
            uint64_t actual = cas(&counter, before, before + 1);
            if (actual == before) {
                seen[n][i] = actual;
                break;
            }
            assert(actual > before);
            assert(++failures[n] <= UINT64_C(10000000));
            before = actual;
        }
    }
    return NULL;
}

static void guard_signal(int signo, siginfo_t *info, void *context) {
    (void)context;
    const volatile unsigned char *p = info->si_addr;
    /* Exact site TEST DL,7; JZ +2; UD2, not an arbitrary signal. */
    if (signo == SIGILL && p && p[-5] == 0xf6 && p[-4] == 0xc2 &&
        p[-3] == 0x07 && p[-2] == 0x74 && p[-1] == 0x02 &&
        p[0] == 0x0f && p[1] == 0x0b)
        _exit(77);
    _exit(78);
}

static void alignment(int bypass) {
    unsigned char *mem = mmap(NULL, 4096, PROT_READ | PROT_WRITE,
                              MAP_SHARED | MAP_ANONYMOUS, -1, 0);
    assert(mem != MAP_FAILED);
    unsigned char initial[32], changed[32];
    for (size_t i = 0; i < sizeof initial; ++i) initial[i] = (unsigned char)(i + 31);
    memcpy(mem, initial, sizeof initial);
    memcpy(changed, initial, sizeof initial);
    uint64_t expected, replacement = UINT64_C(0x123456789abcdef0);
    memcpy(&expected, initial + 1, sizeof expected);
    memcpy(changed + 1, &replacement, sizeof replacement);
    pid_t child = fork();
    assert(child >= 0);
    if (child == 0) {
        struct sigaction sa = {0};
        sa.sa_sigaction = guard_signal;
        sa.sa_flags = SA_SIGINFO;
        assert(sigemptyset(&sa.sa_mask) == 0);
        assert(sigaction(SIGILL, &sa, NULL) == 0);
        uint64_t old = cas(mem + 1, expected, replacement);
        _exit(old == expected ? 79 : 80);
    }
    int status;
    assert(waitpid(child, &status, 0) == child && WIFEXITED(status));
    assert(WEXITSTATUS(status) == (bypass ? 79 : 77));
    assert(memcmp(mem, bypass ? changed : initial, sizeof initial) == 0);
    assert(munmap(mem, 4096) == 0);
}

int main(int argc, char **argv) {
    assert(argc == 2);
    const uint64_t a = UINT64_C(0xfedcba9876543210);
    const uint64_t b = UINT64_C(0x8765432101234567);
    if (strcmp(argv[1], "guard-nop") == 0) {
        alignment(1);
        puts("{\"mode\":\"guard-nop\",\"status\":\"PASS\",\"misaligned_write_detected\":true}");
        return 0;
    }
    atomic_init(&counter, a);
    if (strcmp(argv[1], "nop") == 0) {
        assert(cas(&counter, a, b) == a);
        assert(atomic_load(&counter) == a);
        assert(cas(&counter, b, 0) == b);
        assert(atomic_load(&counter) == a);
        puts("{\"mode\":\"nop\",\"status\":\"PASS\",\"missing_write_detected\":true,\"fake_old_value_detected\":true}");
        return 0;
    }
    assert(strcmp(argv[1], "cas") == 0);
    assert(cas(&counter, a, b) == a);
    assert(atomic_load(&counter) == b);
    assert(cas(&counter, a, 0) == b);
    assert(atomic_load(&counter) == b);
    assert(cas(&counter, b, a) == b);
    assert(atomic_load(&counter) == a);
    alignment(0);
    atomic_store(&counter, 0);
    pthread_t threads[THREADS];
    assert(pthread_barrier_init(&start, NULL, THREADS) == 0);
    for (size_t i = 0; i < THREADS; ++i)
        assert(pthread_create(&threads[i], NULL, worker, (void *)(uintptr_t)i) == 0);
    for (size_t i = 0; i < THREADS; ++i)
        assert(pthread_join(threads[i], NULL) == 0);
    assert(pthread_barrier_destroy(&start) == 0);
    unsigned char covered[TOTAL] = {0};
    uint64_t retries = 0;
    for (size_t i = 0; i < THREADS; ++i) {
        retries += failures[i];
        for (size_t j = 0; j < PER_THREAD; ++j) {
            uint64_t old = seen[i][j];
            assert(old < TOTAL && covered[old] == 0);
            covered[old] = 1;
        }
    }
    for (size_t i = 0; i < TOTAL; ++i) assert(covered[i] == 1);
    assert(atomic_load(&counter) == TOTAL);
    printf("{\"mode\":\"cas\",\"status\":\"PASS\",\"threads\":%d,"
           "\"successful_updates\":%d,\"distinct_old_values\":%d,"
           "\"failed_comparisons\":%" PRIu64 ",\"exact_alignment_trap\":true}\n",
           THREADS, TOTAL, TOTAL, retries);
    return 0;
}
#endif
