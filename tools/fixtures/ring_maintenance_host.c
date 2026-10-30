#define _GNU_SOURCE
#include <dlfcn.h>
#include <errno.h>
#include <limits.h>
#include <pthread.h>
#include <signal.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/resource.h>
#include <sys/wait.h>
#include <time.h>
#include <unistd.h>
#include "ringbuffer.h"

/* This host uses the unchanged upstream public header and dlsym for every
 * operation. The header's three inline helpers cannot bypass the measured
 * implementation. Records are thread-local or protected by this host mutex. */
struct api {
    void (*init)(ring_buffer_t *, char *, size_t);
    void (*queue)(ring_buffer_t *, char);
    void (*queue_arr)(ring_buffer_t *, const char *, ring_buffer_size_t);
    uint8_t (*dequeue)(ring_buffer_t *, char *);
    ring_buffer_size_t (*dequeue_arr)(ring_buffer_t *, char *, ring_buffer_size_t);
    uint8_t (*peek)(ring_buffer_t *, char *, ring_buffer_size_t);
    uint8_t (*is_empty)(ring_buffer_t *);
    uint8_t (*is_full)(ring_buffer_t *);
    ring_buffer_size_t (*num_items)(ring_buffer_t *);
};
static struct api functions;

static void fail(const char *message) {
    fprintf(stderr, "%s\n", message);
    exit(70);
}

static uint64_t now(void) {
    struct timespec value;
    if (clock_gettime(CLOCK_MONOTONIC_RAW, &value)) fail("clock_gettime");
    return (uint64_t)value.tv_sec * UINT64_C(1000000000) + (uint64_t)value.tv_nsec;
}

static void *symbol(void *library, const char *name) {
    dlerror();
    void *result = dlsym(library, name);
    if (dlerror() || !result) fail(name);
    return result;
}

static void *load(const char *path) {
    void *library = dlopen(path, RTLD_NOW | RTLD_LOCAL);
    if (!library) fail(dlerror());
#define LOAD(name) *(void **)(&functions.name) = symbol(library, "ring_buffer_" #name)
    LOAD(init); LOAD(queue); LOAD(queue_arr); LOAD(dequeue); LOAD(dequeue_arr);
    LOAD(peek); LOAD(is_empty); LOAD(is_full); LOAD(num_items);
#undef LOAD
    return library;
}

/* A transaction has an independent byte oracle, not only cross-implementation
 * agreement. Its storage and output sentinel remain live throughout the call. */
static int transaction(ring_buffer_t *ring, unsigned thread, size_t ordinal,
                       uint64_t *checksum, uint64_t *bytes) {
    char input[128], output[128];
    size_t count = (ordinal + thread * 13u) % 96u;
    for (size_t i = 0; i < sizeof(input); i++)
        input[i] = (char)((ordinal * 17u + thread * 23u + i * 7u) & 255u);
    memset(output, 0x5a, sizeof(output));
    if (count) {
        functions.queue(ring, input[0]);
        functions.queue_arr(ring, input + 1, count - 1);
    } else {
        functions.queue_arr(ring, input, 0);
    }
    if (functions.num_items(ring) != count || functions.is_full(ring)) return 1;
    char peek = 0x5a;
    if (functions.peek(ring, &peek, count ? count - 1 : 0) != !!count) return 2;
    if (count && peek != input[count - 1]) return 3;
    if (!count && peek != 0x5a) return 4;
    if (functions.dequeue(ring, output) != !!count) return 5;
    size_t offset = count ? 1 : 0;
    if (functions.dequeue_arr(ring, output + offset, 127) != count - offset) return 6;
    if (memcmp(input, output, count) || output[count] != 0x5a) return 7;
    if (!functions.is_empty(ring) || functions.num_items(ring) || functions.is_full(ring)) return 8;
    for (size_t i = 0; i < count; i++)
        *checksum = (*checksum ^ (unsigned char)output[i]) * UINT64_C(1099511628211);
    *bytes += count;
    return 0;
}

struct context {
    unsigned id;
    size_t batches, transactions;
    pthread_barrier_t *barrier;
    pthread_mutex_t *mutex;
    ring_buffer_t *shared;
    uint64_t *latencies;
    uint64_t checksum, bytes;
    int error;
};

static void *worker(void *argument) {
    struct context *context = argument;
    char storage[256];
    ring_buffer_t local;
    ring_buffer_t *ring = context->shared ? context->shared : &local;
    if (!context->shared) functions.init(ring, storage, sizeof(storage));
    context->checksum = UINT64_C(1469598103934665603);
    int waited = pthread_barrier_wait(context->barrier);
    if (waited && waited != PTHREAD_BARRIER_SERIAL_THREAD) { context->error = 90; return NULL; }
    for (size_t batch = 0; batch < context->batches; batch++) {
        uint64_t begin = now();
        for (size_t index = 0; index < context->transactions; index++) {
            if (context->mutex && pthread_mutex_lock(context->mutex)) { context->error = 91; return NULL; }
            int bad = transaction(ring, context->id, batch * context->transactions + index,
                                  &context->checksum, &context->bytes);
            if (context->mutex && pthread_mutex_unlock(context->mutex)) { context->error = 92; return NULL; }
            if (bad) { context->error = bad; return NULL; }
        }
        context->latencies[batch] = now() - begin;
    }
    return NULL;
}

static void concurrency(unsigned threads, int shared, size_t batches, size_t transactions) {
    if (!(threads == 1 || threads == 4) || !(shared == 0 || shared == 1)
        || batches != 128 || transactions != 128) fail("outside frozen host profile");
    pthread_t workers[4];
    struct context contexts[4] = {0};
    uint64_t latencies[4][128] = {{0}};
    pthread_barrier_t barrier;
    pthread_mutex_t mutex = PTHREAD_MUTEX_INITIALIZER;
    char storage[256];
    ring_buffer_t ring;
    functions.init(&ring, storage, sizeof(storage));
    if (pthread_barrier_init(&barrier, NULL, threads)) fail("barrier init");
    uint64_t begin = now();
    for (unsigned i = 0; i < threads; i++) {
        contexts[i] = (struct context){.id=i, .batches=batches, .transactions=transactions,
            .barrier=&barrier, .mutex=shared ? &mutex : NULL,
            .shared=shared ? &ring : NULL, .latencies=latencies[i]};
        if (pthread_create(&workers[i], NULL, worker, &contexts[i])) fail("pthread_create");
    }
    for (unsigned i = 0; i < threads; i++) {
        if (pthread_join(workers[i], NULL) || contexts[i].error) fail("thread oracle failed");
    }
    uint64_t elapsed = now() - begin;
    if (pthread_barrier_destroy(&barrier) || pthread_mutex_destroy(&mutex)) fail("synchronization cleanup");
    printf("{\"threads\":%u,\"shared\":%s,\"batches_per_thread\":%zu,"
           "\"transactions_per_batch\":%zu,\"transactions\":%zu,\"whole_run_ns\":%llu,"
           "\"checksums\":[", threads, shared ? "true" : "false", batches,
           transactions, threads * batches * transactions, (unsigned long long)elapsed);
    for (unsigned i = 0; i < threads; i++)
        printf("%s%llu", i ? "," : "", (unsigned long long)contexts[i].checksum);
    printf("],\"bytes_per_thread\":[");
    for (unsigned i = 0; i < threads; i++)
        printf("%s%llu", i ? "," : "", (unsigned long long)contexts[i].bytes);
    printf("],\"batch_ns\":[");
    for (unsigned i = 0; i < threads; i++)
        for (size_t j = 0; j < batches; j++)
            printf("%s%llu", i || j ? "," : "", (unsigned long long)latencies[i][j]);
    printf("]}\n");
}

static const char *fault_names[] = {"null_record", "misaligned_record", "record_buffer_overlap",
    "output_buffer_overlap", "input_buffer_overlap", "extent_overflow", "bad_index",
    "null_storage", "zero_capacity"};

static void fault(unsigned mode) {
    char bytes[8];
    ring_buffer_t ring;
    functions.init(&ring, bytes, sizeof(bytes));
    switch (mode) {
        case 0: functions.queue(NULL, 1); break;
        case 1: functions.queue((ring_buffer_t *)((char *)&ring + 1), 1); break;
        case 2: ring.buffer = (char *)&ring; functions.queue(&ring, 1); break;
        case 3: functions.queue(&ring, 1); functions.dequeue(&ring, bytes); break;
        case 4: functions.queue_arr(&ring, bytes, 1); break;
        case 5: ring.buffer_mask = SIZE_MAX; functions.queue(&ring, 1); break;
        case 6: ring.head_index = 999; functions.queue(&ring, 1); break;
        case 7: functions.init(&ring, NULL, 8); break;
        case 8: functions.init(&ring, NULL, 0); break;
        default: _exit(99);
    }
}

static void faults(void) {
    struct rlimit no_core = {0, 0};
    if (setrlimit(RLIMIT_CORE, &no_core)) fail("disable core dumps");
    printf("{\"recovery_scope\":\"separate_child_process\",\"cases\":[");
    fflush(stdout);
    for (unsigned mode = 0; mode < sizeof(fault_names) / sizeof(*fault_names); mode++) {
        pid_t child = fork();
        if (child < 0) fail("fork");
        if (!child) { fault(mode); _exit(0); }
        int status;
        while (waitpid(child, &status, 0) < 0) if (errno != EINTR) fail("waitpid");
        int observed = WIFSIGNALED(status) ? WTERMSIG(status) : 0;
        if (observed != SIGABRT) fail("invalid boundary failed to abort");
        char storage[256];
        ring_buffer_t ring;
        uint64_t checksum = 0, bytes = 0;
        functions.init(&ring, storage, sizeof(storage));
        if (transaction(&ring, 0, mode + 1, &checksum, &bytes)) fail("post-fault parent recovery");
        printf("%s{\"case\":\"%s\",\"child_signal\":%d,\"parent_roundtrip_ok\":true,"
               "\"recovery_bytes\":%llu}", mode ? "," : "", fault_names[mode], observed,
               (unsigned long long)bytes);
        fflush(stdout);
    }
    printf("]}\n");
}

int main(int argc, char **argv) {
    if (argc < 3) return 64;
    void *library = load(argv[1]);
    if (!strcmp(argv[2], "layout")) {
        uint16_t endian_probe = 1;
        printf("{\"size\":%zu,\"align\":%zu,\"buffer\":%zu,\"buffer_mask\":%zu,"
               "\"tail_index\":%zu,\"head_index\":%zu,\"char_min\":%d,\"char_max\":%d,"
               "\"pointer_bytes\":%zu,\"size_t_bytes\":%zu,\"char_bits\":%d,\"little_endian\":%s}\n",
               sizeof(ring_buffer_t), _Alignof(ring_buffer_t), offsetof(ring_buffer_t, buffer),
               offsetof(ring_buffer_t, buffer_mask), offsetof(ring_buffer_t, tail_index),
               offsetof(ring_buffer_t, head_index), CHAR_MIN, CHAR_MAX, sizeof(void *),
               sizeof(size_t), CHAR_BIT, *(unsigned char *)&endian_probe ? "true" : "false");
    } else if (!strcmp(argv[2], "faults")) {
        faults();
    } else if (!strcmp(argv[2], "concurrency") && argc == 7) {
        concurrency((unsigned)strtoul(argv[3], NULL, 10), atoi(argv[4]),
                    strtoul(argv[5], NULL, 10), strtoul(argv[6], NULL, 10));
    } else return 65;
    if (dlclose(library)) fail("dlclose");
    return 0;
}
