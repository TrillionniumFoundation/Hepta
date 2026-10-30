#define _GNU_SOURCE
#include <dirent.h>
#include <errno.h>
#include <inttypes.h>
#include <limits.h>
#include <poll.h>
#include <pthread.h>
#include <stdatomic.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/eventfd.h>
#include <time.h>
#include <unistd.h>

#if !defined(__linux__) || (!defined(__x86_64__) && !defined(__aarch64__)) || defined(__ILP32__)
#error This qualification requires native Linux x86_64 or AArch64 LP64
#endif
#if __BYTE_ORDER__ != __ORDER_LITTLE_ENDIAN__
#error Little-endian host required
#endif
_Static_assert(CHAR_BIT == 8 && sizeof(void *) == 8 && sizeof(size_t) == 8 &&
               sizeof(long) == 8 && sizeof(unsigned int) == 4 && sizeof(uint64_t) == 8,
               "LP64 ABI required");

enum { WORKERS = 3, JOBS = 16, SLOTS = 64 };
extern uint64_t worker_checksum(size_t, uint32_t);
void *__real_malloc(size_t);
void *__real_calloc(size_t, size_t);
void __real_free(void *);

/* Only direct component allocation references are wrapped. libc/pthread
 * internal allocations and allocator overhead are outside this meter. */
static pthread_mutex_t meter_lock = PTHREAD_MUTEX_INITIALIZER;
static _Thread_local int current_job = -1;
struct allocation { void *pointer; size_t bytes; };
static struct {
    struct allocation slots[SLOTS];
    uint64_t attempts, allocations, frees, live_bytes, peak_bytes, live_owners;
    uint64_t failures, invalid_frees, overflow;
    int fail_at, failed_job;
} meter;

static void *tracked_allocate(size_t count, size_t size, int zero) {
    if (current_job < 0) return zero ? __real_calloc(count, size) : __real_malloc(size);
    pthread_mutex_lock(&meter_lock);
    meter.attempts++;
    if (meter.fail_at && meter.attempts == (uint64_t)meter.fail_at) {
        meter.failures++; meter.failed_job = current_job;
        pthread_mutex_unlock(&meter_lock); return NULL;
    }
    if (count && size > SIZE_MAX / count) {
        meter.failures++; pthread_mutex_unlock(&meter_lock); return NULL;
    }
    size_t bytes = count * size;
    void *pointer = zero ? __real_calloc(count, size) : __real_malloc(size);
    if (!pointer) { meter.failures++; pthread_mutex_unlock(&meter_lock); return NULL; }
    int slot;
    for (slot = 0; slot < SLOTS && meter.slots[slot].pointer; ++slot) {}
    if (slot == SLOTS) {
        meter.overflow++; __real_free(pointer); pthread_mutex_unlock(&meter_lock); return NULL;
    }
    meter.slots[slot] = (struct allocation){pointer, bytes};
    meter.allocations++; meter.live_owners++; meter.live_bytes += bytes;
    if (meter.live_bytes > meter.peak_bytes) meter.peak_bytes = meter.live_bytes;
    pthread_mutex_unlock(&meter_lock); return pointer;
}
void *__wrap_malloc(size_t bytes) { return tracked_allocate(1, bytes, 0); }
void *__wrap_calloc(size_t count, size_t size) { return tracked_allocate(count, size, 1); }
void __wrap_free(void *pointer) {
    if (!pointer) return;
    pthread_mutex_lock(&meter_lock);
    int slot;
    for (slot = 0; slot < SLOTS && meter.slots[slot].pointer != pointer; ++slot) {}
    if (slot < SLOTS) {
        meter.live_bytes -= meter.slots[slot].bytes; meter.live_owners--; meter.frees++;
        meter.slots[slot] = (struct allocation){0};
    } else if (current_job >= 0) {
        meter.invalid_frees++; pthread_mutex_unlock(&meter_lock); return;
    }
    pthread_mutex_unlock(&meter_lock); __real_free(pointer);
}

static int directory_count(const char *path, int exclude_directory_fd) {
    DIR *directory = opendir(path);
    if (!directory) return -1;
    int result = 0, own = dirfd(directory);
    struct dirent *entry;
    while ((entry = readdir(directory))) {
        if (entry->d_name[0] < '0' || entry->d_name[0] > '9') continue;
        if (exclude_directory_fd && atoi(entry->d_name) == own) continue;
        result++;
    }
    if (closedir(directory)) return -1;
    return result;
}

/* pthread_join can observe CLONE_CHILD_CLEARTID before procfs has removed the
 * exiting task's directory. Keep the first observation, then wait at most
 * 1000 one-millisecond polls for actual task-table quiescence. A remaining
 * task is a failure; no next case resets or hides it. */
static int settled_threads(int *first, int *polls) {
    int count = *first = directory_count("/proc/self/task", 0);
    *polls = 0;
    while (count > 1 && *polls < 1000) {
        struct timespec pause = {0, 1000000};
        if (nanosleep(&pause, NULL) < 0 && errno != EINTR) return -1;
        ++*polls;
        count = directory_count("/proc/self/task", 0);
    }
    return count;
}

struct scenario {
    const char *name;
    int allocation_failure, eventfd_failure, thread_failure;
    int read_eintr, write_eintr, completion_error, cancel;
};
struct job { size_t count; uint32_t seed; uint64_t result; int state, worker; };
struct runtime {
    struct scenario scenario;
    int work_fd, done_fd, opened, closed, created, joined, startup_error;
    atomic_int stop, fatal, next_job, completed, read_injected, write_injected, completion_injected;
    atomic_int active_jobs, peak_jobs, worker_mask;
    pthread_barrier_t first_jobs;
    struct job jobs[JOBS];
};
struct worker_arg { struct runtime *runtime; int id; };

static int notify(struct runtime *r, int fd, uint64_t count, int completion) {
    for (;;) {
        ssize_t result;
        if (completion && r->scenario.write_eintr && !atomic_exchange(&r->write_injected, 1)) {
            errno = EINTR; result = -1;
        } else if (completion && r->scenario.completion_error &&
                   !atomic_exchange(&r->completion_injected, 1)) {
            errno = EIO; result = -1;
        } else result = write(fd, &count, sizeof(count));
        if (result == (ssize_t)sizeof(count)) return 0;
        if (result < 0 && errno == EINTR) continue;
        return -1;
    }
}

static void *worker(void *value) {
    struct worker_arg *argument = value;
    struct runtime *r = argument->runtime;
    int first = 1;
    while (!atomic_load(&r->stop)) {
        struct pollfd wait = {r->work_fd, POLLIN, 0};
        int ready = poll(&wait, 1, 100);
        if (ready < 0 && errno == EINTR) continue;
        if (ready == 0) continue;
        if (ready < 0 || wait.revents & (POLLERR | POLLHUP | POLLNVAL)) {
            atomic_store(&r->fatal, 1); atomic_store(&r->stop, 1); break;
        }
        uint64_t token = 0;
        ssize_t got;
        if (r->scenario.read_eintr && !atomic_exchange(&r->read_injected, 1)) {
            errno = EINTR; got = -1;
        } else got = read(r->work_fd, &token, sizeof(token));
        if (got < 0 && (errno == EINTR || errno == EAGAIN)) continue;
        if (got != (ssize_t)sizeof(token) || token != 1) {
            atomic_store(&r->fatal, 1); atomic_store(&r->stop, 1); break;
        }
        if (atomic_load(&r->stop)) break;
        int index = atomic_fetch_add(&r->next_job, 1);
        if (index >= JOBS) continue;
        struct job *job = &r->jobs[index];
        job->state = 1; job->worker = argument->id; current_job = index;
        atomic_fetch_or(&r->worker_mask, 1 << argument->id);
        int active = atomic_fetch_add(&r->active_jobs, 1) + 1;
        int peak = atomic_load(&r->peak_jobs);
        while (active > peak && !atomic_compare_exchange_weak(&r->peak_jobs, &peak, active)) {}
        /* Establish three overlapping jobs and actual worker participation.
         * This is synchronization evidence, not parallel speedup evidence. */
        if (first && !r->scenario.cancel) {
            int barrier = pthread_barrier_wait(&r->first_jobs);
            if (barrier != 0 && barrier != PTHREAD_BARRIER_SERIAL_THREAD) exit(5);
        }
        first = 0;
        job->result = worker_checksum(job->count, job->seed);
        current_job = -1; job->state = 2;
        atomic_fetch_sub(&r->active_jobs, 1);
        atomic_fetch_add(&r->completed, 1);
        if (notify(r, r->done_fd, 1, 1)) {
            atomic_store(&r->fatal, 1); atomic_store(&r->stop, 1); break;
        }
    }
    return NULL;
}

static int new_eventfd(struct runtime *r, int ordinal) {
    if (r->scenario.eventfd_failure == ordinal) { errno = EMFILE; return -1; }
    int fd = eventfd(0, EFD_NONBLOCK | EFD_CLOEXEC | EFD_SEMAPHORE);
    if (fd >= 0) r->opened++;
    return fd;
}

static void run_case(struct scenario scenario) {
    struct runtime r = {.scenario = scenario, .work_fd = -1, .done_fd = -1};
    atomic_init(&r.stop, 0); atomic_init(&r.fatal, 0); atomic_init(&r.next_job, 0);
    atomic_init(&r.completed, 0); atomic_init(&r.read_injected, 0);
    atomic_init(&r.write_injected, 0); atomic_init(&r.completion_injected, 0);
    atomic_init(&r.active_jobs, 0); atomic_init(&r.peak_jobs, 0); atomic_init(&r.worker_mask, 0);
    if (pthread_barrier_init(&r.first_jobs, NULL, WORKERS)) exit(5);
    memset(&meter, 0, sizeof(meter)); meter.failed_job = -1; meter.fail_at = scenario.allocation_failure;
    const size_t lengths[] = {64, 1, 7, 0, 32, 2, 16, 3};
    for (int index = 0; index < JOBS; ++index) {
        r.jobs[index].count = lengths[index % 8];
        r.jobs[index].seed = index % 3 == 0 ? UINT32_MAX : (uint32_t)(index * 73);
        r.jobs[index].worker = -1;
    }
    int fd_before = directory_count("/proc/self/fd", 1);
    int threads_before = directory_count("/proc/self/task", 0);
    pthread_t threads[WORKERS];
    struct worker_arg arguments[WORKERS];
    r.work_fd = new_eventfd(&r, 1);
    if (r.work_fd < 0) { r.startup_error = errno; goto cleanup; }
    r.done_fd = new_eventfd(&r, 2);
    if (r.done_fd < 0) { r.startup_error = errno; goto cleanup; }
    for (int index = 0; index < WORKERS; ++index) {
        arguments[index] = (struct worker_arg){&r, index};
        int error = scenario.thread_failure == index + 1 ? EAGAIN :
                    pthread_create(&threads[index], NULL, worker, &arguments[index]);
        if (error) { r.startup_error = error; goto cleanup; }
        r.created++;
    }
    if (notify(&r, r.work_fd, scenario.cancel ? 1 : JOBS, 0)) {
        atomic_store(&r.fatal, 1); goto cleanup;
    }
    for (int waits = 0; waits < 100; ++waits) {
        if (atomic_load(&r.fatal)) break;
        int complete = atomic_load(&r.completed);
        if (complete == JOBS || (scenario.cancel && complete >= 1)) break;
        struct pollfd pending = {r.done_fd, POLLIN, 0};
        int ready = poll(&pending, 1, 50);
        if (ready < 0 && errno == EINTR) continue;
        if (ready < 0 || pending.revents & (POLLERR | POLLHUP | POLLNVAL)) {
            atomic_store(&r.fatal, 1); break;
        }
        if (ready > 0) {
            uint64_t token;
            ssize_t got = read(r.done_fd, &token, sizeof(token));
            if (got < 0 && errno != EAGAIN && errno != EINTR) { atomic_store(&r.fatal, 1); break; }
        }
    }
    if (!atomic_load(&r.fatal) && atomic_load(&r.completed) != (scenario.cancel ? 1 : JOBS))
        atomic_store(&r.fatal, 1);
cleanup:
    atomic_store(&r.stop, 1);
    if (r.work_fd >= 0) (void)notify(&r, r.work_fd, WORKERS, 0);
    for (int index = 0; index < r.created; ++index) {
        if (!pthread_join(threads[index], NULL)) r.joined++;
    }
    if (pthread_barrier_destroy(&r.first_jobs)) exit(5);
    if (r.done_fd >= 0 && !close(r.done_fd)) r.closed++;
    if (r.work_fd >= 0 && !close(r.work_fd)) r.closed++;
    int fd_after = directory_count("/proc/self/fd", 1);
    int threads_after_join, thread_quiescence_polls;
    int threads_after = settled_threads(&threads_after_join, &thread_quiescence_polls);
    printf("{\"schema\":\"hepta.hia.linux-interface-case.v1\",\"case\":\"%s\","
           "\"startup_error\":%d,\"fatal\":%d,\"completed\":%d,"
           "\"fd_before\":%d,\"fd_after\":%d,\"threads_before\":%d,\"threads_after\":%d,"
           "\"threads_after_join\":%d,\"thread_quiescence_polls\":%d,"
           "\"opened\":%d,\"closed\":%d,\"created\":%d,\"joined\":%d,"
           "\"active_jobs\":%d,\"peak_jobs\":%d,\"worker_mask\":%d,"
           "\"read_eintr_injected\":%d,\"write_eintr_injected\":%d,\"completion_error_injected\":%d,"
           "\"allocation_attempts\":%" PRIu64 ",\"allocations\":%" PRIu64 ",\"frees\":%" PRIu64 ","
           "\"allocation_failures\":%" PRIu64 ",\"failed_job\":%d,"
           "\"live_owners\":%" PRIu64 ",\"live_bytes\":%" PRIu64 ",\"peak_bytes\":%" PRIu64 ","
           "\"invalid_frees\":%" PRIu64 ",\"meter_overflow\":%" PRIu64 ",\"jobs\":[",
           scenario.name, r.startup_error, atomic_load(&r.fatal), atomic_load(&r.completed),
           fd_before, fd_after, threads_before, threads_after, threads_after_join, thread_quiescence_polls,
           r.opened, r.closed, r.created, r.joined,
           atomic_load(&r.active_jobs), atomic_load(&r.peak_jobs), atomic_load(&r.worker_mask),
           atomic_load(&r.read_injected), atomic_load(&r.write_injected), atomic_load(&r.completion_injected),
           meter.attempts, meter.allocations, meter.frees, meter.failures, meter.failed_job,
           meter.live_owners, meter.live_bytes, meter.peak_bytes, meter.invalid_frees, meter.overflow);
    for (int index = 0; index < JOBS; ++index)
        printf("%s{\"index\":%d,\"count\":%zu,\"seed\":%u,\"state\":%d,\"worker\":%d,\"result\":%" PRIu64 "}",
               index ? "," : "", index, r.jobs[index].count, r.jobs[index].seed,
               r.jobs[index].state, r.jobs[index].worker, r.jobs[index].result);
    printf("]}\n"); fflush(stdout);
    /* A leak is a hard failure, not a reset that launders the next scenario. */
    if (meter.live_owners || meter.live_bytes || meter.invalid_frees || meter.overflow ||
        fd_before < 0 || fd_before != fd_after || threads_before != threads_after || r.created != r.joined)
        exit(3);
}

static void kernel_errors(void) {
    int before = directory_count("/proc/self/fd", 1);
    int fd = eventfd(0, EFD_NONBLOCK | EFD_CLOEXEC);
    if (fd < 0) exit(4);
    uint64_t value = 0;
    errno = 0; ssize_t empty = read(fd, &value, sizeof(value)); int empty_errno = errno;
    value = UINT64_MAX;
    errno = 0; ssize_t invalid = write(fd, &value, sizeof(value)); int invalid_errno = errno;
    value = UINT64_MAX - 1;
    ssize_t filled = write(fd, &value, sizeof(value)); value = 1;
    errno = 0; ssize_t full = write(fd, &value, sizeof(value)); int full_errno = errno;
    ssize_t drained = read(fd, &value, sizeof(value));
    if (close(fd)) exit(4);
    int after = directory_count("/proc/self/fd", 1);
    printf("{\"schema\":\"hepta.hia.linux-eventfd-errors.v1\",\"empty_read\":%zd,\"empty_errno\":%d,"
           "\"invalid_write\":%zd,\"invalid_errno\":%d,\"filled\":%zd,\"full_write\":%zd,"
           "\"full_errno\":%d,\"drained\":%zd,\"value\":%" PRIu64 ",\"fd_before\":%d,\"fd_after\":%d}\n",
           empty, empty_errno, invalid, invalid_errno, filled, full, full_errno, drained, value, before, after);
}

int main(void) {
#if defined(__x86_64__)
    const char *machine = "x86_64";
#else
    const char *machine = "aarch64";
#endif
    printf("{\"schema\":\"hepta.hia.linux-compiled-abi.v1\",\"machine\":\"%s\","
           "\"pointer_bits\":%zu,\"size_t_bits\":%zu,\"long_bits\":%zu,\"u32_bits\":%zu,"
           "\"workers\":%d,\"jobs\":%d}\n", machine, sizeof(void*)*CHAR_BIT,
           sizeof(size_t)*CHAR_BIT, sizeof(long)*CHAR_BIT, sizeof(uint32_t)*CHAR_BIT, WORKERS, JOBS);
    kernel_errors();
    const struct scenario cases[] = {
        {"normal",0,0,0,0,0,0,0}, {"allocation_fail_1",1,0,0,0,0,0,0},
        {"allocation_fail_3",3,0,0,0,0,0,0}, {"eventfd_fail_1",0,1,0,0,0,0,0},
        {"eventfd_fail_2",0,2,0,0,0,0,0}, {"thread_fail_1",0,0,1,0,0,0,0},
        {"thread_fail_2",0,0,2,0,0,0,0}, {"read_eintr",0,0,0,1,0,0,0},
        {"write_eintr",0,0,0,0,1,0,0}, {"completion_error",0,0,0,0,0,1,0},
        {"cooperative_cancel",0,0,0,0,0,0,1},
    };
    for (size_t index = 0; index < sizeof(cases)/sizeof(cases[0]); ++index) {
        run_case(cases[index]);
        if (index) run_case((struct scenario){"recovery",0,0,0,0,0,0,0});
    }
    return 0;
}
