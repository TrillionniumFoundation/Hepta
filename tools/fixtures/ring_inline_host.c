#define _GNU_SOURCE
#include <dlfcn.h>
#include <dirent.h>
#include <fcntl.h>
#include <stddef.h>
#include <sys/eventfd.h>
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

/* Every host-created ring is fully initialized for observational checks.
 * The unchanged upstream simple.c is built and run separately without this
 * extra initialization. This host uses the unchanged upstream public header and dlsym for every
 * operation. The header's three inline helpers cannot bypass the measured
 * implementation. Records are thread-local or protected by this host mutex. */
struct api {
    void (*init)(ring_buffer_t *);
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
    char input[128], output[256];
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
    ring_buffer_t local;
    memset(&local, 0xa5, sizeof(local));
    ring_buffer_t *ring = context->shared ? context->shared : &local;
    if (!context->shared) functions.init(ring);
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
    ring_buffer_t ring;
    memset(&ring, 0xa5, sizeof(ring));
    functions.init(&ring);
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


/* An independently checked operation stream; output backing is 256 bytes so
 * old dequeue_arr's declared len+1 extent is valid even when len is 255. */
static void hex_bytes(const void *value, size_t size) {
    const unsigned char *bytes = value;
    for (size_t i=0; i<size; i++) printf("%02x", (unsigned)bytes[i]);
}
static void trace(void) {
    ring_buffer_t ring;
    memset(&ring, 0xa5, sizeof(ring));
    functions.init(&ring);
    char op;
    while (scanf(" %c", &op) == 1) {
        unsigned number=0, byte=0, returned=0;
        char input[256], output[256];
        memset(input,0,sizeof(input)); memset(output,0xa5,sizeof(output));
        if (op=='I') functions.init(&ring);
        else if (op=='Q') {
            if (scanf("%u",&byte)!=1 || byte>255) fail("trace queue input");
            functions.queue(&ring,(char)byte);
        } else if (op=='A') {
            if (scanf("%u",&number)!=1 || number>255) fail("trace array count");
            for (unsigned i=0; i<number; i++) {
                if (scanf("%u",&byte)!=1 || byte>255) fail("trace array input");
                input[i]=(char)byte;
            }
            functions.queue_arr(&ring,input,(ring_buffer_size_t)number);
        } else if (op=='D') returned=functions.dequeue(&ring,output);
        else if (op=='R' || op=='P') {
            if (scanf("%u",&number)!=1 || number>255) fail("trace output count");
            returned=op=='R' ? functions.dequeue_arr(&ring,output,(ring_buffer_size_t)number)
                             : functions.peek(&ring,output,(ring_buffer_size_t)number);
        } else if (op!='E') fail("trace unknown operation");
        printf("{\"return\":%u,\"head\":%u,\"tail\":%u,\"count\":%u,\"empty\":%u,\"full\":%u,\"payload\":\"",
            returned,(unsigned)ring.head_index,(unsigned)ring.tail_index,
            (unsigned)functions.num_items(&ring),(unsigned)functions.is_empty(&ring),
            (unsigned)functions.is_full(&ring));
        hex_bytes(ring.buffer,sizeof(ring.buffer));printf("\",\"output\":\"");
        hex_bytes(output,sizeof(output)); printf("\"}\n");
    }
    if (!feof(stdin)) fail("trace input error");
}
static int descriptors(void) {
    DIR *directory=opendir("/proc/self/fd"); if(!directory) fail("open fd inventory");
    int count=0; struct dirent *entry;
    while((entry=readdir(directory))) if(entry->d_name[0]!='.') count++;
    if(closedir(directory)) fail("close fd inventory");
    return count-1; /* exclude the inventory descriptor itself */
}
static void devices(void) {
    int before=descriptors();
    char input[64],output[65]; memset(input,0xa5,sizeof(input));memset(output,0xa5,sizeof(output));
    int zero=open("/dev/zero",O_RDONLY|O_CLOEXEC);if(zero<0) fail("open /dev/zero");
    ssize_t count=read(zero,input,sizeof(input)); if(count!=(ssize_t)sizeof(input)) fail("read /dev/zero");
    if(close(zero)) fail("close /dev/zero");
    for(size_t i=0;i<sizeof(input);i++) if(input[i]!=0) fail("/dev/zero content");
    ring_buffer_t ring;memset(&ring,0xa5,sizeof(ring));functions.init(&ring);
    functions.queue_arr(&ring,input,sizeof(input));
    if(functions.dequeue_arr(&ring,output,sizeof(input))!=sizeof(input)
        || memcmp(input,output,sizeof(input)) || (unsigned char)output[64]!=0xa5) fail("device ring roundtrip");
    int full=open("/dev/full",O_WRONLY|O_CLOEXEC);if(full<0) fail("open /dev/full");
    errno=0;ssize_t written=write(full,input,sizeof(input));int full_errno=errno;
    if(written!=-1 || full_errno!=ENOSPC) fail("/dev/full ENOSPC");
    if(close(full)) fail("close /dev/full");
    int event=eventfd(0,EFD_NONBLOCK|EFD_CLOEXEC);if(event<0) fail("eventfd");
    uint64_t value=0;errno=0;ssize_t empty_read=read(event,&value,sizeof(value));int empty_errno=errno;
    if(empty_read!=-1 || empty_errno!=EAGAIN) fail("eventfd EAGAIN");
    value=2;if(write(event,&value,sizeof(value))!=sizeof(value)) fail("eventfd write");
    value=0;if(read(event,&value,sizeof(value))!=sizeof(value) || value!=2) fail("eventfd read");
    if(close(event)) fail("eventfd close");
    errno=0;ssize_t closed_read=read(event,&value,sizeof(value));int closed_errno=errno;
    if(closed_read!=-1 || closed_errno!=EBADF) fail("eventfd EBADF");
    event=eventfd(0,EFD_NONBLOCK|EFD_CLOEXEC);if(event<0) fail("eventfd recovery open");
    value=3;if(write(event,&value,sizeof(value))!=sizeof(value)) fail("eventfd recovery write");
    value=0;if(read(event,&value,sizeof(value))!=sizeof(value) || value!=3) fail("eventfd recovery read");
    if(close(event)) fail("eventfd recovery close");
    int after=descriptors();if(after!=before) fail("descriptor leak");
    printf("{\"profile\":\"linux_os_descriptors\",\"physical_device\":false,"
        "\"zero_read_bytes\":%zd,\"full_write_return\":%zd,\"full_errno\":%d,"
        "\"event_empty_return\":%zd,\"event_empty_errno\":%d,\"event_roundtrip\":2,"
        "\"closed_read_return\":%zd,\"closed_errno\":%d,\"reopened_roundtrip\":3,"
        "\"descriptors_before\":%d,\"descriptors_after\":%d,\"ring_roundtrip\":true}\n",
        count,written,full_errno,empty_read,empty_errno,closed_read,closed_errno,before,after);
}
static const char *fault_names[]={"null_record","output_record_overlap","input_record_overlap","bad_head_index","null_output","legacy_missing_extra_extent"};
static void fault(unsigned mode) {
    ring_buffer_t ring; char output[256];memset(&ring,0xa5,sizeof(ring));functions.init(&ring);
    switch(mode) {
    case 0:functions.queue(NULL,1);break;
    case 1:functions.queue(&ring,1);functions.dequeue(&ring,ring.buffer);break;
    case 2:functions.queue_arr(&ring,ring.buffer,1);break;
    case 3:ring.head_index=255;functions.queue(&ring,1);break;
    case 4:functions.queue(&ring,1);functions.dequeue(&ring,NULL);break;
    case 5:functions.queue(&ring,1);functions.queue(&ring,2);functions.dequeue_arr(&ring,output,1);break;
    default:fail("unknown fault");
    }
    fail("injected invalid contract was accepted");
}
static void recovery(unsigned mode) {
    if(mode>=sizeof(fault_names)/sizeof(fault_names[0])) fail("fault mode");
    int before=descriptors();
    pid_t child=fork();if(child<0) fail("fork fault");
    if(!child){struct rlimit limit={0,0};setrlimit(RLIMIT_CORE,&limit);fault(mode);_exit(98);}
    int status=0;while(waitpid(child,&status,0)<0){if(errno!=EINTR) fail("wait fault");}
    if(!WIFSIGNALED(status) || WTERMSIG(status)!=SIGABRT) fail("expected guarded SIGABRT");
    ring_buffer_t ring;memset(&ring,0xa5,sizeof(ring));functions.init(&ring);
    uint64_t checksum=UINT64_C(1469598103934665603),bytes=0;
    if(transaction(&ring,0,17,&checksum,&bytes)) fail("post-fault parent recovery");
    int after=descriptors();if(after!=before) fail("fault descriptor leak");
    printf("{\"fault\":\"%s\",\"child_signal\":%d,\"parent_roundtrip\":true,"
           "\"process_isolation\":true,\"in_process_repair\":false,\"descriptors_before\":%d,\"descriptors_after\":%d}\n",
           fault_names[mode],WTERMSIG(status),before,after);
}
static void abi(void) {
    printf("{\"record_size\":%zu,\"record_align\":%zu,\"buffer_offset\":%zu,\"tail_offset\":%zu,\"head_offset\":%zu,"
           "\"pointer_bits\":%zu,\"int_bits\":%zu,\"long_bits\":%zu,\"size_t_bits\":%zu,\"char_min\":%d,\"buffer_capacity\":%u}\n",
           sizeof(ring_buffer_t),_Alignof(ring_buffer_t),offsetof(ring_buffer_t,buffer),offsetof(ring_buffer_t,tail_index),offsetof(ring_buffer_t,head_index),
           sizeof(void*)*CHAR_BIT,sizeof(int)*CHAR_BIT,sizeof(long)*CHAR_BIT,sizeof(size_t)*CHAR_BIT,CHAR_MIN,RING_BUFFER_SIZE);
}
int main(int argc,char **argv) {
    if(argc<3) fail("usage: host LIB MODE [ARGS]");
    void *library=load(argv[1]);
    if(!strcmp(argv[2],"abi")) abi();
    else if(!strcmp(argv[2],"trace")) trace();
    else if(!strcmp(argv[2],"devices")) devices();
    else if(!strcmp(argv[2],"fault") && argc==4) recovery((unsigned)strtoul(argv[3],NULL,10));
    else if(!strcmp(argv[2],"concurrency") && argc==7)
        concurrency((unsigned)strtoul(argv[3],NULL,10),atoi(argv[4]),(size_t)strtoul(argv[5],NULL,10),(size_t)strtoul(argv[6],NULL,10));
    else fail("invalid host mode");
    if(dlclose(library)) fail("dlclose");
    return 0;
}
