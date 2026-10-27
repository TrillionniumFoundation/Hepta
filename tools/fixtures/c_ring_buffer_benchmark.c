/* Authored qualification harness. The upstream library files stay unchanged. */
#define _POSIX_C_SOURCE 200809L
#include "ringbuffer.h"
#include <dlfcn.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <time.h>

static uint64_t ns(void) {
    struct timespec t;
    if (clock_gettime(CLOCK_MONOTONIC, &t) != 0) abort();
    return (uint64_t)t.tv_sec * UINT64_C(1000000000) + (uint64_t)t.tv_nsec;
}
static void *symbol(void *library, const char *name) {
    void *result = dlsym(library, name);
    if (result == NULL) abort();
    return result;
}
int main(int argc, char **argv) {
    if (argc != 4) return 2;
    void *library = dlopen(argv[1], RTLD_NOW | RTLD_LOCAL);
    if (library == NULL) return 3;
    unsigned long iterations = strtoul(argv[3], NULL, 10);
    if (iterations == 0 || iterations > 10000000UL) return 4;
    unsigned long mode = strtoul(argv[2], NULL, 10);
    void (*init)(ring_buffer_t *, char *, size_t) = symbol(library, "ring_buffer_init");
    void (*put)(ring_buffer_t *, char) = symbol(library, "ring_buffer_queue");
    uint8_t (*get)(ring_buffer_t *, char *) = symbol(library, "ring_buffer_dequeue");
    void (*puts_)(ring_buffer_t *, const char *, size_t) = symbol(library, "ring_buffer_queue_arr");
    size_t (*gets_)(ring_buffer_t *, char *, size_t) = symbol(library, "ring_buffer_dequeue_arr");
    size_t (*count)(ring_buffer_t *) = symbol(library, "ring_buffer_num_items");
    uint8_t (*empty)(ring_buffer_t *) = symbol(library, "ring_buffer_is_empty");
    uint8_t (*full)(ring_buffer_t *) = symbol(library, "ring_buffer_is_full");
    char backing[1024] = {0}, input[64] = {0}, output[64] = {0};
    for (size_t i = 0; i < 64; ++i) input[i] = (char)i;
    ring_buffer_t ring;
    init(&ring, backing, sizeof(backing));
    uint64_t checksum = 0;
    uint64_t start = ns();
    for (unsigned long i = 0; i < iterations; ++i) {
        if (mode == 0) {
            put(&ring, (char)i);
            if (get(&ring, output) != 1) return 5;
            checksum += (unsigned char)output[0];
        } else if (mode == 1) {
            puts_(&ring, input, sizeof(input));
            if (gets_(&ring, output, sizeof(output)) != sizeof(output)) return 6;
            checksum += (unsigned char)output[i % sizeof(output)];
        } else if (mode == 2) {
            checksum += count(&ring) + empty(&ring) + full(&ring);
        } else return 7;
    }
    uint64_t elapsed = ns() - start;
    printf("{\"mode\":%lu,\"iterations\":%lu,\"nanoseconds\":%llu,\"checksum\":%llu}\n",
           mode, iterations, (unsigned long long)elapsed, (unsigned long long)checksum);
    dlclose(library);
    return 0;
}
