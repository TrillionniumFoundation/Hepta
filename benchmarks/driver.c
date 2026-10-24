#define _POSIX_C_SOURCE 200809L
#include <errno.h>
#include <inttypes.h>
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

extern uint64_t hepta_sum(const uint64_t *, size_t);
extern void hepta_copy(uint64_t *, const uint64_t *, size_t);

static uint64_t nanoseconds(void) {
    struct timespec value;
    if (clock_gettime(CLOCK_MONOTONIC, &value)) { perror("clock_gettime"); exit(2); }
    return (uint64_t)value.tv_sec * UINT64_C(1000000000) + (uint64_t)value.tv_nsec;
}

static uint64_t parse(const char *text) {
    char *end;
    errno = 0;
    unsigned long long value = strtoull(text, &end, 10);
    if (errno || *end || !value) { fputs("invalid positive integer\n", stderr); exit(2); }
    return value;
}

int main(int argc, char **argv) {
    if (argc != 4 || (strcmp(argv[1], "sum") && strcmp(argv[1], "copy"))) {
        fputs("usage: driver sum|copy count iterations\n", stderr); return 2;
    }
    size_t count = (size_t)parse(argv[2]);
    size_t iterations = (size_t)parse(argv[3]);
    if (count > SIZE_MAX / sizeof(uint64_t)) return 2;
    uint64_t *input = malloc(count * sizeof(uint64_t));
    uint64_t *output = malloc(count * sizeof(uint64_t));
    if (!input || !output) { fputs("allocation failed\n", stderr); return 2; }
    uint64_t expected = 0;
    for (size_t i = 0; i < count; ++i) {
        input[i] = UINT64_C(0x9e3779b97f4a7c15) * (i + 1);
        output[i] = 0;
        expected += input[i];
    }
    /* Validate before timing, including zero-length and non-vector tails. */
    if (hepta_sum(input, count) != expected || hepta_sum(input, 0) != 0) return 3;
    hepta_copy(output, input, count);
    if (memcmp(input, output, count * sizeof(uint64_t))) return 4;
    hepta_copy(output, input, 0);
    int is_sum = !strcmp(argv[1], "sum");
    volatile uint64_t sink = 0;
    for (size_t i = 0; i < 8; ++i) {
        if (is_sum) sink ^= hepta_sum(input, count);
        else hepta_copy(output, input, count);
    }
    uint64_t begin = nanoseconds();
    for (size_t i = 0; i < iterations; ++i) {
        if (is_sum) sink ^= hepta_sum(input, count);
        else hepta_copy(output, input, count);
    }
    uint64_t elapsed = nanoseconds() - begin;
    if (!is_sum && memcmp(input, output, count * sizeof(uint64_t))) return 5;
    printf("{\"kernel\":\"%s\",\"elements\":%zu,\"iterations\":%zu,\"elapsed_ns\":%" PRIu64 ",\"ns_per_element\":%.9f,\"checksum\":%" PRIu64 "}\n",
           argv[1], count, iterations, elapsed,
           (double)elapsed / ((double)count * (double)iterations),
           is_sum ? (uint64_t)sink : output[count - 1]);
    free(input); free(output); return 0;
}
