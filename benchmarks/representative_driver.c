#define _POSIX_C_SOURCE 200809L
#include <inttypes.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

extern uint64_t hepta_fnv1a(const uint8_t *, size_t);
extern uint64_t hepta_histogram(const uint8_t *, size_t, uint64_t *);
extern uint64_t hepta_dot(const uint64_t *, const uint64_t *, size_t);
extern uint64_t hepta_binary_search(const uint64_t *, size_t, const uint64_t *, size_t);

static uint64_t clock_ns(void) {
    struct timespec value;
    if (clock_gettime(CLOCK_MONOTONIC, &value)) exit(2);
    return (uint64_t)value.tv_sec * UINT64_C(1000000000) + (uint64_t)value.tv_nsec;
}

static uint64_t random_value(uint64_t *state) {
    *state ^= *state << 13; *state ^= *state >> 7; *state ^= *state << 17;
    return *state;
}

static int compare_u64(const void *left, const void *right) {
    uint64_t a = *(const uint64_t *)left, b = *(const uint64_t *)right;
    return (a > b) - (a < b);
}

int main(int argc, char **argv) {
    if (argc != 4) return 2;
    char *end;
    size_t count = strtoull(argv[2], &end, 10);
    if (*end || !count || count > (1u << 24)) return 2;
    size_t iterations = strtoull(argv[3], &end, 10);
    if (*end || !iterations) return 2;
    int kind = !strcmp(argv[1], "fnv1a") ? 0 : !strcmp(argv[1], "histogram") ? 1 :
               !strcmp(argv[1], "dot") ? 2 : !strcmp(argv[1], "binary_search") ? 3 : -1;
    if (kind < 0) return 2;
    const size_t query_count = 2048;
    uint8_t *bytes = malloc(count);
    uint64_t *left = malloc(count * sizeof(uint64_t));
    uint64_t *right = malloc(count * sizeof(uint64_t));
    uint64_t *queries = malloc(query_count * sizeof(uint64_t));
    uint64_t *sorted_queries = malloc(query_count * sizeof(uint64_t));
    uint64_t bins[256], expected_bins[256] = {0};
    if (!bytes || !left || !right || !queries || !sorted_queries) return 2;
    uint64_t state = UINT64_C(0x1234567890abcdef);
    uint64_t expected_fnv = UINT64_C(14695981039346656037), expected_dot = 0, expected_hist = 0;
    for (size_t i = 0; i < count; ++i) {
        bytes[i] = (uint8_t)random_value(&state);
        left[i] = random_value(&state);
        right[i] = random_value(&state);
        expected_fnv = (expected_fnv ^ bytes[i]) * UINT64_C(1099511628211);
        expected_dot += left[i] * right[i];
        ++expected_bins[bytes[i]];
    }
    for (size_t i = 0; i < 256; ++i) expected_hist += expected_bins[i] * i;
    if (hepta_fnv1a(bytes, count) != expected_fnv || hepta_dot(left, right, count) != expected_dot) return 3;
    if (hepta_histogram(bytes, count, bins) != expected_hist || memcmp(bins, expected_bins, sizeof bins)) return 4;
    if (hepta_fnv1a(bytes, 0) != UINT64_C(14695981039346656037) || hepta_dot(left, right, 0) != 0) return 5;
    if (hepta_histogram(bytes, 0, bins) != 0) return 6;
    for (size_t i = 0; i < 256; ++i) if (bins[i]) return 6;
    /* Independent search oracle: sort queries, then merge them with the table.
       The table contains duplicates and gaps; no binary-search implementation
       is reused for the expected result. */
    uint64_t expected_search = 0;
    if (kind == 3) {
        for (size_t i = 0; i < count; ++i) left[i] = (i / 3) * 5;
        for (size_t i = 0; i < query_count; ++i) {
            queries[i] = random_value(&state) % ((count / 3) * 5 + 20);
            sorted_queries[i] = queries[i];
        }
        qsort(sorted_queries, query_count, sizeof(uint64_t), compare_u64);
        size_t position = 0;
        for (size_t i = 0; i < query_count; ++i) {
            while (position < count && left[position] < sorted_queries[i]) ++position;
            expected_search += position;
        }
        if (hepta_binary_search(left, count, queries, query_count) != expected_search) return 7;
        if (hepta_binary_search(left, 0, queries, query_count) || hepta_binary_search(left, count, queries, 0)) return 8;
    }
    volatile uint64_t sink = 0;
    for (size_t warm = 0; warm < 8; ++warm) {
        if (kind == 0) sink ^= hepta_fnv1a(bytes, count);
        else if (kind == 1) sink ^= hepta_histogram(bytes, count, bins);
        else if (kind == 2) sink ^= hepta_dot(left, right, count);
        else sink ^= hepta_binary_search(left, count, queries, query_count);
    }
    uint64_t start = clock_ns();
    for (size_t iteration = 0; iteration < iterations; ++iteration) {
        if (kind == 0) sink ^= hepta_fnv1a(bytes, count);
        else if (kind == 1) sink ^= hepta_histogram(bytes, count, bins);
        else if (kind == 2) sink ^= hepta_dot(left, right, count);
        else sink ^= hepta_binary_search(left, count, queries, query_count);
    }
    uint64_t elapsed = clock_ns() - start;
    if (kind == 1 && memcmp(bins, expected_bins, sizeof bins)) return 9;
    uint64_t expected = kind == 0 ? expected_fnv : kind == 1 ? expected_hist : kind == 2 ? expected_dot : expected_search;
    if (sink != (iterations % 2 ? expected : 0)) return 10;
    size_t operations = kind == 3 ? query_count : count;
    printf("{\"kernel\":\"%s\",\"elements\":%zu,\"queries\":%zu,\"iterations\":%zu,\"elapsed_ns\":%" PRIu64 ",\"ns_per_operation\":%.9f,\"reference_checksum\":%" PRIu64 "}\n",
           argv[1], count, kind == 3 ? query_count : 0, iterations, elapsed,
           (double)elapsed / ((double)operations * iterations), expected);
    free(bytes); free(left); free(right); free(queries); free(sorted_queries);
    return 0;
}
