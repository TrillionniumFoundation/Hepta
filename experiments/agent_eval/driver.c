/* Public native RPC wrapper. Expected outputs are never linked into this process. */
#include <stdint.h>
#include <inttypes.h>
#include <stddef.h>
#include <stdio.h>
#include <stdlib.h>

#ifndef TASK_KIND
#error TASK_KIND is required
#endif
#define MAX_ITEMS 8192
#define S32 UINT32_C(2779096485)
#define S64 (-INT64_C(6510615555426900571))

#if TASK_KIND == 1
extern size_t evaluate(const uint32_t *, size_t, uint32_t *, size_t);
#elif TASK_KIND == 2
extern size_t evaluate(const int64_t *, size_t, size_t, int64_t *, size_t);
#elif TASK_KIND == 3
extern size_t evaluate(const int64_t *, size_t, int64_t);
#else
typedef struct { uint64_t value; size_t consumed; uint32_t status; } ParseResult;
extern ParseResult evaluate(const uint8_t *, size_t);
#endif

int main(void) {
    size_t id, n, capacity; int64_t parameter; unsigned alias;
    while (scanf("%zu %zu %zu %" SCNd64 " %u", &id, &n, &capacity, &parameter, &alias) == 5) {
        if (n > MAX_ITEMS || capacity > MAX_ITEMS || (parameter < 0 && TASK_KIND == 2)) return 20;
#if TASK_KIND == 1
        size_t storage = alias && n > capacity ? n : capacity;
        size_t input_storage = alias ? storage : n;
        uint32_t *input = malloc((input_storage + 4) * sizeof(uint32_t));
        uint32_t *owned_output = malloc((storage + 4) * sizeof(uint32_t));
        if (!input || !owned_output) return 21;
        for (size_t i = 0; i < input_storage + 4; ++i) input[i] = S32;
        for (size_t i = 0; i < storage + 4; ++i) owned_output[i] = S32;
        for (size_t i = 0; i < n; ++i) if (scanf("%" SCNu32, &input[i + 2]) != 1) return 22;
        uint32_t *output = alias ? input : owned_output;
        size_t result = evaluate(n ? input + 2 : NULL, n, capacity ? output + 2 : NULL, capacity);
        int guards = input[0] == S32 && input[1] == S32 && input[input_storage + 2] == S32 && input[input_storage + 3] == S32
                     && output[0] == S32 && output[1] == S32 && output[storage + 2] == S32 && output[storage + 3] == S32;
        printf("{\"id\":%zu,\"result\":%zu,\"guards\":%s,\"output\":[", id, result, guards ? "true" : "false");
        for (size_t i = 0; i < storage; ++i) printf("%s%" PRIu32, i ? "," : "", output[i + 2]);
        printf("],\"input_after\":[");
        for (size_t i = 0; i < n; ++i) printf("%s%" PRIu32, i ? "," : "", input[i + 2]);
        printf("]}\n"); free(input); free(owned_output);
#elif TASK_KIND == 2 || TASK_KIND == 3
        int64_t *input = malloc((n + 4) * sizeof(int64_t));
        int64_t *output = malloc((capacity + 4) * sizeof(int64_t));
        if (!input || !output) return 21;
        for (size_t i = 0; i < n + 4; ++i) input[i] = S64;
        for (size_t i = 0; i < capacity + 4; ++i) output[i] = S64;
        for (size_t i = 0; i < n; ++i) if (scanf("%" SCNd64, &input[i + 2]) != 1) return 22;
#if TASK_KIND == 2
        size_t result = evaluate(n ? input + 2 : NULL, n, (size_t)parameter, capacity ? output + 2 : NULL, capacity);
#else
        size_t result = evaluate(n ? input + 2 : NULL, n, parameter);
#endif
        int guards = input[0] == S64 && input[1] == S64 && input[n + 2] == S64 && input[n + 3] == S64
                     && output[0] == S64 && output[1] == S64 && output[capacity + 2] == S64 && output[capacity + 3] == S64;
        printf("{\"id\":%zu,\"result\":%zu,\"guards\":%s", id, result, guards ? "true" : "false");
#if TASK_KIND == 2
        printf(",\"output\":[");
        for (size_t i = 0; i < capacity; ++i) printf("%s%" PRId64, i ? "," : "", output[i + 2]);
        printf("]");
#endif
        printf(",\"input_after\":[");
        for (size_t i = 0; i < n; ++i) printf("%s%" PRId64, i ? "," : "", input[i + 2]);
        printf("]}\n"); free(input); free(output);
#else
        uint8_t *input = malloc(n + 4); if (!input) return 21;
        for (size_t i = 0; i < n + 4; ++i) input[i] = 165;
        for (size_t i = 0; i < n; ++i) { unsigned value; if (scanf("%u", &value) != 1 || value > 255) return 22; input[i + 2] = value; }
        ParseResult result = evaluate(n ? input + 2 : NULL, n);
        int guards = input[0] == 165 && input[1] == 165 && input[n + 2] == 165 && input[n + 3] == 165;
        printf("{\"id\":%zu,\"value\":%" PRIu64 ",\"consumed\":%zu,\"status\":%" PRIu32 ",\"guards\":%s,\"input_after\":[",
               id, result.value, result.consumed, result.status, guards ? "true" : "false");
        for (size_t i = 0; i < n; ++i) printf("%s%u", i ? "," : "", input[i + 2]);
        printf("]}\n"); free(input);
#endif
        fflush(stdout);
    }
    return 0;
}
