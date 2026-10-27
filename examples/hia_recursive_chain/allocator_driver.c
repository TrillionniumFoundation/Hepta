/* Independent native observer for the v7 recursive-chain examples.
 * The fixed table belongs to the observer, not the HIA runtime. Each actual
 * allocation is classified as a one-byte payload or a 24-byte chain node.
 * Only the finite fixture calls are admitted; this is not a general allocator.
 */
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

uint64_t chain_checksum(uint64_t);
bool chain_cancel(uint64_t);
uint64_t chain_head_update(uint64_t);
uint64_t chain_stored_loan(uint64_t);
uint64_t chain_task(uint64_t, uint8_t);
bool chain_empty_pop(void);
uint8_t chain_empty_head(void);
bool chain_empty_payloads(uint64_t);
uint64_t chain_recover(uint64_t);

void *__real_malloc(size_t);
void *__real_calloc(size_t, size_t);
void __real_free(void *);

struct allocation { void *pointer; size_t bytes; };
static struct allocation live[32768];
static uint64_t attempts, refuse_at, allocations, frees;
static uint64_t node_allocations, payload_allocations, node_frees, payload_frees;
static uint64_t live_bytes, peak_bytes, null_frees, bad_frees, unknown_sizes;

static void *allocate(size_t bytes, bool zero) {
    attempts++;
    if (attempts == refuse_at) return NULL;
    void *pointer = zero ? __real_calloc(1, bytes) : __real_malloc(bytes);
    if (!pointer) return NULL;
    size_t slot;
    for (slot = 0; slot < sizeof live / sizeof *live && live[slot].pointer; slot++);
    if (slot == sizeof live / sizeof *live) abort();
    live[slot] = (struct allocation){pointer, bytes};
    allocations++;
    if (bytes == 24) node_allocations++;
    else if (bytes == 1) payload_allocations++;
    else unknown_sizes++;
    live_bytes += bytes;
    if (live_bytes > peak_bytes) peak_bytes = live_bytes;
    return pointer;
}

void *__wrap_malloc(size_t bytes) { return allocate(bytes, false); }
void *__wrap_calloc(size_t count, size_t bytes) {
    if (count && bytes > SIZE_MAX / count) abort();
    return allocate(count * bytes, true);
}
void __wrap_free(void *pointer) {
    if (!pointer) { null_frees++; return; }
    size_t slot;
    for (slot = 0; slot < sizeof live / sizeof *live && live[slot].pointer != pointer; slot++);
    if (slot == sizeof live / sizeof *live) { bad_frees++; return; }
    size_t bytes = live[slot].bytes;
    live[slot] = (struct allocation){NULL, 0};
    live_bytes -= bytes;
    frees++;
    if (bytes == 24) node_frees++;
    else if (bytes == 1) payload_frees++;
    __real_free(pointer);
}

int main(int argc, char **argv) {
    if (argc != 5) return 64;
    uint64_t n = strtoull(argv[2], NULL, 10);
    unsigned mode = (unsigned)strtoul(argv[3], NULL, 10);
    refuse_at = strtoull(argv[4], NULL, 10);
    if (n > 8192 || mode > 2) return 65;
    uint64_t result;
    if (!strcmp(argv[1], "chain_checksum")) result = chain_checksum(n);
    else if (!strcmp(argv[1], "chain_cancel")) result = chain_cancel(n);
    else if (!strcmp(argv[1], "chain_head_update")) result = chain_head_update(n);
    else if (!strcmp(argv[1], "chain_stored_loan")) result = chain_stored_loan(n);
    else if (!strcmp(argv[1], "chain_task")) result = chain_task(n, (uint8_t)mode);
    else if (!strcmp(argv[1], "chain_empty_pop")) result = chain_empty_pop();
    else if (!strcmp(argv[1], "chain_empty_head")) result = chain_empty_head();
    else if (!strcmp(argv[1], "chain_empty_payloads")) result = chain_empty_payloads(n);
    else if (!strcmp(argv[1], "chain_recover")) result = chain_recover(n);
    else return 66;
    printf("{\"result\":%llu,\"attempts\":%llu,\"allocations\":%llu,\"frees\":%llu,"
           "\"node_allocations\":%llu,\"payload_allocations\":%llu,"
           "\"node_frees\":%llu,\"payload_frees\":%llu,\"live_bytes\":%llu,"
           "\"peak_bytes\":%llu,\"null_frees\":%llu,\"bad_frees\":%llu,\"unknown_sizes\":%llu}\n",
           (unsigned long long)result, (unsigned long long)attempts,
           (unsigned long long)allocations, (unsigned long long)frees,
           (unsigned long long)node_allocations, (unsigned long long)payload_allocations,
           (unsigned long long)node_frees, (unsigned long long)payload_frees,
           (unsigned long long)live_bytes, (unsigned long long)peak_bytes,
           (unsigned long long)null_frees, (unsigned long long)bad_frees,
           (unsigned long long)unknown_sizes);
    return 0;
}
