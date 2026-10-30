/* Reuse only the frozen public-ABI loader and clock; all arms get one host. */
#define main ring_maintenance_included_main
#include "ring_maintenance_host.c"
#undef main

int main(int argc, char **argv) {
    uint64_t total_begin = now();
    if (argc != 4) return 64;
    unsigned repeats = (unsigned)strtoul(argv[3], NULL, 10);
    if (!(repeats == 4 || repeats == 16)) fail("unregistered repeat count");
    FILE *input = fopen(argv[2], "rb");
    if (!input) fail("trace open");
    unsigned char header[12];
    if (fread(header, 1, sizeof(header), input) != sizeof(header)
        || memcmp(header, "HRBT0001", 8)) fail("trace header");
    size_t records = (size_t)header[8] | (size_t)header[9] << 8
                   | (size_t)header[10] << 16 | (size_t)header[11] << 24;
    if (records != 4096) fail("unregistered trace size");
    unsigned char *trace = malloc(records * 257);
    if (!trace || fread(trace, 257, records, input) != records || fgetc(input) != EOF) fail("trace extent");
    if (fclose(input)) fail("trace close");
    void *library = load(argv[1]);
    ring_buffer_t ring;
    char storage[256], output[256];
    functions.init(&ring, storage, sizeof(storage));
    uint64_t setup_done = now();
    uint64_t checksum = 0, bytes = 0;
    uint64_t samples[512];
    size_t sample_count = 0;
    for (unsigned repeat = 0; repeat < repeats; repeat++) {
        for (size_t batch = 0; batch < records; batch += 128) {
            uint64_t batch_begin = now();
            for (size_t index = batch; index < batch + 128; index++) {
                const unsigned char *record = trace + index * 257;
                size_t count = record[0];
                const char *data = (const char *)(record + 1);
                memset(output, 0x5a, sizeof(output));
                if (count) {
                    functions.queue(&ring, data[0]);
                    functions.queue_arr(&ring, data + 1, count - 1);
                } else functions.queue_arr(&ring, data, 0);
                if (functions.num_items(&ring) != count || functions.is_full(&ring) != (count == 255)) fail("count oracle");
                char peek = 0x5a;
                if (functions.peek(&ring, &peek, count ? count - 1 : 0) != !!count
                    || (count && peek != data[count - 1]) || (!count && peek != 0x5a)) fail("peek oracle");
                if (functions.dequeue_arr(&ring, output, sizeof(output)) != count
                    || memcmp(output, data, count) || output[count] != 0x5a
                    || !functions.is_empty(&ring)) fail("byte/sentinel oracle");
                char empty = 0x5a;
                if (functions.dequeue(&ring, &empty) || empty != 0x5a) fail("empty oracle");
                for (size_t i = 0; i < count; i++) checksum += (unsigned char)output[i];
                bytes += count;
            }
            samples[sample_count++] = now() - batch_begin;
        }
    }
    uint64_t run_done = now();
    free(trace);
    if (dlclose(library)) fail("dlclose");
    uint64_t cleanup_done = now();
    printf("{\"records\":%zu,\"repeats\":%u,\"transactions\":%zu,\"bytes\":%llu,\"checksum\":%llu,"
           "\"setup_ns\":%llu,\"run_ns\":%llu,\"cleanup_ns\":%llu,\"total_main_ns\":%llu,\"batch_ns\":[",
           records, repeats, records * repeats, (unsigned long long)bytes, (unsigned long long)checksum,
           (unsigned long long)(setup_done - total_begin), (unsigned long long)(run_done - setup_done),
           (unsigned long long)(cleanup_done - run_done), (unsigned long long)(cleanup_done - total_begin));
    for (size_t i = 0; i < sample_count; i++) printf("%s%llu", i ? "," : "", (unsigned long long)samples[i]);
    printf("]}\n");
    return 0;
}
