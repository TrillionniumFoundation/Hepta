/* Hepta migration conformance fixture, authored for the bounded owner profile.
 * This is not third-party production code. malloc bytes are initialized before
 * reads; zero length and allocation failure have explicit observable results.
 */
#include <stdlib.h>
#include <stdint.h>

int64_t owned_malloc_sum(size_t count) {
    if (count == 0) return 0;
    unsigned char *data = malloc(count);
    if (!data) return -1;
    for (size_t i = 0; i < count; ++i) data[i] = (unsigned char)(i % 251u);
    int64_t result = 0;
    for (size_t j = 0; j < count; ++j) result += data[j];
    free(data);
    return result;
}

int64_t owned_calloc_sum(size_t count) {
    if (count == 0) return 0;
    unsigned char *data = calloc(count, 1);
    if (data == NULL) return -1;
    int64_t result = 0;
    for (size_t i = 0; i < count; ++i) result += data[i];
    free(data);
    return result;
}
