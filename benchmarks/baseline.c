#include <stddef.h>
#include <stdint.h>

uint64_t hepta_sum(const uint64_t *data, size_t count) {
    uint64_t sum = 0;
    for (size_t index = 0; index < count; ++index) sum += data[index];
    return sum;
}

void hepta_copy(uint64_t *destination, const uint64_t *source, size_t count) {
    for (size_t index = 0; index < count; ++index) destination[index] = source[index];
}
