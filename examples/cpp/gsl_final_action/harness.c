#include <inttypes.h>
#include <stdint.h>
#include <stdio.h>

#ifndef CASE_FUNCTION
#define CASE_FUNCTION original_case
#endif
extern uint64_t CASE_FUNCTION(uint64_t, uint64_t, uint32_t, uint32_t);

int main(void) {
    uint64_t seed, tag;
    uint32_t mode;
    unsigned count = 0;
    while (scanf("%" SCNu64 " %" SCNu64 " %" SCNu32, &seed, &tag, &mode) == 3) {
        uint64_t trace = CASE_FUNCTION(seed, tag, mode, 0);
        uint64_t calls = CASE_FUNCTION(seed, tag, mode, 1);
        uint64_t status = CASE_FUNCTION(seed, tag, mode, 2);
        printf("%" PRIu64 " %" PRIu64 " %" PRIu64 "\n", trace, calls, status);
        ++count;
    }
    return count ? 0 : 2;
}
