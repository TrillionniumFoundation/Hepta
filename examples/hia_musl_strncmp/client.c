/* Authored scalar adapter, compiled only into the original-C reference. */
#include <stdint.h>
#include <stdlib.h>
#include <string.h>

_Static_assert(sizeof(size_t) == 8 && sizeof(int) == 4, "LP64 scalar profile");

int strncmp_probe(size_t n, uint64_t left_word, uint64_t right_word)
{
    if (n > 8) return -259;
    unsigned char left_zero = 0, right_zero = 0;
    unsigned char *left = n ? calloc(n, 1) : &left_zero;
    if (!left) return -257;
    unsigned char *right = n ? calloc(n, 1) : &right_zero;
    if (!right) {
        if (n) free(left);
        return -258;
    }
    for (size_t index = 0; index < n; ++index) {
        left[index] = (unsigned char)(left_word >> (index * 8));
        right[index] = (unsigned char)(right_word >> (index * 8));
    }
    int compared = strncmp((const char *)left, (const char *)right, n);
    if (n) {
        free(right);
        free(left);
    }
    return compared;
}
