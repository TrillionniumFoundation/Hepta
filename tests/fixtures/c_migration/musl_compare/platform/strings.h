/* Hepta qualification platform adapter, not an upstream musl header. */
#ifndef HEPTA_MUSL_COMPARE_STRINGS_H
#define HEPTA_MUSL_COMPARE_STRINGS_H
#include <stddef.h>
int bcmp(const void *s1, const void *s2, size_t n);
#endif
