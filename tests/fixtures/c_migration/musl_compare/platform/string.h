/* Hepta qualification platform adapter, not an upstream musl header.
 * Bind only this complete component API to the native size_t model. */
#ifndef HEPTA_MUSL_COMPARE_STRING_H
#define HEPTA_MUSL_COMPARE_STRING_H
#include <stddef.h>
int memcmp(const void *vl, const void *vr, size_t n);
#endif
