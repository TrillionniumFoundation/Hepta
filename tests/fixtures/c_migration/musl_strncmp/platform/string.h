#ifndef HEPTA_MUSL_STRNCMP_PLATFORM_STRING_H
#define HEPTA_MUSL_STRNCMP_PLATFORM_STRING_H
/* Authored declaration-only adapter; upstream implementation is unchanged. */
typedef __SIZE_TYPE__ size_t;
int strncmp(const char *_l, const char *_r, size_t n);
#endif
