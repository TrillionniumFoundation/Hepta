#ifndef HEPTA_EXAMPLE_NATIVE_H
#define HEPTA_EXAMPLE_NATIVE_H
#include <stdint.h>
#include <stddef.h>

#define INTEROP_LIMIT 32u
typedef struct NativePoint {
    int32_t x;
    double y;
} NativePoint;

int32_t native_add(int32_t a, int32_t b);
NativePoint native_transform(NativePoint value, const uint8_t *data, size_t count);
#endif
