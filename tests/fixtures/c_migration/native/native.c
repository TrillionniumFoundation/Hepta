#include "native.h"

int32_t native_add(int32_t a, int32_t b) {
    return a + b; /* The example caller must keep the signed sum in range. */
}

NativePoint native_transform(NativePoint value, const uint8_t *data, size_t count) {
    for (size_t i = 0; i < count; ++i) value.x += data[i];
    value.y += (double)count;
    return value;
}
