#ifndef CROSSFILE_API_H
#define CROSSFILE_API_H
#include <stdint.h>
#ifdef __cplusplus
extern "C" {
#endif
typedef struct { int64_t value; int32_t status; } ForeignResult;
int64_t c_adjust(int64_t a, int64_t b);
ForeignResult cpp_scale(int64_t value, int64_t factor);
void cf_native_reset(void);
uint64_t cf_c_calls(void);
uint64_t cf_cpp_calls(void);
#ifdef __cplusplus
}
#endif
#endif
