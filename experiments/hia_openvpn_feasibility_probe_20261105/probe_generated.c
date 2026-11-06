/* Hepta independent C11/GCC backend. No Rust compiler involved. */
#include <stdint.h>
#include <stddef.h>
#include <stdbool.h>
#include <inttypes.h>
#include <limits.h>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <math.h>
_Static_assert(CHAR_BIT == 8 && sizeof(size_t) == 8 && sizeof(intptr_t) == 8, "C backend requires the qualified 64-bit data model");
typedef const uint8_t *__hepta_cb_ptr_0;
static inline uint32_t __hepta_cb_u32_bits(uint64_t x) { uint32_t bits = (uint32_t)x; uint32_t out; memcpy(&out, &bits, sizeof out); return out; }
static inline uint32_t __hepta_cb_u32_add(uint32_t a, uint32_t b) { uint32_t r; if (__builtin_add_overflow(a,b,&r)) abort(); return r; }
static inline uint32_t __hepta_cb_u32_sub(uint32_t a, uint32_t b) { uint32_t r; if (__builtin_sub_overflow(a,b,&r)) abort(); return r; }
static inline uint32_t __hepta_cb_u32_mul(uint32_t a, uint32_t b) { uint32_t r; if (__builtin_mul_overflow(a,b,&r)) abort(); return r; }
static inline uint32_t __hepta_cb_u32_div(uint32_t a, uint32_t b) { if (b == 0) abort(); return a / b; }
static inline uint32_t __hepta_cb_u32_rem(uint32_t a, uint32_t b) { if (b == 0) abort(); return a % b; }
static inline uint32_t __hepta_cb_u32_wrapping_add(uint32_t a, uint32_t b) { return __hepta_cb_u32_bits((uint64_t)a + (uint64_t)b); }
static inline uint32_t __hepta_cb_u32_wrapping_sub(uint32_t a, uint32_t b) { return __hepta_cb_u32_bits((uint64_t)a - (uint64_t)b); }
static inline uint32_t __hepta_cb_u32_wrapping_mul(uint32_t a, uint32_t b) { return __hepta_cb_u32_bits((uint64_t)a * (uint64_t)b); }
static inline uint32_t __hepta_cb_u32_and(uint32_t a, uint32_t b) { return __hepta_cb_u32_bits((uint64_t)a & (uint64_t)b); }
static inline uint32_t __hepta_cb_u32_or(uint32_t a, uint32_t b) { return __hepta_cb_u32_bits((uint64_t)a | (uint64_t)b); }
static inline uint32_t __hepta_cb_u32_xor(uint32_t a, uint32_t b) { return __hepta_cb_u32_bits((uint64_t)a ^ (uint64_t)b); }
static inline uint32_t __hepta_cb_u32_min(uint32_t a, uint32_t b) { return a < b ? a : b; }
static inline uint32_t __hepta_cb_u32_max(uint32_t a, uint32_t b) { return a > b ? a : b; }
static inline uint32_t __hepta_cb_u32_shl(uint32_t a, uint32_t b) { if ((uint64_t)b >= sizeof(a)*CHAR_BIT) abort(); return __hepta_cb_u32_bits((uint64_t)a << b); }
static inline uint32_t __hepta_cb_u32_shr(uint32_t a, uint32_t b) { if ((uint64_t)b >= sizeof(a)*CHAR_BIT) abort(); uint64_t x = (uint64_t)(uint32_t)a >> b; return __hepta_cb_u32_bits(x); }
uint32_t host_mask(uint32_t h_value);
uint32_t probe_opcode(__hepta_cb_ptr_0 h_data, size_t h_count);
uint32_t probe_host_call(uint32_t h_value);
uint32_t probe_opcode(__hepta_cb_ptr_0 h_data, size_t h_count) {
size_t __hepta_cb_v1 = h_count;
size_t __hepta_cb_v2 = (size_t)UINT64_C(0);
bool __hepta_cb_v3 = (__hepta_cb_v1 == __hepta_cb_v2);
if (__hepta_cb_v3) { uint32_t __hepta_cb_v4 = (uint32_t)UINT64_C(256);
return __hepta_cb_v4; } else {  }
{ __hepta_cb_ptr_0 __hepta_cb_v5 = h_data;
size_t __hepta_cb_v6 = (size_t)UINT64_C(0);
uint8_t __hepta_cb_v7 = (__hepta_cb_v5)[__hepta_cb_v6];
uint32_t __hepta_cb_v8 = __hepta_cb_u32_bits((uint64_t)__hepta_cb_v7);
uint32_t __hepta_cb_v9 = (uint32_t)UINT64_C(3);
uint32_t __hepta_cb_v10 = __hepta_cb_u32_shr(__hepta_cb_v8, __hepta_cb_v9);
return __hepta_cb_v10; }
}
uint32_t probe_host_call(uint32_t h_value) {
{ uint32_t __hepta_cb_v11 = h_value;
uint32_t __hepta_cb_v12 = host_mask(__hepta_cb_v11);
return __hepta_cb_v12; }
}
