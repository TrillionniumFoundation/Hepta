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
typedef struct { uint8_t *data; size_t len; } __hepta_cb_buffer;
typedef struct { __hepta_cb_buffer h_data; } __hepta_cb_aggregate_0;
typedef struct { uint32_t tag; union { struct { __hepta_cb_aggregate_0 f_0; } v_Ok; struct { uint8_t f_0; } v_Err; } payload; } __hepta_cb_aggregate_2;
typedef struct { uint32_t tag; union { struct { __hepta_cb_buffer f_0; } v_Ok; struct { uint8_t f_0; } v_Err; } payload; } __hepta_cb_aggregate_3;
typedef struct { const uint8_t *data; size_t len; } __hepta_cb_slice_4;
static inline uint64_t __hepta_cb_u64_bits(uint64_t x) { uint64_t bits = (uint64_t)x; uint64_t out; memcpy(&out, &bits, sizeof out); return out; }
static inline uint64_t __hepta_cb_u64_add(uint64_t a, uint64_t b) { uint64_t r; if (__builtin_add_overflow(a,b,&r)) abort(); return r; }
static inline uint64_t __hepta_cb_u64_sub(uint64_t a, uint64_t b) { uint64_t r; if (__builtin_sub_overflow(a,b,&r)) abort(); return r; }
static inline uint64_t __hepta_cb_u64_mul(uint64_t a, uint64_t b) { uint64_t r; if (__builtin_mul_overflow(a,b,&r)) abort(); return r; }
static inline uint64_t __hepta_cb_u64_div(uint64_t a, uint64_t b) { if (b == 0) abort(); return a / b; }
static inline uint64_t __hepta_cb_u64_rem(uint64_t a, uint64_t b) { if (b == 0) abort(); return a % b; }
static inline uint64_t __hepta_cb_u64_wrapping_add(uint64_t a, uint64_t b) { return __hepta_cb_u64_bits((uint64_t)a + (uint64_t)b); }
static inline uint64_t __hepta_cb_u64_wrapping_sub(uint64_t a, uint64_t b) { return __hepta_cb_u64_bits((uint64_t)a - (uint64_t)b); }
static inline uint64_t __hepta_cb_u64_wrapping_mul(uint64_t a, uint64_t b) { return __hepta_cb_u64_bits((uint64_t)a * (uint64_t)b); }
static inline uint64_t __hepta_cb_u64_and(uint64_t a, uint64_t b) { return __hepta_cb_u64_bits((uint64_t)a & (uint64_t)b); }
static inline uint64_t __hepta_cb_u64_or(uint64_t a, uint64_t b) { return __hepta_cb_u64_bits((uint64_t)a | (uint64_t)b); }
static inline uint64_t __hepta_cb_u64_xor(uint64_t a, uint64_t b) { return __hepta_cb_u64_bits((uint64_t)a ^ (uint64_t)b); }
static inline uint64_t __hepta_cb_u64_min(uint64_t a, uint64_t b) { return a < b ? a : b; }
static inline uint64_t __hepta_cb_u64_max(uint64_t a, uint64_t b) { return a > b ? a : b; }
static inline uint64_t __hepta_cb_u64_shl(uint64_t a, uint64_t b) { if ((uint64_t)b >= sizeof(a)*CHAR_BIT) abort(); return __hepta_cb_u64_bits((uint64_t)a << b); }
static inline uint64_t __hepta_cb_u64_shr(uint64_t a, uint64_t b) { if ((uint64_t)b >= sizeof(a)*CHAR_BIT) abort(); uint64_t x = (uint64_t)(uint64_t)a >> b; return __hepta_cb_u64_bits(x); }
static inline uint8_t __hepta_cb_u8_bits(uint64_t x) { uint8_t bits = (uint8_t)x; uint8_t out; memcpy(&out, &bits, sizeof out); return out; }
static inline uint8_t __hepta_cb_u8_add(uint8_t a, uint8_t b) { uint8_t r; if (__builtin_add_overflow(a,b,&r)) abort(); return r; }
static inline uint8_t __hepta_cb_u8_sub(uint8_t a, uint8_t b) { uint8_t r; if (__builtin_sub_overflow(a,b,&r)) abort(); return r; }
static inline uint8_t __hepta_cb_u8_mul(uint8_t a, uint8_t b) { uint8_t r; if (__builtin_mul_overflow(a,b,&r)) abort(); return r; }
static inline uint8_t __hepta_cb_u8_div(uint8_t a, uint8_t b) { if (b == 0) abort(); return a / b; }
static inline uint8_t __hepta_cb_u8_rem(uint8_t a, uint8_t b) { if (b == 0) abort(); return a % b; }
static inline uint8_t __hepta_cb_u8_wrapping_add(uint8_t a, uint8_t b) { return __hepta_cb_u8_bits((uint64_t)a + (uint64_t)b); }
static inline uint8_t __hepta_cb_u8_wrapping_sub(uint8_t a, uint8_t b) { return __hepta_cb_u8_bits((uint64_t)a - (uint64_t)b); }
static inline uint8_t __hepta_cb_u8_wrapping_mul(uint8_t a, uint8_t b) { return __hepta_cb_u8_bits((uint64_t)a * (uint64_t)b); }
static inline uint8_t __hepta_cb_u8_and(uint8_t a, uint8_t b) { return __hepta_cb_u8_bits((uint64_t)a & (uint64_t)b); }
static inline uint8_t __hepta_cb_u8_or(uint8_t a, uint8_t b) { return __hepta_cb_u8_bits((uint64_t)a | (uint64_t)b); }
static inline uint8_t __hepta_cb_u8_xor(uint8_t a, uint8_t b) { return __hepta_cb_u8_bits((uint64_t)a ^ (uint64_t)b); }
static inline uint8_t __hepta_cb_u8_min(uint8_t a, uint8_t b) { return a < b ? a : b; }
static inline uint8_t __hepta_cb_u8_max(uint8_t a, uint8_t b) { return a > b ? a : b; }
static inline uint8_t __hepta_cb_u8_shl(uint8_t a, uint8_t b) { if ((uint64_t)b >= sizeof(a)*CHAR_BIT) abort(); return __hepta_cb_u8_bits((uint64_t)a << b); }
static inline uint8_t __hepta_cb_u8_shr(uint8_t a, uint8_t b) { if ((uint64_t)b >= sizeof(a)*CHAR_BIT) abort(); uint64_t x = (uint64_t)(uint8_t)a >> b; return __hepta_cb_u8_bits(x); }

static bool __hepta_cb_allocate(size_t size, __hepta_cb_buffer *out) {
    if (size > PTRDIFF_MAX) return false;
    uint8_t *data = size ? calloc(size, sizeof(uint8_t)) : NULL;
    if (size && !data) return false;
    *out = (__hepta_cb_buffer){data, size};
    return true;
}
static __hepta_cb_buffer __hepta_cb_buffer_new(size_t size) {
    __hepta_cb_buffer out;
    if (!__hepta_cb_allocate(size, &out)) abort();
    return out;
}

static __hepta_cb_aggregate_3 __hepta_cb_try_buffer(size_t size) {
    __hepta_cb_buffer out;
    if (!__hepta_cb_allocate(size, &out))
        return (__hepta_cb_aggregate_3){.tag=1, .payload.v_Err={.f_0=1}};
    return (__hepta_cb_aggregate_3){.tag=0, .payload.v_Ok={.f_0=out}};
}

static void __hepta_cb_drop_0(__hepta_cb_buffer value);
static void __hepta_cb_drop_1(__hepta_cb_aggregate_0 value);
static void __hepta_cb_drop_0(__hepta_cb_buffer value) { free(value.data); }
static void __hepta_cb_drop_1(__hepta_cb_aggregate_0 value) { __hepta_cb_drop_0(value.h_data); }
__hepta_cb_aggregate_2 __hepta_cb_fn_Mcf03d00758734ee2_OwnedBytes_new(size_t h_size, bool h_reject);
__hepta_cb_aggregate_0 __hepta_cb_fn_Mcf03d00758734ee2_OwnedBytes_move(__hepta_cb_aggregate_0 h_owner);
void __hepta_cb_fn_Mcf03d00758734ee2_OwnedBytes_drop(__hepta_cb_aggregate_0 h_owner);
size_t __hepta_cb_fn_Mcf03d00758734ee2_OwnedBytes_size(const __hepta_cb_aggregate_0 *h_owner);
__hepta_cb_slice_4 __hepta_cb_fn_Mcf03d00758734ee2_OwnedBytes_data(const __hepta_cb_aggregate_0 *h_owner);
void __hepta_cb_fn_Mcf03d00758734ee2_OwnedBytes_fill(__hepta_cb_aggregate_0 *h_owner, uint8_t h_value);
uint8_t __hepta_cb_fn_Mcf03d00758734ee2_OwnedBytes_get(const __hepta_cb_aggregate_0 *h_owner, size_t h_index);
void __hepta_cb_fn_Mcf03d00758734ee2_OwnedBytes_set(__hepta_cb_aggregate_0 *h_owner, size_t h_index, uint8_t h_value);
uint64_t __hepta_cb_fn_Mcf03d00758734ee2_run_owned(size_t h_size, uint8_t h_value, size_t h_index, bool h_reject_constructor, bool h_early);
uint64_t owned_case(size_t h_size, uint8_t h_value, size_t h_index, uint32_t h_reject, uint32_t h_early);
#line 5 "/workspace/scratch/c7c6ee414a6c/hepta-research/artifacts/cpp-owned-20261025T171524382241Z/cpp-owned/migrated.hepta"
__hepta_cb_aggregate_2 __hepta_cb_fn_Mcf03d00758734ee2_OwnedBytes_new(size_t h_size, bool h_reject) {
#line 6 "/workspace/scratch/c7c6ee414a6c/hepta-research/artifacts/cpp-owned-20261025T171524382241Z/cpp-owned/migrated.hepta"
size_t __hepta_cb_v1 = h_size;
#line 6 "/workspace/scratch/c7c6ee414a6c/hepta-research/artifacts/cpp-owned-20261025T171524382241Z/cpp-owned/migrated.hepta"
__hepta_cb_aggregate_3 __hepta_cb_v2 = __hepta_cb_try_buffer(__hepta_cb_v1);
#line 6 "/workspace/scratch/c7c6ee414a6c/hepta-research/artifacts/cpp-owned-20261025T171524382241Z/cpp-owned/migrated.hepta"
switch (__hepta_cb_v2.tag) {
#line 6 "/workspace/scratch/c7c6ee414a6c/hepta-research/artifacts/cpp-owned-20261025T171524382241Z/cpp-owned/migrated.hepta"
case 1: {
#line 6 "/workspace/scratch/c7c6ee414a6c/hepta-research/artifacts/cpp-owned-20261025T171524382241Z/cpp-owned/migrated.hepta"
uint8_t h_code = __hepta_cb_v2.payload.v_Err.f_0;
#line 7 "/workspace/scratch/c7c6ee414a6c/hepta-research/artifacts/cpp-owned-20261025T171524382241Z/cpp-owned/migrated.hepta"
uint8_t __hepta_cb_v3 = h_code;
#line 7 "/workspace/scratch/c7c6ee414a6c/hepta-research/artifacts/cpp-owned-20261025T171524382241Z/cpp-owned/migrated.hepta"
__hepta_cb_aggregate_2 __hepta_cb_v4 = (__hepta_cb_aggregate_2){ .tag = 1, .payload.v_Err = { .f_0 = __hepta_cb_v3 } };
#line 7 "/workspace/scratch/c7c6ee414a6c/hepta-research/artifacts/cpp-owned-20261025T171524382241Z/cpp-owned/migrated.hepta"
return __hepta_cb_v4;
#line 7 "/workspace/scratch/c7c6ee414a6c/hepta-research/artifacts/cpp-owned-20261025T171524382241Z/cpp-owned/migrated.hepta"
break; }
#line 7 "/workspace/scratch/c7c6ee414a6c/hepta-research/artifacts/cpp-owned-20261025T171524382241Z/cpp-owned/migrated.hepta"
case 0: {
#line 7 "/workspace/scratch/c7c6ee414a6c/hepta-research/artifacts/cpp-owned-20261025T171524382241Z/cpp-owned/migrated.hepta"
__hepta_cb_buffer h_bytes = __hepta_cb_v2.payload.v_Ok.f_0;
#line 9 "/workspace/scratch/c7c6ee414a6c/hepta-research/artifacts/cpp-owned-20261025T171524382241Z/cpp-owned/migrated.hepta"
bool __hepta_cb_v5 = h_reject;
#line 9 "/workspace/scratch/c7c6ee414a6c/hepta-research/artifacts/cpp-owned-20261025T171524382241Z/cpp-owned/migrated.hepta"
if (__hepta_cb_v5) { 
#line 10 "/workspace/scratch/c7c6ee414a6c/hepta-research/artifacts/cpp-owned-20261025T171524382241Z/cpp-owned/migrated.hepta"
__hepta_cb_buffer __hepta_cb_v6 = h_bytes;
#line 10 "/workspace/scratch/c7c6ee414a6c/hepta-research/artifacts/cpp-owned-20261025T171524382241Z/cpp-owned/migrated.hepta"
__hepta_cb_buffer __hepta_cb_v7 = __hepta_cb_v6;
#line 10 "/workspace/scratch/c7c6ee414a6c/hepta-research/artifacts/cpp-owned-20261025T171524382241Z/cpp-owned/migrated.hepta"
__hepta_cb_drop_0(__hepta_cb_v7);
#line 11 "/workspace/scratch/c7c6ee414a6c/hepta-research/artifacts/cpp-owned-20261025T171524382241Z/cpp-owned/migrated.hepta"
uint8_t __hepta_cb_v8 = (uint8_t)UINT64_C(2);
#line 11 "/workspace/scratch/c7c6ee414a6c/hepta-research/artifacts/cpp-owned-20261025T171524382241Z/cpp-owned/migrated.hepta"
__hepta_cb_aggregate_2 __hepta_cb_v9 = (__hepta_cb_aggregate_2){ .tag = 1, .payload.v_Err = { .f_0 = __hepta_cb_v8 } };
#line 11 "/workspace/scratch/c7c6ee414a6c/hepta-research/artifacts/cpp-owned-20261025T171524382241Z/cpp-owned/migrated.hepta"
return __hepta_cb_v9; } else {  }
#line 13 "/workspace/scratch/c7c6ee414a6c/hepta-research/artifacts/cpp-owned-20261025T171524382241Z/cpp-owned/migrated.hepta"
__hepta_cb_buffer __hepta_cb_v10 = h_bytes;
#line 13 "/workspace/scratch/c7c6ee414a6c/hepta-research/artifacts/cpp-owned-20261025T171524382241Z/cpp-owned/migrated.hepta"
__hepta_cb_buffer __hepta_cb_v11 = __hepta_cb_v10;
#line 13 "/workspace/scratch/c7c6ee414a6c/hepta-research/artifacts/cpp-owned-20261025T171524382241Z/cpp-owned/migrated.hepta"
__hepta_cb_aggregate_0 __hepta_cb_v12 = (__hepta_cb_aggregate_0){ .h_data = __hepta_cb_v11 };
#line 13 "/workspace/scratch/c7c6ee414a6c/hepta-research/artifacts/cpp-owned-20261025T171524382241Z/cpp-owned/migrated.hepta"
__hepta_cb_aggregate_2 __hepta_cb_v13 = (__hepta_cb_aggregate_2){ .tag = 0, .payload.v_Ok = { .f_0 = __hepta_cb_v12 } };
#line 13 "/workspace/scratch/c7c6ee414a6c/hepta-research/artifacts/cpp-owned-20261025T171524382241Z/cpp-owned/migrated.hepta"
return __hepta_cb_v13;
#line 13 "/workspace/scratch/c7c6ee414a6c/hepta-research/artifacts/cpp-owned-20261025T171524382241Z/cpp-owned/migrated.hepta"
break; }
#line 13 "/workspace/scratch/c7c6ee414a6c/hepta-research/artifacts/cpp-owned-20261025T171524382241Z/cpp-owned/migrated.hepta"
default: abort(); }
#line 13 "/workspace/scratch/c7c6ee414a6c/hepta-research/artifacts/cpp-owned-20261025T171524382241Z/cpp-owned/migrated.hepta"
}
#line 18 "/workspace/scratch/c7c6ee414a6c/hepta-research/artifacts/cpp-owned-20261025T171524382241Z/cpp-owned/migrated.hepta"
__hepta_cb_aggregate_0 __hepta_cb_fn_Mcf03d00758734ee2_OwnedBytes_move(__hepta_cb_aggregate_0 h_owner) {
#line 19 "/workspace/scratch/c7c6ee414a6c/hepta-research/artifacts/cpp-owned-20261025T171524382241Z/cpp-owned/migrated.hepta"
__hepta_cb_aggregate_0 __hepta_cb_v14 = h_owner;
#line 19 "/workspace/scratch/c7c6ee414a6c/hepta-research/artifacts/cpp-owned-20261025T171524382241Z/cpp-owned/migrated.hepta"
__hepta_cb_aggregate_0 __hepta_cb_v15 = __hepta_cb_v14;
#line 19 "/workspace/scratch/c7c6ee414a6c/hepta-research/artifacts/cpp-owned-20261025T171524382241Z/cpp-owned/migrated.hepta"
return __hepta_cb_v15;
#line 19 "/workspace/scratch/c7c6ee414a6c/hepta-research/artifacts/cpp-owned-20261025T171524382241Z/cpp-owned/migrated.hepta"
}
#line 22 "/workspace/scratch/c7c6ee414a6c/hepta-research/artifacts/cpp-owned-20261025T171524382241Z/cpp-owned/migrated.hepta"
void __hepta_cb_fn_Mcf03d00758734ee2_OwnedBytes_drop(__hepta_cb_aggregate_0 h_owner) {
#line 23 "/workspace/scratch/c7c6ee414a6c/hepta-research/artifacts/cpp-owned-20261025T171524382241Z/cpp-owned/migrated.hepta"
__hepta_cb_aggregate_0 __hepta_cb_v16 = h_owner;
#line 23 "/workspace/scratch/c7c6ee414a6c/hepta-research/artifacts/cpp-owned-20261025T171524382241Z/cpp-owned/migrated.hepta"
__hepta_cb_aggregate_0 __hepta_cb_v17 = __hepta_cb_v16;
#line 23 "/workspace/scratch/c7c6ee414a6c/hepta-research/artifacts/cpp-owned-20261025T171524382241Z/cpp-owned/migrated.hepta"
__hepta_cb_drop_1(__hepta_cb_v17);
#line 23 "/workspace/scratch/c7c6ee414a6c/hepta-research/artifacts/cpp-owned-20261025T171524382241Z/cpp-owned/migrated.hepta"
}
#line 26 "/workspace/scratch/c7c6ee414a6c/hepta-research/artifacts/cpp-owned-20261025T171524382241Z/cpp-owned/migrated.hepta"
size_t __hepta_cb_fn_Mcf03d00758734ee2_OwnedBytes_size(const __hepta_cb_aggregate_0 *h_owner) {
#line 27 "/workspace/scratch/c7c6ee414a6c/hepta-research/artifacts/cpp-owned-20261025T171524382241Z/cpp-owned/migrated.hepta"
size_t __hepta_cb_v18 = (((*h_owner)).h_data).len;
#line 27 "/workspace/scratch/c7c6ee414a6c/hepta-research/artifacts/cpp-owned-20261025T171524382241Z/cpp-owned/migrated.hepta"
return __hepta_cb_v18;
#line 27 "/workspace/scratch/c7c6ee414a6c/hepta-research/artifacts/cpp-owned-20261025T171524382241Z/cpp-owned/migrated.hepta"
}
#line 30 "/workspace/scratch/c7c6ee414a6c/hepta-research/artifacts/cpp-owned-20261025T171524382241Z/cpp-owned/migrated.hepta"
__hepta_cb_slice_4 __hepta_cb_fn_Mcf03d00758734ee2_OwnedBytes_data(const __hepta_cb_aggregate_0 *h_owner) {
#line 31 "/workspace/scratch/c7c6ee414a6c/hepta-research/artifacts/cpp-owned-20261025T171524382241Z/cpp-owned/migrated.hepta"
return (__hepta_cb_slice_4){(((*h_owner)).h_data).data, (((*h_owner)).h_data).len};
#line 31 "/workspace/scratch/c7c6ee414a6c/hepta-research/artifacts/cpp-owned-20261025T171524382241Z/cpp-owned/migrated.hepta"
}
#line 34 "/workspace/scratch/c7c6ee414a6c/hepta-research/artifacts/cpp-owned-20261025T171524382241Z/cpp-owned/migrated.hepta"
void __hepta_cb_fn_Mcf03d00758734ee2_OwnedBytes_fill(__hepta_cb_aggregate_0 *h_owner, uint8_t h_value) {
#line 35 "/workspace/scratch/c7c6ee414a6c/hepta-research/artifacts/cpp-owned-20261025T171524382241Z/cpp-owned/migrated.hepta"
size_t __hepta_cb_v19 = (size_t)UINT64_C(0);
#line 35 "/workspace/scratch/c7c6ee414a6c/hepta-research/artifacts/cpp-owned-20261025T171524382241Z/cpp-owned/migrated.hepta"
size_t __hepta_cb_v20 = (((*h_owner)).h_data).len;
#line 35 "/workspace/scratch/c7c6ee414a6c/hepta-research/artifacts/cpp-owned-20261025T171524382241Z/cpp-owned/migrated.hepta"
for (size_t h_index = __hepta_cb_v19; h_index < __hepta_cb_v20; ++h_index) { 
#line 35 "/workspace/scratch/c7c6ee414a6c/hepta-research/artifacts/cpp-owned-20261025T171524382241Z/cpp-owned/migrated.hepta"
uint8_t __hepta_cb_v21 = h_value;
#line 35 "/workspace/scratch/c7c6ee414a6c/hepta-research/artifacts/cpp-owned-20261025T171524382241Z/cpp-owned/migrated.hepta"
size_t __hepta_cb_v22 = h_index;
#line 35 "/workspace/scratch/c7c6ee414a6c/hepta-research/artifacts/cpp-owned-20261025T171524382241Z/cpp-owned/migrated.hepta"
if (__hepta_cb_v22 >= (((*h_owner)).h_data).len) abort();
#line 35 "/workspace/scratch/c7c6ee414a6c/hepta-research/artifacts/cpp-owned-20261025T171524382241Z/cpp-owned/migrated.hepta"
((((*h_owner)).h_data).data)[__hepta_cb_v22] = __hepta_cb_v21; }
#line 35 "/workspace/scratch/c7c6ee414a6c/hepta-research/artifacts/cpp-owned-20261025T171524382241Z/cpp-owned/migrated.hepta"
}
#line 38 "/workspace/scratch/c7c6ee414a6c/hepta-research/artifacts/cpp-owned-20261025T171524382241Z/cpp-owned/migrated.hepta"
uint8_t __hepta_cb_fn_Mcf03d00758734ee2_OwnedBytes_get(const __hepta_cb_aggregate_0 *h_owner, size_t h_index) {
#line 39 "/workspace/scratch/c7c6ee414a6c/hepta-research/artifacts/cpp-owned-20261025T171524382241Z/cpp-owned/migrated.hepta"
size_t __hepta_cb_v23 = h_index;
#line 39 "/workspace/scratch/c7c6ee414a6c/hepta-research/artifacts/cpp-owned-20261025T171524382241Z/cpp-owned/migrated.hepta"
if (__hepta_cb_v23 >= (((*h_owner)).h_data).len) abort();
#line 39 "/workspace/scratch/c7c6ee414a6c/hepta-research/artifacts/cpp-owned-20261025T171524382241Z/cpp-owned/migrated.hepta"
uint8_t __hepta_cb_v24 = ((((*h_owner)).h_data).data)[__hepta_cb_v23];
#line 39 "/workspace/scratch/c7c6ee414a6c/hepta-research/artifacts/cpp-owned-20261025T171524382241Z/cpp-owned/migrated.hepta"
return __hepta_cb_v24;
#line 39 "/workspace/scratch/c7c6ee414a6c/hepta-research/artifacts/cpp-owned-20261025T171524382241Z/cpp-owned/migrated.hepta"
}
#line 42 "/workspace/scratch/c7c6ee414a6c/hepta-research/artifacts/cpp-owned-20261025T171524382241Z/cpp-owned/migrated.hepta"
void __hepta_cb_fn_Mcf03d00758734ee2_OwnedBytes_set(__hepta_cb_aggregate_0 *h_owner, size_t h_index, uint8_t h_value) {
#line 43 "/workspace/scratch/c7c6ee414a6c/hepta-research/artifacts/cpp-owned-20261025T171524382241Z/cpp-owned/migrated.hepta"
uint8_t __hepta_cb_v25 = h_value;
#line 43 "/workspace/scratch/c7c6ee414a6c/hepta-research/artifacts/cpp-owned-20261025T171524382241Z/cpp-owned/migrated.hepta"
size_t __hepta_cb_v26 = h_index;
#line 43 "/workspace/scratch/c7c6ee414a6c/hepta-research/artifacts/cpp-owned-20261025T171524382241Z/cpp-owned/migrated.hepta"
if (__hepta_cb_v26 >= (((*h_owner)).h_data).len) abort();
#line 43 "/workspace/scratch/c7c6ee414a6c/hepta-research/artifacts/cpp-owned-20261025T171524382241Z/cpp-owned/migrated.hepta"
((((*h_owner)).h_data).data)[__hepta_cb_v26] = __hepta_cb_v25;
#line 43 "/workspace/scratch/c7c6ee414a6c/hepta-research/artifacts/cpp-owned-20261025T171524382241Z/cpp-owned/migrated.hepta"
}
#line 46 "/workspace/scratch/c7c6ee414a6c/hepta-research/artifacts/cpp-owned-20261025T171524382241Z/cpp-owned/migrated.hepta"
uint64_t __hepta_cb_fn_Mcf03d00758734ee2_run_owned(size_t h_size, uint8_t h_value, size_t h_index, bool h_reject_constructor, bool h_early) {
#line 48 "/workspace/scratch/c7c6ee414a6c/hepta-research/artifacts/cpp-owned-20261025T171524382241Z/cpp-owned/migrated.hepta"
size_t __hepta_cb_v27 = h_size;
#line 48 "/workspace/scratch/c7c6ee414a6c/hepta-research/artifacts/cpp-owned-20261025T171524382241Z/cpp-owned/migrated.hepta"
bool __hepta_cb_v28 = h_reject_constructor;
#line 48 "/workspace/scratch/c7c6ee414a6c/hepta-research/artifacts/cpp-owned-20261025T171524382241Z/cpp-owned/migrated.hepta"
__hepta_cb_aggregate_2 __hepta_cb_v29 = __hepta_cb_fn_Mcf03d00758734ee2_OwnedBytes_new(__hepta_cb_v27, __hepta_cb_v28);
#line 48 "/workspace/scratch/c7c6ee414a6c/hepta-research/artifacts/cpp-owned-20261025T171524382241Z/cpp-owned/migrated.hepta"
switch (__hepta_cb_v29.tag) {
#line 48 "/workspace/scratch/c7c6ee414a6c/hepta-research/artifacts/cpp-owned-20261025T171524382241Z/cpp-owned/migrated.hepta"
case 1: {
#line 48 "/workspace/scratch/c7c6ee414a6c/hepta-research/artifacts/cpp-owned-20261025T171524382241Z/cpp-owned/migrated.hepta"
uint8_t h_code = __hepta_cb_v29.payload.v_Err.f_0;
#line 49 "/workspace/scratch/c7c6ee414a6c/hepta-research/artifacts/cpp-owned-20261025T171524382241Z/cpp-owned/migrated.hepta"
uint64_t __hepta_cb_v30 = (uint64_t)UINT64_C(1000);
#line 49 "/workspace/scratch/c7c6ee414a6c/hepta-research/artifacts/cpp-owned-20261025T171524382241Z/cpp-owned/migrated.hepta"
uint8_t __hepta_cb_v31 = h_code;
#line 49 "/workspace/scratch/c7c6ee414a6c/hepta-research/artifacts/cpp-owned-20261025T171524382241Z/cpp-owned/migrated.hepta"
uint64_t __hepta_cb_v32 = __hepta_cb_u64_bits((uint64_t)__hepta_cb_v31);
#line 49 "/workspace/scratch/c7c6ee414a6c/hepta-research/artifacts/cpp-owned-20261025T171524382241Z/cpp-owned/migrated.hepta"
uint64_t __hepta_cb_v33 = __hepta_cb_u64_add(__hepta_cb_v30, __hepta_cb_v32);
#line 49 "/workspace/scratch/c7c6ee414a6c/hepta-research/artifacts/cpp-owned-20261025T171524382241Z/cpp-owned/migrated.hepta"
return __hepta_cb_v33;
#line 49 "/workspace/scratch/c7c6ee414a6c/hepta-research/artifacts/cpp-owned-20261025T171524382241Z/cpp-owned/migrated.hepta"
break; }
#line 49 "/workspace/scratch/c7c6ee414a6c/hepta-research/artifacts/cpp-owned-20261025T171524382241Z/cpp-owned/migrated.hepta"
case 0: {
#line 49 "/workspace/scratch/c7c6ee414a6c/hepta-research/artifacts/cpp-owned-20261025T171524382241Z/cpp-owned/migrated.hepta"
__hepta_cb_aggregate_0 h_created = __hepta_cb_v29.payload.v_Ok.f_0;
#line 51 "/workspace/scratch/c7c6ee414a6c/hepta-research/artifacts/cpp-owned-20261025T171524382241Z/cpp-owned/migrated.hepta"
__hepta_cb_aggregate_0 __hepta_cb_v34 = h_created;
#line 51 "/workspace/scratch/c7c6ee414a6c/hepta-research/artifacts/cpp-owned-20261025T171524382241Z/cpp-owned/migrated.hepta"
__hepta_cb_aggregate_0 __hepta_cb_v35 = __hepta_cb_v34;
#line 51 "/workspace/scratch/c7c6ee414a6c/hepta-research/artifacts/cpp-owned-20261025T171524382241Z/cpp-owned/migrated.hepta"
__hepta_cb_aggregate_0 h_first = __hepta_cb_v35;
#line 52 "/workspace/scratch/c7c6ee414a6c/hepta-research/artifacts/cpp-owned-20261025T171524382241Z/cpp-owned/migrated.hepta"
__hepta_cb_aggregate_0 * __hepta_cb_arg36 = &(h_first);
#line 52 "/workspace/scratch/c7c6ee414a6c/hepta-research/artifacts/cpp-owned-20261025T171524382241Z/cpp-owned/migrated.hepta"
uint8_t __hepta_cb_v37 = h_value;
#line 52 "/workspace/scratch/c7c6ee414a6c/hepta-research/artifacts/cpp-owned-20261025T171524382241Z/cpp-owned/migrated.hepta"
__hepta_cb_fn_Mcf03d00758734ee2_OwnedBytes_fill(__hepta_cb_arg36, __hepta_cb_v37);
#line 53 "/workspace/scratch/c7c6ee414a6c/hepta-research/artifacts/cpp-owned-20261025T171524382241Z/cpp-owned/migrated.hepta"
size_t __hepta_cb_v38 = h_size;
#line 53 "/workspace/scratch/c7c6ee414a6c/hepta-research/artifacts/cpp-owned-20261025T171524382241Z/cpp-owned/migrated.hepta"
size_t __hepta_cb_v39 = (size_t)UINT64_C(0);
#line 53 "/workspace/scratch/c7c6ee414a6c/hepta-research/artifacts/cpp-owned-20261025T171524382241Z/cpp-owned/migrated.hepta"
bool __hepta_cb_v40 = (__hepta_cb_v38 != __hepta_cb_v39);
#line 53 "/workspace/scratch/c7c6ee414a6c/hepta-research/artifacts/cpp-owned-20261025T171524382241Z/cpp-owned/migrated.hepta"
if (__hepta_cb_v40) { 
#line 53 "/workspace/scratch/c7c6ee414a6c/hepta-research/artifacts/cpp-owned-20261025T171524382241Z/cpp-owned/migrated.hepta"
__hepta_cb_aggregate_0 * __hepta_cb_arg41 = &(h_first);
#line 53 "/workspace/scratch/c7c6ee414a6c/hepta-research/artifacts/cpp-owned-20261025T171524382241Z/cpp-owned/migrated.hepta"
size_t __hepta_cb_v42 = (size_t)UINT64_C(0);
#line 53 "/workspace/scratch/c7c6ee414a6c/hepta-research/artifacts/cpp-owned-20261025T171524382241Z/cpp-owned/migrated.hepta"
uint8_t __hepta_cb_v43 = h_value;
#line 53 "/workspace/scratch/c7c6ee414a6c/hepta-research/artifacts/cpp-owned-20261025T171524382241Z/cpp-owned/migrated.hepta"
uint8_t __hepta_cb_v44 = (uint8_t)UINT64_C(90);
#line 53 "/workspace/scratch/c7c6ee414a6c/hepta-research/artifacts/cpp-owned-20261025T171524382241Z/cpp-owned/migrated.hepta"
uint8_t __hepta_cb_v45 = __hepta_cb_u8_xor(__hepta_cb_v43, __hepta_cb_v44);
#line 53 "/workspace/scratch/c7c6ee414a6c/hepta-research/artifacts/cpp-owned-20261025T171524382241Z/cpp-owned/migrated.hepta"
__hepta_cb_fn_Mcf03d00758734ee2_OwnedBytes_set(__hepta_cb_arg41, __hepta_cb_v42, __hepta_cb_v45); } else {  }
#line 54 "/workspace/scratch/c7c6ee414a6c/hepta-research/artifacts/cpp-owned-20261025T171524382241Z/cpp-owned/migrated.hepta"
__hepta_cb_aggregate_0 __hepta_cb_v46 = h_first;
#line 54 "/workspace/scratch/c7c6ee414a6c/hepta-research/artifacts/cpp-owned-20261025T171524382241Z/cpp-owned/migrated.hepta"
__hepta_cb_aggregate_0 __hepta_cb_v47 = __hepta_cb_v46;
#line 54 "/workspace/scratch/c7c6ee414a6c/hepta-research/artifacts/cpp-owned-20261025T171524382241Z/cpp-owned/migrated.hepta"
__hepta_cb_aggregate_0 __hepta_cb_v48 = __hepta_cb_fn_Mcf03d00758734ee2_OwnedBytes_move(__hepta_cb_v47);
#line 54 "/workspace/scratch/c7c6ee414a6c/hepta-research/artifacts/cpp-owned-20261025T171524382241Z/cpp-owned/migrated.hepta"
__hepta_cb_aggregate_0 h_second = __hepta_cb_v48;
#line 55 "/workspace/scratch/c7c6ee414a6c/hepta-research/artifacts/cpp-owned-20261025T171524382241Z/cpp-owned/migrated.hepta"
bool __hepta_cb_v49 = h_early;
#line 55 "/workspace/scratch/c7c6ee414a6c/hepta-research/artifacts/cpp-owned-20261025T171524382241Z/cpp-owned/migrated.hepta"
if (__hepta_cb_v49) { 
#line 56 "/workspace/scratch/c7c6ee414a6c/hepta-research/artifacts/cpp-owned-20261025T171524382241Z/cpp-owned/migrated.hepta"
__hepta_cb_aggregate_0 __hepta_cb_v50 = h_second;
#line 56 "/workspace/scratch/c7c6ee414a6c/hepta-research/artifacts/cpp-owned-20261025T171524382241Z/cpp-owned/migrated.hepta"
__hepta_cb_aggregate_0 __hepta_cb_v51 = __hepta_cb_v50;
#line 56 "/workspace/scratch/c7c6ee414a6c/hepta-research/artifacts/cpp-owned-20261025T171524382241Z/cpp-owned/migrated.hepta"
__hepta_cb_fn_Mcf03d00758734ee2_OwnedBytes_drop(__hepta_cb_v51);
#line 57 "/workspace/scratch/c7c6ee414a6c/hepta-research/artifacts/cpp-owned-20261025T171524382241Z/cpp-owned/migrated.hepta"
uint64_t __hepta_cb_v52 = (uint64_t)UINT64_C(2002);
#line 57 "/workspace/scratch/c7c6ee414a6c/hepta-research/artifacts/cpp-owned-20261025T171524382241Z/cpp-owned/migrated.hepta"
return __hepta_cb_v52; } else {  }
#line 59 "/workspace/scratch/c7c6ee414a6c/hepta-research/artifacts/cpp-owned-20261025T171524382241Z/cpp-owned/migrated.hepta"
size_t __hepta_cb_v53 = h_index;
#line 59 "/workspace/scratch/c7c6ee414a6c/hepta-research/artifacts/cpp-owned-20261025T171524382241Z/cpp-owned/migrated.hepta"
const __hepta_cb_aggregate_0 * __hepta_cb_arg54 = &(h_second);
#line 59 "/workspace/scratch/c7c6ee414a6c/hepta-research/artifacts/cpp-owned-20261025T171524382241Z/cpp-owned/migrated.hepta"
size_t __hepta_cb_v55 = __hepta_cb_fn_Mcf03d00758734ee2_OwnedBytes_size(__hepta_cb_arg54);
#line 59 "/workspace/scratch/c7c6ee414a6c/hepta-research/artifacts/cpp-owned-20261025T171524382241Z/cpp-owned/migrated.hepta"
bool __hepta_cb_v56 = (__hepta_cb_v53 >= __hepta_cb_v55);
#line 59 "/workspace/scratch/c7c6ee414a6c/hepta-research/artifacts/cpp-owned-20261025T171524382241Z/cpp-owned/migrated.hepta"
if (__hepta_cb_v56) { 
#line 60 "/workspace/scratch/c7c6ee414a6c/hepta-research/artifacts/cpp-owned-20261025T171524382241Z/cpp-owned/migrated.hepta"
__hepta_cb_aggregate_0 __hepta_cb_v57 = h_second;
#line 60 "/workspace/scratch/c7c6ee414a6c/hepta-research/artifacts/cpp-owned-20261025T171524382241Z/cpp-owned/migrated.hepta"
__hepta_cb_aggregate_0 __hepta_cb_v58 = __hepta_cb_v57;
#line 60 "/workspace/scratch/c7c6ee414a6c/hepta-research/artifacts/cpp-owned-20261025T171524382241Z/cpp-owned/migrated.hepta"
__hepta_cb_fn_Mcf03d00758734ee2_OwnedBytes_drop(__hepta_cb_v58);
#line 61 "/workspace/scratch/c7c6ee414a6c/hepta-research/artifacts/cpp-owned-20261025T171524382241Z/cpp-owned/migrated.hepta"
uint64_t __hepta_cb_v59 = (uint64_t)UINT64_C(2003);
#line 61 "/workspace/scratch/c7c6ee414a6c/hepta-research/artifacts/cpp-owned-20261025T171524382241Z/cpp-owned/migrated.hepta"
return __hepta_cb_v59; } else {  }
#line 63 "/workspace/scratch/c7c6ee414a6c/hepta-research/artifacts/cpp-owned-20261025T171524382241Z/cpp-owned/migrated.hepta"
const __hepta_cb_aggregate_0 * __hepta_cb_arg60 = &(h_second);
#line 63 "/workspace/scratch/c7c6ee414a6c/hepta-research/artifacts/cpp-owned-20261025T171524382241Z/cpp-owned/migrated.hepta"
__hepta_cb_slice_4 __hepta_cb_view61 = __hepta_cb_fn_Mcf03d00758734ee2_OwnedBytes_data(__hepta_cb_arg60);
#line 63 "/workspace/scratch/c7c6ee414a6c/hepta-research/artifacts/cpp-owned-20261025T171524382241Z/cpp-owned/migrated.hepta"
size_t __hepta_cb_v62 = h_index;
#line 63 "/workspace/scratch/c7c6ee414a6c/hepta-research/artifacts/cpp-owned-20261025T171524382241Z/cpp-owned/migrated.hepta"
if (__hepta_cb_v62 >= (__hepta_cb_view61).len) abort();
#line 63 "/workspace/scratch/c7c6ee414a6c/hepta-research/artifacts/cpp-owned-20261025T171524382241Z/cpp-owned/migrated.hepta"
uint8_t __hepta_cb_v63 = ((__hepta_cb_view61).data)[__hepta_cb_v62];
#line 63 "/workspace/scratch/c7c6ee414a6c/hepta-research/artifacts/cpp-owned-20261025T171524382241Z/cpp-owned/migrated.hepta"
uint64_t __hepta_cb_v64 = __hepta_cb_u64_bits((uint64_t)__hepta_cb_v63);
#line 63 "/workspace/scratch/c7c6ee414a6c/hepta-research/artifacts/cpp-owned-20261025T171524382241Z/cpp-owned/migrated.hepta"
const __hepta_cb_aggregate_0 * __hepta_cb_arg65 = &(h_second);
#line 63 "/workspace/scratch/c7c6ee414a6c/hepta-research/artifacts/cpp-owned-20261025T171524382241Z/cpp-owned/migrated.hepta"
size_t __hepta_cb_v66 = h_index;
#line 63 "/workspace/scratch/c7c6ee414a6c/hepta-research/artifacts/cpp-owned-20261025T171524382241Z/cpp-owned/migrated.hepta"
uint8_t __hepta_cb_v67 = __hepta_cb_fn_Mcf03d00758734ee2_OwnedBytes_get(__hepta_cb_arg65, __hepta_cb_v66);
#line 63 "/workspace/scratch/c7c6ee414a6c/hepta-research/artifacts/cpp-owned-20261025T171524382241Z/cpp-owned/migrated.hepta"
uint64_t __hepta_cb_v68 = __hepta_cb_u64_bits((uint64_t)__hepta_cb_v67);
#line 63 "/workspace/scratch/c7c6ee414a6c/hepta-research/artifacts/cpp-owned-20261025T171524382241Z/cpp-owned/migrated.hepta"
uint64_t __hepta_cb_v69 = __hepta_cb_u64_add(__hepta_cb_v64, __hepta_cb_v68);
#line 63 "/workspace/scratch/c7c6ee414a6c/hepta-research/artifacts/cpp-owned-20261025T171524382241Z/cpp-owned/migrated.hepta"
const __hepta_cb_aggregate_0 * __hepta_cb_arg70 = &(h_second);
#line 63 "/workspace/scratch/c7c6ee414a6c/hepta-research/artifacts/cpp-owned-20261025T171524382241Z/cpp-owned/migrated.hepta"
size_t __hepta_cb_v71 = __hepta_cb_fn_Mcf03d00758734ee2_OwnedBytes_size(__hepta_cb_arg70);
#line 63 "/workspace/scratch/c7c6ee414a6c/hepta-research/artifacts/cpp-owned-20261025T171524382241Z/cpp-owned/migrated.hepta"
uint64_t __hepta_cb_v72 = __hepta_cb_u64_bits((uint64_t)__hepta_cb_v71);
#line 63 "/workspace/scratch/c7c6ee414a6c/hepta-research/artifacts/cpp-owned-20261025T171524382241Z/cpp-owned/migrated.hepta"
uint64_t __hepta_cb_v73 = __hepta_cb_u64_add(__hepta_cb_v69, __hepta_cb_v72);
#line 63 "/workspace/scratch/c7c6ee414a6c/hepta-research/artifacts/cpp-owned-20261025T171524382241Z/cpp-owned/migrated.hepta"
uint64_t h_answer = __hepta_cb_v73;
#line 65 "/workspace/scratch/c7c6ee414a6c/hepta-research/artifacts/cpp-owned-20261025T171524382241Z/cpp-owned/migrated.hepta"
__hepta_cb_aggregate_0 __hepta_cb_v74 = h_second;
#line 65 "/workspace/scratch/c7c6ee414a6c/hepta-research/artifacts/cpp-owned-20261025T171524382241Z/cpp-owned/migrated.hepta"
__hepta_cb_aggregate_0 __hepta_cb_v75 = __hepta_cb_v74;
#line 65 "/workspace/scratch/c7c6ee414a6c/hepta-research/artifacts/cpp-owned-20261025T171524382241Z/cpp-owned/migrated.hepta"
__hepta_cb_fn_Mcf03d00758734ee2_OwnedBytes_drop(__hepta_cb_v75);
#line 66 "/workspace/scratch/c7c6ee414a6c/hepta-research/artifacts/cpp-owned-20261025T171524382241Z/cpp-owned/migrated.hepta"
uint64_t __hepta_cb_v76 = h_answer;
#line 66 "/workspace/scratch/c7c6ee414a6c/hepta-research/artifacts/cpp-owned-20261025T171524382241Z/cpp-owned/migrated.hepta"
return __hepta_cb_v76;
#line 66 "/workspace/scratch/c7c6ee414a6c/hepta-research/artifacts/cpp-owned-20261025T171524382241Z/cpp-owned/migrated.hepta"
break; }
#line 66 "/workspace/scratch/c7c6ee414a6c/hepta-research/artifacts/cpp-owned-20261025T171524382241Z/cpp-owned/migrated.hepta"
default: abort(); }
#line 66 "/workspace/scratch/c7c6ee414a6c/hepta-research/artifacts/cpp-owned-20261025T171524382241Z/cpp-owned/migrated.hepta"
}
#line 4 "/workspace/scratch/c7c6ee414a6c/hepta-research/artifacts/cpp-owned-20261025T171524382241Z/cpp-owned/consumer.hepta"
uint64_t owned_case(size_t h_size, uint8_t h_value, size_t h_index, uint32_t h_reject, uint32_t h_early) {
#line 6 "/workspace/scratch/c7c6ee414a6c/hepta-research/artifacts/cpp-owned-20261025T171524382241Z/cpp-owned/consumer.hepta"
size_t __hepta_cb_v77 = h_size;
#line 6 "/workspace/scratch/c7c6ee414a6c/hepta-research/artifacts/cpp-owned-20261025T171524382241Z/cpp-owned/consumer.hepta"
uint8_t __hepta_cb_v78 = h_value;
#line 6 "/workspace/scratch/c7c6ee414a6c/hepta-research/artifacts/cpp-owned-20261025T171524382241Z/cpp-owned/consumer.hepta"
size_t __hepta_cb_v79 = h_index;
#line 6 "/workspace/scratch/c7c6ee414a6c/hepta-research/artifacts/cpp-owned-20261025T171524382241Z/cpp-owned/consumer.hepta"
uint32_t __hepta_cb_v80 = h_reject;
#line 6 "/workspace/scratch/c7c6ee414a6c/hepta-research/artifacts/cpp-owned-20261025T171524382241Z/cpp-owned/consumer.hepta"
uint32_t __hepta_cb_v81 = (uint32_t)UINT64_C(0);
#line 6 "/workspace/scratch/c7c6ee414a6c/hepta-research/artifacts/cpp-owned-20261025T171524382241Z/cpp-owned/consumer.hepta"
bool __hepta_cb_v82 = (__hepta_cb_v80 != __hepta_cb_v81);
#line 6 "/workspace/scratch/c7c6ee414a6c/hepta-research/artifacts/cpp-owned-20261025T171524382241Z/cpp-owned/consumer.hepta"
uint32_t __hepta_cb_v83 = h_early;
#line 6 "/workspace/scratch/c7c6ee414a6c/hepta-research/artifacts/cpp-owned-20261025T171524382241Z/cpp-owned/consumer.hepta"
uint32_t __hepta_cb_v84 = (uint32_t)UINT64_C(0);
#line 6 "/workspace/scratch/c7c6ee414a6c/hepta-research/artifacts/cpp-owned-20261025T171524382241Z/cpp-owned/consumer.hepta"
bool __hepta_cb_v85 = (__hepta_cb_v83 != __hepta_cb_v84);
#line 6 "/workspace/scratch/c7c6ee414a6c/hepta-research/artifacts/cpp-owned-20261025T171524382241Z/cpp-owned/consumer.hepta"
uint64_t __hepta_cb_v86 = __hepta_cb_fn_Mcf03d00758734ee2_run_owned(__hepta_cb_v77, __hepta_cb_v78, __hepta_cb_v79, __hepta_cb_v82, __hepta_cb_v85);
#line 6 "/workspace/scratch/c7c6ee414a6c/hepta-research/artifacts/cpp-owned-20261025T171524382241Z/cpp-owned/consumer.hepta"
return __hepta_cb_v86;
#line 6 "/workspace/scratch/c7c6ee414a6c/hepta-research/artifacts/cpp-owned-20261025T171524382241Z/cpp-owned/consumer.hepta"
}

/* This harness is also compiled as C++ for the original reference. */
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <inttypes.h>
#include "cases.h"

/* Linker wrapping is applied after optimization. Volatile observations keep
 * the optimizer from assuming an ordinary calloc cannot reach this state. */
static volatile bool observed_tracking = false, observed_refuse = false;
static volatile size_t observed_allocated = 0, observed_freed = 0, observed_refusals = 0;
static volatile size_t observed_attempts = 0;
static volatile intptr_t observed_live = 0;

#ifdef __cplusplus
#include <new>
extern "C" uint64_t owned_case(size_t, uint8_t, size_t, uint32_t, uint32_t) noexcept;
void* operator new[](std::size_t size) {
    if (observed_tracking) {
        observed_attempts = observed_attempts + 1;
        if (observed_refuse) { observed_refusals = observed_refusals + 1; throw std::bad_alloc(); }
    }
    void* pointer = std::malloc(size);
    if (!pointer) { throw std::bad_alloc(); }
    if (observed_tracking) { observed_allocated = observed_allocated + 1; observed_live = observed_live + 1; }
    return pointer;
}
void operator delete[](void* pointer) noexcept {
    if (observed_tracking && pointer) { observed_freed = observed_freed + 1; observed_live = observed_live - 1; }
    std::free(pointer);
}
void operator delete[](void* pointer, std::size_t) noexcept { ::operator delete[](pointer); }
#else
void* __real_calloc(size_t, size_t);
void* __real_malloc(size_t);
void __real_free(void*);
void* __wrap_calloc(size_t count, size_t size) {
    if (observed_tracking) {
        observed_attempts = observed_attempts + 1;
        if (observed_refuse) { observed_refusals = observed_refusals + 1; return NULL; }
    }
    void* pointer = __real_calloc(count, size);
    if (observed_tracking && pointer) { observed_allocated = observed_allocated + 1; observed_live = observed_live + 1; }
    return pointer;
}
void* __wrap_malloc(size_t size) {
    if (observed_tracking) {
        observed_attempts = observed_attempts + 1;
        if (observed_refuse) { observed_refusals = observed_refusals + 1; return NULL; }
    }
    void* pointer = __real_malloc(size);
    if (observed_tracking && pointer) { observed_allocated = observed_allocated + 1; observed_live = observed_live + 1; }
    return pointer;
}
void __wrap_free(void* pointer) {
    if (observed_tracking && pointer) { observed_freed = observed_freed + 1; observed_live = observed_live - 1; }
    __real_free(pointer);
}
#endif

static uint64_t observe_word(uint64_t state, uint64_t word) {
    for (unsigned i = 0; i < 8; ++i) {
        state ^= (word >> (i * 8)) & 255;
        state *= UINT64_C(1099511628211);
    }
    return state;
}

int main(void) {
    uint64_t digest = UINT64_C(14695981039346656037);
    size_t total_allocations = 0, total_frees = 0, total_refusals = 0;
    for (size_t i = 0; i < OWNED_CASE_COUNT; ++i) {
        const struct OwnedCase* current = &owned_cases[i];
        observed_allocated = 0;
        observed_freed = 0;
        observed_refusals = 0;
        observed_attempts = 0;
        observed_live = 0;
        observed_refuse = current->refuse != 0;
        observed_tracking = true;
        uint64_t actual = owned_case(current->size, current->value, current->index, current->reject, current->early);
        observed_tracking = false;
        if (actual != current->expected) {
            printf("{\"ok\":false,\"failure\":\"value\",\"case\":%zu,\"expected\":%" PRIu64 ",\"actual\":%" PRIu64 "}\n",
                   i, current->expected, actual);
            return 2;
        }
        if (observed_allocated != current->allocated || observed_freed != current->allocated ||
            observed_live != 0 || observed_refusals != current->refusals ||
            observed_attempts != current->allocated + current->refusals) {
            printf("{\"ok\":false,\"failure\":\"lifecycle\",\"case\":%zu,\"allocated\":%zu,\"freed\":%zu,\"live\":%" PRIdPTR ",\"refusals\":%zu,\"attempts\":%zu}\n",
                   i, observed_allocated, observed_freed, observed_live, observed_refusals, observed_attempts);
            return 3;
        }
        total_allocations += observed_allocated;
        total_frees += observed_freed;
        total_refusals += observed_refusals;
        digest = observe_word(digest, i);
        digest = observe_word(digest, actual);
        digest = observe_word(digest, observed_allocated);
        digest = observe_word(digest, observed_freed);
        digest = observe_word(digest, observed_refusals);
    }
    printf("{\"ok\":true,\"cases\":%zu,\"observations_fnv64\":\"%016" PRIx64 "\",\"allocations\":%zu,\"frees\":%zu,\"refusals\":%zu,\"live\":0}\n",
           (size_t)OWNED_CASE_COUNT, digest, total_allocations, total_frees, total_refusals);
    return 0;
}
