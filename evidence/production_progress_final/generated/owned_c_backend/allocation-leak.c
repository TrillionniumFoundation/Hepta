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
typedef struct { uint32_t tag; union { struct { __hepta_cb_buffer f_0; } v_Ok; struct { uint8_t f_0; } v_Err; } payload; } __hepta_cb_aggregate_0;
typedef struct { __hepta_cb_buffer h_data; uint64_t h_tag; } __hepta_cb_aggregate_2;
typedef struct { uint32_t tag; union { struct { __hepta_cb_aggregate_2 f_0; } v_Ok; struct { uint8_t f_0; } v_Err; } payload; } __hepta_cb_aggregate_3;
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

static __hepta_cb_aggregate_0 __hepta_cb_try_buffer(size_t size) {
    __hepta_cb_buffer out;
    if (!__hepta_cb_allocate(size, &out))
        return (__hepta_cb_aggregate_0){.tag=1, .payload.v_Err={.f_0=1}};
    return (__hepta_cb_aggregate_0){.tag=0, .payload.v_Ok={.f_0=out}};
}

static void __hepta_cb_drop_0(__hepta_cb_aggregate_2 value);
static void __hepta_cb_drop_1(__hepta_cb_buffer value);
static void __hepta_cb_drop_0(__hepta_cb_aggregate_2 value) { __hepta_cb_drop_1(value.h_data); }
static void __hepta_cb_drop_1(__hepta_cb_buffer value) { (void)value; }
uint64_t __hepta_cb_fn_probe(size_t h_size, bool h_ok);
__hepta_cb_aggregate_3 __hepta_cb_generic_1_finish(__hepta_cb_aggregate_2 h_value, bool h_ok, uint8_t h_error);
const __hepta_cb_buffer * __hepta_cb_generic_2_view(const __hepta_cb_buffer *h_value);
const __hepta_cb_aggregate_2 * __hepta_cb_generic_3_view(const __hepta_cb_aggregate_2 *h_value);
void __hepta_cb_generic_4_dispose(__hepta_cb_aggregate_2 h_value);
__hepta_cb_aggregate_2 __hepta_cb_generic_5_forward(__hepta_cb_aggregate_2 h_value);
#line 11 "/workspace/scratch/0817a147930b/Hepta-work/examples/c_owned_backend/owned.hepta"
uint64_t __hepta_cb_fn_probe(size_t h_size, bool h_ok) {
#line 12 "/workspace/scratch/0817a147930b/Hepta-work/examples/c_owned_backend/owned.hepta"
size_t __hepta_cb_v1 = h_size;
#line 12 "/workspace/scratch/0817a147930b/Hepta-work/examples/c_owned_backend/owned.hepta"
__hepta_cb_aggregate_0 __hepta_cb_v2 = __hepta_cb_try_buffer(__hepta_cb_v1);
#line 12 "/workspace/scratch/0817a147930b/Hepta-work/examples/c_owned_backend/owned.hepta"
__hepta_cb_aggregate_0 h_allocated = __hepta_cb_v2;
#line 13 "/workspace/scratch/0817a147930b/Hepta-work/examples/c_owned_backend/owned.hepta"
__hepta_cb_aggregate_0 __hepta_cb_v3 = h_allocated;
#line 13 "/workspace/scratch/0817a147930b/Hepta-work/examples/c_owned_backend/owned.hepta"
__hepta_cb_aggregate_0 __hepta_cb_v4 = __hepta_cb_v3;
#line 13 "/workspace/scratch/0817a147930b/Hepta-work/examples/c_owned_backend/owned.hepta"
switch (__hepta_cb_v4.tag) {
#line 13 "/workspace/scratch/0817a147930b/Hepta-work/examples/c_owned_backend/owned.hepta"
case 1: {
#line 13 "/workspace/scratch/0817a147930b/Hepta-work/examples/c_owned_backend/owned.hepta"
uint8_t h_allocation_error = __hepta_cb_v4.payload.v_Err.f_0;
#line 14 "/workspace/scratch/0817a147930b/Hepta-work/examples/c_owned_backend/owned.hepta"
uint64_t __hepta_cb_v5 = (uint64_t)UINT64_C(1000);
#line 14 "/workspace/scratch/0817a147930b/Hepta-work/examples/c_owned_backend/owned.hepta"
uint8_t __hepta_cb_v6 = h_allocation_error;
#line 14 "/workspace/scratch/0817a147930b/Hepta-work/examples/c_owned_backend/owned.hepta"
uint64_t __hepta_cb_v7 = __hepta_cb_u64_bits((uint64_t)__hepta_cb_v6);
#line 14 "/workspace/scratch/0817a147930b/Hepta-work/examples/c_owned_backend/owned.hepta"
uint64_t __hepta_cb_v8 = __hepta_cb_u64_add(__hepta_cb_v5, __hepta_cb_v7);
#line 14 "/workspace/scratch/0817a147930b/Hepta-work/examples/c_owned_backend/owned.hepta"
return __hepta_cb_v8;
#line 14 "/workspace/scratch/0817a147930b/Hepta-work/examples/c_owned_backend/owned.hepta"
break; }
#line 14 "/workspace/scratch/0817a147930b/Hepta-work/examples/c_owned_backend/owned.hepta"
case 0: {
#line 14 "/workspace/scratch/0817a147930b/Hepta-work/examples/c_owned_backend/owned.hepta"
__hepta_cb_buffer h_bytes = __hepta_cb_v4.payload.v_Ok.f_0;
#line 16 "/workspace/scratch/0817a147930b/Hepta-work/examples/c_owned_backend/owned.hepta"
__hepta_cb_buffer __hepta_cb_v9 = h_bytes;
#line 16 "/workspace/scratch/0817a147930b/Hepta-work/examples/c_owned_backend/owned.hepta"
__hepta_cb_buffer __hepta_cb_v10 = __hepta_cb_v9;
#line 16 "/workspace/scratch/0817a147930b/Hepta-work/examples/c_owned_backend/owned.hepta"
uint64_t __hepta_cb_v11 = (uint64_t)UINT64_C(23);
#line 16 "/workspace/scratch/0817a147930b/Hepta-work/examples/c_owned_backend/owned.hepta"
__hepta_cb_aggregate_2 __hepta_cb_v12 = (__hepta_cb_aggregate_2){ .h_data = __hepta_cb_v10, .h_tag = __hepta_cb_v11 };
#line 16 "/workspace/scratch/0817a147930b/Hepta-work/examples/c_owned_backend/owned.hepta"
__hepta_cb_aggregate_2 __hepta_cb_v13 = __hepta_cb_v12;
#line 16 "/workspace/scratch/0817a147930b/Hepta-work/examples/c_owned_backend/owned.hepta"
bool __hepta_cb_v14 = h_ok;
#line 16 "/workspace/scratch/0817a147930b/Hepta-work/examples/c_owned_backend/owned.hepta"
uint8_t __hepta_cb_v15 = (uint8_t)UINT64_C(19);
#line 16 "/workspace/scratch/0817a147930b/Hepta-work/examples/c_owned_backend/owned.hepta"
__hepta_cb_aggregate_3 __hepta_cb_v16 = __hepta_cb_generic_1_finish(__hepta_cb_v13, __hepta_cb_v14, __hepta_cb_v15);
#line 16 "/workspace/scratch/0817a147930b/Hepta-work/examples/c_owned_backend/owned.hepta"
__hepta_cb_aggregate_3 h_result = __hepta_cb_v16;
#line 17 "/workspace/scratch/0817a147930b/Hepta-work/examples/c_owned_backend/owned.hepta"
__hepta_cb_aggregate_3 __hepta_cb_v17 = h_result;
#line 17 "/workspace/scratch/0817a147930b/Hepta-work/examples/c_owned_backend/owned.hepta"
__hepta_cb_aggregate_3 __hepta_cb_v18 = __hepta_cb_v17;
#line 17 "/workspace/scratch/0817a147930b/Hepta-work/examples/c_owned_backend/owned.hepta"
switch (__hepta_cb_v18.tag) {
#line 17 "/workspace/scratch/0817a147930b/Hepta-work/examples/c_owned_backend/owned.hepta"
case 0: {
#line 17 "/workspace/scratch/0817a147930b/Hepta-work/examples/c_owned_backend/owned.hepta"
__hepta_cb_aggregate_2 h_packet = __hepta_cb_v18.payload.v_Ok.f_0;
#line 19 "/workspace/scratch/0817a147930b/Hepta-work/examples/c_owned_backend/owned.hepta"
const __hepta_cb_buffer * __hepta_cb_arg19 = &((h_packet).h_data);
#line 19 "/workspace/scratch/0817a147930b/Hepta-work/examples/c_owned_backend/owned.hepta"
const __hepta_cb_buffer * __hepta_cb_view20 = __hepta_cb_generic_2_view(__hepta_cb_arg19);
#line 19 "/workspace/scratch/0817a147930b/Hepta-work/examples/c_owned_backend/owned.hepta"
size_t __hepta_cb_v21 = ((*__hepta_cb_view20)).len;
#line 19 "/workspace/scratch/0817a147930b/Hepta-work/examples/c_owned_backend/owned.hepta"
size_t h_observed_size = __hepta_cb_v21;
#line 20 "/workspace/scratch/0817a147930b/Hepta-work/examples/c_owned_backend/owned.hepta"
size_t __hepta_cb_v22 = h_observed_size;
#line 20 "/workspace/scratch/0817a147930b/Hepta-work/examples/c_owned_backend/owned.hepta"
uint64_t __hepta_cb_v23 = __hepta_cb_u64_bits((uint64_t)__hepta_cb_v22);
#line 20 "/workspace/scratch/0817a147930b/Hepta-work/examples/c_owned_backend/owned.hepta"
const __hepta_cb_aggregate_2 * __hepta_cb_arg24 = &(h_packet);
#line 20 "/workspace/scratch/0817a147930b/Hepta-work/examples/c_owned_backend/owned.hepta"
const __hepta_cb_aggregate_2 * __hepta_cb_view25 = __hepta_cb_generic_3_view(__hepta_cb_arg24);
#line 20 "/workspace/scratch/0817a147930b/Hepta-work/examples/c_owned_backend/owned.hepta"
uint64_t __hepta_cb_v26 = ((*__hepta_cb_view25)).h_tag;
#line 20 "/workspace/scratch/0817a147930b/Hepta-work/examples/c_owned_backend/owned.hepta"
uint64_t __hepta_cb_v27 = __hepta_cb_u64_add(__hepta_cb_v23, __hepta_cb_v26);
#line 20 "/workspace/scratch/0817a147930b/Hepta-work/examples/c_owned_backend/owned.hepta"
uint64_t h_answer = __hepta_cb_v27;
#line 21 "/workspace/scratch/0817a147930b/Hepta-work/examples/c_owned_backend/owned.hepta"
__hepta_cb_aggregate_2 __hepta_cb_v28 = h_packet;
#line 21 "/workspace/scratch/0817a147930b/Hepta-work/examples/c_owned_backend/owned.hepta"
__hepta_cb_aggregate_2 __hepta_cb_v29 = __hepta_cb_v28;
#line 21 "/workspace/scratch/0817a147930b/Hepta-work/examples/c_owned_backend/owned.hepta"
__hepta_cb_generic_4_dispose(__hepta_cb_v29);
#line 21 "/workspace/scratch/0817a147930b/Hepta-work/examples/c_owned_backend/owned.hepta"
uint64_t __hepta_cb_v30 = h_answer;
#line 21 "/workspace/scratch/0817a147930b/Hepta-work/examples/c_owned_backend/owned.hepta"
return __hepta_cb_v30;
#line 21 "/workspace/scratch/0817a147930b/Hepta-work/examples/c_owned_backend/owned.hepta"
break; }
#line 21 "/workspace/scratch/0817a147930b/Hepta-work/examples/c_owned_backend/owned.hepta"
case 1: {
#line 21 "/workspace/scratch/0817a147930b/Hepta-work/examples/c_owned_backend/owned.hepta"
uint8_t h_problem = __hepta_cb_v18.payload.v_Err.f_0;
#line 23 "/workspace/scratch/0817a147930b/Hepta-work/examples/c_owned_backend/owned.hepta"
uint8_t __hepta_cb_v31 = h_problem;
#line 23 "/workspace/scratch/0817a147930b/Hepta-work/examples/c_owned_backend/owned.hepta"
uint64_t __hepta_cb_v32 = __hepta_cb_u64_bits((uint64_t)__hepta_cb_v31);
#line 23 "/workspace/scratch/0817a147930b/Hepta-work/examples/c_owned_backend/owned.hepta"
return __hepta_cb_v32;
#line 23 "/workspace/scratch/0817a147930b/Hepta-work/examples/c_owned_backend/owned.hepta"
break; }
#line 23 "/workspace/scratch/0817a147930b/Hepta-work/examples/c_owned_backend/owned.hepta"
default: abort(); }
#line 23 "/workspace/scratch/0817a147930b/Hepta-work/examples/c_owned_backend/owned.hepta"
break; }
#line 23 "/workspace/scratch/0817a147930b/Hepta-work/examples/c_owned_backend/owned.hepta"
default: abort(); }
#line 23 "/workspace/scratch/0817a147930b/Hepta-work/examples/c_owned_backend/owned.hepta"
}
#line 7 "/workspace/scratch/0817a147930b/Hepta-work/examples/c_owned_backend/owned.hepta"
__hepta_cb_aggregate_3 __hepta_cb_generic_1_finish(__hepta_cb_aggregate_2 h_value, bool h_ok, uint8_t h_error) {
#line 8 "/workspace/scratch/0817a147930b/Hepta-work/examples/c_owned_backend/owned.hepta"
bool __hepta_cb_v33 = h_ok;
#line 8 "/workspace/scratch/0817a147930b/Hepta-work/examples/c_owned_backend/owned.hepta"
bool __hepta_cb_v34 = (!__hepta_cb_v33);
#line 8 "/workspace/scratch/0817a147930b/Hepta-work/examples/c_owned_backend/owned.hepta"
if (__hepta_cb_v34) { 
#line 8 "/workspace/scratch/0817a147930b/Hepta-work/examples/c_owned_backend/owned.hepta"
__hepta_cb_aggregate_2 __hepta_cb_v35 = h_value;
#line 8 "/workspace/scratch/0817a147930b/Hepta-work/examples/c_owned_backend/owned.hepta"
__hepta_cb_aggregate_2 __hepta_cb_v36 = __hepta_cb_v35;
#line 8 "/workspace/scratch/0817a147930b/Hepta-work/examples/c_owned_backend/owned.hepta"
__hepta_cb_generic_4_dispose(__hepta_cb_v36);
#line 8 "/workspace/scratch/0817a147930b/Hepta-work/examples/c_owned_backend/owned.hepta"
uint8_t __hepta_cb_v37 = h_error;
#line 8 "/workspace/scratch/0817a147930b/Hepta-work/examples/c_owned_backend/owned.hepta"
__hepta_cb_aggregate_3 __hepta_cb_v38 = (__hepta_cb_aggregate_3){ .tag = 1, .payload.v_Err = { .f_0 = __hepta_cb_v37 } };
#line 8 "/workspace/scratch/0817a147930b/Hepta-work/examples/c_owned_backend/owned.hepta"
return __hepta_cb_v38; } else {  }
#line 9 "/workspace/scratch/0817a147930b/Hepta-work/examples/c_owned_backend/owned.hepta"
__hepta_cb_aggregate_2 __hepta_cb_v39 = h_value;
#line 9 "/workspace/scratch/0817a147930b/Hepta-work/examples/c_owned_backend/owned.hepta"
__hepta_cb_aggregate_2 __hepta_cb_v40 = __hepta_cb_v39;
#line 9 "/workspace/scratch/0817a147930b/Hepta-work/examples/c_owned_backend/owned.hepta"
__hepta_cb_aggregate_2 __hepta_cb_v41 = __hepta_cb_generic_5_forward(__hepta_cb_v40);
#line 9 "/workspace/scratch/0817a147930b/Hepta-work/examples/c_owned_backend/owned.hepta"
__hepta_cb_aggregate_2 __hepta_cb_v42 = __hepta_cb_v41;
#line 9 "/workspace/scratch/0817a147930b/Hepta-work/examples/c_owned_backend/owned.hepta"
__hepta_cb_aggregate_3 __hepta_cb_v43 = (__hepta_cb_aggregate_3){ .tag = 0, .payload.v_Ok = { .f_0 = __hepta_cb_v42 } };
#line 9 "/workspace/scratch/0817a147930b/Hepta-work/examples/c_owned_backend/owned.hepta"
return __hepta_cb_v43;
#line 9 "/workspace/scratch/0817a147930b/Hepta-work/examples/c_owned_backend/owned.hepta"
}
#line 6 "/workspace/scratch/0817a147930b/Hepta-work/examples/c_owned_backend/owned.hepta"
const __hepta_cb_buffer * __hepta_cb_generic_2_view(const __hepta_cb_buffer *h_value) {
#line 6 "/workspace/scratch/0817a147930b/Hepta-work/examples/c_owned_backend/owned.hepta"
return &((*h_value));
#line 6 "/workspace/scratch/0817a147930b/Hepta-work/examples/c_owned_backend/owned.hepta"
}
#line 6 "/workspace/scratch/0817a147930b/Hepta-work/examples/c_owned_backend/owned.hepta"
const __hepta_cb_aggregate_2 * __hepta_cb_generic_3_view(const __hepta_cb_aggregate_2 *h_value) {
#line 6 "/workspace/scratch/0817a147930b/Hepta-work/examples/c_owned_backend/owned.hepta"
return &((*h_value));
#line 6 "/workspace/scratch/0817a147930b/Hepta-work/examples/c_owned_backend/owned.hepta"
}
#line 5 "/workspace/scratch/0817a147930b/Hepta-work/examples/c_owned_backend/owned.hepta"
void __hepta_cb_generic_4_dispose(__hepta_cb_aggregate_2 h_value) {
#line 5 "/workspace/scratch/0817a147930b/Hepta-work/examples/c_owned_backend/owned.hepta"
__hepta_cb_aggregate_2 __hepta_cb_v44 = h_value;
#line 5 "/workspace/scratch/0817a147930b/Hepta-work/examples/c_owned_backend/owned.hepta"
__hepta_cb_aggregate_2 __hepta_cb_v45 = __hepta_cb_v44;
#line 5 "/workspace/scratch/0817a147930b/Hepta-work/examples/c_owned_backend/owned.hepta"
__hepta_cb_drop_0(__hepta_cb_v45);
#line 5 "/workspace/scratch/0817a147930b/Hepta-work/examples/c_owned_backend/owned.hepta"
}
#line 4 "/workspace/scratch/0817a147930b/Hepta-work/examples/c_owned_backend/owned.hepta"
__hepta_cb_aggregate_2 __hepta_cb_generic_5_forward(__hepta_cb_aggregate_2 h_value) {
#line 4 "/workspace/scratch/0817a147930b/Hepta-work/examples/c_owned_backend/owned.hepta"
__hepta_cb_aggregate_2 __hepta_cb_v46 = h_value;
#line 4 "/workspace/scratch/0817a147930b/Hepta-work/examples/c_owned_backend/owned.hepta"
__hepta_cb_aggregate_2 __hepta_cb_v47 = __hepta_cb_v46;
#line 4 "/workspace/scratch/0817a147930b/Hepta-work/examples/c_owned_backend/owned.hepta"
return __hepta_cb_v47;
#line 4 "/workspace/scratch/0817a147930b/Hepta-work/examples/c_owned_backend/owned.hepta"
}

void *__real_calloc(size_t, size_t);
void __real_free(void *);
static size_t allocations=0, frees=0, live=0, refusals=0;
static bool refuse=false;
void *__wrap_calloc(size_t count,size_t size) {
    if (refuse) { refusals++;return NULL; }
    void *p=__real_calloc(count,size);
    if (p) { allocations++;live++; }
    return p;
}
void __wrap_free(void *p) { if (p) { frees++;live--; } __real_free(p); }
int main(void) {
    if (__hepta_cb_fn_probe(7,true)!=30) return 1;
    if (__hepta_cb_fn_probe(13,false)!=19) return 2;
    refuse=true;
    if (__hepta_cb_fn_probe(65519,true)!=1001) return 3;
    refuse=false;
    if (__hepta_cb_fn_probe(17,true)!=40) return 4;
    if (__hepta_cb_fn_probe(SIZE_MAX,true)!=1001) return 5;
    if (__hepta_cb_fn_probe(0,true)!=23) return 6;
    printf("%zu %zu %zu %zu\n",allocations,frees,live,refusals);
    return allocations!=3 || frees!=3 || live!=0 || refusals!=1;
}
