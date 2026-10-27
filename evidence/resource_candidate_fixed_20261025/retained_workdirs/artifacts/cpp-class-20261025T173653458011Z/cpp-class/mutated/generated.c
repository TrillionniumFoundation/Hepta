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
typedef struct { uint32_t h_word; uint64_t h_wide; int32_t h_balance; int64_t h_position; } __hepta_cb_aggregate_0;
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



__hepta_cb_aggregate_0 __hepta_cb_fn_M71e525fea2e87b14_ScalarState_new(uint32_t h_arg0, uint64_t h_arg1, int32_t h_arg2, int64_t h_arg3);
uint32_t __hepta_cb_fn_M71e525fea2e87b14_ScalarState_add_word(__hepta_cb_aggregate_0 *h_receiver, uint32_t h_arg0);
uint64_t __hepta_cb_fn_M71e525fea2e87b14_ScalarState_mix(__hepta_cb_aggregate_0 *h_receiver, uint64_t h_arg0);
int32_t __hepta_cb_fn_M71e525fea2e87b14_ScalarState_clamp_balance(__hepta_cb_aggregate_0 *h_receiver, int32_t h_arg0, int32_t h_arg1);
int64_t __hepta_cb_fn_M71e525fea2e87b14_ScalarState_replace_position(__hepta_cb_aggregate_0 *h_receiver, int64_t h_arg0);
uint32_t __hepta_cb_fn_M71e525fea2e87b14_ScalarState_word_value(const __hepta_cb_aggregate_0 *h_receiver);
uint64_t __hepta_cb_fn_M71e525fea2e87b14_ScalarState_wide_value(const __hepta_cb_aggregate_0 *h_receiver);
int32_t __hepta_cb_fn_M71e525fea2e87b14_ScalarState_balance_value(const __hepta_cb_aggregate_0 *h_receiver);
int64_t __hepta_cb_fn_M71e525fea2e87b14_ScalarState_position_value(const __hepta_cb_aggregate_0 *h_receiver);
void __hepta_cb_fn_M71e525fea2e87b14_ScalarState_set_word(__hepta_cb_aggregate_0 *h_receiver, uint32_t h_arg0);
uint32_t word_trace(uint32_t h_initial, uint32_t h_step, uint32_t h_reset, uint32_t h_last);
uint64_t wide_trace(uint64_t h_initial, uint64_t h_first, uint64_t h_second);
int32_t balance_trace(int32_t h_initial, int32_t h_lower, int32_t h_upper);
int64_t position_trace(int64_t h_initial, int64_t h_next);
int32_t state_guard(uint32_t h_word, uint64_t h_wide, int32_t h_balance, int64_t h_position, uint32_t h_step, uint64_t h_mix, int32_t h_lower, int32_t h_upper, int64_t h_next);
#line 11 "/workspace/scratch/c7c6ee414a6c/hepta-research/artifacts/cpp-class-20261025T173653458011Z/cpp-class/mutated/scalar_state.hepta"
__hepta_cb_aggregate_0 __hepta_cb_fn_M71e525fea2e87b14_ScalarState_new(uint32_t h_arg0, uint64_t h_arg1, int32_t h_arg2, int64_t h_arg3) {
#line 12 "/workspace/scratch/c7c6ee414a6c/hepta-research/artifacts/cpp-class-20261025T173653458011Z/cpp-class/mutated/scalar_state.hepta"
uint32_t __hepta_cb_v1 = h_arg0;
#line 12 "/workspace/scratch/c7c6ee414a6c/hepta-research/artifacts/cpp-class-20261025T173653458011Z/cpp-class/mutated/scalar_state.hepta"
uint64_t __hepta_cb_v2 = h_arg1;
#line 12 "/workspace/scratch/c7c6ee414a6c/hepta-research/artifacts/cpp-class-20261025T173653458011Z/cpp-class/mutated/scalar_state.hepta"
int32_t __hepta_cb_v3 = h_arg2;
#line 12 "/workspace/scratch/c7c6ee414a6c/hepta-research/artifacts/cpp-class-20261025T173653458011Z/cpp-class/mutated/scalar_state.hepta"
int64_t __hepta_cb_v4 = h_arg3;
#line 12 "/workspace/scratch/c7c6ee414a6c/hepta-research/artifacts/cpp-class-20261025T173653458011Z/cpp-class/mutated/scalar_state.hepta"
__hepta_cb_aggregate_0 __hepta_cb_v5 = (__hepta_cb_aggregate_0){ .h_word = __hepta_cb_v1, .h_wide = __hepta_cb_v2, .h_balance = __hepta_cb_v3, .h_position = __hepta_cb_v4 };
#line 12 "/workspace/scratch/c7c6ee414a6c/hepta-research/artifacts/cpp-class-20261025T173653458011Z/cpp-class/mutated/scalar_state.hepta"
return __hepta_cb_v5;
#line 12 "/workspace/scratch/c7c6ee414a6c/hepta-research/artifacts/cpp-class-20261025T173653458011Z/cpp-class/mutated/scalar_state.hepta"
}
#line 15 "/workspace/scratch/c7c6ee414a6c/hepta-research/artifacts/cpp-class-20261025T173653458011Z/cpp-class/mutated/scalar_state.hepta"
uint32_t __hepta_cb_fn_M71e525fea2e87b14_ScalarState_add_word(__hepta_cb_aggregate_0 *h_receiver, uint32_t h_arg0) {
#line 16 "/workspace/scratch/c7c6ee414a6c/hepta-research/artifacts/cpp-class-20261025T173653458011Z/cpp-class/mutated/scalar_state.hepta"
uint32_t __hepta_cb_v6 = ((*h_receiver)).h_word;
#line 16 "/workspace/scratch/c7c6ee414a6c/hepta-research/artifacts/cpp-class-20261025T173653458011Z/cpp-class/mutated/scalar_state.hepta"
uint32_t __hepta_cb_v7 = h_arg0;
#line 16 "/workspace/scratch/c7c6ee414a6c/hepta-research/artifacts/cpp-class-20261025T173653458011Z/cpp-class/mutated/scalar_state.hepta"
uint32_t __hepta_cb_v8 = __hepta_cb_u32_wrapping_add(__hepta_cb_v6, __hepta_cb_v7);
#line 16 "/workspace/scratch/c7c6ee414a6c/hepta-research/artifacts/cpp-class-20261025T173653458011Z/cpp-class/mutated/scalar_state.hepta"
((*h_receiver)).h_word = __hepta_cb_v8;
#line 17 "/workspace/scratch/c7c6ee414a6c/hepta-research/artifacts/cpp-class-20261025T173653458011Z/cpp-class/mutated/scalar_state.hepta"
uint32_t __hepta_cb_v9 = ((*h_receiver)).h_word;
#line 17 "/workspace/scratch/c7c6ee414a6c/hepta-research/artifacts/cpp-class-20261025T173653458011Z/cpp-class/mutated/scalar_state.hepta"
uint32_t __hepta_cb_v10 = (uint32_t)UINT64_C(1);
#line 17 "/workspace/scratch/c7c6ee414a6c/hepta-research/artifacts/cpp-class-20261025T173653458011Z/cpp-class/mutated/scalar_state.hepta"
uint32_t __hepta_cb_v11 = __hepta_cb_u32_wrapping_add(__hepta_cb_v9, __hepta_cb_v10);
#line 17 "/workspace/scratch/c7c6ee414a6c/hepta-research/artifacts/cpp-class-20261025T173653458011Z/cpp-class/mutated/scalar_state.hepta"
return __hepta_cb_v11;
#line 17 "/workspace/scratch/c7c6ee414a6c/hepta-research/artifacts/cpp-class-20261025T173653458011Z/cpp-class/mutated/scalar_state.hepta"
}
#line 20 "/workspace/scratch/c7c6ee414a6c/hepta-research/artifacts/cpp-class-20261025T173653458011Z/cpp-class/mutated/scalar_state.hepta"
uint64_t __hepta_cb_fn_M71e525fea2e87b14_ScalarState_mix(__hepta_cb_aggregate_0 *h_receiver, uint64_t h_arg0) {
#line 21 "/workspace/scratch/c7c6ee414a6c/hepta-research/artifacts/cpp-class-20261025T173653458011Z/cpp-class/mutated/scalar_state.hepta"
uint64_t __hepta_cb_v12 = ((*h_receiver)).h_wide;
#line 21 "/workspace/scratch/c7c6ee414a6c/hepta-research/artifacts/cpp-class-20261025T173653458011Z/cpp-class/mutated/scalar_state.hepta"
uint64_t __hepta_cb_v13 = h_arg0;
#line 21 "/workspace/scratch/c7c6ee414a6c/hepta-research/artifacts/cpp-class-20261025T173653458011Z/cpp-class/mutated/scalar_state.hepta"
uint64_t __hepta_cb_v14 = __hepta_cb_u64_xor(__hepta_cb_v12, __hepta_cb_v13);
#line 21 "/workspace/scratch/c7c6ee414a6c/hepta-research/artifacts/cpp-class-20261025T173653458011Z/cpp-class/mutated/scalar_state.hepta"
uint64_t __hepta_cb_v15 = (uint64_t)UINT64_C(1);
#line 21 "/workspace/scratch/c7c6ee414a6c/hepta-research/artifacts/cpp-class-20261025T173653458011Z/cpp-class/mutated/scalar_state.hepta"
uint64_t __hepta_cb_v16 = __hepta_cb_u64_wrapping_add(__hepta_cb_v14, __hepta_cb_v15);
#line 21 "/workspace/scratch/c7c6ee414a6c/hepta-research/artifacts/cpp-class-20261025T173653458011Z/cpp-class/mutated/scalar_state.hepta"
((*h_receiver)).h_wide = __hepta_cb_v16;
#line 22 "/workspace/scratch/c7c6ee414a6c/hepta-research/artifacts/cpp-class-20261025T173653458011Z/cpp-class/mutated/scalar_state.hepta"
uint64_t __hepta_cb_v17 = ((*h_receiver)).h_wide;
#line 22 "/workspace/scratch/c7c6ee414a6c/hepta-research/artifacts/cpp-class-20261025T173653458011Z/cpp-class/mutated/scalar_state.hepta"
return __hepta_cb_v17;
#line 22 "/workspace/scratch/c7c6ee414a6c/hepta-research/artifacts/cpp-class-20261025T173653458011Z/cpp-class/mutated/scalar_state.hepta"
}
#line 25 "/workspace/scratch/c7c6ee414a6c/hepta-research/artifacts/cpp-class-20261025T173653458011Z/cpp-class/mutated/scalar_state.hepta"
int32_t __hepta_cb_fn_M71e525fea2e87b14_ScalarState_clamp_balance(__hepta_cb_aggregate_0 *h_receiver, int32_t h_arg0, int32_t h_arg1) {
#line 26 "/workspace/scratch/c7c6ee414a6c/hepta-research/artifacts/cpp-class-20261025T173653458011Z/cpp-class/mutated/scalar_state.hepta"
int32_t __hepta_cb_v18 = ((*h_receiver)).h_balance;
#line 26 "/workspace/scratch/c7c6ee414a6c/hepta-research/artifacts/cpp-class-20261025T173653458011Z/cpp-class/mutated/scalar_state.hepta"
int32_t __hepta_cb_v19 = h_arg0;
#line 26 "/workspace/scratch/c7c6ee414a6c/hepta-research/artifacts/cpp-class-20261025T173653458011Z/cpp-class/mutated/scalar_state.hepta"
bool __hepta_cb_v20 = (__hepta_cb_v18 < __hepta_cb_v19);
#line 26 "/workspace/scratch/c7c6ee414a6c/hepta-research/artifacts/cpp-class-20261025T173653458011Z/cpp-class/mutated/scalar_state.hepta"
if (__hepta_cb_v20) { 
#line 27 "/workspace/scratch/c7c6ee414a6c/hepta-research/artifacts/cpp-class-20261025T173653458011Z/cpp-class/mutated/scalar_state.hepta"
int32_t __hepta_cb_v21 = h_arg0;
#line 27 "/workspace/scratch/c7c6ee414a6c/hepta-research/artifacts/cpp-class-20261025T173653458011Z/cpp-class/mutated/scalar_state.hepta"
((*h_receiver)).h_balance = __hepta_cb_v21; } else { 
#line 30 "/workspace/scratch/c7c6ee414a6c/hepta-research/artifacts/cpp-class-20261025T173653458011Z/cpp-class/mutated/scalar_state.hepta"
int32_t __hepta_cb_v22 = ((*h_receiver)).h_balance;
#line 30 "/workspace/scratch/c7c6ee414a6c/hepta-research/artifacts/cpp-class-20261025T173653458011Z/cpp-class/mutated/scalar_state.hepta"
int32_t __hepta_cb_v23 = h_arg1;
#line 30 "/workspace/scratch/c7c6ee414a6c/hepta-research/artifacts/cpp-class-20261025T173653458011Z/cpp-class/mutated/scalar_state.hepta"
bool __hepta_cb_v24 = (__hepta_cb_v22 > __hepta_cb_v23);
#line 30 "/workspace/scratch/c7c6ee414a6c/hepta-research/artifacts/cpp-class-20261025T173653458011Z/cpp-class/mutated/scalar_state.hepta"
if (__hepta_cb_v24) { 
#line 31 "/workspace/scratch/c7c6ee414a6c/hepta-research/artifacts/cpp-class-20261025T173653458011Z/cpp-class/mutated/scalar_state.hepta"
int32_t __hepta_cb_v25 = h_arg1;
#line 31 "/workspace/scratch/c7c6ee414a6c/hepta-research/artifacts/cpp-class-20261025T173653458011Z/cpp-class/mutated/scalar_state.hepta"
((*h_receiver)).h_balance = __hepta_cb_v25; } else {  } }
#line 34 "/workspace/scratch/c7c6ee414a6c/hepta-research/artifacts/cpp-class-20261025T173653458011Z/cpp-class/mutated/scalar_state.hepta"
int32_t __hepta_cb_v26 = ((*h_receiver)).h_balance;
#line 34 "/workspace/scratch/c7c6ee414a6c/hepta-research/artifacts/cpp-class-20261025T173653458011Z/cpp-class/mutated/scalar_state.hepta"
return __hepta_cb_v26;
#line 34 "/workspace/scratch/c7c6ee414a6c/hepta-research/artifacts/cpp-class-20261025T173653458011Z/cpp-class/mutated/scalar_state.hepta"
}
#line 37 "/workspace/scratch/c7c6ee414a6c/hepta-research/artifacts/cpp-class-20261025T173653458011Z/cpp-class/mutated/scalar_state.hepta"
int64_t __hepta_cb_fn_M71e525fea2e87b14_ScalarState_replace_position(__hepta_cb_aggregate_0 *h_receiver, int64_t h_arg0) {
#line 38 "/workspace/scratch/c7c6ee414a6c/hepta-research/artifacts/cpp-class-20261025T173653458011Z/cpp-class/mutated/scalar_state.hepta"
int64_t __hepta_cb_v27 = h_arg0;
#line 38 "/workspace/scratch/c7c6ee414a6c/hepta-research/artifacts/cpp-class-20261025T173653458011Z/cpp-class/mutated/scalar_state.hepta"
((*h_receiver)).h_position = __hepta_cb_v27;
#line 39 "/workspace/scratch/c7c6ee414a6c/hepta-research/artifacts/cpp-class-20261025T173653458011Z/cpp-class/mutated/scalar_state.hepta"
int64_t __hepta_cb_v28 = ((*h_receiver)).h_position;
#line 39 "/workspace/scratch/c7c6ee414a6c/hepta-research/artifacts/cpp-class-20261025T173653458011Z/cpp-class/mutated/scalar_state.hepta"
return __hepta_cb_v28;
#line 39 "/workspace/scratch/c7c6ee414a6c/hepta-research/artifacts/cpp-class-20261025T173653458011Z/cpp-class/mutated/scalar_state.hepta"
}
#line 42 "/workspace/scratch/c7c6ee414a6c/hepta-research/artifacts/cpp-class-20261025T173653458011Z/cpp-class/mutated/scalar_state.hepta"
uint32_t __hepta_cb_fn_M71e525fea2e87b14_ScalarState_word_value(const __hepta_cb_aggregate_0 *h_receiver) {
#line 43 "/workspace/scratch/c7c6ee414a6c/hepta-research/artifacts/cpp-class-20261025T173653458011Z/cpp-class/mutated/scalar_state.hepta"
uint32_t __hepta_cb_v29 = ((*h_receiver)).h_word;
#line 43 "/workspace/scratch/c7c6ee414a6c/hepta-research/artifacts/cpp-class-20261025T173653458011Z/cpp-class/mutated/scalar_state.hepta"
return __hepta_cb_v29;
#line 43 "/workspace/scratch/c7c6ee414a6c/hepta-research/artifacts/cpp-class-20261025T173653458011Z/cpp-class/mutated/scalar_state.hepta"
}
#line 46 "/workspace/scratch/c7c6ee414a6c/hepta-research/artifacts/cpp-class-20261025T173653458011Z/cpp-class/mutated/scalar_state.hepta"
uint64_t __hepta_cb_fn_M71e525fea2e87b14_ScalarState_wide_value(const __hepta_cb_aggregate_0 *h_receiver) {
#line 47 "/workspace/scratch/c7c6ee414a6c/hepta-research/artifacts/cpp-class-20261025T173653458011Z/cpp-class/mutated/scalar_state.hepta"
uint64_t __hepta_cb_v30 = ((*h_receiver)).h_wide;
#line 47 "/workspace/scratch/c7c6ee414a6c/hepta-research/artifacts/cpp-class-20261025T173653458011Z/cpp-class/mutated/scalar_state.hepta"
return __hepta_cb_v30;
#line 47 "/workspace/scratch/c7c6ee414a6c/hepta-research/artifacts/cpp-class-20261025T173653458011Z/cpp-class/mutated/scalar_state.hepta"
}
#line 50 "/workspace/scratch/c7c6ee414a6c/hepta-research/artifacts/cpp-class-20261025T173653458011Z/cpp-class/mutated/scalar_state.hepta"
int32_t __hepta_cb_fn_M71e525fea2e87b14_ScalarState_balance_value(const __hepta_cb_aggregate_0 *h_receiver) {
#line 51 "/workspace/scratch/c7c6ee414a6c/hepta-research/artifacts/cpp-class-20261025T173653458011Z/cpp-class/mutated/scalar_state.hepta"
int32_t __hepta_cb_v31 = ((*h_receiver)).h_balance;
#line 51 "/workspace/scratch/c7c6ee414a6c/hepta-research/artifacts/cpp-class-20261025T173653458011Z/cpp-class/mutated/scalar_state.hepta"
return __hepta_cb_v31;
#line 51 "/workspace/scratch/c7c6ee414a6c/hepta-research/artifacts/cpp-class-20261025T173653458011Z/cpp-class/mutated/scalar_state.hepta"
}
#line 54 "/workspace/scratch/c7c6ee414a6c/hepta-research/artifacts/cpp-class-20261025T173653458011Z/cpp-class/mutated/scalar_state.hepta"
int64_t __hepta_cb_fn_M71e525fea2e87b14_ScalarState_position_value(const __hepta_cb_aggregate_0 *h_receiver) {
#line 55 "/workspace/scratch/c7c6ee414a6c/hepta-research/artifacts/cpp-class-20261025T173653458011Z/cpp-class/mutated/scalar_state.hepta"
int64_t __hepta_cb_v32 = ((*h_receiver)).h_position;
#line 55 "/workspace/scratch/c7c6ee414a6c/hepta-research/artifacts/cpp-class-20261025T173653458011Z/cpp-class/mutated/scalar_state.hepta"
return __hepta_cb_v32;
#line 55 "/workspace/scratch/c7c6ee414a6c/hepta-research/artifacts/cpp-class-20261025T173653458011Z/cpp-class/mutated/scalar_state.hepta"
}
#line 58 "/workspace/scratch/c7c6ee414a6c/hepta-research/artifacts/cpp-class-20261025T173653458011Z/cpp-class/mutated/scalar_state.hepta"
void __hepta_cb_fn_M71e525fea2e87b14_ScalarState_set_word(__hepta_cb_aggregate_0 *h_receiver, uint32_t h_arg0) {
#line 59 "/workspace/scratch/c7c6ee414a6c/hepta-research/artifacts/cpp-class-20261025T173653458011Z/cpp-class/mutated/scalar_state.hepta"
uint32_t __hepta_cb_v33 = h_arg0;
#line 59 "/workspace/scratch/c7c6ee414a6c/hepta-research/artifacts/cpp-class-20261025T173653458011Z/cpp-class/mutated/scalar_state.hepta"
((*h_receiver)).h_word = __hepta_cb_v33;
#line 59 "/workspace/scratch/c7c6ee414a6c/hepta-research/artifacts/cpp-class-20261025T173653458011Z/cpp-class/mutated/scalar_state.hepta"
}
#line 4 "/workspace/scratch/c7c6ee414a6c/hepta-research/artifacts/cpp-class-20261025T173653458011Z/cpp-class/mutated/consumer.hepta"
uint32_t word_trace(uint32_t h_initial, uint32_t h_step, uint32_t h_reset, uint32_t h_last) {
#line 5 "/workspace/scratch/c7c6ee414a6c/hepta-research/artifacts/cpp-class-20261025T173653458011Z/cpp-class/mutated/consumer.hepta"
uint32_t __hepta_cb_v34 = h_initial;
#line 5 "/workspace/scratch/c7c6ee414a6c/hepta-research/artifacts/cpp-class-20261025T173653458011Z/cpp-class/mutated/consumer.hepta"
uint64_t __hepta_cb_v35 = (uint64_t)UINT64_C(0);
#line 5 "/workspace/scratch/c7c6ee414a6c/hepta-research/artifacts/cpp-class-20261025T173653458011Z/cpp-class/mutated/consumer.hepta"
int32_t __hepta_cb_v36 = (int32_t)INT64_C(0);
#line 5 "/workspace/scratch/c7c6ee414a6c/hepta-research/artifacts/cpp-class-20261025T173653458011Z/cpp-class/mutated/consumer.hepta"
int64_t __hepta_cb_v37 = (int64_t)INT64_C(0);
#line 5 "/workspace/scratch/c7c6ee414a6c/hepta-research/artifacts/cpp-class-20261025T173653458011Z/cpp-class/mutated/consumer.hepta"
__hepta_cb_aggregate_0 __hepta_cb_v38 = __hepta_cb_fn_M71e525fea2e87b14_ScalarState_new(__hepta_cb_v34, __hepta_cb_v35, __hepta_cb_v36, __hepta_cb_v37);
#line 5 "/workspace/scratch/c7c6ee414a6c/hepta-research/artifacts/cpp-class-20261025T173653458011Z/cpp-class/mutated/consumer.hepta"
__hepta_cb_aggregate_0 h_state = __hepta_cb_v38;
#line 6 "/workspace/scratch/c7c6ee414a6c/hepta-research/artifacts/cpp-class-20261025T173653458011Z/cpp-class/mutated/consumer.hepta"
__hepta_cb_aggregate_0 __hepta_cb_v39 = h_state;
#line 6 "/workspace/scratch/c7c6ee414a6c/hepta-research/artifacts/cpp-class-20261025T173653458011Z/cpp-class/mutated/consumer.hepta"
__hepta_cb_aggregate_0 h_snapshot = __hepta_cb_v39;
#line 7 "/workspace/scratch/c7c6ee414a6c/hepta-research/artifacts/cpp-class-20261025T173653458011Z/cpp-class/mutated/consumer.hepta"
__hepta_cb_aggregate_0 * __hepta_cb_arg40 = &(h_state);
#line 7 "/workspace/scratch/c7c6ee414a6c/hepta-research/artifacts/cpp-class-20261025T173653458011Z/cpp-class/mutated/consumer.hepta"
uint32_t __hepta_cb_v41 = h_step;
#line 7 "/workspace/scratch/c7c6ee414a6c/hepta-research/artifacts/cpp-class-20261025T173653458011Z/cpp-class/mutated/consumer.hepta"
uint32_t __hepta_cb_v42 = __hepta_cb_fn_M71e525fea2e87b14_ScalarState_add_word(__hepta_cb_arg40, __hepta_cb_v41);
#line 7 "/workspace/scratch/c7c6ee414a6c/hepta-research/artifacts/cpp-class-20261025T173653458011Z/cpp-class/mutated/consumer.hepta"
uint32_t h_first = __hepta_cb_v42;
#line 8 "/workspace/scratch/c7c6ee414a6c/hepta-research/artifacts/cpp-class-20261025T173653458011Z/cpp-class/mutated/consumer.hepta"
__hepta_cb_aggregate_0 * __hepta_cb_arg43 = &(h_state);
#line 8 "/workspace/scratch/c7c6ee414a6c/hepta-research/artifacts/cpp-class-20261025T173653458011Z/cpp-class/mutated/consumer.hepta"
uint32_t __hepta_cb_v44 = h_reset;
#line 8 "/workspace/scratch/c7c6ee414a6c/hepta-research/artifacts/cpp-class-20261025T173653458011Z/cpp-class/mutated/consumer.hepta"
__hepta_cb_fn_M71e525fea2e87b14_ScalarState_set_word(__hepta_cb_arg43, __hepta_cb_v44);
#line 9 "/workspace/scratch/c7c6ee414a6c/hepta-research/artifacts/cpp-class-20261025T173653458011Z/cpp-class/mutated/consumer.hepta"
__hepta_cb_aggregate_0 * __hepta_cb_arg45 = &(h_state);
#line 9 "/workspace/scratch/c7c6ee414a6c/hepta-research/artifacts/cpp-class-20261025T173653458011Z/cpp-class/mutated/consumer.hepta"
uint32_t __hepta_cb_v46 = h_last;
#line 9 "/workspace/scratch/c7c6ee414a6c/hepta-research/artifacts/cpp-class-20261025T173653458011Z/cpp-class/mutated/consumer.hepta"
uint32_t __hepta_cb_v47 = __hepta_cb_fn_M71e525fea2e87b14_ScalarState_add_word(__hepta_cb_arg45, __hepta_cb_v46);
#line 9 "/workspace/scratch/c7c6ee414a6c/hepta-research/artifacts/cpp-class-20261025T173653458011Z/cpp-class/mutated/consumer.hepta"
uint32_t h_final = __hepta_cb_v47;
#line 10 "/workspace/scratch/c7c6ee414a6c/hepta-research/artifacts/cpp-class-20261025T173653458011Z/cpp-class/mutated/consumer.hepta"
uint32_t __hepta_cb_v48 = h_first;
#line 10 "/workspace/scratch/c7c6ee414a6c/hepta-research/artifacts/cpp-class-20261025T173653458011Z/cpp-class/mutated/consumer.hepta"
uint32_t __hepta_cb_v49 = h_final;
#line 10 "/workspace/scratch/c7c6ee414a6c/hepta-research/artifacts/cpp-class-20261025T173653458011Z/cpp-class/mutated/consumer.hepta"
uint32_t __hepta_cb_v50 = __hepta_cb_u32_xor(__hepta_cb_v48, __hepta_cb_v49);
#line 10 "/workspace/scratch/c7c6ee414a6c/hepta-research/artifacts/cpp-class-20261025T173653458011Z/cpp-class/mutated/consumer.hepta"
const __hepta_cb_aggregate_0 * __hepta_cb_arg51 = &(h_snapshot);
#line 10 "/workspace/scratch/c7c6ee414a6c/hepta-research/artifacts/cpp-class-20261025T173653458011Z/cpp-class/mutated/consumer.hepta"
uint32_t __hepta_cb_v52 = __hepta_cb_fn_M71e525fea2e87b14_ScalarState_word_value(__hepta_cb_arg51);
#line 10 "/workspace/scratch/c7c6ee414a6c/hepta-research/artifacts/cpp-class-20261025T173653458011Z/cpp-class/mutated/consumer.hepta"
uint32_t __hepta_cb_v53 = __hepta_cb_u32_xor(__hepta_cb_v50, __hepta_cb_v52);
#line 10 "/workspace/scratch/c7c6ee414a6c/hepta-research/artifacts/cpp-class-20261025T173653458011Z/cpp-class/mutated/consumer.hepta"
return __hepta_cb_v53;
#line 10 "/workspace/scratch/c7c6ee414a6c/hepta-research/artifacts/cpp-class-20261025T173653458011Z/cpp-class/mutated/consumer.hepta"
}
#line 13 "/workspace/scratch/c7c6ee414a6c/hepta-research/artifacts/cpp-class-20261025T173653458011Z/cpp-class/mutated/consumer.hepta"
uint64_t wide_trace(uint64_t h_initial, uint64_t h_first, uint64_t h_second) {
#line 14 "/workspace/scratch/c7c6ee414a6c/hepta-research/artifacts/cpp-class-20261025T173653458011Z/cpp-class/mutated/consumer.hepta"
uint32_t __hepta_cb_v54 = (uint32_t)UINT64_C(0);
#line 14 "/workspace/scratch/c7c6ee414a6c/hepta-research/artifacts/cpp-class-20261025T173653458011Z/cpp-class/mutated/consumer.hepta"
uint64_t __hepta_cb_v55 = h_initial;
#line 14 "/workspace/scratch/c7c6ee414a6c/hepta-research/artifacts/cpp-class-20261025T173653458011Z/cpp-class/mutated/consumer.hepta"
int32_t __hepta_cb_v56 = (int32_t)INT64_C(0);
#line 14 "/workspace/scratch/c7c6ee414a6c/hepta-research/artifacts/cpp-class-20261025T173653458011Z/cpp-class/mutated/consumer.hepta"
int64_t __hepta_cb_v57 = (int64_t)INT64_C(0);
#line 14 "/workspace/scratch/c7c6ee414a6c/hepta-research/artifacts/cpp-class-20261025T173653458011Z/cpp-class/mutated/consumer.hepta"
__hepta_cb_aggregate_0 __hepta_cb_v58 = __hepta_cb_fn_M71e525fea2e87b14_ScalarState_new(__hepta_cb_v54, __hepta_cb_v55, __hepta_cb_v56, __hepta_cb_v57);
#line 14 "/workspace/scratch/c7c6ee414a6c/hepta-research/artifacts/cpp-class-20261025T173653458011Z/cpp-class/mutated/consumer.hepta"
__hepta_cb_aggregate_0 h_state = __hepta_cb_v58;
#line 15 "/workspace/scratch/c7c6ee414a6c/hepta-research/artifacts/cpp-class-20261025T173653458011Z/cpp-class/mutated/consumer.hepta"
__hepta_cb_aggregate_0 __hepta_cb_v59 = h_state;
#line 15 "/workspace/scratch/c7c6ee414a6c/hepta-research/artifacts/cpp-class-20261025T173653458011Z/cpp-class/mutated/consumer.hepta"
__hepta_cb_aggregate_0 h_snapshot = __hepta_cb_v59;
#line 16 "/workspace/scratch/c7c6ee414a6c/hepta-research/artifacts/cpp-class-20261025T173653458011Z/cpp-class/mutated/consumer.hepta"
__hepta_cb_aggregate_0 * __hepta_cb_arg60 = &(h_state);
#line 16 "/workspace/scratch/c7c6ee414a6c/hepta-research/artifacts/cpp-class-20261025T173653458011Z/cpp-class/mutated/consumer.hepta"
uint64_t __hepta_cb_v61 = h_first;
#line 16 "/workspace/scratch/c7c6ee414a6c/hepta-research/artifacts/cpp-class-20261025T173653458011Z/cpp-class/mutated/consumer.hepta"
uint64_t __hepta_cb_v62 = __hepta_cb_fn_M71e525fea2e87b14_ScalarState_mix(__hepta_cb_arg60, __hepta_cb_v61);
#line 16 "/workspace/scratch/c7c6ee414a6c/hepta-research/artifacts/cpp-class-20261025T173653458011Z/cpp-class/mutated/consumer.hepta"
uint64_t h_a = __hepta_cb_v62;
#line 17 "/workspace/scratch/c7c6ee414a6c/hepta-research/artifacts/cpp-class-20261025T173653458011Z/cpp-class/mutated/consumer.hepta"
__hepta_cb_aggregate_0 * __hepta_cb_arg63 = &(h_state);
#line 17 "/workspace/scratch/c7c6ee414a6c/hepta-research/artifacts/cpp-class-20261025T173653458011Z/cpp-class/mutated/consumer.hepta"
uint64_t __hepta_cb_v64 = h_second;
#line 17 "/workspace/scratch/c7c6ee414a6c/hepta-research/artifacts/cpp-class-20261025T173653458011Z/cpp-class/mutated/consumer.hepta"
uint64_t __hepta_cb_v65 = __hepta_cb_fn_M71e525fea2e87b14_ScalarState_mix(__hepta_cb_arg63, __hepta_cb_v64);
#line 17 "/workspace/scratch/c7c6ee414a6c/hepta-research/artifacts/cpp-class-20261025T173653458011Z/cpp-class/mutated/consumer.hepta"
uint64_t h_b = __hepta_cb_v65;
#line 18 "/workspace/scratch/c7c6ee414a6c/hepta-research/artifacts/cpp-class-20261025T173653458011Z/cpp-class/mutated/consumer.hepta"
uint64_t __hepta_cb_v66 = h_a;
#line 18 "/workspace/scratch/c7c6ee414a6c/hepta-research/artifacts/cpp-class-20261025T173653458011Z/cpp-class/mutated/consumer.hepta"
uint64_t __hepta_cb_v67 = h_b;
#line 18 "/workspace/scratch/c7c6ee414a6c/hepta-research/artifacts/cpp-class-20261025T173653458011Z/cpp-class/mutated/consumer.hepta"
uint64_t __hepta_cb_v68 = __hepta_cb_u64_xor(__hepta_cb_v66, __hepta_cb_v67);
#line 18 "/workspace/scratch/c7c6ee414a6c/hepta-research/artifacts/cpp-class-20261025T173653458011Z/cpp-class/mutated/consumer.hepta"
const __hepta_cb_aggregate_0 * __hepta_cb_arg69 = &(h_snapshot);
#line 18 "/workspace/scratch/c7c6ee414a6c/hepta-research/artifacts/cpp-class-20261025T173653458011Z/cpp-class/mutated/consumer.hepta"
uint64_t __hepta_cb_v70 = __hepta_cb_fn_M71e525fea2e87b14_ScalarState_wide_value(__hepta_cb_arg69);
#line 18 "/workspace/scratch/c7c6ee414a6c/hepta-research/artifacts/cpp-class-20261025T173653458011Z/cpp-class/mutated/consumer.hepta"
uint64_t __hepta_cb_v71 = __hepta_cb_u64_xor(__hepta_cb_v68, __hepta_cb_v70);
#line 18 "/workspace/scratch/c7c6ee414a6c/hepta-research/artifacts/cpp-class-20261025T173653458011Z/cpp-class/mutated/consumer.hepta"
return __hepta_cb_v71;
#line 18 "/workspace/scratch/c7c6ee414a6c/hepta-research/artifacts/cpp-class-20261025T173653458011Z/cpp-class/mutated/consumer.hepta"
}
#line 21 "/workspace/scratch/c7c6ee414a6c/hepta-research/artifacts/cpp-class-20261025T173653458011Z/cpp-class/mutated/consumer.hepta"
int32_t balance_trace(int32_t h_initial, int32_t h_lower, int32_t h_upper) {
#line 22 "/workspace/scratch/c7c6ee414a6c/hepta-research/artifacts/cpp-class-20261025T173653458011Z/cpp-class/mutated/consumer.hepta"
uint32_t __hepta_cb_v72 = (uint32_t)UINT64_C(0);
#line 22 "/workspace/scratch/c7c6ee414a6c/hepta-research/artifacts/cpp-class-20261025T173653458011Z/cpp-class/mutated/consumer.hepta"
uint64_t __hepta_cb_v73 = (uint64_t)UINT64_C(0);
#line 22 "/workspace/scratch/c7c6ee414a6c/hepta-research/artifacts/cpp-class-20261025T173653458011Z/cpp-class/mutated/consumer.hepta"
int32_t __hepta_cb_v74 = h_initial;
#line 22 "/workspace/scratch/c7c6ee414a6c/hepta-research/artifacts/cpp-class-20261025T173653458011Z/cpp-class/mutated/consumer.hepta"
int64_t __hepta_cb_v75 = (int64_t)INT64_C(0);
#line 22 "/workspace/scratch/c7c6ee414a6c/hepta-research/artifacts/cpp-class-20261025T173653458011Z/cpp-class/mutated/consumer.hepta"
__hepta_cb_aggregate_0 __hepta_cb_v76 = __hepta_cb_fn_M71e525fea2e87b14_ScalarState_new(__hepta_cb_v72, __hepta_cb_v73, __hepta_cb_v74, __hepta_cb_v75);
#line 22 "/workspace/scratch/c7c6ee414a6c/hepta-research/artifacts/cpp-class-20261025T173653458011Z/cpp-class/mutated/consumer.hepta"
__hepta_cb_aggregate_0 h_state = __hepta_cb_v76;
#line 23 "/workspace/scratch/c7c6ee414a6c/hepta-research/artifacts/cpp-class-20261025T173653458011Z/cpp-class/mutated/consumer.hepta"
__hepta_cb_aggregate_0 * __hepta_cb_arg77 = &(h_state);
#line 23 "/workspace/scratch/c7c6ee414a6c/hepta-research/artifacts/cpp-class-20261025T173653458011Z/cpp-class/mutated/consumer.hepta"
int32_t __hepta_cb_v78 = h_lower;
#line 23 "/workspace/scratch/c7c6ee414a6c/hepta-research/artifacts/cpp-class-20261025T173653458011Z/cpp-class/mutated/consumer.hepta"
int32_t __hepta_cb_v79 = h_upper;
#line 23 "/workspace/scratch/c7c6ee414a6c/hepta-research/artifacts/cpp-class-20261025T173653458011Z/cpp-class/mutated/consumer.hepta"
int32_t __hepta_cb_v80 = __hepta_cb_fn_M71e525fea2e87b14_ScalarState_clamp_balance(__hepta_cb_arg77, __hepta_cb_v78, __hepta_cb_v79);
#line 24 "/workspace/scratch/c7c6ee414a6c/hepta-research/artifacts/cpp-class-20261025T173653458011Z/cpp-class/mutated/consumer.hepta"
const __hepta_cb_aggregate_0 * __hepta_cb_arg81 = &(h_state);
#line 24 "/workspace/scratch/c7c6ee414a6c/hepta-research/artifacts/cpp-class-20261025T173653458011Z/cpp-class/mutated/consumer.hepta"
int32_t __hepta_cb_v82 = __hepta_cb_fn_M71e525fea2e87b14_ScalarState_balance_value(__hepta_cb_arg81);
#line 24 "/workspace/scratch/c7c6ee414a6c/hepta-research/artifacts/cpp-class-20261025T173653458011Z/cpp-class/mutated/consumer.hepta"
return __hepta_cb_v82;
#line 24 "/workspace/scratch/c7c6ee414a6c/hepta-research/artifacts/cpp-class-20261025T173653458011Z/cpp-class/mutated/consumer.hepta"
}
#line 27 "/workspace/scratch/c7c6ee414a6c/hepta-research/artifacts/cpp-class-20261025T173653458011Z/cpp-class/mutated/consumer.hepta"
int64_t position_trace(int64_t h_initial, int64_t h_next) {
#line 28 "/workspace/scratch/c7c6ee414a6c/hepta-research/artifacts/cpp-class-20261025T173653458011Z/cpp-class/mutated/consumer.hepta"
uint32_t __hepta_cb_v83 = (uint32_t)UINT64_C(0);
#line 28 "/workspace/scratch/c7c6ee414a6c/hepta-research/artifacts/cpp-class-20261025T173653458011Z/cpp-class/mutated/consumer.hepta"
uint64_t __hepta_cb_v84 = (uint64_t)UINT64_C(0);
#line 28 "/workspace/scratch/c7c6ee414a6c/hepta-research/artifacts/cpp-class-20261025T173653458011Z/cpp-class/mutated/consumer.hepta"
int32_t __hepta_cb_v85 = (int32_t)INT64_C(0);
#line 28 "/workspace/scratch/c7c6ee414a6c/hepta-research/artifacts/cpp-class-20261025T173653458011Z/cpp-class/mutated/consumer.hepta"
int64_t __hepta_cb_v86 = h_initial;
#line 28 "/workspace/scratch/c7c6ee414a6c/hepta-research/artifacts/cpp-class-20261025T173653458011Z/cpp-class/mutated/consumer.hepta"
__hepta_cb_aggregate_0 __hepta_cb_v87 = __hepta_cb_fn_M71e525fea2e87b14_ScalarState_new(__hepta_cb_v83, __hepta_cb_v84, __hepta_cb_v85, __hepta_cb_v86);
#line 28 "/workspace/scratch/c7c6ee414a6c/hepta-research/artifacts/cpp-class-20261025T173653458011Z/cpp-class/mutated/consumer.hepta"
__hepta_cb_aggregate_0 h_state = __hepta_cb_v87;
#line 29 "/workspace/scratch/c7c6ee414a6c/hepta-research/artifacts/cpp-class-20261025T173653458011Z/cpp-class/mutated/consumer.hepta"
__hepta_cb_aggregate_0 * __hepta_cb_arg88 = &(h_state);
#line 29 "/workspace/scratch/c7c6ee414a6c/hepta-research/artifacts/cpp-class-20261025T173653458011Z/cpp-class/mutated/consumer.hepta"
int64_t __hepta_cb_v89 = h_next;
#line 29 "/workspace/scratch/c7c6ee414a6c/hepta-research/artifacts/cpp-class-20261025T173653458011Z/cpp-class/mutated/consumer.hepta"
int64_t __hepta_cb_v90 = __hepta_cb_fn_M71e525fea2e87b14_ScalarState_replace_position(__hepta_cb_arg88, __hepta_cb_v89);
#line 30 "/workspace/scratch/c7c6ee414a6c/hepta-research/artifacts/cpp-class-20261025T173653458011Z/cpp-class/mutated/consumer.hepta"
const __hepta_cb_aggregate_0 * __hepta_cb_arg91 = &(h_state);
#line 30 "/workspace/scratch/c7c6ee414a6c/hepta-research/artifacts/cpp-class-20261025T173653458011Z/cpp-class/mutated/consumer.hepta"
int64_t __hepta_cb_v92 = __hepta_cb_fn_M71e525fea2e87b14_ScalarState_position_value(__hepta_cb_arg91);
#line 30 "/workspace/scratch/c7c6ee414a6c/hepta-research/artifacts/cpp-class-20261025T173653458011Z/cpp-class/mutated/consumer.hepta"
return __hepta_cb_v92;
#line 30 "/workspace/scratch/c7c6ee414a6c/hepta-research/artifacts/cpp-class-20261025T173653458011Z/cpp-class/mutated/consumer.hepta"
}
#line 33 "/workspace/scratch/c7c6ee414a6c/hepta-research/artifacts/cpp-class-20261025T173653458011Z/cpp-class/mutated/consumer.hepta"
int32_t state_guard(uint32_t h_word, uint64_t h_wide, int32_t h_balance, int64_t h_position, uint32_t h_step, uint64_t h_mix, int32_t h_lower, int32_t h_upper, int64_t h_next) {
#line 35 "/workspace/scratch/c7c6ee414a6c/hepta-research/artifacts/cpp-class-20261025T173653458011Z/cpp-class/mutated/consumer.hepta"
uint32_t __hepta_cb_v93 = h_word;
#line 35 "/workspace/scratch/c7c6ee414a6c/hepta-research/artifacts/cpp-class-20261025T173653458011Z/cpp-class/mutated/consumer.hepta"
uint64_t __hepta_cb_v94 = h_wide;
#line 35 "/workspace/scratch/c7c6ee414a6c/hepta-research/artifacts/cpp-class-20261025T173653458011Z/cpp-class/mutated/consumer.hepta"
int32_t __hepta_cb_v95 = h_balance;
#line 35 "/workspace/scratch/c7c6ee414a6c/hepta-research/artifacts/cpp-class-20261025T173653458011Z/cpp-class/mutated/consumer.hepta"
int64_t __hepta_cb_v96 = h_position;
#line 35 "/workspace/scratch/c7c6ee414a6c/hepta-research/artifacts/cpp-class-20261025T173653458011Z/cpp-class/mutated/consumer.hepta"
__hepta_cb_aggregate_0 __hepta_cb_v97 = __hepta_cb_fn_M71e525fea2e87b14_ScalarState_new(__hepta_cb_v93, __hepta_cb_v94, __hepta_cb_v95, __hepta_cb_v96);
#line 35 "/workspace/scratch/c7c6ee414a6c/hepta-research/artifacts/cpp-class-20261025T173653458011Z/cpp-class/mutated/consumer.hepta"
__hepta_cb_aggregate_0 h_state = __hepta_cb_v97;
#line 36 "/workspace/scratch/c7c6ee414a6c/hepta-research/artifacts/cpp-class-20261025T173653458011Z/cpp-class/mutated/consumer.hepta"
__hepta_cb_aggregate_0 * __hepta_cb_arg98 = &(h_state);
#line 36 "/workspace/scratch/c7c6ee414a6c/hepta-research/artifacts/cpp-class-20261025T173653458011Z/cpp-class/mutated/consumer.hepta"
uint32_t __hepta_cb_v99 = h_step;
#line 36 "/workspace/scratch/c7c6ee414a6c/hepta-research/artifacts/cpp-class-20261025T173653458011Z/cpp-class/mutated/consumer.hepta"
uint32_t __hepta_cb_v100 = __hepta_cb_fn_M71e525fea2e87b14_ScalarState_add_word(__hepta_cb_arg98, __hepta_cb_v99);
#line 36 "/workspace/scratch/c7c6ee414a6c/hepta-research/artifacts/cpp-class-20261025T173653458011Z/cpp-class/mutated/consumer.hepta"
uint32_t h_new_word = __hepta_cb_v100;
#line 37 "/workspace/scratch/c7c6ee414a6c/hepta-research/artifacts/cpp-class-20261025T173653458011Z/cpp-class/mutated/consumer.hepta"
const __hepta_cb_aggregate_0 * __hepta_cb_arg101 = &(h_state);
#line 37 "/workspace/scratch/c7c6ee414a6c/hepta-research/artifacts/cpp-class-20261025T173653458011Z/cpp-class/mutated/consumer.hepta"
uint32_t __hepta_cb_v102 = __hepta_cb_fn_M71e525fea2e87b14_ScalarState_word_value(__hepta_cb_arg101);
#line 37 "/workspace/scratch/c7c6ee414a6c/hepta-research/artifacts/cpp-class-20261025T173653458011Z/cpp-class/mutated/consumer.hepta"
uint32_t __hepta_cb_v103 = h_new_word;
#line 37 "/workspace/scratch/c7c6ee414a6c/hepta-research/artifacts/cpp-class-20261025T173653458011Z/cpp-class/mutated/consumer.hepta"
bool __hepta_cb_v104 = (__hepta_cb_v102 != __hepta_cb_v103);
#line 37 "/workspace/scratch/c7c6ee414a6c/hepta-research/artifacts/cpp-class-20261025T173653458011Z/cpp-class/mutated/consumer.hepta"
bool __hepta_cb_v105 = __hepta_cb_v104;
#line 37 "/workspace/scratch/c7c6ee414a6c/hepta-research/artifacts/cpp-class-20261025T173653458011Z/cpp-class/mutated/consumer.hepta"
if (!__hepta_cb_v105) { const __hepta_cb_aggregate_0 * __hepta_cb_arg106 = &(h_state); uint64_t __hepta_cb_v107 = __hepta_cb_fn_M71e525fea2e87b14_ScalarState_wide_value(__hepta_cb_arg106); uint64_t __hepta_cb_v108 = h_wide; bool __hepta_cb_v109 = (__hepta_cb_v107 != __hepta_cb_v108); __hepta_cb_v105 = __hepta_cb_v109; }
#line 37 "/workspace/scratch/c7c6ee414a6c/hepta-research/artifacts/cpp-class-20261025T173653458011Z/cpp-class/mutated/consumer.hepta"
bool __hepta_cb_v110 = __hepta_cb_v105;
#line 37 "/workspace/scratch/c7c6ee414a6c/hepta-research/artifacts/cpp-class-20261025T173653458011Z/cpp-class/mutated/consumer.hepta"
if (!__hepta_cb_v110) { const __hepta_cb_aggregate_0 * __hepta_cb_arg111 = &(h_state); int32_t __hepta_cb_v112 = __hepta_cb_fn_M71e525fea2e87b14_ScalarState_balance_value(__hepta_cb_arg111); int32_t __hepta_cb_v113 = h_balance; bool __hepta_cb_v114 = (__hepta_cb_v112 != __hepta_cb_v113); __hepta_cb_v110 = __hepta_cb_v114; }
#line 37 "/workspace/scratch/c7c6ee414a6c/hepta-research/artifacts/cpp-class-20261025T173653458011Z/cpp-class/mutated/consumer.hepta"
bool __hepta_cb_v115 = __hepta_cb_v110;
#line 37 "/workspace/scratch/c7c6ee414a6c/hepta-research/artifacts/cpp-class-20261025T173653458011Z/cpp-class/mutated/consumer.hepta"
if (!__hepta_cb_v115) { const __hepta_cb_aggregate_0 * __hepta_cb_arg116 = &(h_state); int64_t __hepta_cb_v117 = __hepta_cb_fn_M71e525fea2e87b14_ScalarState_position_value(__hepta_cb_arg116); int64_t __hepta_cb_v118 = h_position; bool __hepta_cb_v119 = (__hepta_cb_v117 != __hepta_cb_v118); __hepta_cb_v115 = __hepta_cb_v119; }
#line 37 "/workspace/scratch/c7c6ee414a6c/hepta-research/artifacts/cpp-class-20261025T173653458011Z/cpp-class/mutated/consumer.hepta"
if (__hepta_cb_v115) { 
#line 39 "/workspace/scratch/c7c6ee414a6c/hepta-research/artifacts/cpp-class-20261025T173653458011Z/cpp-class/mutated/consumer.hepta"
int32_t __hepta_cb_v120 = (int32_t)INT64_C(1);
#line 39 "/workspace/scratch/c7c6ee414a6c/hepta-research/artifacts/cpp-class-20261025T173653458011Z/cpp-class/mutated/consumer.hepta"
return __hepta_cb_v120; } else {  }
#line 41 "/workspace/scratch/c7c6ee414a6c/hepta-research/artifacts/cpp-class-20261025T173653458011Z/cpp-class/mutated/consumer.hepta"
__hepta_cb_aggregate_0 * __hepta_cb_arg121 = &(h_state);
#line 41 "/workspace/scratch/c7c6ee414a6c/hepta-research/artifacts/cpp-class-20261025T173653458011Z/cpp-class/mutated/consumer.hepta"
uint64_t __hepta_cb_v122 = h_mix;
#line 41 "/workspace/scratch/c7c6ee414a6c/hepta-research/artifacts/cpp-class-20261025T173653458011Z/cpp-class/mutated/consumer.hepta"
uint64_t __hepta_cb_v123 = __hepta_cb_fn_M71e525fea2e87b14_ScalarState_mix(__hepta_cb_arg121, __hepta_cb_v122);
#line 41 "/workspace/scratch/c7c6ee414a6c/hepta-research/artifacts/cpp-class-20261025T173653458011Z/cpp-class/mutated/consumer.hepta"
uint64_t h_new_wide = __hepta_cb_v123;
#line 42 "/workspace/scratch/c7c6ee414a6c/hepta-research/artifacts/cpp-class-20261025T173653458011Z/cpp-class/mutated/consumer.hepta"
const __hepta_cb_aggregate_0 * __hepta_cb_arg124 = &(h_state);
#line 42 "/workspace/scratch/c7c6ee414a6c/hepta-research/artifacts/cpp-class-20261025T173653458011Z/cpp-class/mutated/consumer.hepta"
uint32_t __hepta_cb_v125 = __hepta_cb_fn_M71e525fea2e87b14_ScalarState_word_value(__hepta_cb_arg124);
#line 42 "/workspace/scratch/c7c6ee414a6c/hepta-research/artifacts/cpp-class-20261025T173653458011Z/cpp-class/mutated/consumer.hepta"
uint32_t __hepta_cb_v126 = h_new_word;
#line 42 "/workspace/scratch/c7c6ee414a6c/hepta-research/artifacts/cpp-class-20261025T173653458011Z/cpp-class/mutated/consumer.hepta"
bool __hepta_cb_v127 = (__hepta_cb_v125 != __hepta_cb_v126);
#line 42 "/workspace/scratch/c7c6ee414a6c/hepta-research/artifacts/cpp-class-20261025T173653458011Z/cpp-class/mutated/consumer.hepta"
bool __hepta_cb_v128 = __hepta_cb_v127;
#line 42 "/workspace/scratch/c7c6ee414a6c/hepta-research/artifacts/cpp-class-20261025T173653458011Z/cpp-class/mutated/consumer.hepta"
if (!__hepta_cb_v128) { const __hepta_cb_aggregate_0 * __hepta_cb_arg129 = &(h_state); uint64_t __hepta_cb_v130 = __hepta_cb_fn_M71e525fea2e87b14_ScalarState_wide_value(__hepta_cb_arg129); uint64_t __hepta_cb_v131 = h_new_wide; bool __hepta_cb_v132 = (__hepta_cb_v130 != __hepta_cb_v131); __hepta_cb_v128 = __hepta_cb_v132; }
#line 42 "/workspace/scratch/c7c6ee414a6c/hepta-research/artifacts/cpp-class-20261025T173653458011Z/cpp-class/mutated/consumer.hepta"
bool __hepta_cb_v133 = __hepta_cb_v128;
#line 42 "/workspace/scratch/c7c6ee414a6c/hepta-research/artifacts/cpp-class-20261025T173653458011Z/cpp-class/mutated/consumer.hepta"
if (!__hepta_cb_v133) { const __hepta_cb_aggregate_0 * __hepta_cb_arg134 = &(h_state); int32_t __hepta_cb_v135 = __hepta_cb_fn_M71e525fea2e87b14_ScalarState_balance_value(__hepta_cb_arg134); int32_t __hepta_cb_v136 = h_balance; bool __hepta_cb_v137 = (__hepta_cb_v135 != __hepta_cb_v136); __hepta_cb_v133 = __hepta_cb_v137; }
#line 42 "/workspace/scratch/c7c6ee414a6c/hepta-research/artifacts/cpp-class-20261025T173653458011Z/cpp-class/mutated/consumer.hepta"
bool __hepta_cb_v138 = __hepta_cb_v133;
#line 42 "/workspace/scratch/c7c6ee414a6c/hepta-research/artifacts/cpp-class-20261025T173653458011Z/cpp-class/mutated/consumer.hepta"
if (!__hepta_cb_v138) { const __hepta_cb_aggregate_0 * __hepta_cb_arg139 = &(h_state); int64_t __hepta_cb_v140 = __hepta_cb_fn_M71e525fea2e87b14_ScalarState_position_value(__hepta_cb_arg139); int64_t __hepta_cb_v141 = h_position; bool __hepta_cb_v142 = (__hepta_cb_v140 != __hepta_cb_v141); __hepta_cb_v138 = __hepta_cb_v142; }
#line 42 "/workspace/scratch/c7c6ee414a6c/hepta-research/artifacts/cpp-class-20261025T173653458011Z/cpp-class/mutated/consumer.hepta"
if (__hepta_cb_v138) { 
#line 44 "/workspace/scratch/c7c6ee414a6c/hepta-research/artifacts/cpp-class-20261025T173653458011Z/cpp-class/mutated/consumer.hepta"
int32_t __hepta_cb_v143 = (int32_t)INT64_C(2);
#line 44 "/workspace/scratch/c7c6ee414a6c/hepta-research/artifacts/cpp-class-20261025T173653458011Z/cpp-class/mutated/consumer.hepta"
return __hepta_cb_v143; } else {  }
#line 46 "/workspace/scratch/c7c6ee414a6c/hepta-research/artifacts/cpp-class-20261025T173653458011Z/cpp-class/mutated/consumer.hepta"
__hepta_cb_aggregate_0 * __hepta_cb_arg144 = &(h_state);
#line 46 "/workspace/scratch/c7c6ee414a6c/hepta-research/artifacts/cpp-class-20261025T173653458011Z/cpp-class/mutated/consumer.hepta"
int32_t __hepta_cb_v145 = h_lower;
#line 46 "/workspace/scratch/c7c6ee414a6c/hepta-research/artifacts/cpp-class-20261025T173653458011Z/cpp-class/mutated/consumer.hepta"
int32_t __hepta_cb_v146 = h_upper;
#line 46 "/workspace/scratch/c7c6ee414a6c/hepta-research/artifacts/cpp-class-20261025T173653458011Z/cpp-class/mutated/consumer.hepta"
int32_t __hepta_cb_v147 = __hepta_cb_fn_M71e525fea2e87b14_ScalarState_clamp_balance(__hepta_cb_arg144, __hepta_cb_v145, __hepta_cb_v146);
#line 46 "/workspace/scratch/c7c6ee414a6c/hepta-research/artifacts/cpp-class-20261025T173653458011Z/cpp-class/mutated/consumer.hepta"
int32_t h_new_balance = __hepta_cb_v147;
#line 47 "/workspace/scratch/c7c6ee414a6c/hepta-research/artifacts/cpp-class-20261025T173653458011Z/cpp-class/mutated/consumer.hepta"
const __hepta_cb_aggregate_0 * __hepta_cb_arg148 = &(h_state);
#line 47 "/workspace/scratch/c7c6ee414a6c/hepta-research/artifacts/cpp-class-20261025T173653458011Z/cpp-class/mutated/consumer.hepta"
uint32_t __hepta_cb_v149 = __hepta_cb_fn_M71e525fea2e87b14_ScalarState_word_value(__hepta_cb_arg148);
#line 47 "/workspace/scratch/c7c6ee414a6c/hepta-research/artifacts/cpp-class-20261025T173653458011Z/cpp-class/mutated/consumer.hepta"
uint32_t __hepta_cb_v150 = h_new_word;
#line 47 "/workspace/scratch/c7c6ee414a6c/hepta-research/artifacts/cpp-class-20261025T173653458011Z/cpp-class/mutated/consumer.hepta"
bool __hepta_cb_v151 = (__hepta_cb_v149 != __hepta_cb_v150);
#line 47 "/workspace/scratch/c7c6ee414a6c/hepta-research/artifacts/cpp-class-20261025T173653458011Z/cpp-class/mutated/consumer.hepta"
bool __hepta_cb_v152 = __hepta_cb_v151;
#line 47 "/workspace/scratch/c7c6ee414a6c/hepta-research/artifacts/cpp-class-20261025T173653458011Z/cpp-class/mutated/consumer.hepta"
if (!__hepta_cb_v152) { const __hepta_cb_aggregate_0 * __hepta_cb_arg153 = &(h_state); uint64_t __hepta_cb_v154 = __hepta_cb_fn_M71e525fea2e87b14_ScalarState_wide_value(__hepta_cb_arg153); uint64_t __hepta_cb_v155 = h_new_wide; bool __hepta_cb_v156 = (__hepta_cb_v154 != __hepta_cb_v155); __hepta_cb_v152 = __hepta_cb_v156; }
#line 47 "/workspace/scratch/c7c6ee414a6c/hepta-research/artifacts/cpp-class-20261025T173653458011Z/cpp-class/mutated/consumer.hepta"
bool __hepta_cb_v157 = __hepta_cb_v152;
#line 47 "/workspace/scratch/c7c6ee414a6c/hepta-research/artifacts/cpp-class-20261025T173653458011Z/cpp-class/mutated/consumer.hepta"
if (!__hepta_cb_v157) { const __hepta_cb_aggregate_0 * __hepta_cb_arg158 = &(h_state); int32_t __hepta_cb_v159 = __hepta_cb_fn_M71e525fea2e87b14_ScalarState_balance_value(__hepta_cb_arg158); int32_t __hepta_cb_v160 = h_new_balance; bool __hepta_cb_v161 = (__hepta_cb_v159 != __hepta_cb_v160); __hepta_cb_v157 = __hepta_cb_v161; }
#line 47 "/workspace/scratch/c7c6ee414a6c/hepta-research/artifacts/cpp-class-20261025T173653458011Z/cpp-class/mutated/consumer.hepta"
bool __hepta_cb_v162 = __hepta_cb_v157;
#line 47 "/workspace/scratch/c7c6ee414a6c/hepta-research/artifacts/cpp-class-20261025T173653458011Z/cpp-class/mutated/consumer.hepta"
if (!__hepta_cb_v162) { const __hepta_cb_aggregate_0 * __hepta_cb_arg163 = &(h_state); int64_t __hepta_cb_v164 = __hepta_cb_fn_M71e525fea2e87b14_ScalarState_position_value(__hepta_cb_arg163); int64_t __hepta_cb_v165 = h_position; bool __hepta_cb_v166 = (__hepta_cb_v164 != __hepta_cb_v165); __hepta_cb_v162 = __hepta_cb_v166; }
#line 47 "/workspace/scratch/c7c6ee414a6c/hepta-research/artifacts/cpp-class-20261025T173653458011Z/cpp-class/mutated/consumer.hepta"
if (__hepta_cb_v162) { 
#line 49 "/workspace/scratch/c7c6ee414a6c/hepta-research/artifacts/cpp-class-20261025T173653458011Z/cpp-class/mutated/consumer.hepta"
int32_t __hepta_cb_v167 = (int32_t)INT64_C(3);
#line 49 "/workspace/scratch/c7c6ee414a6c/hepta-research/artifacts/cpp-class-20261025T173653458011Z/cpp-class/mutated/consumer.hepta"
return __hepta_cb_v167; } else {  }
#line 51 "/workspace/scratch/c7c6ee414a6c/hepta-research/artifacts/cpp-class-20261025T173653458011Z/cpp-class/mutated/consumer.hepta"
__hepta_cb_aggregate_0 * __hepta_cb_arg168 = &(h_state);
#line 51 "/workspace/scratch/c7c6ee414a6c/hepta-research/artifacts/cpp-class-20261025T173653458011Z/cpp-class/mutated/consumer.hepta"
int64_t __hepta_cb_v169 = h_next;
#line 51 "/workspace/scratch/c7c6ee414a6c/hepta-research/artifacts/cpp-class-20261025T173653458011Z/cpp-class/mutated/consumer.hepta"
int64_t __hepta_cb_v170 = __hepta_cb_fn_M71e525fea2e87b14_ScalarState_replace_position(__hepta_cb_arg168, __hepta_cb_v169);
#line 51 "/workspace/scratch/c7c6ee414a6c/hepta-research/artifacts/cpp-class-20261025T173653458011Z/cpp-class/mutated/consumer.hepta"
int64_t h_new_position = __hepta_cb_v170;
#line 52 "/workspace/scratch/c7c6ee414a6c/hepta-research/artifacts/cpp-class-20261025T173653458011Z/cpp-class/mutated/consumer.hepta"
const __hepta_cb_aggregate_0 * __hepta_cb_arg171 = &(h_state);
#line 52 "/workspace/scratch/c7c6ee414a6c/hepta-research/artifacts/cpp-class-20261025T173653458011Z/cpp-class/mutated/consumer.hepta"
uint32_t __hepta_cb_v172 = __hepta_cb_fn_M71e525fea2e87b14_ScalarState_word_value(__hepta_cb_arg171);
#line 52 "/workspace/scratch/c7c6ee414a6c/hepta-research/artifacts/cpp-class-20261025T173653458011Z/cpp-class/mutated/consumer.hepta"
uint32_t __hepta_cb_v173 = h_new_word;
#line 52 "/workspace/scratch/c7c6ee414a6c/hepta-research/artifacts/cpp-class-20261025T173653458011Z/cpp-class/mutated/consumer.hepta"
bool __hepta_cb_v174 = (__hepta_cb_v172 != __hepta_cb_v173);
#line 52 "/workspace/scratch/c7c6ee414a6c/hepta-research/artifacts/cpp-class-20261025T173653458011Z/cpp-class/mutated/consumer.hepta"
bool __hepta_cb_v175 = __hepta_cb_v174;
#line 52 "/workspace/scratch/c7c6ee414a6c/hepta-research/artifacts/cpp-class-20261025T173653458011Z/cpp-class/mutated/consumer.hepta"
if (!__hepta_cb_v175) { const __hepta_cb_aggregate_0 * __hepta_cb_arg176 = &(h_state); uint64_t __hepta_cb_v177 = __hepta_cb_fn_M71e525fea2e87b14_ScalarState_wide_value(__hepta_cb_arg176); uint64_t __hepta_cb_v178 = h_new_wide; bool __hepta_cb_v179 = (__hepta_cb_v177 != __hepta_cb_v178); __hepta_cb_v175 = __hepta_cb_v179; }
#line 52 "/workspace/scratch/c7c6ee414a6c/hepta-research/artifacts/cpp-class-20261025T173653458011Z/cpp-class/mutated/consumer.hepta"
bool __hepta_cb_v180 = __hepta_cb_v175;
#line 52 "/workspace/scratch/c7c6ee414a6c/hepta-research/artifacts/cpp-class-20261025T173653458011Z/cpp-class/mutated/consumer.hepta"
if (!__hepta_cb_v180) { const __hepta_cb_aggregate_0 * __hepta_cb_arg181 = &(h_state); int32_t __hepta_cb_v182 = __hepta_cb_fn_M71e525fea2e87b14_ScalarState_balance_value(__hepta_cb_arg181); int32_t __hepta_cb_v183 = h_new_balance; bool __hepta_cb_v184 = (__hepta_cb_v182 != __hepta_cb_v183); __hepta_cb_v180 = __hepta_cb_v184; }
#line 52 "/workspace/scratch/c7c6ee414a6c/hepta-research/artifacts/cpp-class-20261025T173653458011Z/cpp-class/mutated/consumer.hepta"
bool __hepta_cb_v185 = __hepta_cb_v180;
#line 52 "/workspace/scratch/c7c6ee414a6c/hepta-research/artifacts/cpp-class-20261025T173653458011Z/cpp-class/mutated/consumer.hepta"
if (!__hepta_cb_v185) { const __hepta_cb_aggregate_0 * __hepta_cb_arg186 = &(h_state); int64_t __hepta_cb_v187 = __hepta_cb_fn_M71e525fea2e87b14_ScalarState_position_value(__hepta_cb_arg186); int64_t __hepta_cb_v188 = h_new_position; bool __hepta_cb_v189 = (__hepta_cb_v187 != __hepta_cb_v188); __hepta_cb_v185 = __hepta_cb_v189; }
#line 52 "/workspace/scratch/c7c6ee414a6c/hepta-research/artifacts/cpp-class-20261025T173653458011Z/cpp-class/mutated/consumer.hepta"
if (__hepta_cb_v185) { 
#line 54 "/workspace/scratch/c7c6ee414a6c/hepta-research/artifacts/cpp-class-20261025T173653458011Z/cpp-class/mutated/consumer.hepta"
int32_t __hepta_cb_v190 = (int32_t)INT64_C(4);
#line 54 "/workspace/scratch/c7c6ee414a6c/hepta-research/artifacts/cpp-class-20261025T173653458011Z/cpp-class/mutated/consumer.hepta"
return __hepta_cb_v190; } else {  }
#line 56 "/workspace/scratch/c7c6ee414a6c/hepta-research/artifacts/cpp-class-20261025T173653458011Z/cpp-class/mutated/consumer.hepta"
int32_t __hepta_cb_v191 = (int32_t)INT64_C(0);
#line 56 "/workspace/scratch/c7c6ee414a6c/hepta-research/artifacts/cpp-class-20261025T173653458011Z/cpp-class/mutated/consumer.hepta"
return __hepta_cb_v191;
#line 56 "/workspace/scratch/c7c6ee414a6c/hepta-research/artifacts/cpp-class-20261025T173653458011Z/cpp-class/mutated/consumer.hepta"
}
