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
#line 11 "/workspace/scratch/c7c6ee414a6c/hepta-research/artifacts/cpp-class-20261025T171524382241Z/cpp-class/scalar_state.hepta"
__hepta_cb_aggregate_0 __hepta_cb_fn_M71e525fea2e87b14_ScalarState_new(uint32_t h_arg0, uint64_t h_arg1, int32_t h_arg2, int64_t h_arg3) {
#line 12 "/workspace/scratch/c7c6ee414a6c/hepta-research/artifacts/cpp-class-20261025T171524382241Z/cpp-class/scalar_state.hepta"
uint32_t __hepta_cb_v1 = h_arg0;
#line 12 "/workspace/scratch/c7c6ee414a6c/hepta-research/artifacts/cpp-class-20261025T171524382241Z/cpp-class/scalar_state.hepta"
uint64_t __hepta_cb_v2 = h_arg1;
#line 12 "/workspace/scratch/c7c6ee414a6c/hepta-research/artifacts/cpp-class-20261025T171524382241Z/cpp-class/scalar_state.hepta"
int32_t __hepta_cb_v3 = h_arg2;
#line 12 "/workspace/scratch/c7c6ee414a6c/hepta-research/artifacts/cpp-class-20261025T171524382241Z/cpp-class/scalar_state.hepta"
int64_t __hepta_cb_v4 = h_arg3;
#line 12 "/workspace/scratch/c7c6ee414a6c/hepta-research/artifacts/cpp-class-20261025T171524382241Z/cpp-class/scalar_state.hepta"
__hepta_cb_aggregate_0 __hepta_cb_v5 = (__hepta_cb_aggregate_0){ .h_word = __hepta_cb_v1, .h_wide = __hepta_cb_v2, .h_balance = __hepta_cb_v3, .h_position = __hepta_cb_v4 };
#line 12 "/workspace/scratch/c7c6ee414a6c/hepta-research/artifacts/cpp-class-20261025T171524382241Z/cpp-class/scalar_state.hepta"
return __hepta_cb_v5;
#line 12 "/workspace/scratch/c7c6ee414a6c/hepta-research/artifacts/cpp-class-20261025T171524382241Z/cpp-class/scalar_state.hepta"
}
#line 15 "/workspace/scratch/c7c6ee414a6c/hepta-research/artifacts/cpp-class-20261025T171524382241Z/cpp-class/scalar_state.hepta"
uint32_t __hepta_cb_fn_M71e525fea2e87b14_ScalarState_add_word(__hepta_cb_aggregate_0 *h_receiver, uint32_t h_arg0) {
#line 16 "/workspace/scratch/c7c6ee414a6c/hepta-research/artifacts/cpp-class-20261025T171524382241Z/cpp-class/scalar_state.hepta"
uint32_t __hepta_cb_v6 = ((*h_receiver)).h_word;
#line 16 "/workspace/scratch/c7c6ee414a6c/hepta-research/artifacts/cpp-class-20261025T171524382241Z/cpp-class/scalar_state.hepta"
uint32_t __hepta_cb_v7 = h_arg0;
#line 16 "/workspace/scratch/c7c6ee414a6c/hepta-research/artifacts/cpp-class-20261025T171524382241Z/cpp-class/scalar_state.hepta"
uint32_t __hepta_cb_v8 = __hepta_cb_u32_wrapping_add(__hepta_cb_v6, __hepta_cb_v7);
#line 16 "/workspace/scratch/c7c6ee414a6c/hepta-research/artifacts/cpp-class-20261025T171524382241Z/cpp-class/scalar_state.hepta"
((*h_receiver)).h_word = __hepta_cb_v8;
#line 17 "/workspace/scratch/c7c6ee414a6c/hepta-research/artifacts/cpp-class-20261025T171524382241Z/cpp-class/scalar_state.hepta"
uint32_t __hepta_cb_v9 = ((*h_receiver)).h_word;
#line 17 "/workspace/scratch/c7c6ee414a6c/hepta-research/artifacts/cpp-class-20261025T171524382241Z/cpp-class/scalar_state.hepta"
return __hepta_cb_v9;
#line 17 "/workspace/scratch/c7c6ee414a6c/hepta-research/artifacts/cpp-class-20261025T171524382241Z/cpp-class/scalar_state.hepta"
}
#line 20 "/workspace/scratch/c7c6ee414a6c/hepta-research/artifacts/cpp-class-20261025T171524382241Z/cpp-class/scalar_state.hepta"
uint64_t __hepta_cb_fn_M71e525fea2e87b14_ScalarState_mix(__hepta_cb_aggregate_0 *h_receiver, uint64_t h_arg0) {
#line 21 "/workspace/scratch/c7c6ee414a6c/hepta-research/artifacts/cpp-class-20261025T171524382241Z/cpp-class/scalar_state.hepta"
uint64_t __hepta_cb_v10 = ((*h_receiver)).h_wide;
#line 21 "/workspace/scratch/c7c6ee414a6c/hepta-research/artifacts/cpp-class-20261025T171524382241Z/cpp-class/scalar_state.hepta"
uint64_t __hepta_cb_v11 = h_arg0;
#line 21 "/workspace/scratch/c7c6ee414a6c/hepta-research/artifacts/cpp-class-20261025T171524382241Z/cpp-class/scalar_state.hepta"
uint64_t __hepta_cb_v12 = __hepta_cb_u64_xor(__hepta_cb_v10, __hepta_cb_v11);
#line 21 "/workspace/scratch/c7c6ee414a6c/hepta-research/artifacts/cpp-class-20261025T171524382241Z/cpp-class/scalar_state.hepta"
uint64_t __hepta_cb_v13 = (uint64_t)UINT64_C(1);
#line 21 "/workspace/scratch/c7c6ee414a6c/hepta-research/artifacts/cpp-class-20261025T171524382241Z/cpp-class/scalar_state.hepta"
uint64_t __hepta_cb_v14 = __hepta_cb_u64_wrapping_add(__hepta_cb_v12, __hepta_cb_v13);
#line 21 "/workspace/scratch/c7c6ee414a6c/hepta-research/artifacts/cpp-class-20261025T171524382241Z/cpp-class/scalar_state.hepta"
((*h_receiver)).h_wide = __hepta_cb_v14;
#line 22 "/workspace/scratch/c7c6ee414a6c/hepta-research/artifacts/cpp-class-20261025T171524382241Z/cpp-class/scalar_state.hepta"
uint64_t __hepta_cb_v15 = ((*h_receiver)).h_wide;
#line 22 "/workspace/scratch/c7c6ee414a6c/hepta-research/artifacts/cpp-class-20261025T171524382241Z/cpp-class/scalar_state.hepta"
return __hepta_cb_v15;
#line 22 "/workspace/scratch/c7c6ee414a6c/hepta-research/artifacts/cpp-class-20261025T171524382241Z/cpp-class/scalar_state.hepta"
}
#line 25 "/workspace/scratch/c7c6ee414a6c/hepta-research/artifacts/cpp-class-20261025T171524382241Z/cpp-class/scalar_state.hepta"
int32_t __hepta_cb_fn_M71e525fea2e87b14_ScalarState_clamp_balance(__hepta_cb_aggregate_0 *h_receiver, int32_t h_arg0, int32_t h_arg1) {
#line 26 "/workspace/scratch/c7c6ee414a6c/hepta-research/artifacts/cpp-class-20261025T171524382241Z/cpp-class/scalar_state.hepta"
int32_t __hepta_cb_v16 = ((*h_receiver)).h_balance;
#line 26 "/workspace/scratch/c7c6ee414a6c/hepta-research/artifacts/cpp-class-20261025T171524382241Z/cpp-class/scalar_state.hepta"
int32_t __hepta_cb_v17 = h_arg0;
#line 26 "/workspace/scratch/c7c6ee414a6c/hepta-research/artifacts/cpp-class-20261025T171524382241Z/cpp-class/scalar_state.hepta"
bool __hepta_cb_v18 = (__hepta_cb_v16 < __hepta_cb_v17);
#line 26 "/workspace/scratch/c7c6ee414a6c/hepta-research/artifacts/cpp-class-20261025T171524382241Z/cpp-class/scalar_state.hepta"
if (__hepta_cb_v18) { 
#line 27 "/workspace/scratch/c7c6ee414a6c/hepta-research/artifacts/cpp-class-20261025T171524382241Z/cpp-class/scalar_state.hepta"
int32_t __hepta_cb_v19 = h_arg0;
#line 27 "/workspace/scratch/c7c6ee414a6c/hepta-research/artifacts/cpp-class-20261025T171524382241Z/cpp-class/scalar_state.hepta"
((*h_receiver)).h_balance = __hepta_cb_v19; } else { 
#line 30 "/workspace/scratch/c7c6ee414a6c/hepta-research/artifacts/cpp-class-20261025T171524382241Z/cpp-class/scalar_state.hepta"
int32_t __hepta_cb_v20 = ((*h_receiver)).h_balance;
#line 30 "/workspace/scratch/c7c6ee414a6c/hepta-research/artifacts/cpp-class-20261025T171524382241Z/cpp-class/scalar_state.hepta"
int32_t __hepta_cb_v21 = h_arg1;
#line 30 "/workspace/scratch/c7c6ee414a6c/hepta-research/artifacts/cpp-class-20261025T171524382241Z/cpp-class/scalar_state.hepta"
bool __hepta_cb_v22 = (__hepta_cb_v20 > __hepta_cb_v21);
#line 30 "/workspace/scratch/c7c6ee414a6c/hepta-research/artifacts/cpp-class-20261025T171524382241Z/cpp-class/scalar_state.hepta"
if (__hepta_cb_v22) { 
#line 31 "/workspace/scratch/c7c6ee414a6c/hepta-research/artifacts/cpp-class-20261025T171524382241Z/cpp-class/scalar_state.hepta"
int32_t __hepta_cb_v23 = h_arg1;
#line 31 "/workspace/scratch/c7c6ee414a6c/hepta-research/artifacts/cpp-class-20261025T171524382241Z/cpp-class/scalar_state.hepta"
((*h_receiver)).h_balance = __hepta_cb_v23; } else {  } }
#line 34 "/workspace/scratch/c7c6ee414a6c/hepta-research/artifacts/cpp-class-20261025T171524382241Z/cpp-class/scalar_state.hepta"
int32_t __hepta_cb_v24 = ((*h_receiver)).h_balance;
#line 34 "/workspace/scratch/c7c6ee414a6c/hepta-research/artifacts/cpp-class-20261025T171524382241Z/cpp-class/scalar_state.hepta"
return __hepta_cb_v24;
#line 34 "/workspace/scratch/c7c6ee414a6c/hepta-research/artifacts/cpp-class-20261025T171524382241Z/cpp-class/scalar_state.hepta"
}
#line 37 "/workspace/scratch/c7c6ee414a6c/hepta-research/artifacts/cpp-class-20261025T171524382241Z/cpp-class/scalar_state.hepta"
int64_t __hepta_cb_fn_M71e525fea2e87b14_ScalarState_replace_position(__hepta_cb_aggregate_0 *h_receiver, int64_t h_arg0) {
#line 38 "/workspace/scratch/c7c6ee414a6c/hepta-research/artifacts/cpp-class-20261025T171524382241Z/cpp-class/scalar_state.hepta"
int64_t __hepta_cb_v25 = h_arg0;
#line 38 "/workspace/scratch/c7c6ee414a6c/hepta-research/artifacts/cpp-class-20261025T171524382241Z/cpp-class/scalar_state.hepta"
((*h_receiver)).h_position = __hepta_cb_v25;
#line 39 "/workspace/scratch/c7c6ee414a6c/hepta-research/artifacts/cpp-class-20261025T171524382241Z/cpp-class/scalar_state.hepta"
int64_t __hepta_cb_v26 = ((*h_receiver)).h_position;
#line 39 "/workspace/scratch/c7c6ee414a6c/hepta-research/artifacts/cpp-class-20261025T171524382241Z/cpp-class/scalar_state.hepta"
return __hepta_cb_v26;
#line 39 "/workspace/scratch/c7c6ee414a6c/hepta-research/artifacts/cpp-class-20261025T171524382241Z/cpp-class/scalar_state.hepta"
}
#line 42 "/workspace/scratch/c7c6ee414a6c/hepta-research/artifacts/cpp-class-20261025T171524382241Z/cpp-class/scalar_state.hepta"
uint32_t __hepta_cb_fn_M71e525fea2e87b14_ScalarState_word_value(const __hepta_cb_aggregate_0 *h_receiver) {
#line 43 "/workspace/scratch/c7c6ee414a6c/hepta-research/artifacts/cpp-class-20261025T171524382241Z/cpp-class/scalar_state.hepta"
uint32_t __hepta_cb_v27 = ((*h_receiver)).h_word;
#line 43 "/workspace/scratch/c7c6ee414a6c/hepta-research/artifacts/cpp-class-20261025T171524382241Z/cpp-class/scalar_state.hepta"
return __hepta_cb_v27;
#line 43 "/workspace/scratch/c7c6ee414a6c/hepta-research/artifacts/cpp-class-20261025T171524382241Z/cpp-class/scalar_state.hepta"
}
#line 46 "/workspace/scratch/c7c6ee414a6c/hepta-research/artifacts/cpp-class-20261025T171524382241Z/cpp-class/scalar_state.hepta"
uint64_t __hepta_cb_fn_M71e525fea2e87b14_ScalarState_wide_value(const __hepta_cb_aggregate_0 *h_receiver) {
#line 47 "/workspace/scratch/c7c6ee414a6c/hepta-research/artifacts/cpp-class-20261025T171524382241Z/cpp-class/scalar_state.hepta"
uint64_t __hepta_cb_v28 = ((*h_receiver)).h_wide;
#line 47 "/workspace/scratch/c7c6ee414a6c/hepta-research/artifacts/cpp-class-20261025T171524382241Z/cpp-class/scalar_state.hepta"
return __hepta_cb_v28;
#line 47 "/workspace/scratch/c7c6ee414a6c/hepta-research/artifacts/cpp-class-20261025T171524382241Z/cpp-class/scalar_state.hepta"
}
#line 50 "/workspace/scratch/c7c6ee414a6c/hepta-research/artifacts/cpp-class-20261025T171524382241Z/cpp-class/scalar_state.hepta"
int32_t __hepta_cb_fn_M71e525fea2e87b14_ScalarState_balance_value(const __hepta_cb_aggregate_0 *h_receiver) {
#line 51 "/workspace/scratch/c7c6ee414a6c/hepta-research/artifacts/cpp-class-20261025T171524382241Z/cpp-class/scalar_state.hepta"
int32_t __hepta_cb_v29 = ((*h_receiver)).h_balance;
#line 51 "/workspace/scratch/c7c6ee414a6c/hepta-research/artifacts/cpp-class-20261025T171524382241Z/cpp-class/scalar_state.hepta"
return __hepta_cb_v29;
#line 51 "/workspace/scratch/c7c6ee414a6c/hepta-research/artifacts/cpp-class-20261025T171524382241Z/cpp-class/scalar_state.hepta"
}
#line 54 "/workspace/scratch/c7c6ee414a6c/hepta-research/artifacts/cpp-class-20261025T171524382241Z/cpp-class/scalar_state.hepta"
int64_t __hepta_cb_fn_M71e525fea2e87b14_ScalarState_position_value(const __hepta_cb_aggregate_0 *h_receiver) {
#line 55 "/workspace/scratch/c7c6ee414a6c/hepta-research/artifacts/cpp-class-20261025T171524382241Z/cpp-class/scalar_state.hepta"
int64_t __hepta_cb_v30 = ((*h_receiver)).h_position;
#line 55 "/workspace/scratch/c7c6ee414a6c/hepta-research/artifacts/cpp-class-20261025T171524382241Z/cpp-class/scalar_state.hepta"
return __hepta_cb_v30;
#line 55 "/workspace/scratch/c7c6ee414a6c/hepta-research/artifacts/cpp-class-20261025T171524382241Z/cpp-class/scalar_state.hepta"
}
#line 58 "/workspace/scratch/c7c6ee414a6c/hepta-research/artifacts/cpp-class-20261025T171524382241Z/cpp-class/scalar_state.hepta"
void __hepta_cb_fn_M71e525fea2e87b14_ScalarState_set_word(__hepta_cb_aggregate_0 *h_receiver, uint32_t h_arg0) {
#line 59 "/workspace/scratch/c7c6ee414a6c/hepta-research/artifacts/cpp-class-20261025T171524382241Z/cpp-class/scalar_state.hepta"
uint32_t __hepta_cb_v31 = h_arg0;
#line 59 "/workspace/scratch/c7c6ee414a6c/hepta-research/artifacts/cpp-class-20261025T171524382241Z/cpp-class/scalar_state.hepta"
((*h_receiver)).h_word = __hepta_cb_v31;
#line 59 "/workspace/scratch/c7c6ee414a6c/hepta-research/artifacts/cpp-class-20261025T171524382241Z/cpp-class/scalar_state.hepta"
}
#line 4 "/workspace/scratch/c7c6ee414a6c/hepta-research/artifacts/cpp-class-20261025T171524382241Z/cpp-class/consumer.hepta"
uint32_t word_trace(uint32_t h_initial, uint32_t h_step, uint32_t h_reset, uint32_t h_last) {
#line 5 "/workspace/scratch/c7c6ee414a6c/hepta-research/artifacts/cpp-class-20261025T171524382241Z/cpp-class/consumer.hepta"
uint32_t __hepta_cb_v32 = h_initial;
#line 5 "/workspace/scratch/c7c6ee414a6c/hepta-research/artifacts/cpp-class-20261025T171524382241Z/cpp-class/consumer.hepta"
uint64_t __hepta_cb_v33 = (uint64_t)UINT64_C(0);
#line 5 "/workspace/scratch/c7c6ee414a6c/hepta-research/artifacts/cpp-class-20261025T171524382241Z/cpp-class/consumer.hepta"
int32_t __hepta_cb_v34 = (int32_t)INT64_C(0);
#line 5 "/workspace/scratch/c7c6ee414a6c/hepta-research/artifacts/cpp-class-20261025T171524382241Z/cpp-class/consumer.hepta"
int64_t __hepta_cb_v35 = (int64_t)INT64_C(0);
#line 5 "/workspace/scratch/c7c6ee414a6c/hepta-research/artifacts/cpp-class-20261025T171524382241Z/cpp-class/consumer.hepta"
__hepta_cb_aggregate_0 __hepta_cb_v36 = __hepta_cb_fn_M71e525fea2e87b14_ScalarState_new(__hepta_cb_v32, __hepta_cb_v33, __hepta_cb_v34, __hepta_cb_v35);
#line 5 "/workspace/scratch/c7c6ee414a6c/hepta-research/artifacts/cpp-class-20261025T171524382241Z/cpp-class/consumer.hepta"
__hepta_cb_aggregate_0 h_state = __hepta_cb_v36;
#line 6 "/workspace/scratch/c7c6ee414a6c/hepta-research/artifacts/cpp-class-20261025T171524382241Z/cpp-class/consumer.hepta"
__hepta_cb_aggregate_0 __hepta_cb_v37 = h_state;
#line 6 "/workspace/scratch/c7c6ee414a6c/hepta-research/artifacts/cpp-class-20261025T171524382241Z/cpp-class/consumer.hepta"
__hepta_cb_aggregate_0 h_snapshot = __hepta_cb_v37;
#line 7 "/workspace/scratch/c7c6ee414a6c/hepta-research/artifacts/cpp-class-20261025T171524382241Z/cpp-class/consumer.hepta"
__hepta_cb_aggregate_0 * __hepta_cb_arg38 = &(h_state);
#line 7 "/workspace/scratch/c7c6ee414a6c/hepta-research/artifacts/cpp-class-20261025T171524382241Z/cpp-class/consumer.hepta"
uint32_t __hepta_cb_v39 = h_step;
#line 7 "/workspace/scratch/c7c6ee414a6c/hepta-research/artifacts/cpp-class-20261025T171524382241Z/cpp-class/consumer.hepta"
uint32_t __hepta_cb_v40 = __hepta_cb_fn_M71e525fea2e87b14_ScalarState_add_word(__hepta_cb_arg38, __hepta_cb_v39);
#line 7 "/workspace/scratch/c7c6ee414a6c/hepta-research/artifacts/cpp-class-20261025T171524382241Z/cpp-class/consumer.hepta"
uint32_t h_first = __hepta_cb_v40;
#line 8 "/workspace/scratch/c7c6ee414a6c/hepta-research/artifacts/cpp-class-20261025T171524382241Z/cpp-class/consumer.hepta"
__hepta_cb_aggregate_0 * __hepta_cb_arg41 = &(h_state);
#line 8 "/workspace/scratch/c7c6ee414a6c/hepta-research/artifacts/cpp-class-20261025T171524382241Z/cpp-class/consumer.hepta"
uint32_t __hepta_cb_v42 = h_reset;
#line 8 "/workspace/scratch/c7c6ee414a6c/hepta-research/artifacts/cpp-class-20261025T171524382241Z/cpp-class/consumer.hepta"
__hepta_cb_fn_M71e525fea2e87b14_ScalarState_set_word(__hepta_cb_arg41, __hepta_cb_v42);
#line 9 "/workspace/scratch/c7c6ee414a6c/hepta-research/artifacts/cpp-class-20261025T171524382241Z/cpp-class/consumer.hepta"
__hepta_cb_aggregate_0 * __hepta_cb_arg43 = &(h_state);
#line 9 "/workspace/scratch/c7c6ee414a6c/hepta-research/artifacts/cpp-class-20261025T171524382241Z/cpp-class/consumer.hepta"
uint32_t __hepta_cb_v44 = h_last;
#line 9 "/workspace/scratch/c7c6ee414a6c/hepta-research/artifacts/cpp-class-20261025T171524382241Z/cpp-class/consumer.hepta"
uint32_t __hepta_cb_v45 = __hepta_cb_fn_M71e525fea2e87b14_ScalarState_add_word(__hepta_cb_arg43, __hepta_cb_v44);
#line 9 "/workspace/scratch/c7c6ee414a6c/hepta-research/artifacts/cpp-class-20261025T171524382241Z/cpp-class/consumer.hepta"
uint32_t h_final = __hepta_cb_v45;
#line 10 "/workspace/scratch/c7c6ee414a6c/hepta-research/artifacts/cpp-class-20261025T171524382241Z/cpp-class/consumer.hepta"
uint32_t __hepta_cb_v46 = h_first;
#line 10 "/workspace/scratch/c7c6ee414a6c/hepta-research/artifacts/cpp-class-20261025T171524382241Z/cpp-class/consumer.hepta"
uint32_t __hepta_cb_v47 = h_final;
#line 10 "/workspace/scratch/c7c6ee414a6c/hepta-research/artifacts/cpp-class-20261025T171524382241Z/cpp-class/consumer.hepta"
uint32_t __hepta_cb_v48 = __hepta_cb_u32_xor(__hepta_cb_v46, __hepta_cb_v47);
#line 10 "/workspace/scratch/c7c6ee414a6c/hepta-research/artifacts/cpp-class-20261025T171524382241Z/cpp-class/consumer.hepta"
const __hepta_cb_aggregate_0 * __hepta_cb_arg49 = &(h_snapshot);
#line 10 "/workspace/scratch/c7c6ee414a6c/hepta-research/artifacts/cpp-class-20261025T171524382241Z/cpp-class/consumer.hepta"
uint32_t __hepta_cb_v50 = __hepta_cb_fn_M71e525fea2e87b14_ScalarState_word_value(__hepta_cb_arg49);
#line 10 "/workspace/scratch/c7c6ee414a6c/hepta-research/artifacts/cpp-class-20261025T171524382241Z/cpp-class/consumer.hepta"
uint32_t __hepta_cb_v51 = __hepta_cb_u32_xor(__hepta_cb_v48, __hepta_cb_v50);
#line 10 "/workspace/scratch/c7c6ee414a6c/hepta-research/artifacts/cpp-class-20261025T171524382241Z/cpp-class/consumer.hepta"
return __hepta_cb_v51;
#line 10 "/workspace/scratch/c7c6ee414a6c/hepta-research/artifacts/cpp-class-20261025T171524382241Z/cpp-class/consumer.hepta"
}
#line 13 "/workspace/scratch/c7c6ee414a6c/hepta-research/artifacts/cpp-class-20261025T171524382241Z/cpp-class/consumer.hepta"
uint64_t wide_trace(uint64_t h_initial, uint64_t h_first, uint64_t h_second) {
#line 14 "/workspace/scratch/c7c6ee414a6c/hepta-research/artifacts/cpp-class-20261025T171524382241Z/cpp-class/consumer.hepta"
uint32_t __hepta_cb_v52 = (uint32_t)UINT64_C(0);
#line 14 "/workspace/scratch/c7c6ee414a6c/hepta-research/artifacts/cpp-class-20261025T171524382241Z/cpp-class/consumer.hepta"
uint64_t __hepta_cb_v53 = h_initial;
#line 14 "/workspace/scratch/c7c6ee414a6c/hepta-research/artifacts/cpp-class-20261025T171524382241Z/cpp-class/consumer.hepta"
int32_t __hepta_cb_v54 = (int32_t)INT64_C(0);
#line 14 "/workspace/scratch/c7c6ee414a6c/hepta-research/artifacts/cpp-class-20261025T171524382241Z/cpp-class/consumer.hepta"
int64_t __hepta_cb_v55 = (int64_t)INT64_C(0);
#line 14 "/workspace/scratch/c7c6ee414a6c/hepta-research/artifacts/cpp-class-20261025T171524382241Z/cpp-class/consumer.hepta"
__hepta_cb_aggregate_0 __hepta_cb_v56 = __hepta_cb_fn_M71e525fea2e87b14_ScalarState_new(__hepta_cb_v52, __hepta_cb_v53, __hepta_cb_v54, __hepta_cb_v55);
#line 14 "/workspace/scratch/c7c6ee414a6c/hepta-research/artifacts/cpp-class-20261025T171524382241Z/cpp-class/consumer.hepta"
__hepta_cb_aggregate_0 h_state = __hepta_cb_v56;
#line 15 "/workspace/scratch/c7c6ee414a6c/hepta-research/artifacts/cpp-class-20261025T171524382241Z/cpp-class/consumer.hepta"
__hepta_cb_aggregate_0 __hepta_cb_v57 = h_state;
#line 15 "/workspace/scratch/c7c6ee414a6c/hepta-research/artifacts/cpp-class-20261025T171524382241Z/cpp-class/consumer.hepta"
__hepta_cb_aggregate_0 h_snapshot = __hepta_cb_v57;
#line 16 "/workspace/scratch/c7c6ee414a6c/hepta-research/artifacts/cpp-class-20261025T171524382241Z/cpp-class/consumer.hepta"
__hepta_cb_aggregate_0 * __hepta_cb_arg58 = &(h_state);
#line 16 "/workspace/scratch/c7c6ee414a6c/hepta-research/artifacts/cpp-class-20261025T171524382241Z/cpp-class/consumer.hepta"
uint64_t __hepta_cb_v59 = h_first;
#line 16 "/workspace/scratch/c7c6ee414a6c/hepta-research/artifacts/cpp-class-20261025T171524382241Z/cpp-class/consumer.hepta"
uint64_t __hepta_cb_v60 = __hepta_cb_fn_M71e525fea2e87b14_ScalarState_mix(__hepta_cb_arg58, __hepta_cb_v59);
#line 16 "/workspace/scratch/c7c6ee414a6c/hepta-research/artifacts/cpp-class-20261025T171524382241Z/cpp-class/consumer.hepta"
uint64_t h_a = __hepta_cb_v60;
#line 17 "/workspace/scratch/c7c6ee414a6c/hepta-research/artifacts/cpp-class-20261025T171524382241Z/cpp-class/consumer.hepta"
__hepta_cb_aggregate_0 * __hepta_cb_arg61 = &(h_state);
#line 17 "/workspace/scratch/c7c6ee414a6c/hepta-research/artifacts/cpp-class-20261025T171524382241Z/cpp-class/consumer.hepta"
uint64_t __hepta_cb_v62 = h_second;
#line 17 "/workspace/scratch/c7c6ee414a6c/hepta-research/artifacts/cpp-class-20261025T171524382241Z/cpp-class/consumer.hepta"
uint64_t __hepta_cb_v63 = __hepta_cb_fn_M71e525fea2e87b14_ScalarState_mix(__hepta_cb_arg61, __hepta_cb_v62);
#line 17 "/workspace/scratch/c7c6ee414a6c/hepta-research/artifacts/cpp-class-20261025T171524382241Z/cpp-class/consumer.hepta"
uint64_t h_b = __hepta_cb_v63;
#line 18 "/workspace/scratch/c7c6ee414a6c/hepta-research/artifacts/cpp-class-20261025T171524382241Z/cpp-class/consumer.hepta"
uint64_t __hepta_cb_v64 = h_a;
#line 18 "/workspace/scratch/c7c6ee414a6c/hepta-research/artifacts/cpp-class-20261025T171524382241Z/cpp-class/consumer.hepta"
uint64_t __hepta_cb_v65 = h_b;
#line 18 "/workspace/scratch/c7c6ee414a6c/hepta-research/artifacts/cpp-class-20261025T171524382241Z/cpp-class/consumer.hepta"
uint64_t __hepta_cb_v66 = __hepta_cb_u64_xor(__hepta_cb_v64, __hepta_cb_v65);
#line 18 "/workspace/scratch/c7c6ee414a6c/hepta-research/artifacts/cpp-class-20261025T171524382241Z/cpp-class/consumer.hepta"
const __hepta_cb_aggregate_0 * __hepta_cb_arg67 = &(h_snapshot);
#line 18 "/workspace/scratch/c7c6ee414a6c/hepta-research/artifacts/cpp-class-20261025T171524382241Z/cpp-class/consumer.hepta"
uint64_t __hepta_cb_v68 = __hepta_cb_fn_M71e525fea2e87b14_ScalarState_wide_value(__hepta_cb_arg67);
#line 18 "/workspace/scratch/c7c6ee414a6c/hepta-research/artifacts/cpp-class-20261025T171524382241Z/cpp-class/consumer.hepta"
uint64_t __hepta_cb_v69 = __hepta_cb_u64_xor(__hepta_cb_v66, __hepta_cb_v68);
#line 18 "/workspace/scratch/c7c6ee414a6c/hepta-research/artifacts/cpp-class-20261025T171524382241Z/cpp-class/consumer.hepta"
return __hepta_cb_v69;
#line 18 "/workspace/scratch/c7c6ee414a6c/hepta-research/artifacts/cpp-class-20261025T171524382241Z/cpp-class/consumer.hepta"
}
#line 21 "/workspace/scratch/c7c6ee414a6c/hepta-research/artifacts/cpp-class-20261025T171524382241Z/cpp-class/consumer.hepta"
int32_t balance_trace(int32_t h_initial, int32_t h_lower, int32_t h_upper) {
#line 22 "/workspace/scratch/c7c6ee414a6c/hepta-research/artifacts/cpp-class-20261025T171524382241Z/cpp-class/consumer.hepta"
uint32_t __hepta_cb_v70 = (uint32_t)UINT64_C(0);
#line 22 "/workspace/scratch/c7c6ee414a6c/hepta-research/artifacts/cpp-class-20261025T171524382241Z/cpp-class/consumer.hepta"
uint64_t __hepta_cb_v71 = (uint64_t)UINT64_C(0);
#line 22 "/workspace/scratch/c7c6ee414a6c/hepta-research/artifacts/cpp-class-20261025T171524382241Z/cpp-class/consumer.hepta"
int32_t __hepta_cb_v72 = h_initial;
#line 22 "/workspace/scratch/c7c6ee414a6c/hepta-research/artifacts/cpp-class-20261025T171524382241Z/cpp-class/consumer.hepta"
int64_t __hepta_cb_v73 = (int64_t)INT64_C(0);
#line 22 "/workspace/scratch/c7c6ee414a6c/hepta-research/artifacts/cpp-class-20261025T171524382241Z/cpp-class/consumer.hepta"
__hepta_cb_aggregate_0 __hepta_cb_v74 = __hepta_cb_fn_M71e525fea2e87b14_ScalarState_new(__hepta_cb_v70, __hepta_cb_v71, __hepta_cb_v72, __hepta_cb_v73);
#line 22 "/workspace/scratch/c7c6ee414a6c/hepta-research/artifacts/cpp-class-20261025T171524382241Z/cpp-class/consumer.hepta"
__hepta_cb_aggregate_0 h_state = __hepta_cb_v74;
#line 23 "/workspace/scratch/c7c6ee414a6c/hepta-research/artifacts/cpp-class-20261025T171524382241Z/cpp-class/consumer.hepta"
__hepta_cb_aggregate_0 * __hepta_cb_arg75 = &(h_state);
#line 23 "/workspace/scratch/c7c6ee414a6c/hepta-research/artifacts/cpp-class-20261025T171524382241Z/cpp-class/consumer.hepta"
int32_t __hepta_cb_v76 = h_lower;
#line 23 "/workspace/scratch/c7c6ee414a6c/hepta-research/artifacts/cpp-class-20261025T171524382241Z/cpp-class/consumer.hepta"
int32_t __hepta_cb_v77 = h_upper;
#line 23 "/workspace/scratch/c7c6ee414a6c/hepta-research/artifacts/cpp-class-20261025T171524382241Z/cpp-class/consumer.hepta"
int32_t __hepta_cb_v78 = __hepta_cb_fn_M71e525fea2e87b14_ScalarState_clamp_balance(__hepta_cb_arg75, __hepta_cb_v76, __hepta_cb_v77);
#line 24 "/workspace/scratch/c7c6ee414a6c/hepta-research/artifacts/cpp-class-20261025T171524382241Z/cpp-class/consumer.hepta"
const __hepta_cb_aggregate_0 * __hepta_cb_arg79 = &(h_state);
#line 24 "/workspace/scratch/c7c6ee414a6c/hepta-research/artifacts/cpp-class-20261025T171524382241Z/cpp-class/consumer.hepta"
int32_t __hepta_cb_v80 = __hepta_cb_fn_M71e525fea2e87b14_ScalarState_balance_value(__hepta_cb_arg79);
#line 24 "/workspace/scratch/c7c6ee414a6c/hepta-research/artifacts/cpp-class-20261025T171524382241Z/cpp-class/consumer.hepta"
return __hepta_cb_v80;
#line 24 "/workspace/scratch/c7c6ee414a6c/hepta-research/artifacts/cpp-class-20261025T171524382241Z/cpp-class/consumer.hepta"
}
#line 27 "/workspace/scratch/c7c6ee414a6c/hepta-research/artifacts/cpp-class-20261025T171524382241Z/cpp-class/consumer.hepta"
int64_t position_trace(int64_t h_initial, int64_t h_next) {
#line 28 "/workspace/scratch/c7c6ee414a6c/hepta-research/artifacts/cpp-class-20261025T171524382241Z/cpp-class/consumer.hepta"
uint32_t __hepta_cb_v81 = (uint32_t)UINT64_C(0);
#line 28 "/workspace/scratch/c7c6ee414a6c/hepta-research/artifacts/cpp-class-20261025T171524382241Z/cpp-class/consumer.hepta"
uint64_t __hepta_cb_v82 = (uint64_t)UINT64_C(0);
#line 28 "/workspace/scratch/c7c6ee414a6c/hepta-research/artifacts/cpp-class-20261025T171524382241Z/cpp-class/consumer.hepta"
int32_t __hepta_cb_v83 = (int32_t)INT64_C(0);
#line 28 "/workspace/scratch/c7c6ee414a6c/hepta-research/artifacts/cpp-class-20261025T171524382241Z/cpp-class/consumer.hepta"
int64_t __hepta_cb_v84 = h_initial;
#line 28 "/workspace/scratch/c7c6ee414a6c/hepta-research/artifacts/cpp-class-20261025T171524382241Z/cpp-class/consumer.hepta"
__hepta_cb_aggregate_0 __hepta_cb_v85 = __hepta_cb_fn_M71e525fea2e87b14_ScalarState_new(__hepta_cb_v81, __hepta_cb_v82, __hepta_cb_v83, __hepta_cb_v84);
#line 28 "/workspace/scratch/c7c6ee414a6c/hepta-research/artifacts/cpp-class-20261025T171524382241Z/cpp-class/consumer.hepta"
__hepta_cb_aggregate_0 h_state = __hepta_cb_v85;
#line 29 "/workspace/scratch/c7c6ee414a6c/hepta-research/artifacts/cpp-class-20261025T171524382241Z/cpp-class/consumer.hepta"
__hepta_cb_aggregate_0 * __hepta_cb_arg86 = &(h_state);
#line 29 "/workspace/scratch/c7c6ee414a6c/hepta-research/artifacts/cpp-class-20261025T171524382241Z/cpp-class/consumer.hepta"
int64_t __hepta_cb_v87 = h_next;
#line 29 "/workspace/scratch/c7c6ee414a6c/hepta-research/artifacts/cpp-class-20261025T171524382241Z/cpp-class/consumer.hepta"
int64_t __hepta_cb_v88 = __hepta_cb_fn_M71e525fea2e87b14_ScalarState_replace_position(__hepta_cb_arg86, __hepta_cb_v87);
#line 30 "/workspace/scratch/c7c6ee414a6c/hepta-research/artifacts/cpp-class-20261025T171524382241Z/cpp-class/consumer.hepta"
const __hepta_cb_aggregate_0 * __hepta_cb_arg89 = &(h_state);
#line 30 "/workspace/scratch/c7c6ee414a6c/hepta-research/artifacts/cpp-class-20261025T171524382241Z/cpp-class/consumer.hepta"
int64_t __hepta_cb_v90 = __hepta_cb_fn_M71e525fea2e87b14_ScalarState_position_value(__hepta_cb_arg89);
#line 30 "/workspace/scratch/c7c6ee414a6c/hepta-research/artifacts/cpp-class-20261025T171524382241Z/cpp-class/consumer.hepta"
return __hepta_cb_v90;
#line 30 "/workspace/scratch/c7c6ee414a6c/hepta-research/artifacts/cpp-class-20261025T171524382241Z/cpp-class/consumer.hepta"
}
#line 33 "/workspace/scratch/c7c6ee414a6c/hepta-research/artifacts/cpp-class-20261025T171524382241Z/cpp-class/consumer.hepta"
int32_t state_guard(uint32_t h_word, uint64_t h_wide, int32_t h_balance, int64_t h_position, uint32_t h_step, uint64_t h_mix, int32_t h_lower, int32_t h_upper, int64_t h_next) {
#line 35 "/workspace/scratch/c7c6ee414a6c/hepta-research/artifacts/cpp-class-20261025T171524382241Z/cpp-class/consumer.hepta"
uint32_t __hepta_cb_v91 = h_word;
#line 35 "/workspace/scratch/c7c6ee414a6c/hepta-research/artifacts/cpp-class-20261025T171524382241Z/cpp-class/consumer.hepta"
uint64_t __hepta_cb_v92 = h_wide;
#line 35 "/workspace/scratch/c7c6ee414a6c/hepta-research/artifacts/cpp-class-20261025T171524382241Z/cpp-class/consumer.hepta"
int32_t __hepta_cb_v93 = h_balance;
#line 35 "/workspace/scratch/c7c6ee414a6c/hepta-research/artifacts/cpp-class-20261025T171524382241Z/cpp-class/consumer.hepta"
int64_t __hepta_cb_v94 = h_position;
#line 35 "/workspace/scratch/c7c6ee414a6c/hepta-research/artifacts/cpp-class-20261025T171524382241Z/cpp-class/consumer.hepta"
__hepta_cb_aggregate_0 __hepta_cb_v95 = __hepta_cb_fn_M71e525fea2e87b14_ScalarState_new(__hepta_cb_v91, __hepta_cb_v92, __hepta_cb_v93, __hepta_cb_v94);
#line 35 "/workspace/scratch/c7c6ee414a6c/hepta-research/artifacts/cpp-class-20261025T171524382241Z/cpp-class/consumer.hepta"
__hepta_cb_aggregate_0 h_state = __hepta_cb_v95;
#line 36 "/workspace/scratch/c7c6ee414a6c/hepta-research/artifacts/cpp-class-20261025T171524382241Z/cpp-class/consumer.hepta"
__hepta_cb_aggregate_0 * __hepta_cb_arg96 = &(h_state);
#line 36 "/workspace/scratch/c7c6ee414a6c/hepta-research/artifacts/cpp-class-20261025T171524382241Z/cpp-class/consumer.hepta"
uint32_t __hepta_cb_v97 = h_step;
#line 36 "/workspace/scratch/c7c6ee414a6c/hepta-research/artifacts/cpp-class-20261025T171524382241Z/cpp-class/consumer.hepta"
uint32_t __hepta_cb_v98 = __hepta_cb_fn_M71e525fea2e87b14_ScalarState_add_word(__hepta_cb_arg96, __hepta_cb_v97);
#line 36 "/workspace/scratch/c7c6ee414a6c/hepta-research/artifacts/cpp-class-20261025T171524382241Z/cpp-class/consumer.hepta"
uint32_t h_new_word = __hepta_cb_v98;
#line 37 "/workspace/scratch/c7c6ee414a6c/hepta-research/artifacts/cpp-class-20261025T171524382241Z/cpp-class/consumer.hepta"
const __hepta_cb_aggregate_0 * __hepta_cb_arg99 = &(h_state);
#line 37 "/workspace/scratch/c7c6ee414a6c/hepta-research/artifacts/cpp-class-20261025T171524382241Z/cpp-class/consumer.hepta"
uint32_t __hepta_cb_v100 = __hepta_cb_fn_M71e525fea2e87b14_ScalarState_word_value(__hepta_cb_arg99);
#line 37 "/workspace/scratch/c7c6ee414a6c/hepta-research/artifacts/cpp-class-20261025T171524382241Z/cpp-class/consumer.hepta"
uint32_t __hepta_cb_v101 = h_new_word;
#line 37 "/workspace/scratch/c7c6ee414a6c/hepta-research/artifacts/cpp-class-20261025T171524382241Z/cpp-class/consumer.hepta"
bool __hepta_cb_v102 = (__hepta_cb_v100 != __hepta_cb_v101);
#line 37 "/workspace/scratch/c7c6ee414a6c/hepta-research/artifacts/cpp-class-20261025T171524382241Z/cpp-class/consumer.hepta"
bool __hepta_cb_v103 = __hepta_cb_v102;
#line 37 "/workspace/scratch/c7c6ee414a6c/hepta-research/artifacts/cpp-class-20261025T171524382241Z/cpp-class/consumer.hepta"
if (!__hepta_cb_v103) { const __hepta_cb_aggregate_0 * __hepta_cb_arg104 = &(h_state); uint64_t __hepta_cb_v105 = __hepta_cb_fn_M71e525fea2e87b14_ScalarState_wide_value(__hepta_cb_arg104); uint64_t __hepta_cb_v106 = h_wide; bool __hepta_cb_v107 = (__hepta_cb_v105 != __hepta_cb_v106); __hepta_cb_v103 = __hepta_cb_v107; }
#line 37 "/workspace/scratch/c7c6ee414a6c/hepta-research/artifacts/cpp-class-20261025T171524382241Z/cpp-class/consumer.hepta"
bool __hepta_cb_v108 = __hepta_cb_v103;
#line 37 "/workspace/scratch/c7c6ee414a6c/hepta-research/artifacts/cpp-class-20261025T171524382241Z/cpp-class/consumer.hepta"
if (!__hepta_cb_v108) { const __hepta_cb_aggregate_0 * __hepta_cb_arg109 = &(h_state); int32_t __hepta_cb_v110 = __hepta_cb_fn_M71e525fea2e87b14_ScalarState_balance_value(__hepta_cb_arg109); int32_t __hepta_cb_v111 = h_balance; bool __hepta_cb_v112 = (__hepta_cb_v110 != __hepta_cb_v111); __hepta_cb_v108 = __hepta_cb_v112; }
#line 37 "/workspace/scratch/c7c6ee414a6c/hepta-research/artifacts/cpp-class-20261025T171524382241Z/cpp-class/consumer.hepta"
bool __hepta_cb_v113 = __hepta_cb_v108;
#line 37 "/workspace/scratch/c7c6ee414a6c/hepta-research/artifacts/cpp-class-20261025T171524382241Z/cpp-class/consumer.hepta"
if (!__hepta_cb_v113) { const __hepta_cb_aggregate_0 * __hepta_cb_arg114 = &(h_state); int64_t __hepta_cb_v115 = __hepta_cb_fn_M71e525fea2e87b14_ScalarState_position_value(__hepta_cb_arg114); int64_t __hepta_cb_v116 = h_position; bool __hepta_cb_v117 = (__hepta_cb_v115 != __hepta_cb_v116); __hepta_cb_v113 = __hepta_cb_v117; }
#line 37 "/workspace/scratch/c7c6ee414a6c/hepta-research/artifacts/cpp-class-20261025T171524382241Z/cpp-class/consumer.hepta"
if (__hepta_cb_v113) { 
#line 39 "/workspace/scratch/c7c6ee414a6c/hepta-research/artifacts/cpp-class-20261025T171524382241Z/cpp-class/consumer.hepta"
int32_t __hepta_cb_v118 = (int32_t)INT64_C(1);
#line 39 "/workspace/scratch/c7c6ee414a6c/hepta-research/artifacts/cpp-class-20261025T171524382241Z/cpp-class/consumer.hepta"
return __hepta_cb_v118; } else {  }
#line 41 "/workspace/scratch/c7c6ee414a6c/hepta-research/artifacts/cpp-class-20261025T171524382241Z/cpp-class/consumer.hepta"
__hepta_cb_aggregate_0 * __hepta_cb_arg119 = &(h_state);
#line 41 "/workspace/scratch/c7c6ee414a6c/hepta-research/artifacts/cpp-class-20261025T171524382241Z/cpp-class/consumer.hepta"
uint64_t __hepta_cb_v120 = h_mix;
#line 41 "/workspace/scratch/c7c6ee414a6c/hepta-research/artifacts/cpp-class-20261025T171524382241Z/cpp-class/consumer.hepta"
uint64_t __hepta_cb_v121 = __hepta_cb_fn_M71e525fea2e87b14_ScalarState_mix(__hepta_cb_arg119, __hepta_cb_v120);
#line 41 "/workspace/scratch/c7c6ee414a6c/hepta-research/artifacts/cpp-class-20261025T171524382241Z/cpp-class/consumer.hepta"
uint64_t h_new_wide = __hepta_cb_v121;
#line 42 "/workspace/scratch/c7c6ee414a6c/hepta-research/artifacts/cpp-class-20261025T171524382241Z/cpp-class/consumer.hepta"
const __hepta_cb_aggregate_0 * __hepta_cb_arg122 = &(h_state);
#line 42 "/workspace/scratch/c7c6ee414a6c/hepta-research/artifacts/cpp-class-20261025T171524382241Z/cpp-class/consumer.hepta"
uint32_t __hepta_cb_v123 = __hepta_cb_fn_M71e525fea2e87b14_ScalarState_word_value(__hepta_cb_arg122);
#line 42 "/workspace/scratch/c7c6ee414a6c/hepta-research/artifacts/cpp-class-20261025T171524382241Z/cpp-class/consumer.hepta"
uint32_t __hepta_cb_v124 = h_new_word;
#line 42 "/workspace/scratch/c7c6ee414a6c/hepta-research/artifacts/cpp-class-20261025T171524382241Z/cpp-class/consumer.hepta"
bool __hepta_cb_v125 = (__hepta_cb_v123 != __hepta_cb_v124);
#line 42 "/workspace/scratch/c7c6ee414a6c/hepta-research/artifacts/cpp-class-20261025T171524382241Z/cpp-class/consumer.hepta"
bool __hepta_cb_v126 = __hepta_cb_v125;
#line 42 "/workspace/scratch/c7c6ee414a6c/hepta-research/artifacts/cpp-class-20261025T171524382241Z/cpp-class/consumer.hepta"
if (!__hepta_cb_v126) { const __hepta_cb_aggregate_0 * __hepta_cb_arg127 = &(h_state); uint64_t __hepta_cb_v128 = __hepta_cb_fn_M71e525fea2e87b14_ScalarState_wide_value(__hepta_cb_arg127); uint64_t __hepta_cb_v129 = h_new_wide; bool __hepta_cb_v130 = (__hepta_cb_v128 != __hepta_cb_v129); __hepta_cb_v126 = __hepta_cb_v130; }
#line 42 "/workspace/scratch/c7c6ee414a6c/hepta-research/artifacts/cpp-class-20261025T171524382241Z/cpp-class/consumer.hepta"
bool __hepta_cb_v131 = __hepta_cb_v126;
#line 42 "/workspace/scratch/c7c6ee414a6c/hepta-research/artifacts/cpp-class-20261025T171524382241Z/cpp-class/consumer.hepta"
if (!__hepta_cb_v131) { const __hepta_cb_aggregate_0 * __hepta_cb_arg132 = &(h_state); int32_t __hepta_cb_v133 = __hepta_cb_fn_M71e525fea2e87b14_ScalarState_balance_value(__hepta_cb_arg132); int32_t __hepta_cb_v134 = h_balance; bool __hepta_cb_v135 = (__hepta_cb_v133 != __hepta_cb_v134); __hepta_cb_v131 = __hepta_cb_v135; }
#line 42 "/workspace/scratch/c7c6ee414a6c/hepta-research/artifacts/cpp-class-20261025T171524382241Z/cpp-class/consumer.hepta"
bool __hepta_cb_v136 = __hepta_cb_v131;
#line 42 "/workspace/scratch/c7c6ee414a6c/hepta-research/artifacts/cpp-class-20261025T171524382241Z/cpp-class/consumer.hepta"
if (!__hepta_cb_v136) { const __hepta_cb_aggregate_0 * __hepta_cb_arg137 = &(h_state); int64_t __hepta_cb_v138 = __hepta_cb_fn_M71e525fea2e87b14_ScalarState_position_value(__hepta_cb_arg137); int64_t __hepta_cb_v139 = h_position; bool __hepta_cb_v140 = (__hepta_cb_v138 != __hepta_cb_v139); __hepta_cb_v136 = __hepta_cb_v140; }
#line 42 "/workspace/scratch/c7c6ee414a6c/hepta-research/artifacts/cpp-class-20261025T171524382241Z/cpp-class/consumer.hepta"
if (__hepta_cb_v136) { 
#line 44 "/workspace/scratch/c7c6ee414a6c/hepta-research/artifacts/cpp-class-20261025T171524382241Z/cpp-class/consumer.hepta"
int32_t __hepta_cb_v141 = (int32_t)INT64_C(2);
#line 44 "/workspace/scratch/c7c6ee414a6c/hepta-research/artifacts/cpp-class-20261025T171524382241Z/cpp-class/consumer.hepta"
return __hepta_cb_v141; } else {  }
#line 46 "/workspace/scratch/c7c6ee414a6c/hepta-research/artifacts/cpp-class-20261025T171524382241Z/cpp-class/consumer.hepta"
__hepta_cb_aggregate_0 * __hepta_cb_arg142 = &(h_state);
#line 46 "/workspace/scratch/c7c6ee414a6c/hepta-research/artifacts/cpp-class-20261025T171524382241Z/cpp-class/consumer.hepta"
int32_t __hepta_cb_v143 = h_lower;
#line 46 "/workspace/scratch/c7c6ee414a6c/hepta-research/artifacts/cpp-class-20261025T171524382241Z/cpp-class/consumer.hepta"
int32_t __hepta_cb_v144 = h_upper;
#line 46 "/workspace/scratch/c7c6ee414a6c/hepta-research/artifacts/cpp-class-20261025T171524382241Z/cpp-class/consumer.hepta"
int32_t __hepta_cb_v145 = __hepta_cb_fn_M71e525fea2e87b14_ScalarState_clamp_balance(__hepta_cb_arg142, __hepta_cb_v143, __hepta_cb_v144);
#line 46 "/workspace/scratch/c7c6ee414a6c/hepta-research/artifacts/cpp-class-20261025T171524382241Z/cpp-class/consumer.hepta"
int32_t h_new_balance = __hepta_cb_v145;
#line 47 "/workspace/scratch/c7c6ee414a6c/hepta-research/artifacts/cpp-class-20261025T171524382241Z/cpp-class/consumer.hepta"
const __hepta_cb_aggregate_0 * __hepta_cb_arg146 = &(h_state);
#line 47 "/workspace/scratch/c7c6ee414a6c/hepta-research/artifacts/cpp-class-20261025T171524382241Z/cpp-class/consumer.hepta"
uint32_t __hepta_cb_v147 = __hepta_cb_fn_M71e525fea2e87b14_ScalarState_word_value(__hepta_cb_arg146);
#line 47 "/workspace/scratch/c7c6ee414a6c/hepta-research/artifacts/cpp-class-20261025T171524382241Z/cpp-class/consumer.hepta"
uint32_t __hepta_cb_v148 = h_new_word;
#line 47 "/workspace/scratch/c7c6ee414a6c/hepta-research/artifacts/cpp-class-20261025T171524382241Z/cpp-class/consumer.hepta"
bool __hepta_cb_v149 = (__hepta_cb_v147 != __hepta_cb_v148);
#line 47 "/workspace/scratch/c7c6ee414a6c/hepta-research/artifacts/cpp-class-20261025T171524382241Z/cpp-class/consumer.hepta"
bool __hepta_cb_v150 = __hepta_cb_v149;
#line 47 "/workspace/scratch/c7c6ee414a6c/hepta-research/artifacts/cpp-class-20261025T171524382241Z/cpp-class/consumer.hepta"
if (!__hepta_cb_v150) { const __hepta_cb_aggregate_0 * __hepta_cb_arg151 = &(h_state); uint64_t __hepta_cb_v152 = __hepta_cb_fn_M71e525fea2e87b14_ScalarState_wide_value(__hepta_cb_arg151); uint64_t __hepta_cb_v153 = h_new_wide; bool __hepta_cb_v154 = (__hepta_cb_v152 != __hepta_cb_v153); __hepta_cb_v150 = __hepta_cb_v154; }
#line 47 "/workspace/scratch/c7c6ee414a6c/hepta-research/artifacts/cpp-class-20261025T171524382241Z/cpp-class/consumer.hepta"
bool __hepta_cb_v155 = __hepta_cb_v150;
#line 47 "/workspace/scratch/c7c6ee414a6c/hepta-research/artifacts/cpp-class-20261025T171524382241Z/cpp-class/consumer.hepta"
if (!__hepta_cb_v155) { const __hepta_cb_aggregate_0 * __hepta_cb_arg156 = &(h_state); int32_t __hepta_cb_v157 = __hepta_cb_fn_M71e525fea2e87b14_ScalarState_balance_value(__hepta_cb_arg156); int32_t __hepta_cb_v158 = h_new_balance; bool __hepta_cb_v159 = (__hepta_cb_v157 != __hepta_cb_v158); __hepta_cb_v155 = __hepta_cb_v159; }
#line 47 "/workspace/scratch/c7c6ee414a6c/hepta-research/artifacts/cpp-class-20261025T171524382241Z/cpp-class/consumer.hepta"
bool __hepta_cb_v160 = __hepta_cb_v155;
#line 47 "/workspace/scratch/c7c6ee414a6c/hepta-research/artifacts/cpp-class-20261025T171524382241Z/cpp-class/consumer.hepta"
if (!__hepta_cb_v160) { const __hepta_cb_aggregate_0 * __hepta_cb_arg161 = &(h_state); int64_t __hepta_cb_v162 = __hepta_cb_fn_M71e525fea2e87b14_ScalarState_position_value(__hepta_cb_arg161); int64_t __hepta_cb_v163 = h_position; bool __hepta_cb_v164 = (__hepta_cb_v162 != __hepta_cb_v163); __hepta_cb_v160 = __hepta_cb_v164; }
#line 47 "/workspace/scratch/c7c6ee414a6c/hepta-research/artifacts/cpp-class-20261025T171524382241Z/cpp-class/consumer.hepta"
if (__hepta_cb_v160) { 
#line 49 "/workspace/scratch/c7c6ee414a6c/hepta-research/artifacts/cpp-class-20261025T171524382241Z/cpp-class/consumer.hepta"
int32_t __hepta_cb_v165 = (int32_t)INT64_C(3);
#line 49 "/workspace/scratch/c7c6ee414a6c/hepta-research/artifacts/cpp-class-20261025T171524382241Z/cpp-class/consumer.hepta"
return __hepta_cb_v165; } else {  }
#line 51 "/workspace/scratch/c7c6ee414a6c/hepta-research/artifacts/cpp-class-20261025T171524382241Z/cpp-class/consumer.hepta"
__hepta_cb_aggregate_0 * __hepta_cb_arg166 = &(h_state);
#line 51 "/workspace/scratch/c7c6ee414a6c/hepta-research/artifacts/cpp-class-20261025T171524382241Z/cpp-class/consumer.hepta"
int64_t __hepta_cb_v167 = h_next;
#line 51 "/workspace/scratch/c7c6ee414a6c/hepta-research/artifacts/cpp-class-20261025T171524382241Z/cpp-class/consumer.hepta"
int64_t __hepta_cb_v168 = __hepta_cb_fn_M71e525fea2e87b14_ScalarState_replace_position(__hepta_cb_arg166, __hepta_cb_v167);
#line 51 "/workspace/scratch/c7c6ee414a6c/hepta-research/artifacts/cpp-class-20261025T171524382241Z/cpp-class/consumer.hepta"
int64_t h_new_position = __hepta_cb_v168;
#line 52 "/workspace/scratch/c7c6ee414a6c/hepta-research/artifacts/cpp-class-20261025T171524382241Z/cpp-class/consumer.hepta"
const __hepta_cb_aggregate_0 * __hepta_cb_arg169 = &(h_state);
#line 52 "/workspace/scratch/c7c6ee414a6c/hepta-research/artifacts/cpp-class-20261025T171524382241Z/cpp-class/consumer.hepta"
uint32_t __hepta_cb_v170 = __hepta_cb_fn_M71e525fea2e87b14_ScalarState_word_value(__hepta_cb_arg169);
#line 52 "/workspace/scratch/c7c6ee414a6c/hepta-research/artifacts/cpp-class-20261025T171524382241Z/cpp-class/consumer.hepta"
uint32_t __hepta_cb_v171 = h_new_word;
#line 52 "/workspace/scratch/c7c6ee414a6c/hepta-research/artifacts/cpp-class-20261025T171524382241Z/cpp-class/consumer.hepta"
bool __hepta_cb_v172 = (__hepta_cb_v170 != __hepta_cb_v171);
#line 52 "/workspace/scratch/c7c6ee414a6c/hepta-research/artifacts/cpp-class-20261025T171524382241Z/cpp-class/consumer.hepta"
bool __hepta_cb_v173 = __hepta_cb_v172;
#line 52 "/workspace/scratch/c7c6ee414a6c/hepta-research/artifacts/cpp-class-20261025T171524382241Z/cpp-class/consumer.hepta"
if (!__hepta_cb_v173) { const __hepta_cb_aggregate_0 * __hepta_cb_arg174 = &(h_state); uint64_t __hepta_cb_v175 = __hepta_cb_fn_M71e525fea2e87b14_ScalarState_wide_value(__hepta_cb_arg174); uint64_t __hepta_cb_v176 = h_new_wide; bool __hepta_cb_v177 = (__hepta_cb_v175 != __hepta_cb_v176); __hepta_cb_v173 = __hepta_cb_v177; }
#line 52 "/workspace/scratch/c7c6ee414a6c/hepta-research/artifacts/cpp-class-20261025T171524382241Z/cpp-class/consumer.hepta"
bool __hepta_cb_v178 = __hepta_cb_v173;
#line 52 "/workspace/scratch/c7c6ee414a6c/hepta-research/artifacts/cpp-class-20261025T171524382241Z/cpp-class/consumer.hepta"
if (!__hepta_cb_v178) { const __hepta_cb_aggregate_0 * __hepta_cb_arg179 = &(h_state); int32_t __hepta_cb_v180 = __hepta_cb_fn_M71e525fea2e87b14_ScalarState_balance_value(__hepta_cb_arg179); int32_t __hepta_cb_v181 = h_new_balance; bool __hepta_cb_v182 = (__hepta_cb_v180 != __hepta_cb_v181); __hepta_cb_v178 = __hepta_cb_v182; }
#line 52 "/workspace/scratch/c7c6ee414a6c/hepta-research/artifacts/cpp-class-20261025T171524382241Z/cpp-class/consumer.hepta"
bool __hepta_cb_v183 = __hepta_cb_v178;
#line 52 "/workspace/scratch/c7c6ee414a6c/hepta-research/artifacts/cpp-class-20261025T171524382241Z/cpp-class/consumer.hepta"
if (!__hepta_cb_v183) { const __hepta_cb_aggregate_0 * __hepta_cb_arg184 = &(h_state); int64_t __hepta_cb_v185 = __hepta_cb_fn_M71e525fea2e87b14_ScalarState_position_value(__hepta_cb_arg184); int64_t __hepta_cb_v186 = h_new_position; bool __hepta_cb_v187 = (__hepta_cb_v185 != __hepta_cb_v186); __hepta_cb_v183 = __hepta_cb_v187; }
#line 52 "/workspace/scratch/c7c6ee414a6c/hepta-research/artifacts/cpp-class-20261025T171524382241Z/cpp-class/consumer.hepta"
if (__hepta_cb_v183) { 
#line 54 "/workspace/scratch/c7c6ee414a6c/hepta-research/artifacts/cpp-class-20261025T171524382241Z/cpp-class/consumer.hepta"
int32_t __hepta_cb_v188 = (int32_t)INT64_C(4);
#line 54 "/workspace/scratch/c7c6ee414a6c/hepta-research/artifacts/cpp-class-20261025T171524382241Z/cpp-class/consumer.hepta"
return __hepta_cb_v188; } else {  }
#line 56 "/workspace/scratch/c7c6ee414a6c/hepta-research/artifacts/cpp-class-20261025T171524382241Z/cpp-class/consumer.hepta"
int32_t __hepta_cb_v189 = (int32_t)INT64_C(0);
#line 56 "/workspace/scratch/c7c6ee414a6c/hepta-research/artifacts/cpp-class-20261025T171524382241Z/cpp-class/consumer.hepta"
return __hepta_cb_v189;
#line 56 "/workspace/scratch/c7c6ee414a6c/hepta-research/artifacts/cpp-class-20261025T171524382241Z/cpp-class/consumer.hepta"
}
