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
typedef struct { uint32_t h_state; } __hepta_cb_aggregate_0;
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



__hepta_cb_aggregate_0 __hepta_cb_fn_Mc866f98b7c09dcac_Mixer_new(uint32_t h_arg0);
uint32_t __hepta_cb_fn_Mc866f98b7c09dcac_Mixer_advance(__hepta_cb_aggregate_0 *h_receiver, uint32_t h_arg0);
uint32_t __hepta_cb_fn_Mc866f98b7c09dcac_Mixer_checksum(const __hepta_cb_aggregate_0 *h_receiver, uint32_t h_arg0);
uint32_t __hepta_cb_fn_Mc866f98b7c09dcac_Mixer_drain(__hepta_cb_aggregate_0 *h_receiver, uint32_t h_arg0);
uint32_t __hepta_cb_fn_Mc866f98b7c09dcac_Mixer_shadowed(const __hepta_cb_aggregate_0 *h_receiver, uint32_t h_arg0);
uint32_t mixer_trace(uint32_t h_seed, uint32_t h_first_count, uint32_t h_second_count);
uint32_t mixer_read_guard(uint32_t h_seed, uint32_t h_count);
#line 8 "/workspace/scratch/100b1728036f/Hepta-work/evidence/full-scale-20261026/qualified/cpp-extensions/class/mutation/mixer.hepta"
__hepta_cb_aggregate_0 __hepta_cb_fn_Mc866f98b7c09dcac_Mixer_new(uint32_t h_arg0) {
#line 9 "/workspace/scratch/100b1728036f/Hepta-work/evidence/full-scale-20261026/qualified/cpp-extensions/class/mutation/mixer.hepta"
uint32_t __hepta_cb_v1 = h_arg0;
#line 9 "/workspace/scratch/100b1728036f/Hepta-work/evidence/full-scale-20261026/qualified/cpp-extensions/class/mutation/mixer.hepta"
__hepta_cb_aggregate_0 __hepta_cb_v2 = (__hepta_cb_aggregate_0){ .h_state = __hepta_cb_v1 };
#line 9 "/workspace/scratch/100b1728036f/Hepta-work/evidence/full-scale-20261026/qualified/cpp-extensions/class/mutation/mixer.hepta"
return __hepta_cb_v2;
#line 9 "/workspace/scratch/100b1728036f/Hepta-work/evidence/full-scale-20261026/qualified/cpp-extensions/class/mutation/mixer.hepta"
}
#line 12 "/workspace/scratch/100b1728036f/Hepta-work/evidence/full-scale-20261026/qualified/cpp-extensions/class/mutation/mixer.hepta"
uint32_t __hepta_cb_fn_Mc866f98b7c09dcac_Mixer_advance(__hepta_cb_aggregate_0 *h_receiver, uint32_t h_arg0) {
#line 13 "/workspace/scratch/100b1728036f/Hepta-work/evidence/full-scale-20261026/qualified/cpp-extensions/class/mutation/mixer.hepta"
uint32_t __hepta_cb_v3 = ((*h_receiver)).h_state;
#line 13 "/workspace/scratch/100b1728036f/Hepta-work/evidence/full-scale-20261026/qualified/cpp-extensions/class/mutation/mixer.hepta"
uint32_t h_localbinding0 = __hepta_cb_v3;
#line 14 "/workspace/scratch/100b1728036f/Hepta-work/evidence/full-scale-20261026/qualified/cpp-extensions/class/mutation/mixer.hepta"
uint32_t __hepta_cb_v4 = (uint32_t)UINT64_C(0);
#line 14 "/workspace/scratch/100b1728036f/Hepta-work/evidence/full-scale-20261026/qualified/cpp-extensions/class/mutation/mixer.hepta"
uint32_t h_hepta_for_372_localbinding1 = __hepta_cb_v4;
#line 15 "/workspace/scratch/100b1728036f/Hepta-work/evidence/full-scale-20261026/qualified/cpp-extensions/class/mutation/mixer.hepta"
while (true) { uint32_t __hepta_cb_v5 = h_hepta_for_372_localbinding1; uint32_t __hepta_cb_v6 = h_arg0; bool __hepta_cb_v7 = (__hepta_cb_v5 < __hepta_cb_v6); if (!__hepta_cb_v7) break; 
#line 16 "/workspace/scratch/100b1728036f/Hepta-work/evidence/full-scale-20261026/qualified/cpp-extensions/class/mutation/mixer.hepta"
uint32_t __hepta_cb_v8 = h_localbinding0;
#line 16 "/workspace/scratch/100b1728036f/Hepta-work/evidence/full-scale-20261026/qualified/cpp-extensions/class/mutation/mixer.hepta"
uint32_t __hepta_cb_v9 = (uint32_t)UINT64_C(1664527);
#line 16 "/workspace/scratch/100b1728036f/Hepta-work/evidence/full-scale-20261026/qualified/cpp-extensions/class/mutation/mixer.hepta"
uint32_t __hepta_cb_v10 = __hepta_cb_u32_wrapping_mul(__hepta_cb_v8, __hepta_cb_v9);
#line 16 "/workspace/scratch/100b1728036f/Hepta-work/evidence/full-scale-20261026/qualified/cpp-extensions/class/mutation/mixer.hepta"
uint32_t __hepta_cb_v11 = (uint32_t)UINT64_C(1013904223);
#line 16 "/workspace/scratch/100b1728036f/Hepta-work/evidence/full-scale-20261026/qualified/cpp-extensions/class/mutation/mixer.hepta"
uint32_t __hepta_cb_v12 = __hepta_cb_u32_wrapping_add(__hepta_cb_v10, __hepta_cb_v11);
#line 16 "/workspace/scratch/100b1728036f/Hepta-work/evidence/full-scale-20261026/qualified/cpp-extensions/class/mutation/mixer.hepta"
h_localbinding0 = __hepta_cb_v12;
#line 17 "/workspace/scratch/100b1728036f/Hepta-work/evidence/full-scale-20261026/qualified/cpp-extensions/class/mutation/mixer.hepta"
uint32_t __hepta_cb_v13 = h_hepta_for_372_localbinding1;
#line 17 "/workspace/scratch/100b1728036f/Hepta-work/evidence/full-scale-20261026/qualified/cpp-extensions/class/mutation/mixer.hepta"
uint32_t __hepta_cb_v14 = (uint32_t)UINT64_C(1);
#line 17 "/workspace/scratch/100b1728036f/Hepta-work/evidence/full-scale-20261026/qualified/cpp-extensions/class/mutation/mixer.hepta"
uint32_t __hepta_cb_v15 = __hepta_cb_u32_wrapping_add(__hepta_cb_v13, __hepta_cb_v14);
#line 17 "/workspace/scratch/100b1728036f/Hepta-work/evidence/full-scale-20261026/qualified/cpp-extensions/class/mutation/mixer.hepta"
h_hepta_for_372_localbinding1 = __hepta_cb_v15; }
#line 19 "/workspace/scratch/100b1728036f/Hepta-work/evidence/full-scale-20261026/qualified/cpp-extensions/class/mutation/mixer.hepta"
uint32_t __hepta_cb_v16 = h_localbinding0;
#line 19 "/workspace/scratch/100b1728036f/Hepta-work/evidence/full-scale-20261026/qualified/cpp-extensions/class/mutation/mixer.hepta"
((*h_receiver)).h_state = __hepta_cb_v16;
#line 20 "/workspace/scratch/100b1728036f/Hepta-work/evidence/full-scale-20261026/qualified/cpp-extensions/class/mutation/mixer.hepta"
uint32_t __hepta_cb_v17 = ((*h_receiver)).h_state;
#line 20 "/workspace/scratch/100b1728036f/Hepta-work/evidence/full-scale-20261026/qualified/cpp-extensions/class/mutation/mixer.hepta"
return __hepta_cb_v17;
#line 20 "/workspace/scratch/100b1728036f/Hepta-work/evidence/full-scale-20261026/qualified/cpp-extensions/class/mutation/mixer.hepta"
}
#line 23 "/workspace/scratch/100b1728036f/Hepta-work/evidence/full-scale-20261026/qualified/cpp-extensions/class/mutation/mixer.hepta"
uint32_t __hepta_cb_fn_Mc866f98b7c09dcac_Mixer_checksum(const __hepta_cb_aggregate_0 *h_receiver, uint32_t h_arg0) {
#line 24 "/workspace/scratch/100b1728036f/Hepta-work/evidence/full-scale-20261026/qualified/cpp-extensions/class/mutation/mixer.hepta"
uint32_t __hepta_cb_v18 = ((*h_receiver)).h_state;
#line 24 "/workspace/scratch/100b1728036f/Hepta-work/evidence/full-scale-20261026/qualified/cpp-extensions/class/mutation/mixer.hepta"
uint32_t h_localbinding0 = __hepta_cb_v18;
#line 25 "/workspace/scratch/100b1728036f/Hepta-work/evidence/full-scale-20261026/qualified/cpp-extensions/class/mutation/mixer.hepta"
uint32_t __hepta_cb_v19 = h_arg0;
#line 25 "/workspace/scratch/100b1728036f/Hepta-work/evidence/full-scale-20261026/qualified/cpp-extensions/class/mutation/mixer.hepta"
uint32_t h_localbinding1 = __hepta_cb_v19;
#line 26 "/workspace/scratch/100b1728036f/Hepta-work/evidence/full-scale-20261026/qualified/cpp-extensions/class/mutation/mixer.hepta"
while (true) { uint32_t __hepta_cb_v20 = h_localbinding1; uint32_t __hepta_cb_v21 = (uint32_t)UINT64_C(0); bool __hepta_cb_v22 = (__hepta_cb_v20 > __hepta_cb_v21); if (!__hepta_cb_v22) break; 
#line 27 "/workspace/scratch/100b1728036f/Hepta-work/evidence/full-scale-20261026/qualified/cpp-extensions/class/mutation/mixer.hepta"
uint32_t __hepta_cb_v23 = h_localbinding0;
#line 27 "/workspace/scratch/100b1728036f/Hepta-work/evidence/full-scale-20261026/qualified/cpp-extensions/class/mutation/mixer.hepta"
uint32_t __hepta_cb_v24 = h_localbinding1;
#line 27 "/workspace/scratch/100b1728036f/Hepta-work/evidence/full-scale-20261026/qualified/cpp-extensions/class/mutation/mixer.hepta"
uint32_t __hepta_cb_v25 = __hepta_cb_u32_xor(__hepta_cb_v23, __hepta_cb_v24);
#line 27 "/workspace/scratch/100b1728036f/Hepta-work/evidence/full-scale-20261026/qualified/cpp-extensions/class/mutation/mixer.hepta"
h_localbinding0 = __hepta_cb_v25;
#line 28 "/workspace/scratch/100b1728036f/Hepta-work/evidence/full-scale-20261026/qualified/cpp-extensions/class/mutation/mixer.hepta"
uint32_t __hepta_cb_v26 = h_localbinding1;
#line 28 "/workspace/scratch/100b1728036f/Hepta-work/evidence/full-scale-20261026/qualified/cpp-extensions/class/mutation/mixer.hepta"
uint32_t __hepta_cb_v27 = (uint32_t)UINT64_C(1);
#line 28 "/workspace/scratch/100b1728036f/Hepta-work/evidence/full-scale-20261026/qualified/cpp-extensions/class/mutation/mixer.hepta"
uint32_t __hepta_cb_v28 = __hepta_cb_u32_wrapping_sub(__hepta_cb_v26, __hepta_cb_v27);
#line 28 "/workspace/scratch/100b1728036f/Hepta-work/evidence/full-scale-20261026/qualified/cpp-extensions/class/mutation/mixer.hepta"
h_localbinding1 = __hepta_cb_v28; }
#line 30 "/workspace/scratch/100b1728036f/Hepta-work/evidence/full-scale-20261026/qualified/cpp-extensions/class/mutation/mixer.hepta"
uint32_t __hepta_cb_v29 = h_localbinding0;
#line 30 "/workspace/scratch/100b1728036f/Hepta-work/evidence/full-scale-20261026/qualified/cpp-extensions/class/mutation/mixer.hepta"
return __hepta_cb_v29;
#line 30 "/workspace/scratch/100b1728036f/Hepta-work/evidence/full-scale-20261026/qualified/cpp-extensions/class/mutation/mixer.hepta"
}
#line 33 "/workspace/scratch/100b1728036f/Hepta-work/evidence/full-scale-20261026/qualified/cpp-extensions/class/mutation/mixer.hepta"
uint32_t __hepta_cb_fn_Mc866f98b7c09dcac_Mixer_drain(__hepta_cb_aggregate_0 *h_receiver, uint32_t h_arg0) {
#line 34 "/workspace/scratch/100b1728036f/Hepta-work/evidence/full-scale-20261026/qualified/cpp-extensions/class/mutation/mixer.hepta"
uint32_t __hepta_cb_v30 = h_arg0;
#line 34 "/workspace/scratch/100b1728036f/Hepta-work/evidence/full-scale-20261026/qualified/cpp-extensions/class/mutation/mixer.hepta"
uint32_t h_localbinding0 = __hepta_cb_v30;
#line 35 "/workspace/scratch/100b1728036f/Hepta-work/evidence/full-scale-20261026/qualified/cpp-extensions/class/mutation/mixer.hepta"
uint32_t __hepta_cb_v31 = h_localbinding0;
#line 35 "/workspace/scratch/100b1728036f/Hepta-work/evidence/full-scale-20261026/qualified/cpp-extensions/class/mutation/mixer.hepta"
uint32_t __hepta_cb_v32 = (uint32_t)UINT64_C(0);
#line 35 "/workspace/scratch/100b1728036f/Hepta-work/evidence/full-scale-20261026/qualified/cpp-extensions/class/mutation/mixer.hepta"
bool __hepta_cb_v33 = (__hepta_cb_v31 > __hepta_cb_v32);
#line 35 "/workspace/scratch/100b1728036f/Hepta-work/evidence/full-scale-20261026/qualified/cpp-extensions/class/mutation/mixer.hepta"
if (__hepta_cb_v33) { 
#line 36 "/workspace/scratch/100b1728036f/Hepta-work/evidence/full-scale-20261026/qualified/cpp-extensions/class/mutation/mixer.hepta"
uint32_t __hepta_cb_v34 = ((*h_receiver)).h_state;
#line 36 "/workspace/scratch/100b1728036f/Hepta-work/evidence/full-scale-20261026/qualified/cpp-extensions/class/mutation/mixer.hepta"
uint32_t __hepta_cb_v35 = h_localbinding0;
#line 36 "/workspace/scratch/100b1728036f/Hepta-work/evidence/full-scale-20261026/qualified/cpp-extensions/class/mutation/mixer.hepta"
uint32_t __hepta_cb_v36 = __hepta_cb_u32_wrapping_add(__hepta_cb_v34, __hepta_cb_v35);
#line 36 "/workspace/scratch/100b1728036f/Hepta-work/evidence/full-scale-20261026/qualified/cpp-extensions/class/mutation/mixer.hepta"
((*h_receiver)).h_state = __hepta_cb_v36;
#line 37 "/workspace/scratch/100b1728036f/Hepta-work/evidence/full-scale-20261026/qualified/cpp-extensions/class/mutation/mixer.hepta"
uint32_t __hepta_cb_v37 = h_localbinding0;
#line 37 "/workspace/scratch/100b1728036f/Hepta-work/evidence/full-scale-20261026/qualified/cpp-extensions/class/mutation/mixer.hepta"
uint32_t __hepta_cb_v38 = (uint32_t)UINT64_C(1);
#line 37 "/workspace/scratch/100b1728036f/Hepta-work/evidence/full-scale-20261026/qualified/cpp-extensions/class/mutation/mixer.hepta"
uint32_t __hepta_cb_v39 = __hepta_cb_u32_wrapping_sub(__hepta_cb_v37, __hepta_cb_v38);
#line 37 "/workspace/scratch/100b1728036f/Hepta-work/evidence/full-scale-20261026/qualified/cpp-extensions/class/mutation/mixer.hepta"
h_localbinding0 = __hepta_cb_v39;
#line 38 "/workspace/scratch/100b1728036f/Hepta-work/evidence/full-scale-20261026/qualified/cpp-extensions/class/mutation/mixer.hepta"
while (true) { uint32_t __hepta_cb_v40 = h_localbinding0; uint32_t __hepta_cb_v41 = (uint32_t)UINT64_C(0); bool __hepta_cb_v42 = (__hepta_cb_v40 > __hepta_cb_v41); if (!__hepta_cb_v42) break; 
#line 39 "/workspace/scratch/100b1728036f/Hepta-work/evidence/full-scale-20261026/qualified/cpp-extensions/class/mutation/mixer.hepta"
uint32_t __hepta_cb_v43 = ((*h_receiver)).h_state;
#line 39 "/workspace/scratch/100b1728036f/Hepta-work/evidence/full-scale-20261026/qualified/cpp-extensions/class/mutation/mixer.hepta"
uint32_t __hepta_cb_v44 = h_localbinding0;
#line 39 "/workspace/scratch/100b1728036f/Hepta-work/evidence/full-scale-20261026/qualified/cpp-extensions/class/mutation/mixer.hepta"
uint32_t __hepta_cb_v45 = __hepta_cb_u32_wrapping_add(__hepta_cb_v43, __hepta_cb_v44);
#line 39 "/workspace/scratch/100b1728036f/Hepta-work/evidence/full-scale-20261026/qualified/cpp-extensions/class/mutation/mixer.hepta"
((*h_receiver)).h_state = __hepta_cb_v45;
#line 40 "/workspace/scratch/100b1728036f/Hepta-work/evidence/full-scale-20261026/qualified/cpp-extensions/class/mutation/mixer.hepta"
uint32_t __hepta_cb_v46 = h_localbinding0;
#line 40 "/workspace/scratch/100b1728036f/Hepta-work/evidence/full-scale-20261026/qualified/cpp-extensions/class/mutation/mixer.hepta"
uint32_t __hepta_cb_v47 = (uint32_t)UINT64_C(1);
#line 40 "/workspace/scratch/100b1728036f/Hepta-work/evidence/full-scale-20261026/qualified/cpp-extensions/class/mutation/mixer.hepta"
uint32_t __hepta_cb_v48 = __hepta_cb_u32_wrapping_sub(__hepta_cb_v46, __hepta_cb_v47);
#line 40 "/workspace/scratch/100b1728036f/Hepta-work/evidence/full-scale-20261026/qualified/cpp-extensions/class/mutation/mixer.hepta"
h_localbinding0 = __hepta_cb_v48; } } else {  }
#line 43 "/workspace/scratch/100b1728036f/Hepta-work/evidence/full-scale-20261026/qualified/cpp-extensions/class/mutation/mixer.hepta"
uint32_t __hepta_cb_v49 = ((*h_receiver)).h_state;
#line 43 "/workspace/scratch/100b1728036f/Hepta-work/evidence/full-scale-20261026/qualified/cpp-extensions/class/mutation/mixer.hepta"
return __hepta_cb_v49;
#line 43 "/workspace/scratch/100b1728036f/Hepta-work/evidence/full-scale-20261026/qualified/cpp-extensions/class/mutation/mixer.hepta"
}
#line 46 "/workspace/scratch/100b1728036f/Hepta-work/evidence/full-scale-20261026/qualified/cpp-extensions/class/mutation/mixer.hepta"
uint32_t __hepta_cb_fn_Mc866f98b7c09dcac_Mixer_shadowed(const __hepta_cb_aggregate_0 *h_receiver, uint32_t h_arg0) {
#line 47 "/workspace/scratch/100b1728036f/Hepta-work/evidence/full-scale-20261026/qualified/cpp-extensions/class/mutation/mixer.hepta"
uint32_t __hepta_cb_v50 = ((*h_receiver)).h_state;
#line 47 "/workspace/scratch/100b1728036f/Hepta-work/evidence/full-scale-20261026/qualified/cpp-extensions/class/mutation/mixer.hepta"
uint32_t h_localbinding0 = __hepta_cb_v50;
#line 48 "/workspace/scratch/100b1728036f/Hepta-work/evidence/full-scale-20261026/qualified/cpp-extensions/class/mutation/mixer.hepta"
uint32_t __hepta_cb_v51 = (uint32_t)UINT64_C(0);
#line 48 "/workspace/scratch/100b1728036f/Hepta-work/evidence/full-scale-20261026/qualified/cpp-extensions/class/mutation/mixer.hepta"
uint32_t h_hepta_for_1138_localbinding1 = __hepta_cb_v51;
#line 49 "/workspace/scratch/100b1728036f/Hepta-work/evidence/full-scale-20261026/qualified/cpp-extensions/class/mutation/mixer.hepta"
while (true) { uint32_t __hepta_cb_v52 = h_hepta_for_1138_localbinding1; uint32_t __hepta_cb_v53 = h_arg0; bool __hepta_cb_v54 = (__hepta_cb_v52 < __hepta_cb_v53); if (!__hepta_cb_v54) break; 
#line 50 "/workspace/scratch/100b1728036f/Hepta-work/evidence/full-scale-20261026/qualified/cpp-extensions/class/mutation/mixer.hepta"
uint32_t __hepta_cb_v55 = h_localbinding0;
#line 50 "/workspace/scratch/100b1728036f/Hepta-work/evidence/full-scale-20261026/qualified/cpp-extensions/class/mutation/mixer.hepta"
uint32_t __hepta_cb_v56 = h_hepta_for_1138_localbinding1;
#line 50 "/workspace/scratch/100b1728036f/Hepta-work/evidence/full-scale-20261026/qualified/cpp-extensions/class/mutation/mixer.hepta"
uint32_t __hepta_cb_v57 = __hepta_cb_u32_xor(__hepta_cb_v55, __hepta_cb_v56);
#line 50 "/workspace/scratch/100b1728036f/Hepta-work/evidence/full-scale-20261026/qualified/cpp-extensions/class/mutation/mixer.hepta"
h_localbinding0 = __hepta_cb_v57;
#line 51 "/workspace/scratch/100b1728036f/Hepta-work/evidence/full-scale-20261026/qualified/cpp-extensions/class/mutation/mixer.hepta"
uint32_t __hepta_cb_v58 = h_hepta_for_1138_localbinding1;
#line 51 "/workspace/scratch/100b1728036f/Hepta-work/evidence/full-scale-20261026/qualified/cpp-extensions/class/mutation/mixer.hepta"
uint32_t __hepta_cb_v59 = (uint32_t)UINT64_C(1);
#line 51 "/workspace/scratch/100b1728036f/Hepta-work/evidence/full-scale-20261026/qualified/cpp-extensions/class/mutation/mixer.hepta"
uint32_t __hepta_cb_v60 = __hepta_cb_u32_wrapping_add(__hepta_cb_v58, __hepta_cb_v59);
#line 51 "/workspace/scratch/100b1728036f/Hepta-work/evidence/full-scale-20261026/qualified/cpp-extensions/class/mutation/mixer.hepta"
h_hepta_for_1138_localbinding1 = __hepta_cb_v60; }
#line 53 "/workspace/scratch/100b1728036f/Hepta-work/evidence/full-scale-20261026/qualified/cpp-extensions/class/mutation/mixer.hepta"
uint32_t __hepta_cb_v61 = (uint32_t)UINT64_C(0);
#line 53 "/workspace/scratch/100b1728036f/Hepta-work/evidence/full-scale-20261026/qualified/cpp-extensions/class/mutation/mixer.hepta"
uint32_t h_hepta_for_1242_localbinding2 = __hepta_cb_v61;
#line 54 "/workspace/scratch/100b1728036f/Hepta-work/evidence/full-scale-20261026/qualified/cpp-extensions/class/mutation/mixer.hepta"
while (true) { uint32_t __hepta_cb_v62 = h_hepta_for_1242_localbinding2; uint32_t __hepta_cb_v63 = h_arg0; bool __hepta_cb_v64 = (__hepta_cb_v62 < __hepta_cb_v63); if (!__hepta_cb_v64) break; 
#line 55 "/workspace/scratch/100b1728036f/Hepta-work/evidence/full-scale-20261026/qualified/cpp-extensions/class/mutation/mixer.hepta"
uint32_t __hepta_cb_v65 = h_localbinding0;
#line 55 "/workspace/scratch/100b1728036f/Hepta-work/evidence/full-scale-20261026/qualified/cpp-extensions/class/mutation/mixer.hepta"
uint32_t __hepta_cb_v66 = h_hepta_for_1242_localbinding2;
#line 55 "/workspace/scratch/100b1728036f/Hepta-work/evidence/full-scale-20261026/qualified/cpp-extensions/class/mutation/mixer.hepta"
uint32_t __hepta_cb_v67 = __hepta_cb_u32_wrapping_add(__hepta_cb_v65, __hepta_cb_v66);
#line 55 "/workspace/scratch/100b1728036f/Hepta-work/evidence/full-scale-20261026/qualified/cpp-extensions/class/mutation/mixer.hepta"
h_localbinding0 = __hepta_cb_v67;
#line 56 "/workspace/scratch/100b1728036f/Hepta-work/evidence/full-scale-20261026/qualified/cpp-extensions/class/mutation/mixer.hepta"
uint32_t __hepta_cb_v68 = h_hepta_for_1242_localbinding2;
#line 56 "/workspace/scratch/100b1728036f/Hepta-work/evidence/full-scale-20261026/qualified/cpp-extensions/class/mutation/mixer.hepta"
uint32_t __hepta_cb_v69 = (uint32_t)UINT64_C(1);
#line 56 "/workspace/scratch/100b1728036f/Hepta-work/evidence/full-scale-20261026/qualified/cpp-extensions/class/mutation/mixer.hepta"
uint32_t __hepta_cb_v70 = __hepta_cb_u32_wrapping_add(__hepta_cb_v68, __hepta_cb_v69);
#line 56 "/workspace/scratch/100b1728036f/Hepta-work/evidence/full-scale-20261026/qualified/cpp-extensions/class/mutation/mixer.hepta"
h_hepta_for_1242_localbinding2 = __hepta_cb_v70; }
#line 58 "/workspace/scratch/100b1728036f/Hepta-work/evidence/full-scale-20261026/qualified/cpp-extensions/class/mutation/mixer.hepta"
uint32_t __hepta_cb_v71 = h_localbinding0;
#line 58 "/workspace/scratch/100b1728036f/Hepta-work/evidence/full-scale-20261026/qualified/cpp-extensions/class/mutation/mixer.hepta"
return __hepta_cb_v71;
#line 58 "/workspace/scratch/100b1728036f/Hepta-work/evidence/full-scale-20261026/qualified/cpp-extensions/class/mutation/mixer.hepta"
}
#line 4 "/workspace/scratch/100b1728036f/Hepta-work/evidence/full-scale-20261026/qualified/cpp-extensions/class/mutation/consumer.hepta"
uint32_t mixer_trace(uint32_t h_seed, uint32_t h_first_count, uint32_t h_second_count) {
#line 6 "/workspace/scratch/100b1728036f/Hepta-work/evidence/full-scale-20261026/qualified/cpp-extensions/class/mutation/consumer.hepta"
uint32_t __hepta_cb_v72 = h_seed;
#line 6 "/workspace/scratch/100b1728036f/Hepta-work/evidence/full-scale-20261026/qualified/cpp-extensions/class/mutation/consumer.hepta"
__hepta_cb_aggregate_0 __hepta_cb_v73 = __hepta_cb_fn_Mc866f98b7c09dcac_Mixer_new(__hepta_cb_v72);
#line 6 "/workspace/scratch/100b1728036f/Hepta-work/evidence/full-scale-20261026/qualified/cpp-extensions/class/mutation/consumer.hepta"
__hepta_cb_aggregate_0 h_state = __hepta_cb_v73;
#line 7 "/workspace/scratch/100b1728036f/Hepta-work/evidence/full-scale-20261026/qualified/cpp-extensions/class/mutation/consumer.hepta"
__hepta_cb_aggregate_0 __hepta_cb_v74 = h_state;
#line 7 "/workspace/scratch/100b1728036f/Hepta-work/evidence/full-scale-20261026/qualified/cpp-extensions/class/mutation/consumer.hepta"
__hepta_cb_aggregate_0 h_snapshot = __hepta_cb_v74;
#line 8 "/workspace/scratch/100b1728036f/Hepta-work/evidence/full-scale-20261026/qualified/cpp-extensions/class/mutation/consumer.hepta"
__hepta_cb_aggregate_0 * __hepta_cb_arg75 = &(h_state);
#line 8 "/workspace/scratch/100b1728036f/Hepta-work/evidence/full-scale-20261026/qualified/cpp-extensions/class/mutation/consumer.hepta"
uint32_t __hepta_cb_v76 = h_first_count;
#line 8 "/workspace/scratch/100b1728036f/Hepta-work/evidence/full-scale-20261026/qualified/cpp-extensions/class/mutation/consumer.hepta"
uint32_t __hepta_cb_v77 = __hepta_cb_fn_Mc866f98b7c09dcac_Mixer_advance(__hepta_cb_arg75, __hepta_cb_v76);
#line 8 "/workspace/scratch/100b1728036f/Hepta-work/evidence/full-scale-20261026/qualified/cpp-extensions/class/mutation/consumer.hepta"
uint32_t h_first = __hepta_cb_v77;
#line 9 "/workspace/scratch/100b1728036f/Hepta-work/evidence/full-scale-20261026/qualified/cpp-extensions/class/mutation/consumer.hepta"
const __hepta_cb_aggregate_0 * __hepta_cb_arg78 = &(h_state);
#line 9 "/workspace/scratch/100b1728036f/Hepta-work/evidence/full-scale-20261026/qualified/cpp-extensions/class/mutation/consumer.hepta"
uint32_t __hepta_cb_v79 = h_second_count;
#line 9 "/workspace/scratch/100b1728036f/Hepta-work/evidence/full-scale-20261026/qualified/cpp-extensions/class/mutation/consumer.hepta"
uint32_t __hepta_cb_v80 = __hepta_cb_fn_Mc866f98b7c09dcac_Mixer_checksum(__hepta_cb_arg78, __hepta_cb_v79);
#line 9 "/workspace/scratch/100b1728036f/Hepta-work/evidence/full-scale-20261026/qualified/cpp-extensions/class/mutation/consumer.hepta"
uint32_t h_checksum = __hepta_cb_v80;
#line 10 "/workspace/scratch/100b1728036f/Hepta-work/evidence/full-scale-20261026/qualified/cpp-extensions/class/mutation/consumer.hepta"
__hepta_cb_aggregate_0 * __hepta_cb_arg81 = &(h_state);
#line 10 "/workspace/scratch/100b1728036f/Hepta-work/evidence/full-scale-20261026/qualified/cpp-extensions/class/mutation/consumer.hepta"
uint32_t __hepta_cb_v82 = h_second_count;
#line 10 "/workspace/scratch/100b1728036f/Hepta-work/evidence/full-scale-20261026/qualified/cpp-extensions/class/mutation/consumer.hepta"
uint32_t __hepta_cb_v83 = __hepta_cb_fn_Mc866f98b7c09dcac_Mixer_drain(__hepta_cb_arg81, __hepta_cb_v82);
#line 10 "/workspace/scratch/100b1728036f/Hepta-work/evidence/full-scale-20261026/qualified/cpp-extensions/class/mutation/consumer.hepta"
uint32_t h_drained = __hepta_cb_v83;
#line 11 "/workspace/scratch/100b1728036f/Hepta-work/evidence/full-scale-20261026/qualified/cpp-extensions/class/mutation/consumer.hepta"
__hepta_cb_aggregate_0 * __hepta_cb_arg84 = &(h_state);
#line 11 "/workspace/scratch/100b1728036f/Hepta-work/evidence/full-scale-20261026/qualified/cpp-extensions/class/mutation/consumer.hepta"
uint32_t __hepta_cb_v85 = h_second_count;
#line 11 "/workspace/scratch/100b1728036f/Hepta-work/evidence/full-scale-20261026/qualified/cpp-extensions/class/mutation/consumer.hepta"
uint32_t __hepta_cb_v86 = __hepta_cb_fn_Mc866f98b7c09dcac_Mixer_advance(__hepta_cb_arg84, __hepta_cb_v85);
#line 11 "/workspace/scratch/100b1728036f/Hepta-work/evidence/full-scale-20261026/qualified/cpp-extensions/class/mutation/consumer.hepta"
uint32_t h_second = __hepta_cb_v86;
#line 12 "/workspace/scratch/100b1728036f/Hepta-work/evidence/full-scale-20261026/qualified/cpp-extensions/class/mutation/consumer.hepta"
uint32_t __hepta_cb_v87 = h_first;
#line 12 "/workspace/scratch/100b1728036f/Hepta-work/evidence/full-scale-20261026/qualified/cpp-extensions/class/mutation/consumer.hepta"
uint32_t __hepta_cb_v88 = h_checksum;
#line 12 "/workspace/scratch/100b1728036f/Hepta-work/evidence/full-scale-20261026/qualified/cpp-extensions/class/mutation/consumer.hepta"
uint32_t __hepta_cb_v89 = __hepta_cb_u32_xor(__hepta_cb_v87, __hepta_cb_v88);
#line 12 "/workspace/scratch/100b1728036f/Hepta-work/evidence/full-scale-20261026/qualified/cpp-extensions/class/mutation/consumer.hepta"
uint32_t __hepta_cb_v90 = h_drained;
#line 12 "/workspace/scratch/100b1728036f/Hepta-work/evidence/full-scale-20261026/qualified/cpp-extensions/class/mutation/consumer.hepta"
uint32_t __hepta_cb_v91 = __hepta_cb_u32_xor(__hepta_cb_v89, __hepta_cb_v90);
#line 12 "/workspace/scratch/100b1728036f/Hepta-work/evidence/full-scale-20261026/qualified/cpp-extensions/class/mutation/consumer.hepta"
uint32_t __hepta_cb_v92 = h_second;
#line 12 "/workspace/scratch/100b1728036f/Hepta-work/evidence/full-scale-20261026/qualified/cpp-extensions/class/mutation/consumer.hepta"
uint32_t __hepta_cb_v93 = __hepta_cb_u32_xor(__hepta_cb_v91, __hepta_cb_v92);
#line 12 "/workspace/scratch/100b1728036f/Hepta-work/evidence/full-scale-20261026/qualified/cpp-extensions/class/mutation/consumer.hepta"
const __hepta_cb_aggregate_0 * __hepta_cb_arg94 = &(h_snapshot);
#line 12 "/workspace/scratch/100b1728036f/Hepta-work/evidence/full-scale-20261026/qualified/cpp-extensions/class/mutation/consumer.hepta"
uint32_t __hepta_cb_v95 = h_first_count;
#line 12 "/workspace/scratch/100b1728036f/Hepta-work/evidence/full-scale-20261026/qualified/cpp-extensions/class/mutation/consumer.hepta"
uint32_t __hepta_cb_v96 = __hepta_cb_fn_Mc866f98b7c09dcac_Mixer_shadowed(__hepta_cb_arg94, __hepta_cb_v95);
#line 12 "/workspace/scratch/100b1728036f/Hepta-work/evidence/full-scale-20261026/qualified/cpp-extensions/class/mutation/consumer.hepta"
uint32_t __hepta_cb_v97 = __hepta_cb_u32_xor(__hepta_cb_v93, __hepta_cb_v96);
#line 12 "/workspace/scratch/100b1728036f/Hepta-work/evidence/full-scale-20261026/qualified/cpp-extensions/class/mutation/consumer.hepta"
return __hepta_cb_v97;
#line 12 "/workspace/scratch/100b1728036f/Hepta-work/evidence/full-scale-20261026/qualified/cpp-extensions/class/mutation/consumer.hepta"
}
#line 15 "/workspace/scratch/100b1728036f/Hepta-work/evidence/full-scale-20261026/qualified/cpp-extensions/class/mutation/consumer.hepta"
uint32_t mixer_read_guard(uint32_t h_seed, uint32_t h_count) {
#line 17 "/workspace/scratch/100b1728036f/Hepta-work/evidence/full-scale-20261026/qualified/cpp-extensions/class/mutation/consumer.hepta"
uint32_t __hepta_cb_v98 = h_seed;
#line 17 "/workspace/scratch/100b1728036f/Hepta-work/evidence/full-scale-20261026/qualified/cpp-extensions/class/mutation/consumer.hepta"
__hepta_cb_aggregate_0 __hepta_cb_v99 = __hepta_cb_fn_Mc866f98b7c09dcac_Mixer_new(__hepta_cb_v98);
#line 17 "/workspace/scratch/100b1728036f/Hepta-work/evidence/full-scale-20261026/qualified/cpp-extensions/class/mutation/consumer.hepta"
__hepta_cb_aggregate_0 h_state = __hepta_cb_v99;
#line 18 "/workspace/scratch/100b1728036f/Hepta-work/evidence/full-scale-20261026/qualified/cpp-extensions/class/mutation/consumer.hepta"
const __hepta_cb_aggregate_0 * __hepta_cb_arg100 = &(h_state);
#line 18 "/workspace/scratch/100b1728036f/Hepta-work/evidence/full-scale-20261026/qualified/cpp-extensions/class/mutation/consumer.hepta"
uint32_t __hepta_cb_v101 = h_count;
#line 18 "/workspace/scratch/100b1728036f/Hepta-work/evidence/full-scale-20261026/qualified/cpp-extensions/class/mutation/consumer.hepta"
uint32_t __hepta_cb_v102 = __hepta_cb_fn_Mc866f98b7c09dcac_Mixer_checksum(__hepta_cb_arg100, __hepta_cb_v101);
#line 18 "/workspace/scratch/100b1728036f/Hepta-work/evidence/full-scale-20261026/qualified/cpp-extensions/class/mutation/consumer.hepta"
uint32_t h_checksum = __hepta_cb_v102;
#line 19 "/workspace/scratch/100b1728036f/Hepta-work/evidence/full-scale-20261026/qualified/cpp-extensions/class/mutation/consumer.hepta"
const __hepta_cb_aggregate_0 * __hepta_cb_arg103 = &(h_state);
#line 19 "/workspace/scratch/100b1728036f/Hepta-work/evidence/full-scale-20261026/qualified/cpp-extensions/class/mutation/consumer.hepta"
uint32_t __hepta_cb_v104 = h_count;
#line 19 "/workspace/scratch/100b1728036f/Hepta-work/evidence/full-scale-20261026/qualified/cpp-extensions/class/mutation/consumer.hepta"
uint32_t __hepta_cb_v105 = __hepta_cb_fn_Mc866f98b7c09dcac_Mixer_shadowed(__hepta_cb_arg103, __hepta_cb_v104);
#line 19 "/workspace/scratch/100b1728036f/Hepta-work/evidence/full-scale-20261026/qualified/cpp-extensions/class/mutation/consumer.hepta"
uint32_t h_shadowed = __hepta_cb_v105;
#line 20 "/workspace/scratch/100b1728036f/Hepta-work/evidence/full-scale-20261026/qualified/cpp-extensions/class/mutation/consumer.hepta"
__hepta_cb_aggregate_0 * __hepta_cb_arg106 = &(h_state);
#line 20 "/workspace/scratch/100b1728036f/Hepta-work/evidence/full-scale-20261026/qualified/cpp-extensions/class/mutation/consumer.hepta"
uint32_t __hepta_cb_v107 = (uint32_t)UINT64_C(0);
#line 20 "/workspace/scratch/100b1728036f/Hepta-work/evidence/full-scale-20261026/qualified/cpp-extensions/class/mutation/consumer.hepta"
uint32_t __hepta_cb_v108 = __hepta_cb_fn_Mc866f98b7c09dcac_Mixer_advance(__hepta_cb_arg106, __hepta_cb_v107);
#line 20 "/workspace/scratch/100b1728036f/Hepta-work/evidence/full-scale-20261026/qualified/cpp-extensions/class/mutation/consumer.hepta"
return __hepta_cb_v108;
#line 20 "/workspace/scratch/100b1728036f/Hepta-work/evidence/full-scale-20261026/qualified/cpp-extensions/class/mutation/consumer.hepta"
}
