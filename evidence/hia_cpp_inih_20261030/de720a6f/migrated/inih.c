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

static inline int32_t __hepta_cb_i32_bits(uint64_t x) { uint32_t bits = (uint32_t)x; int32_t out; memcpy(&out, &bits, sizeof out); return out; }
static inline int32_t __hepta_cb_i32_add(int32_t a, int32_t b) { int32_t r; if (__builtin_add_overflow(a,b,&r)) abort(); return r; }
static inline int32_t __hepta_cb_i32_sub(int32_t a, int32_t b) { int32_t r; if (__builtin_sub_overflow(a,b,&r)) abort(); return r; }
static inline int32_t __hepta_cb_i32_mul(int32_t a, int32_t b) { int32_t r; if (__builtin_mul_overflow(a,b,&r)) abort(); return r; }
static inline int32_t __hepta_cb_i32_div(int32_t a, int32_t b) { if (b == 0 || (a == INT32_MIN && b == -1)) abort(); return a / b; }
static inline int32_t __hepta_cb_i32_rem(int32_t a, int32_t b) { if (b == 0 || (a == INT32_MIN && b == -1)) abort(); return a % b; }
static inline int32_t __hepta_cb_i32_wrapping_add(int32_t a, int32_t b) { return __hepta_cb_i32_bits((uint64_t)a + (uint64_t)b); }
static inline int32_t __hepta_cb_i32_wrapping_sub(int32_t a, int32_t b) { return __hepta_cb_i32_bits((uint64_t)a - (uint64_t)b); }
static inline int32_t __hepta_cb_i32_wrapping_mul(int32_t a, int32_t b) { return __hepta_cb_i32_bits((uint64_t)a * (uint64_t)b); }
static inline int32_t __hepta_cb_i32_and(int32_t a, int32_t b) { return __hepta_cb_i32_bits((uint64_t)a & (uint64_t)b); }
static inline int32_t __hepta_cb_i32_or(int32_t a, int32_t b) { return __hepta_cb_i32_bits((uint64_t)a | (uint64_t)b); }
static inline int32_t __hepta_cb_i32_xor(int32_t a, int32_t b) { return __hepta_cb_i32_bits((uint64_t)a ^ (uint64_t)b); }
static inline int32_t __hepta_cb_i32_min(int32_t a, int32_t b) { return a < b ? a : b; }
static inline int32_t __hepta_cb_i32_max(int32_t a, int32_t b) { return a > b ? a : b; }
static inline int32_t __hepta_cb_i32_shl(int32_t a, int32_t b) { if ((uint64_t)b >= sizeof(a)*CHAR_BIT) abort(); return __hepta_cb_i32_bits((uint64_t)a << b); }
static inline int32_t __hepta_cb_i32_shr(int32_t a, int32_t b) { if ((uint64_t)b >= sizeof(a)*CHAR_BIT) abort(); uint64_t x = (uint64_t)(uint32_t)a >> b; if (a < 0 && b) x |= UINT64_MAX << (sizeof(a)*CHAR_BIT - b); return __hepta_cb_i32_bits(x); }



uint32_t hia_ini_bool_step(uint32_t h_state, uint32_t h_byte);
uint32_t hia_ini_bool_finish(uint32_t h_state, uint32_t h_fallback);
uint32_t hia_ini_error_kind(int32_t h_error);
uint32_t hia_ini_callback_action(uint32_t h_has_name, uint32_t h_has_value, uint32_t h_nonempty);
uint32_t hia_ini_lease_step(uint32_t h_phase, uint32_t h_event);
#line 5 "/workspace/scratch/2a90364b341d/inih-native-final01/de720a6f/migrated/inih.hepta"
uint32_t hia_ini_bool_step(uint32_t h_state, uint32_t h_byte) {
#line 6 "/workspace/scratch/2a90364b341d/inih-native-final01/de720a6f/migrated/inih.hepta"
uint32_t __hepta_cb_v1 = h_state;
#line 6 "/workspace/scratch/2a90364b341d/inih-native-final01/de720a6f/migrated/inih.hepta"
uint32_t __hepta_cb_v2 = (uint32_t)UINT64_C(0);
#line 6 "/workspace/scratch/2a90364b341d/inih-native-final01/de720a6f/migrated/inih.hepta"
bool __hepta_cb_v3 = (__hepta_cb_v1 == __hepta_cb_v2);
#line 6 "/workspace/scratch/2a90364b341d/inih-native-final01/de720a6f/migrated/inih.hepta"
bool __hepta_cb_v4 = __hepta_cb_v3;
#line 6 "/workspace/scratch/2a90364b341d/inih-native-final01/de720a6f/migrated/inih.hepta"
if (__hepta_cb_v4) { uint32_t __hepta_cb_v5 = h_byte; uint32_t __hepta_cb_v6 = (uint32_t)UINT64_C(48); bool __hepta_cb_v7 = (__hepta_cb_v5 == __hepta_cb_v6); __hepta_cb_v4 = __hepta_cb_v7; }
#line 6 "/workspace/scratch/2a90364b341d/inih-native-final01/de720a6f/migrated/inih.hepta"
if (__hepta_cb_v4) { 
#line 6 "/workspace/scratch/2a90364b341d/inih-native-final01/de720a6f/migrated/inih.hepta"
uint32_t __hepta_cb_v8 = (uint32_t)UINT64_C(20);
#line 6 "/workspace/scratch/2a90364b341d/inih-native-final01/de720a6f/migrated/inih.hepta"
return __hepta_cb_v8; } else {  }
#line 7 "/workspace/scratch/2a90364b341d/inih-native-final01/de720a6f/migrated/inih.hepta"
uint32_t __hepta_cb_v9 = h_state;
#line 7 "/workspace/scratch/2a90364b341d/inih-native-final01/de720a6f/migrated/inih.hepta"
uint32_t __hepta_cb_v10 = (uint32_t)UINT64_C(0);
#line 7 "/workspace/scratch/2a90364b341d/inih-native-final01/de720a6f/migrated/inih.hepta"
bool __hepta_cb_v11 = (__hepta_cb_v9 == __hepta_cb_v10);
#line 7 "/workspace/scratch/2a90364b341d/inih-native-final01/de720a6f/migrated/inih.hepta"
bool __hepta_cb_v12 = __hepta_cb_v11;
#line 7 "/workspace/scratch/2a90364b341d/inih-native-final01/de720a6f/migrated/inih.hepta"
if (__hepta_cb_v12) { uint32_t __hepta_cb_v13 = h_byte; uint32_t __hepta_cb_v14 = (uint32_t)UINT64_C(49); bool __hepta_cb_v15 = (__hepta_cb_v13 == __hepta_cb_v14); __hepta_cb_v12 = __hepta_cb_v15; }
#line 7 "/workspace/scratch/2a90364b341d/inih-native-final01/de720a6f/migrated/inih.hepta"
if (__hepta_cb_v12) { 
#line 7 "/workspace/scratch/2a90364b341d/inih-native-final01/de720a6f/migrated/inih.hepta"
uint32_t __hepta_cb_v16 = (uint32_t)UINT64_C(10);
#line 7 "/workspace/scratch/2a90364b341d/inih-native-final01/de720a6f/migrated/inih.hepta"
return __hepta_cb_v16; } else {  }
#line 8 "/workspace/scratch/2a90364b341d/inih-native-final01/de720a6f/migrated/inih.hepta"
uint32_t __hepta_cb_v17 = h_state;
#line 8 "/workspace/scratch/2a90364b341d/inih-native-final01/de720a6f/migrated/inih.hepta"
uint32_t __hepta_cb_v18 = (uint32_t)UINT64_C(0);
#line 8 "/workspace/scratch/2a90364b341d/inih-native-final01/de720a6f/migrated/inih.hepta"
bool __hepta_cb_v19 = (__hepta_cb_v17 == __hepta_cb_v18);
#line 8 "/workspace/scratch/2a90364b341d/inih-native-final01/de720a6f/migrated/inih.hepta"
bool __hepta_cb_v20 = __hepta_cb_v19;
#line 8 "/workspace/scratch/2a90364b341d/inih-native-final01/de720a6f/migrated/inih.hepta"
if (__hepta_cb_v20) { uint32_t __hepta_cb_v21 = h_byte; uint32_t __hepta_cb_v22 = (uint32_t)UINT64_C(102); bool __hepta_cb_v23 = (__hepta_cb_v21 == __hepta_cb_v22); __hepta_cb_v20 = __hepta_cb_v23; }
#line 8 "/workspace/scratch/2a90364b341d/inih-native-final01/de720a6f/migrated/inih.hepta"
if (__hepta_cb_v20) { 
#line 8 "/workspace/scratch/2a90364b341d/inih-native-final01/de720a6f/migrated/inih.hepta"
uint32_t __hepta_cb_v24 = (uint32_t)UINT64_C(11);
#line 8 "/workspace/scratch/2a90364b341d/inih-native-final01/de720a6f/migrated/inih.hepta"
return __hepta_cb_v24; } else {  }
#line 9 "/workspace/scratch/2a90364b341d/inih-native-final01/de720a6f/migrated/inih.hepta"
uint32_t __hepta_cb_v25 = h_state;
#line 9 "/workspace/scratch/2a90364b341d/inih-native-final01/de720a6f/migrated/inih.hepta"
uint32_t __hepta_cb_v26 = (uint32_t)UINT64_C(0);
#line 9 "/workspace/scratch/2a90364b341d/inih-native-final01/de720a6f/migrated/inih.hepta"
bool __hepta_cb_v27 = (__hepta_cb_v25 == __hepta_cb_v26);
#line 9 "/workspace/scratch/2a90364b341d/inih-native-final01/de720a6f/migrated/inih.hepta"
bool __hepta_cb_v28 = __hepta_cb_v27;
#line 9 "/workspace/scratch/2a90364b341d/inih-native-final01/de720a6f/migrated/inih.hepta"
if (__hepta_cb_v28) { uint32_t __hepta_cb_v29 = h_byte; uint32_t __hepta_cb_v30 = (uint32_t)UINT64_C(110); bool __hepta_cb_v31 = (__hepta_cb_v29 == __hepta_cb_v30); __hepta_cb_v28 = __hepta_cb_v31; }
#line 9 "/workspace/scratch/2a90364b341d/inih-native-final01/de720a6f/migrated/inih.hepta"
if (__hepta_cb_v28) { 
#line 9 "/workspace/scratch/2a90364b341d/inih-native-final01/de720a6f/migrated/inih.hepta"
uint32_t __hepta_cb_v32 = (uint32_t)UINT64_C(16);
#line 9 "/workspace/scratch/2a90364b341d/inih-native-final01/de720a6f/migrated/inih.hepta"
return __hepta_cb_v32; } else {  }
#line 10 "/workspace/scratch/2a90364b341d/inih-native-final01/de720a6f/migrated/inih.hepta"
uint32_t __hepta_cb_v33 = h_state;
#line 10 "/workspace/scratch/2a90364b341d/inih-native-final01/de720a6f/migrated/inih.hepta"
uint32_t __hepta_cb_v34 = (uint32_t)UINT64_C(0);
#line 10 "/workspace/scratch/2a90364b341d/inih-native-final01/de720a6f/migrated/inih.hepta"
bool __hepta_cb_v35 = (__hepta_cb_v33 == __hepta_cb_v34);
#line 10 "/workspace/scratch/2a90364b341d/inih-native-final01/de720a6f/migrated/inih.hepta"
bool __hepta_cb_v36 = __hepta_cb_v35;
#line 10 "/workspace/scratch/2a90364b341d/inih-native-final01/de720a6f/migrated/inih.hepta"
if (__hepta_cb_v36) { uint32_t __hepta_cb_v37 = h_byte; uint32_t __hepta_cb_v38 = (uint32_t)UINT64_C(111); bool __hepta_cb_v39 = (__hepta_cb_v37 == __hepta_cb_v38); __hepta_cb_v36 = __hepta_cb_v39; }
#line 10 "/workspace/scratch/2a90364b341d/inih-native-final01/de720a6f/migrated/inih.hepta"
if (__hepta_cb_v36) { 
#line 10 "/workspace/scratch/2a90364b341d/inih-native-final01/de720a6f/migrated/inih.hepta"
uint32_t __hepta_cb_v40 = (uint32_t)UINT64_C(8);
#line 10 "/workspace/scratch/2a90364b341d/inih-native-final01/de720a6f/migrated/inih.hepta"
return __hepta_cb_v40; } else {  }
#line 11 "/workspace/scratch/2a90364b341d/inih-native-final01/de720a6f/migrated/inih.hepta"
uint32_t __hepta_cb_v41 = h_state;
#line 11 "/workspace/scratch/2a90364b341d/inih-native-final01/de720a6f/migrated/inih.hepta"
uint32_t __hepta_cb_v42 = (uint32_t)UINT64_C(0);
#line 11 "/workspace/scratch/2a90364b341d/inih-native-final01/de720a6f/migrated/inih.hepta"
bool __hepta_cb_v43 = (__hepta_cb_v41 == __hepta_cb_v42);
#line 11 "/workspace/scratch/2a90364b341d/inih-native-final01/de720a6f/migrated/inih.hepta"
bool __hepta_cb_v44 = __hepta_cb_v43;
#line 11 "/workspace/scratch/2a90364b341d/inih-native-final01/de720a6f/migrated/inih.hepta"
if (__hepta_cb_v44) { uint32_t __hepta_cb_v45 = h_byte; uint32_t __hepta_cb_v46 = (uint32_t)UINT64_C(116); bool __hepta_cb_v47 = (__hepta_cb_v45 == __hepta_cb_v46); __hepta_cb_v44 = __hepta_cb_v47; }
#line 11 "/workspace/scratch/2a90364b341d/inih-native-final01/de720a6f/migrated/inih.hepta"
if (__hepta_cb_v44) { 
#line 11 "/workspace/scratch/2a90364b341d/inih-native-final01/de720a6f/migrated/inih.hepta"
uint32_t __hepta_cb_v48 = (uint32_t)UINT64_C(1);
#line 11 "/workspace/scratch/2a90364b341d/inih-native-final01/de720a6f/migrated/inih.hepta"
return __hepta_cb_v48; } else {  }
#line 12 "/workspace/scratch/2a90364b341d/inih-native-final01/de720a6f/migrated/inih.hepta"
uint32_t __hepta_cb_v49 = h_state;
#line 12 "/workspace/scratch/2a90364b341d/inih-native-final01/de720a6f/migrated/inih.hepta"
uint32_t __hepta_cb_v50 = (uint32_t)UINT64_C(0);
#line 12 "/workspace/scratch/2a90364b341d/inih-native-final01/de720a6f/migrated/inih.hepta"
bool __hepta_cb_v51 = (__hepta_cb_v49 == __hepta_cb_v50);
#line 12 "/workspace/scratch/2a90364b341d/inih-native-final01/de720a6f/migrated/inih.hepta"
bool __hepta_cb_v52 = __hepta_cb_v51;
#line 12 "/workspace/scratch/2a90364b341d/inih-native-final01/de720a6f/migrated/inih.hepta"
if (__hepta_cb_v52) { uint32_t __hepta_cb_v53 = h_byte; uint32_t __hepta_cb_v54 = (uint32_t)UINT64_C(121); bool __hepta_cb_v55 = (__hepta_cb_v53 == __hepta_cb_v54); __hepta_cb_v52 = __hepta_cb_v55; }
#line 12 "/workspace/scratch/2a90364b341d/inih-native-final01/de720a6f/migrated/inih.hepta"
if (__hepta_cb_v52) { 
#line 12 "/workspace/scratch/2a90364b341d/inih-native-final01/de720a6f/migrated/inih.hepta"
uint32_t __hepta_cb_v56 = (uint32_t)UINT64_C(5);
#line 12 "/workspace/scratch/2a90364b341d/inih-native-final01/de720a6f/migrated/inih.hepta"
return __hepta_cb_v56; } else {  }
#line 13 "/workspace/scratch/2a90364b341d/inih-native-final01/de720a6f/migrated/inih.hepta"
uint32_t __hepta_cb_v57 = h_state;
#line 13 "/workspace/scratch/2a90364b341d/inih-native-final01/de720a6f/migrated/inih.hepta"
uint32_t __hepta_cb_v58 = (uint32_t)UINT64_C(1);
#line 13 "/workspace/scratch/2a90364b341d/inih-native-final01/de720a6f/migrated/inih.hepta"
bool __hepta_cb_v59 = (__hepta_cb_v57 == __hepta_cb_v58);
#line 13 "/workspace/scratch/2a90364b341d/inih-native-final01/de720a6f/migrated/inih.hepta"
bool __hepta_cb_v60 = __hepta_cb_v59;
#line 13 "/workspace/scratch/2a90364b341d/inih-native-final01/de720a6f/migrated/inih.hepta"
if (__hepta_cb_v60) { uint32_t __hepta_cb_v61 = h_byte; uint32_t __hepta_cb_v62 = (uint32_t)UINT64_C(114); bool __hepta_cb_v63 = (__hepta_cb_v61 == __hepta_cb_v62); __hepta_cb_v60 = __hepta_cb_v63; }
#line 13 "/workspace/scratch/2a90364b341d/inih-native-final01/de720a6f/migrated/inih.hepta"
if (__hepta_cb_v60) { 
#line 13 "/workspace/scratch/2a90364b341d/inih-native-final01/de720a6f/migrated/inih.hepta"
uint32_t __hepta_cb_v64 = (uint32_t)UINT64_C(2);
#line 13 "/workspace/scratch/2a90364b341d/inih-native-final01/de720a6f/migrated/inih.hepta"
return __hepta_cb_v64; } else {  }
#line 14 "/workspace/scratch/2a90364b341d/inih-native-final01/de720a6f/migrated/inih.hepta"
uint32_t __hepta_cb_v65 = h_state;
#line 14 "/workspace/scratch/2a90364b341d/inih-native-final01/de720a6f/migrated/inih.hepta"
uint32_t __hepta_cb_v66 = (uint32_t)UINT64_C(2);
#line 14 "/workspace/scratch/2a90364b341d/inih-native-final01/de720a6f/migrated/inih.hepta"
bool __hepta_cb_v67 = (__hepta_cb_v65 == __hepta_cb_v66);
#line 14 "/workspace/scratch/2a90364b341d/inih-native-final01/de720a6f/migrated/inih.hepta"
bool __hepta_cb_v68 = __hepta_cb_v67;
#line 14 "/workspace/scratch/2a90364b341d/inih-native-final01/de720a6f/migrated/inih.hepta"
if (__hepta_cb_v68) { uint32_t __hepta_cb_v69 = h_byte; uint32_t __hepta_cb_v70 = (uint32_t)UINT64_C(117); bool __hepta_cb_v71 = (__hepta_cb_v69 == __hepta_cb_v70); __hepta_cb_v68 = __hepta_cb_v71; }
#line 14 "/workspace/scratch/2a90364b341d/inih-native-final01/de720a6f/migrated/inih.hepta"
if (__hepta_cb_v68) { 
#line 14 "/workspace/scratch/2a90364b341d/inih-native-final01/de720a6f/migrated/inih.hepta"
uint32_t __hepta_cb_v72 = (uint32_t)UINT64_C(3);
#line 14 "/workspace/scratch/2a90364b341d/inih-native-final01/de720a6f/migrated/inih.hepta"
return __hepta_cb_v72; } else {  }
#line 15 "/workspace/scratch/2a90364b341d/inih-native-final01/de720a6f/migrated/inih.hepta"
uint32_t __hepta_cb_v73 = h_state;
#line 15 "/workspace/scratch/2a90364b341d/inih-native-final01/de720a6f/migrated/inih.hepta"
uint32_t __hepta_cb_v74 = (uint32_t)UINT64_C(3);
#line 15 "/workspace/scratch/2a90364b341d/inih-native-final01/de720a6f/migrated/inih.hepta"
bool __hepta_cb_v75 = (__hepta_cb_v73 == __hepta_cb_v74);
#line 15 "/workspace/scratch/2a90364b341d/inih-native-final01/de720a6f/migrated/inih.hepta"
bool __hepta_cb_v76 = __hepta_cb_v75;
#line 15 "/workspace/scratch/2a90364b341d/inih-native-final01/de720a6f/migrated/inih.hepta"
if (__hepta_cb_v76) { uint32_t __hepta_cb_v77 = h_byte; uint32_t __hepta_cb_v78 = (uint32_t)UINT64_C(101); bool __hepta_cb_v79 = (__hepta_cb_v77 == __hepta_cb_v78); __hepta_cb_v76 = __hepta_cb_v79; }
#line 15 "/workspace/scratch/2a90364b341d/inih-native-final01/de720a6f/migrated/inih.hepta"
if (__hepta_cb_v76) { 
#line 15 "/workspace/scratch/2a90364b341d/inih-native-final01/de720a6f/migrated/inih.hepta"
uint32_t __hepta_cb_v80 = (uint32_t)UINT64_C(4);
#line 15 "/workspace/scratch/2a90364b341d/inih-native-final01/de720a6f/migrated/inih.hepta"
return __hepta_cb_v80; } else {  }
#line 16 "/workspace/scratch/2a90364b341d/inih-native-final01/de720a6f/migrated/inih.hepta"
uint32_t __hepta_cb_v81 = h_state;
#line 16 "/workspace/scratch/2a90364b341d/inih-native-final01/de720a6f/migrated/inih.hepta"
uint32_t __hepta_cb_v82 = (uint32_t)UINT64_C(5);
#line 16 "/workspace/scratch/2a90364b341d/inih-native-final01/de720a6f/migrated/inih.hepta"
bool __hepta_cb_v83 = (__hepta_cb_v81 == __hepta_cb_v82);
#line 16 "/workspace/scratch/2a90364b341d/inih-native-final01/de720a6f/migrated/inih.hepta"
bool __hepta_cb_v84 = __hepta_cb_v83;
#line 16 "/workspace/scratch/2a90364b341d/inih-native-final01/de720a6f/migrated/inih.hepta"
if (__hepta_cb_v84) { uint32_t __hepta_cb_v85 = h_byte; uint32_t __hepta_cb_v86 = (uint32_t)UINT64_C(101); bool __hepta_cb_v87 = (__hepta_cb_v85 == __hepta_cb_v86); __hepta_cb_v84 = __hepta_cb_v87; }
#line 16 "/workspace/scratch/2a90364b341d/inih-native-final01/de720a6f/migrated/inih.hepta"
if (__hepta_cb_v84) { 
#line 16 "/workspace/scratch/2a90364b341d/inih-native-final01/de720a6f/migrated/inih.hepta"
uint32_t __hepta_cb_v88 = (uint32_t)UINT64_C(6);
#line 16 "/workspace/scratch/2a90364b341d/inih-native-final01/de720a6f/migrated/inih.hepta"
return __hepta_cb_v88; } else {  }
#line 17 "/workspace/scratch/2a90364b341d/inih-native-final01/de720a6f/migrated/inih.hepta"
uint32_t __hepta_cb_v89 = h_state;
#line 17 "/workspace/scratch/2a90364b341d/inih-native-final01/de720a6f/migrated/inih.hepta"
uint32_t __hepta_cb_v90 = (uint32_t)UINT64_C(6);
#line 17 "/workspace/scratch/2a90364b341d/inih-native-final01/de720a6f/migrated/inih.hepta"
bool __hepta_cb_v91 = (__hepta_cb_v89 == __hepta_cb_v90);
#line 17 "/workspace/scratch/2a90364b341d/inih-native-final01/de720a6f/migrated/inih.hepta"
bool __hepta_cb_v92 = __hepta_cb_v91;
#line 17 "/workspace/scratch/2a90364b341d/inih-native-final01/de720a6f/migrated/inih.hepta"
if (__hepta_cb_v92) { uint32_t __hepta_cb_v93 = h_byte; uint32_t __hepta_cb_v94 = (uint32_t)UINT64_C(115); bool __hepta_cb_v95 = (__hepta_cb_v93 == __hepta_cb_v94); __hepta_cb_v92 = __hepta_cb_v95; }
#line 17 "/workspace/scratch/2a90364b341d/inih-native-final01/de720a6f/migrated/inih.hepta"
if (__hepta_cb_v92) { 
#line 17 "/workspace/scratch/2a90364b341d/inih-native-final01/de720a6f/migrated/inih.hepta"
uint32_t __hepta_cb_v96 = (uint32_t)UINT64_C(7);
#line 17 "/workspace/scratch/2a90364b341d/inih-native-final01/de720a6f/migrated/inih.hepta"
return __hepta_cb_v96; } else {  }
#line 18 "/workspace/scratch/2a90364b341d/inih-native-final01/de720a6f/migrated/inih.hepta"
uint32_t __hepta_cb_v97 = h_state;
#line 18 "/workspace/scratch/2a90364b341d/inih-native-final01/de720a6f/migrated/inih.hepta"
uint32_t __hepta_cb_v98 = (uint32_t)UINT64_C(8);
#line 18 "/workspace/scratch/2a90364b341d/inih-native-final01/de720a6f/migrated/inih.hepta"
bool __hepta_cb_v99 = (__hepta_cb_v97 == __hepta_cb_v98);
#line 18 "/workspace/scratch/2a90364b341d/inih-native-final01/de720a6f/migrated/inih.hepta"
bool __hepta_cb_v100 = __hepta_cb_v99;
#line 18 "/workspace/scratch/2a90364b341d/inih-native-final01/de720a6f/migrated/inih.hepta"
if (__hepta_cb_v100) { uint32_t __hepta_cb_v101 = h_byte; uint32_t __hepta_cb_v102 = (uint32_t)UINT64_C(102); bool __hepta_cb_v103 = (__hepta_cb_v101 == __hepta_cb_v102); __hepta_cb_v100 = __hepta_cb_v103; }
#line 18 "/workspace/scratch/2a90364b341d/inih-native-final01/de720a6f/migrated/inih.hepta"
if (__hepta_cb_v100) { 
#line 18 "/workspace/scratch/2a90364b341d/inih-native-final01/de720a6f/migrated/inih.hepta"
uint32_t __hepta_cb_v104 = (uint32_t)UINT64_C(18);
#line 18 "/workspace/scratch/2a90364b341d/inih-native-final01/de720a6f/migrated/inih.hepta"
return __hepta_cb_v104; } else {  }
#line 19 "/workspace/scratch/2a90364b341d/inih-native-final01/de720a6f/migrated/inih.hepta"
uint32_t __hepta_cb_v105 = h_state;
#line 19 "/workspace/scratch/2a90364b341d/inih-native-final01/de720a6f/migrated/inih.hepta"
uint32_t __hepta_cb_v106 = (uint32_t)UINT64_C(8);
#line 19 "/workspace/scratch/2a90364b341d/inih-native-final01/de720a6f/migrated/inih.hepta"
bool __hepta_cb_v107 = (__hepta_cb_v105 == __hepta_cb_v106);
#line 19 "/workspace/scratch/2a90364b341d/inih-native-final01/de720a6f/migrated/inih.hepta"
bool __hepta_cb_v108 = __hepta_cb_v107;
#line 19 "/workspace/scratch/2a90364b341d/inih-native-final01/de720a6f/migrated/inih.hepta"
if (__hepta_cb_v108) { uint32_t __hepta_cb_v109 = h_byte; uint32_t __hepta_cb_v110 = (uint32_t)UINT64_C(110); bool __hepta_cb_v111 = (__hepta_cb_v109 == __hepta_cb_v110); __hepta_cb_v108 = __hepta_cb_v111; }
#line 19 "/workspace/scratch/2a90364b341d/inih-native-final01/de720a6f/migrated/inih.hepta"
if (__hepta_cb_v108) { 
#line 19 "/workspace/scratch/2a90364b341d/inih-native-final01/de720a6f/migrated/inih.hepta"
uint32_t __hepta_cb_v112 = (uint32_t)UINT64_C(9);
#line 19 "/workspace/scratch/2a90364b341d/inih-native-final01/de720a6f/migrated/inih.hepta"
return __hepta_cb_v112; } else {  }
#line 20 "/workspace/scratch/2a90364b341d/inih-native-final01/de720a6f/migrated/inih.hepta"
uint32_t __hepta_cb_v113 = h_state;
#line 20 "/workspace/scratch/2a90364b341d/inih-native-final01/de720a6f/migrated/inih.hepta"
uint32_t __hepta_cb_v114 = (uint32_t)UINT64_C(11);
#line 20 "/workspace/scratch/2a90364b341d/inih-native-final01/de720a6f/migrated/inih.hepta"
bool __hepta_cb_v115 = (__hepta_cb_v113 == __hepta_cb_v114);
#line 20 "/workspace/scratch/2a90364b341d/inih-native-final01/de720a6f/migrated/inih.hepta"
bool __hepta_cb_v116 = __hepta_cb_v115;
#line 20 "/workspace/scratch/2a90364b341d/inih-native-final01/de720a6f/migrated/inih.hepta"
if (__hepta_cb_v116) { uint32_t __hepta_cb_v117 = h_byte; uint32_t __hepta_cb_v118 = (uint32_t)UINT64_C(97); bool __hepta_cb_v119 = (__hepta_cb_v117 == __hepta_cb_v118); __hepta_cb_v116 = __hepta_cb_v119; }
#line 20 "/workspace/scratch/2a90364b341d/inih-native-final01/de720a6f/migrated/inih.hepta"
if (__hepta_cb_v116) { 
#line 20 "/workspace/scratch/2a90364b341d/inih-native-final01/de720a6f/migrated/inih.hepta"
uint32_t __hepta_cb_v120 = (uint32_t)UINT64_C(12);
#line 20 "/workspace/scratch/2a90364b341d/inih-native-final01/de720a6f/migrated/inih.hepta"
return __hepta_cb_v120; } else {  }
#line 21 "/workspace/scratch/2a90364b341d/inih-native-final01/de720a6f/migrated/inih.hepta"
uint32_t __hepta_cb_v121 = h_state;
#line 21 "/workspace/scratch/2a90364b341d/inih-native-final01/de720a6f/migrated/inih.hepta"
uint32_t __hepta_cb_v122 = (uint32_t)UINT64_C(12);
#line 21 "/workspace/scratch/2a90364b341d/inih-native-final01/de720a6f/migrated/inih.hepta"
bool __hepta_cb_v123 = (__hepta_cb_v121 == __hepta_cb_v122);
#line 21 "/workspace/scratch/2a90364b341d/inih-native-final01/de720a6f/migrated/inih.hepta"
bool __hepta_cb_v124 = __hepta_cb_v123;
#line 21 "/workspace/scratch/2a90364b341d/inih-native-final01/de720a6f/migrated/inih.hepta"
if (__hepta_cb_v124) { uint32_t __hepta_cb_v125 = h_byte; uint32_t __hepta_cb_v126 = (uint32_t)UINT64_C(108); bool __hepta_cb_v127 = (__hepta_cb_v125 == __hepta_cb_v126); __hepta_cb_v124 = __hepta_cb_v127; }
#line 21 "/workspace/scratch/2a90364b341d/inih-native-final01/de720a6f/migrated/inih.hepta"
if (__hepta_cb_v124) { 
#line 21 "/workspace/scratch/2a90364b341d/inih-native-final01/de720a6f/migrated/inih.hepta"
uint32_t __hepta_cb_v128 = (uint32_t)UINT64_C(13);
#line 21 "/workspace/scratch/2a90364b341d/inih-native-final01/de720a6f/migrated/inih.hepta"
return __hepta_cb_v128; } else {  }
#line 22 "/workspace/scratch/2a90364b341d/inih-native-final01/de720a6f/migrated/inih.hepta"
uint32_t __hepta_cb_v129 = h_state;
#line 22 "/workspace/scratch/2a90364b341d/inih-native-final01/de720a6f/migrated/inih.hepta"
uint32_t __hepta_cb_v130 = (uint32_t)UINT64_C(13);
#line 22 "/workspace/scratch/2a90364b341d/inih-native-final01/de720a6f/migrated/inih.hepta"
bool __hepta_cb_v131 = (__hepta_cb_v129 == __hepta_cb_v130);
#line 22 "/workspace/scratch/2a90364b341d/inih-native-final01/de720a6f/migrated/inih.hepta"
bool __hepta_cb_v132 = __hepta_cb_v131;
#line 22 "/workspace/scratch/2a90364b341d/inih-native-final01/de720a6f/migrated/inih.hepta"
if (__hepta_cb_v132) { uint32_t __hepta_cb_v133 = h_byte; uint32_t __hepta_cb_v134 = (uint32_t)UINT64_C(115); bool __hepta_cb_v135 = (__hepta_cb_v133 == __hepta_cb_v134); __hepta_cb_v132 = __hepta_cb_v135; }
#line 22 "/workspace/scratch/2a90364b341d/inih-native-final01/de720a6f/migrated/inih.hepta"
if (__hepta_cb_v132) { 
#line 22 "/workspace/scratch/2a90364b341d/inih-native-final01/de720a6f/migrated/inih.hepta"
uint32_t __hepta_cb_v136 = (uint32_t)UINT64_C(14);
#line 22 "/workspace/scratch/2a90364b341d/inih-native-final01/de720a6f/migrated/inih.hepta"
return __hepta_cb_v136; } else {  }
#line 23 "/workspace/scratch/2a90364b341d/inih-native-final01/de720a6f/migrated/inih.hepta"
uint32_t __hepta_cb_v137 = h_state;
#line 23 "/workspace/scratch/2a90364b341d/inih-native-final01/de720a6f/migrated/inih.hepta"
uint32_t __hepta_cb_v138 = (uint32_t)UINT64_C(14);
#line 23 "/workspace/scratch/2a90364b341d/inih-native-final01/de720a6f/migrated/inih.hepta"
bool __hepta_cb_v139 = (__hepta_cb_v137 == __hepta_cb_v138);
#line 23 "/workspace/scratch/2a90364b341d/inih-native-final01/de720a6f/migrated/inih.hepta"
bool __hepta_cb_v140 = __hepta_cb_v139;
#line 23 "/workspace/scratch/2a90364b341d/inih-native-final01/de720a6f/migrated/inih.hepta"
if (__hepta_cb_v140) { uint32_t __hepta_cb_v141 = h_byte; uint32_t __hepta_cb_v142 = (uint32_t)UINT64_C(101); bool __hepta_cb_v143 = (__hepta_cb_v141 == __hepta_cb_v142); __hepta_cb_v140 = __hepta_cb_v143; }
#line 23 "/workspace/scratch/2a90364b341d/inih-native-final01/de720a6f/migrated/inih.hepta"
if (__hepta_cb_v140) { 
#line 23 "/workspace/scratch/2a90364b341d/inih-native-final01/de720a6f/migrated/inih.hepta"
uint32_t __hepta_cb_v144 = (uint32_t)UINT64_C(15);
#line 23 "/workspace/scratch/2a90364b341d/inih-native-final01/de720a6f/migrated/inih.hepta"
return __hepta_cb_v144; } else {  }
#line 24 "/workspace/scratch/2a90364b341d/inih-native-final01/de720a6f/migrated/inih.hepta"
uint32_t __hepta_cb_v145 = h_state;
#line 24 "/workspace/scratch/2a90364b341d/inih-native-final01/de720a6f/migrated/inih.hepta"
uint32_t __hepta_cb_v146 = (uint32_t)UINT64_C(16);
#line 24 "/workspace/scratch/2a90364b341d/inih-native-final01/de720a6f/migrated/inih.hepta"
bool __hepta_cb_v147 = (__hepta_cb_v145 == __hepta_cb_v146);
#line 24 "/workspace/scratch/2a90364b341d/inih-native-final01/de720a6f/migrated/inih.hepta"
bool __hepta_cb_v148 = __hepta_cb_v147;
#line 24 "/workspace/scratch/2a90364b341d/inih-native-final01/de720a6f/migrated/inih.hepta"
if (__hepta_cb_v148) { uint32_t __hepta_cb_v149 = h_byte; uint32_t __hepta_cb_v150 = (uint32_t)UINT64_C(111); bool __hepta_cb_v151 = (__hepta_cb_v149 == __hepta_cb_v150); __hepta_cb_v148 = __hepta_cb_v151; }
#line 24 "/workspace/scratch/2a90364b341d/inih-native-final01/de720a6f/migrated/inih.hepta"
if (__hepta_cb_v148) { 
#line 24 "/workspace/scratch/2a90364b341d/inih-native-final01/de720a6f/migrated/inih.hepta"
uint32_t __hepta_cb_v152 = (uint32_t)UINT64_C(17);
#line 24 "/workspace/scratch/2a90364b341d/inih-native-final01/de720a6f/migrated/inih.hepta"
return __hepta_cb_v152; } else {  }
#line 25 "/workspace/scratch/2a90364b341d/inih-native-final01/de720a6f/migrated/inih.hepta"
uint32_t __hepta_cb_v153 = h_state;
#line 25 "/workspace/scratch/2a90364b341d/inih-native-final01/de720a6f/migrated/inih.hepta"
uint32_t __hepta_cb_v154 = (uint32_t)UINT64_C(18);
#line 25 "/workspace/scratch/2a90364b341d/inih-native-final01/de720a6f/migrated/inih.hepta"
bool __hepta_cb_v155 = (__hepta_cb_v153 == __hepta_cb_v154);
#line 25 "/workspace/scratch/2a90364b341d/inih-native-final01/de720a6f/migrated/inih.hepta"
bool __hepta_cb_v156 = __hepta_cb_v155;
#line 25 "/workspace/scratch/2a90364b341d/inih-native-final01/de720a6f/migrated/inih.hepta"
if (__hepta_cb_v156) { uint32_t __hepta_cb_v157 = h_byte; uint32_t __hepta_cb_v158 = (uint32_t)UINT64_C(102); bool __hepta_cb_v159 = (__hepta_cb_v157 == __hepta_cb_v158); __hepta_cb_v156 = __hepta_cb_v159; }
#line 25 "/workspace/scratch/2a90364b341d/inih-native-final01/de720a6f/migrated/inih.hepta"
if (__hepta_cb_v156) { 
#line 25 "/workspace/scratch/2a90364b341d/inih-native-final01/de720a6f/migrated/inih.hepta"
uint32_t __hepta_cb_v160 = (uint32_t)UINT64_C(19);
#line 25 "/workspace/scratch/2a90364b341d/inih-native-final01/de720a6f/migrated/inih.hepta"
return __hepta_cb_v160; } else {  }
#line 26 "/workspace/scratch/2a90364b341d/inih-native-final01/de720a6f/migrated/inih.hepta"
uint32_t __hepta_cb_v161 = (uint32_t)UINT64_C(4294967295);
#line 26 "/workspace/scratch/2a90364b341d/inih-native-final01/de720a6f/migrated/inih.hepta"
return __hepta_cb_v161;
#line 26 "/workspace/scratch/2a90364b341d/inih-native-final01/de720a6f/migrated/inih.hepta"
}
#line 29 "/workspace/scratch/2a90364b341d/inih-native-final01/de720a6f/migrated/inih.hepta"
uint32_t hia_ini_bool_finish(uint32_t h_state, uint32_t h_fallback) {
#line 30 "/workspace/scratch/2a90364b341d/inih-native-final01/de720a6f/migrated/inih.hepta"
uint32_t __hepta_cb_v162 = h_state;
#line 30 "/workspace/scratch/2a90364b341d/inih-native-final01/de720a6f/migrated/inih.hepta"
uint32_t __hepta_cb_v163 = (uint32_t)UINT64_C(4);
#line 30 "/workspace/scratch/2a90364b341d/inih-native-final01/de720a6f/migrated/inih.hepta"
bool __hepta_cb_v164 = (__hepta_cb_v162 == __hepta_cb_v163);
#line 30 "/workspace/scratch/2a90364b341d/inih-native-final01/de720a6f/migrated/inih.hepta"
if (__hepta_cb_v164) { 
#line 30 "/workspace/scratch/2a90364b341d/inih-native-final01/de720a6f/migrated/inih.hepta"
uint32_t __hepta_cb_v165 = (uint32_t)UINT64_C(1);
#line 30 "/workspace/scratch/2a90364b341d/inih-native-final01/de720a6f/migrated/inih.hepta"
return __hepta_cb_v165; } else {  }
#line 31 "/workspace/scratch/2a90364b341d/inih-native-final01/de720a6f/migrated/inih.hepta"
uint32_t __hepta_cb_v166 = h_state;
#line 31 "/workspace/scratch/2a90364b341d/inih-native-final01/de720a6f/migrated/inih.hepta"
uint32_t __hepta_cb_v167 = (uint32_t)UINT64_C(7);
#line 31 "/workspace/scratch/2a90364b341d/inih-native-final01/de720a6f/migrated/inih.hepta"
bool __hepta_cb_v168 = (__hepta_cb_v166 == __hepta_cb_v167);
#line 31 "/workspace/scratch/2a90364b341d/inih-native-final01/de720a6f/migrated/inih.hepta"
if (__hepta_cb_v168) { 
#line 31 "/workspace/scratch/2a90364b341d/inih-native-final01/de720a6f/migrated/inih.hepta"
uint32_t __hepta_cb_v169 = (uint32_t)UINT64_C(1);
#line 31 "/workspace/scratch/2a90364b341d/inih-native-final01/de720a6f/migrated/inih.hepta"
return __hepta_cb_v169; } else {  }
#line 32 "/workspace/scratch/2a90364b341d/inih-native-final01/de720a6f/migrated/inih.hepta"
uint32_t __hepta_cb_v170 = h_state;
#line 32 "/workspace/scratch/2a90364b341d/inih-native-final01/de720a6f/migrated/inih.hepta"
uint32_t __hepta_cb_v171 = (uint32_t)UINT64_C(9);
#line 32 "/workspace/scratch/2a90364b341d/inih-native-final01/de720a6f/migrated/inih.hepta"
bool __hepta_cb_v172 = (__hepta_cb_v170 == __hepta_cb_v171);
#line 32 "/workspace/scratch/2a90364b341d/inih-native-final01/de720a6f/migrated/inih.hepta"
if (__hepta_cb_v172) { 
#line 32 "/workspace/scratch/2a90364b341d/inih-native-final01/de720a6f/migrated/inih.hepta"
uint32_t __hepta_cb_v173 = (uint32_t)UINT64_C(1);
#line 32 "/workspace/scratch/2a90364b341d/inih-native-final01/de720a6f/migrated/inih.hepta"
return __hepta_cb_v173; } else {  }
#line 33 "/workspace/scratch/2a90364b341d/inih-native-final01/de720a6f/migrated/inih.hepta"
uint32_t __hepta_cb_v174 = h_state;
#line 33 "/workspace/scratch/2a90364b341d/inih-native-final01/de720a6f/migrated/inih.hepta"
uint32_t __hepta_cb_v175 = (uint32_t)UINT64_C(10);
#line 33 "/workspace/scratch/2a90364b341d/inih-native-final01/de720a6f/migrated/inih.hepta"
bool __hepta_cb_v176 = (__hepta_cb_v174 == __hepta_cb_v175);
#line 33 "/workspace/scratch/2a90364b341d/inih-native-final01/de720a6f/migrated/inih.hepta"
if (__hepta_cb_v176) { 
#line 33 "/workspace/scratch/2a90364b341d/inih-native-final01/de720a6f/migrated/inih.hepta"
uint32_t __hepta_cb_v177 = (uint32_t)UINT64_C(1);
#line 33 "/workspace/scratch/2a90364b341d/inih-native-final01/de720a6f/migrated/inih.hepta"
return __hepta_cb_v177; } else {  }
#line 34 "/workspace/scratch/2a90364b341d/inih-native-final01/de720a6f/migrated/inih.hepta"
uint32_t __hepta_cb_v178 = h_state;
#line 34 "/workspace/scratch/2a90364b341d/inih-native-final01/de720a6f/migrated/inih.hepta"
uint32_t __hepta_cb_v179 = (uint32_t)UINT64_C(15);
#line 34 "/workspace/scratch/2a90364b341d/inih-native-final01/de720a6f/migrated/inih.hepta"
bool __hepta_cb_v180 = (__hepta_cb_v178 == __hepta_cb_v179);
#line 34 "/workspace/scratch/2a90364b341d/inih-native-final01/de720a6f/migrated/inih.hepta"
if (__hepta_cb_v180) { 
#line 34 "/workspace/scratch/2a90364b341d/inih-native-final01/de720a6f/migrated/inih.hepta"
uint32_t __hepta_cb_v181 = (uint32_t)UINT64_C(0);
#line 34 "/workspace/scratch/2a90364b341d/inih-native-final01/de720a6f/migrated/inih.hepta"
return __hepta_cb_v181; } else {  }
#line 35 "/workspace/scratch/2a90364b341d/inih-native-final01/de720a6f/migrated/inih.hepta"
uint32_t __hepta_cb_v182 = h_state;
#line 35 "/workspace/scratch/2a90364b341d/inih-native-final01/de720a6f/migrated/inih.hepta"
uint32_t __hepta_cb_v183 = (uint32_t)UINT64_C(17);
#line 35 "/workspace/scratch/2a90364b341d/inih-native-final01/de720a6f/migrated/inih.hepta"
bool __hepta_cb_v184 = (__hepta_cb_v182 == __hepta_cb_v183);
#line 35 "/workspace/scratch/2a90364b341d/inih-native-final01/de720a6f/migrated/inih.hepta"
if (__hepta_cb_v184) { 
#line 35 "/workspace/scratch/2a90364b341d/inih-native-final01/de720a6f/migrated/inih.hepta"
uint32_t __hepta_cb_v185 = (uint32_t)UINT64_C(0);
#line 35 "/workspace/scratch/2a90364b341d/inih-native-final01/de720a6f/migrated/inih.hepta"
return __hepta_cb_v185; } else {  }
#line 36 "/workspace/scratch/2a90364b341d/inih-native-final01/de720a6f/migrated/inih.hepta"
uint32_t __hepta_cb_v186 = h_state;
#line 36 "/workspace/scratch/2a90364b341d/inih-native-final01/de720a6f/migrated/inih.hepta"
uint32_t __hepta_cb_v187 = (uint32_t)UINT64_C(19);
#line 36 "/workspace/scratch/2a90364b341d/inih-native-final01/de720a6f/migrated/inih.hepta"
bool __hepta_cb_v188 = (__hepta_cb_v186 == __hepta_cb_v187);
#line 36 "/workspace/scratch/2a90364b341d/inih-native-final01/de720a6f/migrated/inih.hepta"
if (__hepta_cb_v188) { 
#line 36 "/workspace/scratch/2a90364b341d/inih-native-final01/de720a6f/migrated/inih.hepta"
uint32_t __hepta_cb_v189 = (uint32_t)UINT64_C(0);
#line 36 "/workspace/scratch/2a90364b341d/inih-native-final01/de720a6f/migrated/inih.hepta"
return __hepta_cb_v189; } else {  }
#line 37 "/workspace/scratch/2a90364b341d/inih-native-final01/de720a6f/migrated/inih.hepta"
uint32_t __hepta_cb_v190 = h_state;
#line 37 "/workspace/scratch/2a90364b341d/inih-native-final01/de720a6f/migrated/inih.hepta"
uint32_t __hepta_cb_v191 = (uint32_t)UINT64_C(20);
#line 37 "/workspace/scratch/2a90364b341d/inih-native-final01/de720a6f/migrated/inih.hepta"
bool __hepta_cb_v192 = (__hepta_cb_v190 == __hepta_cb_v191);
#line 37 "/workspace/scratch/2a90364b341d/inih-native-final01/de720a6f/migrated/inih.hepta"
if (__hepta_cb_v192) { 
#line 37 "/workspace/scratch/2a90364b341d/inih-native-final01/de720a6f/migrated/inih.hepta"
uint32_t __hepta_cb_v193 = (uint32_t)UINT64_C(0);
#line 37 "/workspace/scratch/2a90364b341d/inih-native-final01/de720a6f/migrated/inih.hepta"
return __hepta_cb_v193; } else {  }
#line 38 "/workspace/scratch/2a90364b341d/inih-native-final01/de720a6f/migrated/inih.hepta"
uint32_t __hepta_cb_v194 = h_fallback;
#line 38 "/workspace/scratch/2a90364b341d/inih-native-final01/de720a6f/migrated/inih.hepta"
uint32_t __hepta_cb_v195 = (uint32_t)UINT64_C(0);
#line 38 "/workspace/scratch/2a90364b341d/inih-native-final01/de720a6f/migrated/inih.hepta"
bool __hepta_cb_v196 = (__hepta_cb_v194 != __hepta_cb_v195);
#line 38 "/workspace/scratch/2a90364b341d/inih-native-final01/de720a6f/migrated/inih.hepta"
if (__hepta_cb_v196) { 
#line 38 "/workspace/scratch/2a90364b341d/inih-native-final01/de720a6f/migrated/inih.hepta"
uint32_t __hepta_cb_v197 = (uint32_t)UINT64_C(1);
#line 38 "/workspace/scratch/2a90364b341d/inih-native-final01/de720a6f/migrated/inih.hepta"
return __hepta_cb_v197; } else {  }
#line 39 "/workspace/scratch/2a90364b341d/inih-native-final01/de720a6f/migrated/inih.hepta"
uint32_t __hepta_cb_v198 = (uint32_t)UINT64_C(0);
#line 39 "/workspace/scratch/2a90364b341d/inih-native-final01/de720a6f/migrated/inih.hepta"
return __hepta_cb_v198;
#line 39 "/workspace/scratch/2a90364b341d/inih-native-final01/de720a6f/migrated/inih.hepta"
}
#line 42 "/workspace/scratch/2a90364b341d/inih-native-final01/de720a6f/migrated/inih.hepta"
uint32_t hia_ini_error_kind(int32_t h_error) {
#line 43 "/workspace/scratch/2a90364b341d/inih-native-final01/de720a6f/migrated/inih.hepta"
int32_t __hepta_cb_v199 = h_error;
#line 43 "/workspace/scratch/2a90364b341d/inih-native-final01/de720a6f/migrated/inih.hepta"
int32_t __hepta_cb_v200 = (int32_t)INT64_C(0);
#line 43 "/workspace/scratch/2a90364b341d/inih-native-final01/de720a6f/migrated/inih.hepta"
bool __hepta_cb_v201 = (__hepta_cb_v199 > __hepta_cb_v200);
#line 43 "/workspace/scratch/2a90364b341d/inih-native-final01/de720a6f/migrated/inih.hepta"
if (__hepta_cb_v201) { 
#line 43 "/workspace/scratch/2a90364b341d/inih-native-final01/de720a6f/migrated/inih.hepta"
uint32_t __hepta_cb_v202 = (uint32_t)UINT64_C(1);
#line 43 "/workspace/scratch/2a90364b341d/inih-native-final01/de720a6f/migrated/inih.hepta"
return __hepta_cb_v202; } else {  }
#line 44 "/workspace/scratch/2a90364b341d/inih-native-final01/de720a6f/migrated/inih.hepta"
int32_t __hepta_cb_v203 = h_error;
#line 44 "/workspace/scratch/2a90364b341d/inih-native-final01/de720a6f/migrated/inih.hepta"
int32_t __hepta_cb_v204 = (int32_t)INT64_C(2);
#line 44 "/workspace/scratch/2a90364b341d/inih-native-final01/de720a6f/migrated/inih.hepta"
int32_t __hepta_cb_v205 = __hepta_cb_i32_sub(0, __hepta_cb_v204);
#line 44 "/workspace/scratch/2a90364b341d/inih-native-final01/de720a6f/migrated/inih.hepta"
bool __hepta_cb_v206 = (__hepta_cb_v203 == __hepta_cb_v205);
#line 44 "/workspace/scratch/2a90364b341d/inih-native-final01/de720a6f/migrated/inih.hepta"
if (__hepta_cb_v206) { 
#line 44 "/workspace/scratch/2a90364b341d/inih-native-final01/de720a6f/migrated/inih.hepta"
uint32_t __hepta_cb_v207 = (uint32_t)UINT64_C(2);
#line 44 "/workspace/scratch/2a90364b341d/inih-native-final01/de720a6f/migrated/inih.hepta"
return __hepta_cb_v207; } else {  }
#line 45 "/workspace/scratch/2a90364b341d/inih-native-final01/de720a6f/migrated/inih.hepta"
int32_t __hepta_cb_v208 = h_error;
#line 45 "/workspace/scratch/2a90364b341d/inih-native-final01/de720a6f/migrated/inih.hepta"
int32_t __hepta_cb_v209 = (int32_t)INT64_C(1);
#line 45 "/workspace/scratch/2a90364b341d/inih-native-final01/de720a6f/migrated/inih.hepta"
int32_t __hepta_cb_v210 = __hepta_cb_i32_sub(0, __hepta_cb_v209);
#line 45 "/workspace/scratch/2a90364b341d/inih-native-final01/de720a6f/migrated/inih.hepta"
bool __hepta_cb_v211 = (__hepta_cb_v208 == __hepta_cb_v210);
#line 45 "/workspace/scratch/2a90364b341d/inih-native-final01/de720a6f/migrated/inih.hepta"
if (__hepta_cb_v211) { 
#line 45 "/workspace/scratch/2a90364b341d/inih-native-final01/de720a6f/migrated/inih.hepta"
uint32_t __hepta_cb_v212 = (uint32_t)UINT64_C(3);
#line 45 "/workspace/scratch/2a90364b341d/inih-native-final01/de720a6f/migrated/inih.hepta"
return __hepta_cb_v212; } else {  }
#line 46 "/workspace/scratch/2a90364b341d/inih-native-final01/de720a6f/migrated/inih.hepta"
int32_t __hepta_cb_v213 = h_error;
#line 46 "/workspace/scratch/2a90364b341d/inih-native-final01/de720a6f/migrated/inih.hepta"
int32_t __hepta_cb_v214 = (int32_t)INT64_C(0);
#line 46 "/workspace/scratch/2a90364b341d/inih-native-final01/de720a6f/migrated/inih.hepta"
bool __hepta_cb_v215 = (__hepta_cb_v213 == __hepta_cb_v214);
#line 46 "/workspace/scratch/2a90364b341d/inih-native-final01/de720a6f/migrated/inih.hepta"
if (__hepta_cb_v215) { 
#line 46 "/workspace/scratch/2a90364b341d/inih-native-final01/de720a6f/migrated/inih.hepta"
uint32_t __hepta_cb_v216 = (uint32_t)UINT64_C(4);
#line 46 "/workspace/scratch/2a90364b341d/inih-native-final01/de720a6f/migrated/inih.hepta"
return __hepta_cb_v216; } else {  }
#line 47 "/workspace/scratch/2a90364b341d/inih-native-final01/de720a6f/migrated/inih.hepta"
uint32_t __hepta_cb_v217 = (uint32_t)UINT64_C(255);
#line 47 "/workspace/scratch/2a90364b341d/inih-native-final01/de720a6f/migrated/inih.hepta"
return __hepta_cb_v217;
#line 47 "/workspace/scratch/2a90364b341d/inih-native-final01/de720a6f/migrated/inih.hepta"
}
#line 50 "/workspace/scratch/2a90364b341d/inih-native-final01/de720a6f/migrated/inih.hepta"
uint32_t hia_ini_callback_action(uint32_t h_has_name, uint32_t h_has_value, uint32_t h_nonempty) {
#line 51 "/workspace/scratch/2a90364b341d/inih-native-final01/de720a6f/migrated/inih.hepta"
uint32_t __hepta_cb_v218 = h_has_name;
#line 51 "/workspace/scratch/2a90364b341d/inih-native-final01/de720a6f/migrated/inih.hepta"
uint32_t __hepta_cb_v219 = (uint32_t)UINT64_C(0);
#line 51 "/workspace/scratch/2a90364b341d/inih-native-final01/de720a6f/migrated/inih.hepta"
bool __hepta_cb_v220 = (__hepta_cb_v218 == __hepta_cb_v219);
#line 51 "/workspace/scratch/2a90364b341d/inih-native-final01/de720a6f/migrated/inih.hepta"
if (__hepta_cb_v220) { 
#line 51 "/workspace/scratch/2a90364b341d/inih-native-final01/de720a6f/migrated/inih.hepta"
uint32_t __hepta_cb_v221 = (uint32_t)UINT64_C(0);
#line 51 "/workspace/scratch/2a90364b341d/inih-native-final01/de720a6f/migrated/inih.hepta"
return __hepta_cb_v221; } else {  }
#line 52 "/workspace/scratch/2a90364b341d/inih-native-final01/de720a6f/migrated/inih.hepta"
uint32_t __hepta_cb_v222 = h_nonempty;
#line 52 "/workspace/scratch/2a90364b341d/inih-native-final01/de720a6f/migrated/inih.hepta"
uint32_t __hepta_cb_v223 = (uint32_t)UINT64_C(0);
#line 52 "/workspace/scratch/2a90364b341d/inih-native-final01/de720a6f/migrated/inih.hepta"
bool __hepta_cb_v224 = (__hepta_cb_v222 != __hepta_cb_v223);
#line 52 "/workspace/scratch/2a90364b341d/inih-native-final01/de720a6f/migrated/inih.hepta"
if (__hepta_cb_v224) { 
#line 53 "/workspace/scratch/2a90364b341d/inih-native-final01/de720a6f/migrated/inih.hepta"
uint32_t __hepta_cb_v225 = h_has_value;
#line 53 "/workspace/scratch/2a90364b341d/inih-native-final01/de720a6f/migrated/inih.hepta"
uint32_t __hepta_cb_v226 = (uint32_t)UINT64_C(0);
#line 53 "/workspace/scratch/2a90364b341d/inih-native-final01/de720a6f/migrated/inih.hepta"
bool __hepta_cb_v227 = (__hepta_cb_v225 != __hepta_cb_v226);
#line 53 "/workspace/scratch/2a90364b341d/inih-native-final01/de720a6f/migrated/inih.hepta"
if (__hepta_cb_v227) { 
#line 53 "/workspace/scratch/2a90364b341d/inih-native-final01/de720a6f/migrated/inih.hepta"
uint32_t __hepta_cb_v228 = (uint32_t)UINT64_C(4);
#line 53 "/workspace/scratch/2a90364b341d/inih-native-final01/de720a6f/migrated/inih.hepta"
return __hepta_cb_v228; } else {  }
#line 54 "/workspace/scratch/2a90364b341d/inih-native-final01/de720a6f/migrated/inih.hepta"
uint32_t __hepta_cb_v229 = (uint32_t)UINT64_C(3);
#line 54 "/workspace/scratch/2a90364b341d/inih-native-final01/de720a6f/migrated/inih.hepta"
return __hepta_cb_v229; } else {  }
#line 56 "/workspace/scratch/2a90364b341d/inih-native-final01/de720a6f/migrated/inih.hepta"
uint32_t __hepta_cb_v230 = h_has_value;
#line 56 "/workspace/scratch/2a90364b341d/inih-native-final01/de720a6f/migrated/inih.hepta"
uint32_t __hepta_cb_v231 = (uint32_t)UINT64_C(0);
#line 56 "/workspace/scratch/2a90364b341d/inih-native-final01/de720a6f/migrated/inih.hepta"
bool __hepta_cb_v232 = (__hepta_cb_v230 != __hepta_cb_v231);
#line 56 "/workspace/scratch/2a90364b341d/inih-native-final01/de720a6f/migrated/inih.hepta"
if (__hepta_cb_v232) { 
#line 56 "/workspace/scratch/2a90364b341d/inih-native-final01/de720a6f/migrated/inih.hepta"
uint32_t __hepta_cb_v233 = (uint32_t)UINT64_C(2);
#line 56 "/workspace/scratch/2a90364b341d/inih-native-final01/de720a6f/migrated/inih.hepta"
return __hepta_cb_v233; } else {  }
#line 57 "/workspace/scratch/2a90364b341d/inih-native-final01/de720a6f/migrated/inih.hepta"
uint32_t __hepta_cb_v234 = (uint32_t)UINT64_C(1);
#line 57 "/workspace/scratch/2a90364b341d/inih-native-final01/de720a6f/migrated/inih.hepta"
return __hepta_cb_v234;
#line 57 "/workspace/scratch/2a90364b341d/inih-native-final01/de720a6f/migrated/inih.hepta"
}
#line 60 "/workspace/scratch/2a90364b341d/inih-native-final01/de720a6f/migrated/inih.hepta"
uint32_t hia_ini_lease_step(uint32_t h_phase, uint32_t h_event) {
#line 61 "/workspace/scratch/2a90364b341d/inih-native-final01/de720a6f/migrated/inih.hepta"
uint32_t __hepta_cb_v235 = h_phase;
#line 61 "/workspace/scratch/2a90364b341d/inih-native-final01/de720a6f/migrated/inih.hepta"
uint32_t __hepta_cb_v236 = (uint32_t)UINT64_C(0);
#line 61 "/workspace/scratch/2a90364b341d/inih-native-final01/de720a6f/migrated/inih.hepta"
bool __hepta_cb_v237 = (__hepta_cb_v235 == __hepta_cb_v236);
#line 61 "/workspace/scratch/2a90364b341d/inih-native-final01/de720a6f/migrated/inih.hepta"
bool __hepta_cb_v238 = __hepta_cb_v237;
#line 61 "/workspace/scratch/2a90364b341d/inih-native-final01/de720a6f/migrated/inih.hepta"
if (__hepta_cb_v238) { uint32_t __hepta_cb_v239 = h_event; uint32_t __hepta_cb_v240 = (uint32_t)UINT64_C(0); bool __hepta_cb_v241 = (__hepta_cb_v239 == __hepta_cb_v240); __hepta_cb_v238 = __hepta_cb_v241; }
#line 61 "/workspace/scratch/2a90364b341d/inih-native-final01/de720a6f/migrated/inih.hepta"
if (__hepta_cb_v238) { 
#line 61 "/workspace/scratch/2a90364b341d/inih-native-final01/de720a6f/migrated/inih.hepta"
uint32_t __hepta_cb_v242 = (uint32_t)UINT64_C(1);
#line 61 "/workspace/scratch/2a90364b341d/inih-native-final01/de720a6f/migrated/inih.hepta"
return __hepta_cb_v242; } else {  }
#line 62 "/workspace/scratch/2a90364b341d/inih-native-final01/de720a6f/migrated/inih.hepta"
uint32_t __hepta_cb_v243 = h_phase;
#line 62 "/workspace/scratch/2a90364b341d/inih-native-final01/de720a6f/migrated/inih.hepta"
uint32_t __hepta_cb_v244 = (uint32_t)UINT64_C(1);
#line 62 "/workspace/scratch/2a90364b341d/inih-native-final01/de720a6f/migrated/inih.hepta"
bool __hepta_cb_v245 = (__hepta_cb_v243 == __hepta_cb_v244);
#line 62 "/workspace/scratch/2a90364b341d/inih-native-final01/de720a6f/migrated/inih.hepta"
bool __hepta_cb_v246 = __hepta_cb_v245;
#line 62 "/workspace/scratch/2a90364b341d/inih-native-final01/de720a6f/migrated/inih.hepta"
if (__hepta_cb_v246) { uint32_t __hepta_cb_v247 = h_event; uint32_t __hepta_cb_v248 = (uint32_t)UINT64_C(1); bool __hepta_cb_v249 = (__hepta_cb_v247 == __hepta_cb_v248); __hepta_cb_v246 = __hepta_cb_v249; }
#line 62 "/workspace/scratch/2a90364b341d/inih-native-final01/de720a6f/migrated/inih.hepta"
if (__hepta_cb_v246) { 
#line 62 "/workspace/scratch/2a90364b341d/inih-native-final01/de720a6f/migrated/inih.hepta"
uint32_t __hepta_cb_v250 = (uint32_t)UINT64_C(2);
#line 62 "/workspace/scratch/2a90364b341d/inih-native-final01/de720a6f/migrated/inih.hepta"
return __hepta_cb_v250; } else {  }
#line 63 "/workspace/scratch/2a90364b341d/inih-native-final01/de720a6f/migrated/inih.hepta"
uint32_t __hepta_cb_v251 = h_phase;
#line 63 "/workspace/scratch/2a90364b341d/inih-native-final01/de720a6f/migrated/inih.hepta"
uint32_t __hepta_cb_v252 = (uint32_t)UINT64_C(2);
#line 63 "/workspace/scratch/2a90364b341d/inih-native-final01/de720a6f/migrated/inih.hepta"
bool __hepta_cb_v253 = (__hepta_cb_v251 == __hepta_cb_v252);
#line 63 "/workspace/scratch/2a90364b341d/inih-native-final01/de720a6f/migrated/inih.hepta"
bool __hepta_cb_v254 = __hepta_cb_v253;
#line 63 "/workspace/scratch/2a90364b341d/inih-native-final01/de720a6f/migrated/inih.hepta"
if (__hepta_cb_v254) { uint32_t __hepta_cb_v255 = h_event; uint32_t __hepta_cb_v256 = (uint32_t)UINT64_C(2); bool __hepta_cb_v257 = (__hepta_cb_v255 == __hepta_cb_v256); __hepta_cb_v254 = __hepta_cb_v257; }
#line 63 "/workspace/scratch/2a90364b341d/inih-native-final01/de720a6f/migrated/inih.hepta"
if (__hepta_cb_v254) { 
#line 63 "/workspace/scratch/2a90364b341d/inih-native-final01/de720a6f/migrated/inih.hepta"
uint32_t __hepta_cb_v258 = (uint32_t)UINT64_C(1);
#line 63 "/workspace/scratch/2a90364b341d/inih-native-final01/de720a6f/migrated/inih.hepta"
return __hepta_cb_v258; } else {  }
#line 64 "/workspace/scratch/2a90364b341d/inih-native-final01/de720a6f/migrated/inih.hepta"
uint32_t __hepta_cb_v259 = h_phase;
#line 64 "/workspace/scratch/2a90364b341d/inih-native-final01/de720a6f/migrated/inih.hepta"
uint32_t __hepta_cb_v260 = (uint32_t)UINT64_C(1);
#line 64 "/workspace/scratch/2a90364b341d/inih-native-final01/de720a6f/migrated/inih.hepta"
bool __hepta_cb_v261 = (__hepta_cb_v259 == __hepta_cb_v260);
#line 64 "/workspace/scratch/2a90364b341d/inih-native-final01/de720a6f/migrated/inih.hepta"
bool __hepta_cb_v262 = __hepta_cb_v261;
#line 64 "/workspace/scratch/2a90364b341d/inih-native-final01/de720a6f/migrated/inih.hepta"
if (__hepta_cb_v262) { uint32_t __hepta_cb_v263 = h_event; uint32_t __hepta_cb_v264 = (uint32_t)UINT64_C(3); bool __hepta_cb_v265 = (__hepta_cb_v263 == __hepta_cb_v264); __hepta_cb_v262 = __hepta_cb_v265; }
#line 64 "/workspace/scratch/2a90364b341d/inih-native-final01/de720a6f/migrated/inih.hepta"
if (__hepta_cb_v262) { 
#line 64 "/workspace/scratch/2a90364b341d/inih-native-final01/de720a6f/migrated/inih.hepta"
uint32_t __hepta_cb_v266 = (uint32_t)UINT64_C(3);
#line 64 "/workspace/scratch/2a90364b341d/inih-native-final01/de720a6f/migrated/inih.hepta"
return __hepta_cb_v266; } else {  }
#line 65 "/workspace/scratch/2a90364b341d/inih-native-final01/de720a6f/migrated/inih.hepta"
uint32_t __hepta_cb_v267 = (uint32_t)UINT64_C(255);
#line 65 "/workspace/scratch/2a90364b341d/inih-native-final01/de720a6f/migrated/inih.hepta"
return __hepta_cb_v267;
#line 65 "/workspace/scratch/2a90364b341d/inih-native-final01/de720a6f/migrated/inih.hepta"
}
