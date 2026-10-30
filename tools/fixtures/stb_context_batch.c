/* Same batch ABI and loop for every C/LLVM arm; library implementation remains pinned. */
#include <stdint.h>
#include <stddef.h>
#include <limits.h>
#if defined(ARM_STB)
#define STB_DIVIDE_IMPLEMENTATION
#define C_INTEGER_DIVISION_TRUNCATES
#include "stb_divide.h"
#define DIVIDE(a,d) stb_div_trunc((a),(d))
#elif defined(ARM_HIA)
extern int32_t c_stb_div_trunc(int32_t, int32_t);
extern int32_t c_stb_div_trunc_hot(int32_t, int32_t);
#define DIVIDE(a,d) c_stb_div_trunc((a),(d))
#else
#define LIBDIVIDE_AVX2
#define LIBDIVIDE_AVX512
#include "libdivide.h"
#endif
__attribute__((visibility("default")))
uint64_t batch(const int32_t *input, int32_t *output, size_t n, int32_t divisor, uint32_t rounds) {
    uint64_t checksum=0;
#ifdef ARM_HIA
    /* This explicit batch guard is an audited foreign bridge, outside the
       scalar Core theorem. Both its target bodies and every native output
       are independently checked. A miss uses the original guarded Core. */
    if (divisor == HIA_CONTEXT_VALUE) {
        for (uint32_t round=0; round<rounds; ++round) {
            __asm__ __volatile__("" ::: "memory");
            for (size_t i=0; i<n; ++i) output[i]=c_stb_div_trunc_hot(input[i],divisor);
            checksum+=(uint32_t)output[round % n];
        }
        return checksum;
    }
#endif
#if defined(ARM_LIB_FULL) || defined(ARM_LIB_AVX2) || defined(ARM_LIB_AVX512)
    const struct libdivide_s32_t divider=libdivide_s32_gen(divisor);
#elif defined(ARM_LIB_FREE) || defined(ARM_LIB_AVX2_FREE) || defined(ARM_LIB_AVX512_FREE)
    const struct libdivide_s32_branchfree_t divider=libdivide_s32_branchfree_gen(divisor);
#endif
    for (uint32_t round=0; round<rounds; ++round) {
        __asm__ __volatile__("" ::: "memory");
        size_t i=0;
#if defined(ARM_LIB_AVX512) || defined(ARM_LIB_AVX512_FREE)
        for (; i+16<=n; i+=16) {
            __m512i x=_mm512_loadu_si512((const void*)(input+i));
#ifdef ARM_LIB_AVX512
            __m512i y=libdivide_s32_do_vec512(x,&divider);
#else
            __m512i y=libdivide_s32_branchfree_do_vec512(x,&divider);
#endif
            _mm512_storeu_si512((void*)(output+i),y);
        }
#elif defined(ARM_LIB_AVX2) || defined(ARM_LIB_AVX2_FREE)
        for (; i+8<=n; i+=8) {
            __m256i x=_mm256_loadu_si256((const __m256i*)(input+i));
#ifdef ARM_LIB_AVX2
            __m256i y=libdivide_s32_do_vec256(x,&divider);
#else
            __m256i y=libdivide_s32_branchfree_do_vec256(x,&divider);
#endif
            _mm256_storeu_si256((__m256i*)(output+i),y);
        }
#endif
        for (;i<n;++i) {
#if defined(ARM_STB) || defined(ARM_HIA)
            output[i]=DIVIDE(input[i],divisor);
#elif defined(ARM_LIB_FULL) || defined(ARM_LIB_AVX2) || defined(ARM_LIB_AVX512)
            output[i]=libdivide_s32_do(input[i],&divider);
#else
            output[i]=libdivide_s32_branchfree_do(input[i],&divider);
#endif
        }
        checksum+=(uint32_t)output[round % n];
    }
    return checksum;
}
