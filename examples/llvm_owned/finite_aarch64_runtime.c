/* Experimental finite, single-owner Linux runtime for one fixed Owned LLVM ABI.
 * Not a general malloc, production libc, DMA driver or concurrent runtime.
 * No libc dependency and no target execution without an explicit runner.
 */
typedef __SIZE_TYPE__ hepta_size;
typedef __UINT8_TYPE__ hepta_u8;
typedef __UINT32_TYPE__ hepta_u32;
typedef __UINT64_TYPE__ hepta_u64;
#if !defined(__BYTE_ORDER__) || (__BYTE_ORDER__ != __ORDER_LITTLE_ENDIAN__)
#error requires little endian
#endif
_Static_assert(__CHAR_BIT__ == 8 && sizeof(void *) == 8 && sizeof(hepta_size) == 8,
               "strict LP64 test ABI");
#define HEPTA_CAPACITY 4096u
static _Alignas(16) hepta_u8 arena[HEPTA_CAPACITY];
static volatile hepta_u32 outstanding;
static volatile hepta_u32 successful_allocations;
static volatile hepta_u32 releases;
static volatile hepta_u32 denied_allocations;

__attribute__((noreturn)) static void hepta_exit(hepta_u32 code) {
#if defined(__aarch64__)
    register long x0 __asm__("x0") = (long)code;
    register long x8 __asm__("x8") = 93;
    __asm__ volatile("svc 0" : : "r"(x0), "r"(x8) : "memory");
#elif defined(__x86_64__)
    __asm__ volatile("syscall" : : "a"(60L), "D"((long)code) : "rcx", "r11", "memory");
#else
#error unsupported test execution architecture
#endif
    __builtin_unreachable();
}

__attribute__((noreturn)) void abort(void) { hepta_exit(134); }
__attribute__((noinline)) void *malloc(hepta_size n) {
    if (n == 0 || n > HEPTA_CAPACITY || outstanding) {
        ++denied_allocations;
        return (void *)0;
    }
    outstanding = 1;
    ++successful_allocations;
    return (void *)arena;
}
__attribute__((noinline)) void free(void *p) {
    if (p == 0) return;
    if (p != (void *)arena || !outstanding) abort();
    outstanding = 0;
    ++releases;
}
void *memset(void *dest, int value, hepta_size n) {
    hepta_u8 *d = (hepta_u8 *)dest;
    for (hepta_size i = 0; i < n; ++i) d[i] = (hepta_u8)value;
    return dest;
}
void *memcpy(void *dest, const void *src, hepta_size n) {
    hepta_u8 *d = (hepta_u8 *)dest;
    const hepta_u8 *s = (const hepta_u8 *)src;
    for (hepta_size i = 0; i < n; ++i) d[i] = s[i];
    return dest;
}
void *memmove(void *dest, const void *src, hepta_size n) {
    hepta_u8 *d = (hepta_u8 *)dest;
    const hepta_u8 *s = (const hepta_u8 *)src;
    if (d == s || n == 0) return dest;
    if (d < s) { for (hepta_size i = 0; i < n; ++i) d[i] = s[i]; }
    else { for (hepta_size i = n; i > 0; --i) d[i - 1] = s[i - 1]; }
    return dest;
}

/* Exact selected Hepta export; unlike the synthetic stub, invoked for real. */
extern hepta_u64 owned_case(hepta_size size, hepta_u8 value, hepta_size index,
                            hepta_u32 reject, hepta_u32 early);
static int smoke(void) {
    if (owned_case(16, 7, 3, 0, 0) != 30) return 11;
    if (owned_case(16, 7, 0, 0, 0) != 202) return 12;
    if (owned_case(16, 7, 12, 0, 1) != 2002) return 13;
    if (owned_case(16, 7, 16, 0, 0) != 2003) return 14;
    if (owned_case(16, 7, 3, 1, 0) != 1002) return 15;
    if (owned_case(5000, 7, 3, 0, 0) != 1001) return 16;
    if (owned_case(0, 7, 0, 0, 0) != 2003) return 17;
    if (outstanding != 0 || successful_allocations == 0 ||
        successful_allocations != releases || denied_allocations == 0) return 18;
    return 0;
}
__attribute__((noreturn)) void _start(void) { hepta_exit((hepta_u32)smoke()); }
