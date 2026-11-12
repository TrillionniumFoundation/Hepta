/* Finite eight-slot allocator for the standalone composite HIA AArch64 test.
 * Eight independent 4096-byte slots; no concurrency, realloc or production claim.
 * Exact pointer identity, per-slot lifetime, peak live count and refusal injection
 * are observed independently of the HIA program under test.
 */
typedef __SIZE_TYPE__ hepta_size;
typedef __UINT8_TYPE__ hepta_u8;
typedef __UINT32_TYPE__ hepta_u32;
typedef __UINT64_TYPE__ hepta_u64;
typedef __UINTPTR_TYPE__ hepta_uintptr;
#if !defined(__BYTE_ORDER__) || (__BYTE_ORDER__ != __ORDER_LITTLE_ENDIAN__)
#error requires little endian
#endif
_Static_assert(__CHAR_BIT__ == 8 && sizeof(void *) == 8 && sizeof(hepta_size) == 8,
               "strict LP64 test ABI");
#define HEPTA_CAPACITY 4096u
#define HEPTA_SLOTS 8u
static _Alignas(16) hepta_u8 arenas[HEPTA_SLOTS][HEPTA_CAPACITY];
static volatile hepta_u8 occupied[HEPTA_SLOTS];
static volatile hepta_u32 failure_countdown;
static volatile hepta_u32 peak_outstanding;
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
    if (failure_countdown && --failure_countdown == 0) {
        ++denied_allocations;
        return (void *)0;
    }
    if (n == 0 || n > HEPTA_CAPACITY) {
        ++denied_allocations;
        return (void *)0;
    }
    for (hepta_size slot = 0; slot < HEPTA_SLOTS; ++slot) {
        if (!occupied[slot]) {
            occupied[slot] = 1;
            ++outstanding;
            if (outstanding > peak_outstanding) peak_outstanding = outstanding;
            ++successful_allocations;
            return (void *)arenas[slot];
        }
    }
    ++denied_allocations;
    return (void *)0;
}
__attribute__((noinline)) void free(void *p) {
    if (p == 0) return;
    for (hepta_size slot = 0; slot < HEPTA_SLOTS; ++slot) {
        if (p == (void *)arenas[slot]) {
            if (!occupied[slot] || !outstanding) abort();
            occupied[slot] = 0;
            --outstanding;
            ++releases;
            return;
        }
    }
    abort();
}
__attribute__((noinline)) void *memset(void *dest, int value, hepta_size n) {
    hepta_u8 *d = (hepta_u8 *)dest;
    for (hepta_size i = 0; i < n; ++i) d[i] = (hepta_u8)value;
    return dest;
}
__attribute__((noinline)) void *memcpy(void *dest, const void *src, hepta_size n) {
    hepta_u8 *d = (hepta_u8 *)dest;
    const hepta_u8 *s = (const hepta_u8 *)src;
    for (hepta_size i = 0; i < n; ++i) d[i] = s[i];
    return dest;
}
__attribute__((noinline)) void *memmove(void *dest, const void *src, hepta_size n) {
    hepta_u8 *d = (hepta_u8 *)dest;
    const hepta_u8 *s = (const hepta_u8 *)src;
    if (d == s || n == 0) return dest;
    /* Flat LP64 addresses: do not relationally compare unrelated C pointers. */
    if ((hepta_uintptr)d < (hepta_uintptr)s) {
        for (hepta_size i = 0; i < n; ++i) d[i] = s[i];
    }
    else { for (hepta_size i = n; i > 0; --i) d[i - 1] = s[i - 1]; }
    return dest;
}

/* Independently exercise both directions of overlap and disjoint objects. */
static int memory_primitives_ok(void) {
    hepta_u8 a[8], b[8];
    memset(a, 0, 8);
    for (hepta_size i = 0; i < 8; ++i) a[i] = (hepta_u8)(i + 1);
    memcpy(b, a, 8);
    memmove(b + 1, b, 7);
    for (hepta_size i = 0; i < 7; ++i) {
        if (b[i + 1] != a[i]) return 0;
    }
    memmove(b, b + 1, 7);
    for (hepta_size i = 0; i < 7; ++i) {
        if (b[i] != a[i]) return 0;
    }
    memmove(b, a, 8);
    for (hepta_size i = 0; i < 8; ++i) {
        if (b[i] != a[i]) return 0;
    }
    return 1;
}

