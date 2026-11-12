/* Finite RV64GC / LP64D and AArch64 Linux userspace qualification runtime.
 * 64 independent 4096-byte slots, no concurrency, realloc or production claim.
 * This code runs under QEMU; it is not physical-board or device evidence.
 */
typedef __SIZE_TYPE__ hepta_size;
typedef __UINT8_TYPE__ hepta_u8;
typedef __UINT32_TYPE__ hepta_u32;
typedef __UINT64_TYPE__ hepta_u64;
typedef __UINTPTR_TYPE__ hepta_uintptr;
#if !defined(__aarch64__) && (!defined(__riscv) || __riscv_xlen != 64 || !defined(__riscv_float_abi_double))
#error requires AArch64 or RV64 LP64D
#endif
#if !defined(__BYTE_ORDER__) || __BYTE_ORDER__ != __ORDER_LITTLE_ENDIAN__
#error requires little endian
#endif
_Static_assert(__CHAR_BIT__ == 8 && sizeof(void *) == 8 && sizeof(hepta_size) == 8,
               "strict LP64 test ABI");
#define HEPTA_CAPACITY 4096u
#define HEPTA_SLOTS 64u
static _Alignas(16) hepta_u8 arenas[HEPTA_SLOTS][HEPTA_CAPACITY];
static volatile hepta_u8 occupied[HEPTA_SLOTS];
static volatile hepta_u32 failure_countdown;
static volatile hepta_u32 peak_outstanding, outstanding;
static volatile hepta_u32 successful_allocations, releases, denied_allocations;
static volatile hepta_u32 null_frees;
/* Requested payload bytes, separate from the observer's fixed backing arena. */
static hepta_size requested_sizes[HEPTA_SLOTS];
static volatile hepta_size live_bytes, peak_bytes;

#ifdef HEPTA_RETURNED_LOAN_OBSERVER
static void report_abort(void);
#endif

__attribute__((noreturn)) static void hepta_exit(hepta_u32 code) {
#if defined(__aarch64__)
    register long x0 __asm__("x0") = (long)code;
    register long x8 __asm__("x8") = 93;
    __asm__ volatile("svc 0" : : "r"(x0), "r"(x8) : "memory");
#else
    register long a0 __asm__("a0") = (long)code;
    register long a7 __asm__("a7") = 93;
    __asm__ volatile("ecall" : : "r"(a0), "r"(a7) : "memory");
#endif
    __builtin_unreachable();
}
__attribute__((noreturn)) void abort(void) {
#ifdef HEPTA_RETURNED_LOAN_OBSERVER
    report_abort();
#endif
    hepta_exit(134);
}
__attribute__((noinline)) void *malloc(hepta_size n) {
    if (failure_countdown && --failure_countdown == 0) {
        ++denied_allocations;
        return (void *)0;
    }
    if (n == 0 || n > HEPTA_CAPACITY) {
        ++denied_allocations;
        return (void *)0;
    }
    for (hepta_size i = 0; i < HEPTA_SLOTS; ++i) {
        if (!occupied[i]) {
            occupied[i] = 1;
            requested_sizes[i] = n;
            live_bytes += n;
            if (live_bytes > peak_bytes) peak_bytes = live_bytes;
            ++outstanding;
            if (outstanding > peak_outstanding) peak_outstanding = outstanding;
            ++successful_allocations;
            return (void *)arenas[i];
        }
    }
    ++denied_allocations;
    return (void *)0;
}
__attribute__((noinline)) void free(void *p) {
    if (!p) { ++null_frees; return; }
    for (hepta_size i = 0; i < HEPTA_SLOTS; ++i) {
        if (p == (void *)arenas[i]) {
            if (!occupied[i] || !outstanding) abort();
            occupied[i] = 0;
            live_bytes -= requested_sizes[i];
            requested_sizes[i] = 0;
            --outstanding;
            ++releases;
            return;
        }
    }
    abort();
}
__attribute__((noinline)) void *memset(void *destination, int value, hepta_size n) {
    hepta_u8 *p = (hepta_u8 *)destination;
    for (hepta_size i = 0; i < n; ++i) p[i] = (hepta_u8)value;
    return destination;
}
__attribute__((noinline)) void *calloc(hepta_size count, hepta_size width) {
    if (width && count > ((hepta_size)-1) / width) {
        ++denied_allocations;
        return (void *)0;
    }
    hepta_size bytes = count * width;
    void *p = malloc(bytes);
    if (p) memset(p, 0, bytes);
    return p;
}
__attribute__((noinline)) void *memcpy(void *destination, const void *source, hepta_size n) {
    hepta_u8 *d = (hepta_u8 *)destination;
    const hepta_u8 *s = (const hepta_u8 *)source;
    for (hepta_size i = 0; i < n; ++i) d[i] = s[i];
    return destination;
}
__attribute__((noinline)) void *memmove(void *destination, const void *source, hepta_size n) {
    hepta_u8 *d = (hepta_u8 *)destination;
    const hepta_u8 *s = (const hepta_u8 *)source;
    if (d == s || !n) return destination;
    if ((hepta_uintptr)d < (hepta_uintptr)s) {
        for (hepta_size i = 0; i < n; ++i) d[i] = s[i];
    } else {
        for (hepta_size i = n; i; --i) d[i - 1] = s[i - 1];
    }
    return destination;
}
static int memory_primitives_ok(void) {
    hepta_u8 a[8], b[8];
    memset(a, 0, 8);
    for (hepta_size i = 0; i < 8; ++i) a[i] = (hepta_u8)(i + 1);
    memcpy(b, a, 8);
    memmove(b + 1, b, 7);
    for (hepta_size i = 0; i < 7; ++i) if (b[i + 1] != a[i]) return 0;
    memmove(b, b + 1, 7);
    for (hepta_size i = 0; i < 7; ++i) if (b[i] != a[i]) return 0;
    memmove(b, a, 8);
    for (hepta_size i = 0; i < 8; ++i) if (b[i] != a[i]) return 0;
    return 1;
}
static void write_values(const char *prefix, const hepta_u64 *values, hepta_size count) {
    char text[256];
    hepta_size used = 0;
    while (*prefix) text[used++] = *prefix++;
    for (hepta_size i = 0; i < count; ++i) {
        char digits[20];
        hepta_size n = 0;
        hepta_u64 value = values[i];
        do { digits[n++] = (char)('0' + value % 10); value /= 10; } while (value);
        while (n) text[used++] = digits[--n];
        text[used++] = i + 1 == count ? '\n' : ' ';
    }
#if defined(__aarch64__)
    register long x0 __asm__("x0") = 1;
    register const char *x1 __asm__("x1") = text;
    register hepta_size x2 __asm__("x2") = used;
    register long x8 __asm__("x8") = 64;
    __asm__ volatile("svc 0" : "+r"(x0) : "r"(x1), "r"(x2), "r"(x8) : "memory");
    if (x0 != (long)used) hepta_exit(90);
#else
    register long a0 __asm__("a0") = 1;
    register const char *a1 __asm__("a1") = text;
    register hepta_size a2 __asm__("a2") = used;
    register long a7 __asm__("a7") = 64;
    __asm__ volatile("ecall" : "+r"(a0) : "r"(a1), "r"(a2), "r"(a7) : "memory");
    if (a0 != (long)used) hepta_exit(90);
#endif
}
static void write_resources(void) {
    hepta_u64 values[] = {successful_allocations, releases, outstanding,
                         denied_allocations, peak_outstanding};
    write_values("HIA_RISCV64 resources ", values, 5);
}
