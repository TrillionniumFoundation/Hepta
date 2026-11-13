# 0 "/home/qq/hia-rewrite-20261113-e26e-r1/sqlite-btree-cell-native-r1/candidate/reference/native-oracle/oracle-sqlite-3.53.2.c"
# 0 "<built-in>"
# 0 "<command-line>"
# 1 "/usr/include/stdc-predef.h" 1 3 4
# 0 "<command-line>" 2
# 1 "/home/qq/hia-rewrite-20261113-e26e-r1/sqlite-btree-cell-native-r1/candidate/reference/native-oracle/oracle-sqlite-3.53.2.c"





# 1 "/usr/include/assert.h" 1 3 4
# 35 "/usr/include/assert.h" 3 4
# 1 "/usr/include/features.h" 1 3 4
# 431 "/usr/include/features.h" 3 4
# 1 "/usr/include/features-time64.h" 1 3 4
# 20 "/usr/include/features-time64.h" 3 4
# 1 "/usr/include/x86_64-linux-gnu/bits/wordsize.h" 1 3 4
# 21 "/usr/include/features-time64.h" 2 3 4
# 1 "/usr/include/x86_64-linux-gnu/bits/timesize.h" 1 3 4
# 19 "/usr/include/x86_64-linux-gnu/bits/timesize.h" 3 4
# 1 "/usr/include/x86_64-linux-gnu/bits/wordsize.h" 1 3 4
# 20 "/usr/include/x86_64-linux-gnu/bits/timesize.h" 2 3 4
# 22 "/usr/include/features-time64.h" 2 3 4
# 432 "/usr/include/features.h" 2 3 4
# 539 "/usr/include/features.h" 3 4
# 1 "/usr/include/x86_64-linux-gnu/sys/cdefs.h" 1 3 4
# 730 "/usr/include/x86_64-linux-gnu/sys/cdefs.h" 3 4
# 1 "/usr/include/x86_64-linux-gnu/bits/wordsize.h" 1 3 4
# 731 "/usr/include/x86_64-linux-gnu/sys/cdefs.h" 2 3 4
# 1 "/usr/include/x86_64-linux-gnu/bits/long-double.h" 1 3 4
# 732 "/usr/include/x86_64-linux-gnu/sys/cdefs.h" 2 3 4
# 540 "/usr/include/features.h" 2 3 4
# 563 "/usr/include/features.h" 3 4
# 1 "/usr/include/x86_64-linux-gnu/gnu/stubs.h" 1 3 4
# 10 "/usr/include/x86_64-linux-gnu/gnu/stubs.h" 3 4
# 1 "/usr/include/x86_64-linux-gnu/gnu/stubs-64.h" 1 3 4
# 11 "/usr/include/x86_64-linux-gnu/gnu/stubs.h" 2 3 4
# 564 "/usr/include/features.h" 2 3 4
# 36 "/usr/include/assert.h" 2 3 4
# 94 "/usr/include/assert.h" 3 4




# 97 "/usr/include/assert.h" 3 4
extern void __assert_fail (const char *__assertion, const char *__file,
      unsigned int __line, const char *__function)
     __attribute__ ((__nothrow__ , __leaf__)) __attribute__ ((__noreturn__)) __attribute__ ((__cold__));


extern void __assert_perror_fail (int __errnum, const char *__file,
      unsigned int __line, const char *__function)
     __attribute__ ((__nothrow__ , __leaf__)) __attribute__ ((__noreturn__)) __attribute__ ((__cold__));




extern void __assert (const char *__assertion, const char *__file, int __line)
     __attribute__ ((__nothrow__ , __leaf__)) __attribute__ ((__noreturn__)) __attribute__ ((__cold__));
# 120 "/usr/include/assert.h" 3 4

# 7 "/home/qq/hia-rewrite-20261113-e26e-r1/sqlite-btree-cell-native-r1/candidate/reference/native-oracle/oracle-sqlite-3.53.2.c" 2
# 1 "/usr/lib/gcc/x86_64-linux-gnu/15/include/limits.h" 1 3 4
# 34 "/usr/lib/gcc/x86_64-linux-gnu/15/include/limits.h" 3 4
# 1 "/usr/lib/gcc/x86_64-linux-gnu/15/include/syslimits.h" 1 3 4






 
# 7 "/usr/lib/gcc/x86_64-linux-gnu/15/include/syslimits.h" 3 4
#pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-Wpedantic"
# 1 "/usr/lib/gcc/x86_64-linux-gnu/15/include/limits.h" 1 3 4
# 210 "/usr/lib/gcc/x86_64-linux-gnu/15/include/limits.h" 3 4
# 1 "/usr/include/limits.h" 1 3 4
# 26 "/usr/include/limits.h" 3 4
# 1 "/usr/include/x86_64-linux-gnu/bits/libc-header-start.h" 1 3 4
# 27 "/usr/include/limits.h" 2 3 4
# 211 "/usr/lib/gcc/x86_64-linux-gnu/15/include/limits.h" 2 3 4
# 10 "/usr/lib/gcc/x86_64-linux-gnu/15/include/syslimits.h" 2 3 4
#pragma GCC diagnostic pop
# 35 "/usr/lib/gcc/x86_64-linux-gnu/15/include/limits.h" 2 3 4
# 8 "/home/qq/hia-rewrite-20261113-e26e-r1/sqlite-btree-cell-native-r1/candidate/reference/native-oracle/oracle-sqlite-3.53.2.c" 2
# 1 "/usr/lib/gcc/x86_64-linux-gnu/15/include/stddef.h" 1 3 4
# 160 "/usr/lib/gcc/x86_64-linux-gnu/15/include/stddef.h" 3 4
typedef long int ptrdiff_t;
# 229 "/usr/lib/gcc/x86_64-linux-gnu/15/include/stddef.h" 3 4
typedef long unsigned int size_t;
# 344 "/usr/lib/gcc/x86_64-linux-gnu/15/include/stddef.h" 3 4
typedef int wchar_t;
# 440 "/usr/lib/gcc/x86_64-linux-gnu/15/include/stddef.h" 3 4
typedef struct {
  long long __max_align_ll __attribute__((__aligned__(__alignof__(long long))));
  long double __max_align_ld __attribute__((__aligned__(__alignof__(long double))));
# 451 "/usr/lib/gcc/x86_64-linux-gnu/15/include/stddef.h" 3 4
} max_align_t;
# 9 "/home/qq/hia-rewrite-20261113-e26e-r1/sqlite-btree-cell-native-r1/candidate/reference/native-oracle/oracle-sqlite-3.53.2.c" 2
# 1 "/usr/lib/gcc/x86_64-linux-gnu/15/include/stdint.h" 1 3 4
# 9 "/usr/lib/gcc/x86_64-linux-gnu/15/include/stdint.h" 3 4
#pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-Wpedantic"
# 1 "/usr/include/stdint.h" 1 3 4
# 26 "/usr/include/stdint.h" 3 4
# 1 "/usr/include/x86_64-linux-gnu/bits/libc-header-start.h" 1 3 4
# 27 "/usr/include/stdint.h" 2 3 4
# 1 "/usr/include/x86_64-linux-gnu/bits/types.h" 1 3 4
# 27 "/usr/include/x86_64-linux-gnu/bits/types.h" 3 4
# 1 "/usr/include/x86_64-linux-gnu/bits/wordsize.h" 1 3 4
# 28 "/usr/include/x86_64-linux-gnu/bits/types.h" 2 3 4
# 1 "/usr/include/x86_64-linux-gnu/bits/timesize.h" 1 3 4
# 19 "/usr/include/x86_64-linux-gnu/bits/timesize.h" 3 4
# 1 "/usr/include/x86_64-linux-gnu/bits/wordsize.h" 1 3 4
# 20 "/usr/include/x86_64-linux-gnu/bits/timesize.h" 2 3 4
# 29 "/usr/include/x86_64-linux-gnu/bits/types.h" 2 3 4


typedef unsigned char __u_char;
typedef unsigned short int __u_short;
typedef unsigned int __u_int;
typedef unsigned long int __u_long;


typedef signed char __int8_t;
typedef unsigned char __uint8_t;
typedef signed short int __int16_t;
typedef unsigned short int __uint16_t;
typedef signed int __int32_t;
typedef unsigned int __uint32_t;

typedef signed long int __int64_t;
typedef unsigned long int __uint64_t;






typedef __int8_t __int_least8_t;
typedef __uint8_t __uint_least8_t;
typedef __int16_t __int_least16_t;
typedef __uint16_t __uint_least16_t;
typedef __int32_t __int_least32_t;
typedef __uint32_t __uint_least32_t;
typedef __int64_t __int_least64_t;
typedef __uint64_t __uint_least64_t;



typedef long int __quad_t;
typedef unsigned long int __u_quad_t;







typedef long int __intmax_t;
typedef unsigned long int __uintmax_t;
# 141 "/usr/include/x86_64-linux-gnu/bits/types.h" 3 4
# 1 "/usr/include/x86_64-linux-gnu/bits/typesizes.h" 1 3 4
# 142 "/usr/include/x86_64-linux-gnu/bits/types.h" 2 3 4
# 1 "/usr/include/x86_64-linux-gnu/bits/time64.h" 1 3 4
# 143 "/usr/include/x86_64-linux-gnu/bits/types.h" 2 3 4


typedef unsigned long int __dev_t;
typedef unsigned int __uid_t;
typedef unsigned int __gid_t;
typedef unsigned long int __ino_t;
typedef unsigned long int __ino64_t;
typedef unsigned int __mode_t;
typedef unsigned long int __nlink_t;
typedef long int __off_t;
typedef long int __off64_t;
typedef int __pid_t;
typedef struct { int __val[2]; } __fsid_t;
typedef long int __clock_t;
typedef unsigned long int __rlim_t;
typedef unsigned long int __rlim64_t;
typedef unsigned int __id_t;
typedef long int __time_t;
typedef unsigned int __useconds_t;
typedef long int __suseconds_t;
typedef long int __suseconds64_t;

typedef int __daddr_t;
typedef int __key_t;


typedef int __clockid_t;


typedef void * __timer_t;


typedef long int __blksize_t;




typedef long int __blkcnt_t;
typedef long int __blkcnt64_t;


typedef unsigned long int __fsblkcnt_t;
typedef unsigned long int __fsblkcnt64_t;


typedef unsigned long int __fsfilcnt_t;
typedef unsigned long int __fsfilcnt64_t;


typedef long int __fsword_t;

typedef long int __ssize_t;


typedef long int __syscall_slong_t;

typedef unsigned long int __syscall_ulong_t;



typedef __off64_t __loff_t;
typedef char *__caddr_t;


typedef long int __intptr_t;


typedef unsigned int __socklen_t;




typedef int __sig_atomic_t;
# 28 "/usr/include/stdint.h" 2 3 4
# 1 "/usr/include/x86_64-linux-gnu/bits/wchar.h" 1 3 4
# 29 "/usr/include/stdint.h" 2 3 4
# 1 "/usr/include/x86_64-linux-gnu/bits/wordsize.h" 1 3 4
# 30 "/usr/include/stdint.h" 2 3 4
# 38 "/usr/include/stdint.h" 3 4
# 1 "/usr/include/x86_64-linux-gnu/bits/stdint-intn.h" 1 3 4
# 24 "/usr/include/x86_64-linux-gnu/bits/stdint-intn.h" 3 4
typedef __int8_t int8_t;
typedef __int16_t int16_t;
typedef __int32_t int32_t;
typedef __int64_t int64_t;
# 39 "/usr/include/stdint.h" 2 3 4


# 1 "/usr/include/x86_64-linux-gnu/bits/stdint-uintn.h" 1 3 4
# 24 "/usr/include/x86_64-linux-gnu/bits/stdint-uintn.h" 3 4
typedef __uint8_t uint8_t;
typedef __uint16_t uint16_t;
typedef __uint32_t uint32_t;
typedef __uint64_t uint64_t;
# 42 "/usr/include/stdint.h" 2 3 4



# 1 "/usr/include/x86_64-linux-gnu/bits/stdint-least.h" 1 3 4
# 25 "/usr/include/x86_64-linux-gnu/bits/stdint-least.h" 3 4
typedef __int_least8_t int_least8_t;
typedef __int_least16_t int_least16_t;
typedef __int_least32_t int_least32_t;
typedef __int_least64_t int_least64_t;


typedef __uint_least8_t uint_least8_t;
typedef __uint_least16_t uint_least16_t;
typedef __uint_least32_t uint_least32_t;
typedef __uint_least64_t uint_least64_t;
# 46 "/usr/include/stdint.h" 2 3 4





typedef signed char int_fast8_t;

typedef long int int_fast16_t;
typedef long int int_fast32_t;
typedef long int int_fast64_t;
# 64 "/usr/include/stdint.h" 3 4
typedef unsigned char uint_fast8_t;

typedef unsigned long int uint_fast16_t;
typedef unsigned long int uint_fast32_t;
typedef unsigned long int uint_fast64_t;
# 80 "/usr/include/stdint.h" 3 4
typedef long int intptr_t;


typedef unsigned long int uintptr_t;
# 94 "/usr/include/stdint.h" 3 4
typedef __intmax_t intmax_t;
typedef __uintmax_t uintmax_t;
# 12 "/usr/lib/gcc/x86_64-linux-gnu/15/include/stdint.h" 2 3 4
#pragma GCC diagnostic pop
# 10 "/home/qq/hia-rewrite-20261113-e26e-r1/sqlite-btree-cell-native-r1/candidate/reference/native-oracle/oracle-sqlite-3.53.2.c" 2
# 1 "/usr/include/string.h" 1 3 4
# 26 "/usr/include/string.h" 3 4
# 1 "/usr/include/x86_64-linux-gnu/bits/libc-header-start.h" 1 3 4
# 27 "/usr/include/string.h" 2 3 4


# 37 "/usr/include/string.h" 3 4
# 1 "/usr/lib/gcc/x86_64-linux-gnu/15/include/stddef.h" 1 3 4
# 38 "/usr/include/string.h" 2 3 4
# 47 "/usr/include/string.h" 3 4
extern void *memcpy (void *__restrict __dest, const void *__restrict __src,
       size_t __n) __attribute__ ((__nothrow__ , __leaf__)) __attribute__ ((__nonnull__ (1, 2)));


extern void *memmove (void *__dest, const void *__src, size_t __n)
     __attribute__ ((__nothrow__ , __leaf__)) __attribute__ ((__nonnull__ (1, 2)));
# 65 "/usr/include/string.h" 3 4
extern void *memset (void *__s, int __c, size_t __n) __attribute__ ((__nothrow__ , __leaf__)) __attribute__ ((__nonnull__ (1)));
# 75 "/usr/include/string.h" 3 4
extern int memcmp (const void *__s1, const void *__s2, size_t __n)
     __attribute__ ((__nothrow__ , __leaf__)) __attribute__ ((__pure__)) __attribute__ ((__nonnull__ (1, 2)));
# 91 "/usr/include/string.h" 3 4
extern int __memcmpeq (const void *__s1, const void *__s2, size_t __n)
     __attribute__ ((__nothrow__ , __leaf__)) __attribute__ ((__pure__)) __attribute__ ((__nonnull__ (1, 2)));
# 118 "/usr/include/string.h" 3 4
extern void *memchr (const void *__s, int __c, size_t __n)
      __attribute__ ((__nothrow__ , __leaf__)) __attribute__ ((__pure__)) __attribute__ ((__nonnull__ (1)));
# 156 "/usr/include/string.h" 3 4
extern char *strcpy (char *__restrict __dest, const char *__restrict __src)
     __attribute__ ((__nothrow__ , __leaf__)) __attribute__ ((__nonnull__ (1, 2)));

extern char *strncpy (char *__restrict __dest,
        const char *__restrict __src, size_t __n)
     __attribute__ ((__nothrow__ , __leaf__)) __attribute__ ((__nonnull__ (1, 2)));


extern char *strcat (char *__restrict __dest, const char *__restrict __src)
     __attribute__ ((__nothrow__ , __leaf__)) __attribute__ ((__nonnull__ (1, 2)));

extern char *strncat (char *__restrict __dest, const char *__restrict __src,
        size_t __n) __attribute__ ((__nothrow__ , __leaf__)) __attribute__ ((__nonnull__ (1, 2)));


extern int strcmp (const char *__s1, const char *__s2)
     __attribute__ ((__nothrow__ , __leaf__)) __attribute__ ((__pure__)) __attribute__ ((__nonnull__ (1, 2)));

extern int strncmp (const char *__s1, const char *__s2, size_t __n)
     __attribute__ ((__nothrow__ , __leaf__)) __attribute__ ((__pure__)) __attribute__ ((__nonnull__ (1, 2)));


extern int strcoll (const char *__s1, const char *__s2)
     __attribute__ ((__nothrow__ , __leaf__)) __attribute__ ((__pure__)) __attribute__ ((__nonnull__ (1, 2)));

extern size_t strxfrm (char *__restrict __dest,
         const char *__restrict __src, size_t __n)
    __attribute__ ((__nothrow__ , __leaf__)) __attribute__ ((__nonnull__ (2))) __attribute__ ((__access__ (__write_only__, 1, 3)));
# 261 "/usr/include/string.h" 3 4
extern char *strchr (const char *__s, int __c)
     __attribute__ ((__nothrow__ , __leaf__)) __attribute__ ((__pure__)) __attribute__ ((__nonnull__ (1)));
# 292 "/usr/include/string.h" 3 4
extern char *strrchr (const char *__s, int __c)
     __attribute__ ((__nothrow__ , __leaf__)) __attribute__ ((__pure__)) __attribute__ ((__nonnull__ (1)));
# 316 "/usr/include/string.h" 3 4
extern size_t strcspn (const char *__s, const char *__reject)
     __attribute__ ((__nothrow__ , __leaf__)) __attribute__ ((__pure__)) __attribute__ ((__nonnull__ (1, 2)));


extern size_t strspn (const char *__s, const char *__accept)
     __attribute__ ((__nothrow__ , __leaf__)) __attribute__ ((__pure__)) __attribute__ ((__nonnull__ (1, 2)));
# 346 "/usr/include/string.h" 3 4
extern char *strpbrk (const char *__s, const char *__accept)
     __attribute__ ((__nothrow__ , __leaf__)) __attribute__ ((__pure__)) __attribute__ ((__nonnull__ (1, 2)));
# 377 "/usr/include/string.h" 3 4
extern char *strstr (const char *__haystack, const char *__needle)
     __attribute__ ((__nothrow__ , __leaf__)) __attribute__ ((__pure__)) __attribute__ ((__nonnull__ (1, 2)));
# 388 "/usr/include/string.h" 3 4
extern char *strtok (char *__restrict __s, const char *__restrict __delim)
     __attribute__ ((__nothrow__ , __leaf__)) __attribute__ ((__nonnull__ (2)));



extern char *__strtok_r (char *__restrict __s,
    const char *__restrict __delim,
    char **__restrict __save_ptr)
     __attribute__ ((__nothrow__ , __leaf__)) __attribute__ ((__nonnull__ (2, 3)));
# 439 "/usr/include/string.h" 3 4
extern size_t strlen (const char *__s)
     __attribute__ ((__nothrow__ , __leaf__)) __attribute__ ((__pure__)) __attribute__ ((__nonnull__ (1)));
# 451 "/usr/include/string.h" 3 4
extern char *strerror (int __errnum) __attribute__ ((__nothrow__ , __leaf__));
# 580 "/usr/include/string.h" 3 4
# 1 "/usr/include/x86_64-linux-gnu/bits/string_fortified.h" 1 3 4
# 25 "/usr/include/x86_64-linux-gnu/bits/string_fortified.h" 3 4
extern __inline __attribute__ ((__always_inline__)) __attribute__ ((__gnu_inline__)) __attribute__ ((__artificial__)) void *
__attribute__ ((__nothrow__ , __leaf__)) memcpy (void *__restrict __dest, const void *__restrict __src, size_t __len)

{
  return __builtin___memcpy_chk (__dest, __src, __len,
     __builtin_dynamic_object_size (__dest, 0));
}

extern __inline __attribute__ ((__always_inline__)) __attribute__ ((__gnu_inline__)) __attribute__ ((__artificial__)) void *
__attribute__ ((__nothrow__ , __leaf__)) memmove (void *__dest, const void *__src, size_t __len)
{
  return __builtin___memmove_chk (__dest, __src, __len,
      __builtin_dynamic_object_size (__dest, 0));
}
# 56 "/usr/include/x86_64-linux-gnu/bits/string_fortified.h" 3 4
extern __inline __attribute__ ((__always_inline__)) __attribute__ ((__gnu_inline__)) __attribute__ ((__artificial__)) void *
__attribute__ ((__nothrow__ , __leaf__)) memset (void *__dest, int __ch, size_t __len)
{
  return __builtin___memset_chk (__dest, __ch, __len,
     __builtin_dynamic_object_size (__dest, 0));
}
# 88 "/usr/include/x86_64-linux-gnu/bits/string_fortified.h" 3 4
extern __inline __attribute__ ((__always_inline__)) __attribute__ ((__gnu_inline__)) __attribute__ ((__artificial__)) char *
__attribute__ ((__nothrow__ , __leaf__)) strcpy (char * __restrict __dest, const char *__restrict __src)

    
{
  return __builtin___strcpy_chk (__dest, __src, __builtin_dynamic_object_size (__dest, 1));
}
# 107 "/usr/include/x86_64-linux-gnu/bits/string_fortified.h" 3 4
extern __inline __attribute__ ((__always_inline__)) __attribute__ ((__gnu_inline__)) __attribute__ ((__artificial__)) char *
__attribute__ ((__nothrow__ , __leaf__)) strncpy (char * __restrict __dest, const char *__restrict __src, size_t __len)

    
{
  return __builtin___strncpy_chk (__dest, __src, __len,
      __builtin_dynamic_object_size (__dest, 1));
}
# 147 "/usr/include/x86_64-linux-gnu/bits/string_fortified.h" 3 4
extern __inline __attribute__ ((__always_inline__)) __attribute__ ((__gnu_inline__)) __attribute__ ((__artificial__)) char *
__attribute__ ((__nothrow__ , __leaf__)) strcat (char * __restrict __dest, const char *__restrict __src)

    
{
  return __builtin___strcat_chk (__dest, __src, __builtin_dynamic_object_size (__dest, 1));
}


extern __inline __attribute__ ((__always_inline__)) __attribute__ ((__gnu_inline__)) __attribute__ ((__artificial__)) char *
__attribute__ ((__nothrow__ , __leaf__)) strncat (char * __restrict __dest, const char *__restrict __src, size_t __len)

    
{
  return __builtin___strncat_chk (__dest, __src, __len,
      __builtin_dynamic_object_size (__dest, 1));
}
# 581 "/usr/include/string.h" 2 3 4




# 11 "/home/qq/hia-rewrite-20261113-e26e-r1/sqlite-btree-cell-native-r1/candidate/reference/native-oracle/oracle-sqlite-3.53.2.c" 2







# 17 "/home/qq/hia-rewrite-20261113-e26e-r1/sqlite-btree-cell-native-r1/candidate/reference/native-oracle/oracle-sqlite-3.53.2.c"
typedef long long sqlite_int64;
typedef unsigned long long sqlite_uint64;
# 60 "/home/qq/hia-rewrite-20261113-e26e-r1/sqlite-btree-cell-native-r1/candidate/reference/native-oracle/oracle-sqlite-3.53.2.c"
typedef sqlite_int64 i64;
typedef sqlite_uint64 u64;
typedef unsigned int u32;
typedef unsigned short int u16;
typedef short int i16;
typedef unsigned char u8;
typedef signed char i8;
# 86 "/home/qq/hia-rewrite-20261113-e26e-r1/sqlite-btree-cell-native-r1/candidate/reference/native-oracle/oracle-sqlite-3.53.2.c"
typedef u32 Pgno;
typedef struct MemPage MemPage;
typedef struct BtShared BtShared;
typedef struct CellInfo CellInfo;
typedef struct Pager Pager;
typedef struct sqlite3 sqlite3;
typedef struct BtCursor BtCursor;
typedef struct sqlite3_mutex sqlite3_mutex;
typedef struct Bitvec Bitvec;
typedef struct BtLock BtLock;
typedef struct Btree Btree;
typedef struct PgHdr DbPage;

_Static_assert(8 
# 99 "/home/qq/hia-rewrite-20261113-e26e-r1/sqlite-btree-cell-native-r1/candidate/reference/native-oracle/oracle-sqlite-3.53.2.c"
                       == 8, "eight-bit bytes");
_Static_assert(sizeof(u8) == 1 && sizeof(u16) == 2 && sizeof(u32) == 4, "original unsigned widths");
_Static_assert(sizeof(u64) == 8 && sizeof(i64) == 8, "original 64-bit widths");
_Static_assert(sizeof(uint32_t) == 4 && sizeof(uint64_t) == 8, "export widths");
_Static_assert((i64)-1 < 0 && (u64)-1 > 0, "original signedness");
_Static_assert(sizeof(uintptr_t) == sizeof(void *), "pointer observation width");



static int oracle_mutex_held(sqlite3_mutex *mutex){ return mutex == 
# 108 "/home/qq/hia-rewrite-20261113-e26e-r1/sqlite-btree-cell-native-r1/candidate/reference/native-oracle/oracle-sqlite-3.53.2.c" 3 4
                                                                   ((void *)0)
# 108 "/home/qq/hia-rewrite-20261113-e26e-r1/sqlite-btree-cell-native-r1/candidate/reference/native-oracle/oracle-sqlite-3.53.2.c"
                                                                       ; }
# 118 "/home/qq/hia-rewrite-20261113-e26e-r1/sqlite-btree-cell-native-r1/candidate/reference/native-oracle/oracle-sqlite-3.53.2.c"
struct MemPage {
  u8 isInit;
  u8 intKey;
  u8 intKeyLeaf;
  Pgno pgno;


  u8 leaf;
  u8 hdrOffset;
  u8 childPtrSize;
  u8 max1bytePayload;
  u8 nOverflow;
  u16 maxLocal;
  u16 minLocal;
  u16 cellOffset;
  int nFree;
  u16 nCell;
  u16 maskPage;
  u16 aiOvfl[4];

  u8 *apOvfl[4];
  BtShared *pBt;
  u8 *aData;
  u8 *aDataEnd;


  u8 *aCellIdx;
  u8 *aDataOfst;
  DbPage *pDbPage;
  u16 (*xCellSize)(MemPage*,u8*);
  void (*xParseCell)(MemPage*,u8*,CellInfo*);
};

struct BtShared {
  Pager *pPager;
  sqlite3 *db;
  BtCursor *pCursor;
  MemPage *pPage1;
  u8 openFlags;

  u8 autoVacuum;
  u8 incrVacuum;
  u8 bDoTruncate;

  u8 inTransaction;
  u8 max1bytePayload;
  u8 nReserveWanted;
  u16 btsFlags;
  u16 maxLocal;
  u16 minLocal;
  u16 maxLeaf;
  u16 minLeaf;
  u32 pageSize;
  u32 usableSize;
  int nTransaction;
  u32 nPage;
  void *pSchema;
  void (*xFreeSchema)(void*);
  sqlite3_mutex *mutex;
  Bitvec *pHasContent;

  int nRef;
  BtShared *pNext;
  BtLock *pLock;
  Btree *pWriter;

  u8 *pTmpSpace;
  int nPreformatSize;
};

struct CellInfo {
  i64 nKey;
  u8 *pPayload;
  u32 nPayload;
  u16 nLocal;
  u16 nSize;
};






u8 hia_oracle_3532_GetVarint(const unsigned char *p, u64 *v){
  u32 a,b,s;

  if( ((signed char*)p)[0]>=0 ){
    *v = *p;
    return 1;
  }
  if( ((signed char*)p)[1]>=0 ){
    *v = ((u32)(p[0]&0x7f)<<7) | p[1];
    return 2;
  }


  
# 214 "/home/qq/hia-rewrite-20261113-e26e-r1/sqlite-btree-cell-native-r1/candidate/reference/native-oracle/oracle-sqlite-3.53.2.c" 3 4
 ((
# 214 "/home/qq/hia-rewrite-20261113-e26e-r1/sqlite-btree-cell-native-r1/candidate/reference/native-oracle/oracle-sqlite-3.53.2.c"
 0x001fc07f == ((0x7f<<14) | (0x7f))
# 214 "/home/qq/hia-rewrite-20261113-e26e-r1/sqlite-btree-cell-native-r1/candidate/reference/native-oracle/oracle-sqlite-3.53.2.c" 3 4
 ) ? (void) (0) : __assert_fail (
# 214 "/home/qq/hia-rewrite-20261113-e26e-r1/sqlite-btree-cell-native-r1/candidate/reference/native-oracle/oracle-sqlite-3.53.2.c"
 "SLOT_2_0 == ((0x7f<<14) | (0x7f))"
# 214 "/home/qq/hia-rewrite-20261113-e26e-r1/sqlite-btree-cell-native-r1/candidate/reference/native-oracle/oracle-sqlite-3.53.2.c" 3 4
 , "/home/qq/hia-rewrite-20261113-e26e-r1/sqlite-btree-cell-native-r1/candidate/reference/native-oracle/oracle-sqlite-3.53.2.c", 214, __extension__ __PRETTY_FUNCTION__))
# 214 "/home/qq/hia-rewrite-20261113-e26e-r1/sqlite-btree-cell-native-r1/candidate/reference/native-oracle/oracle-sqlite-3.53.2.c"
                                            ;
  
# 215 "/home/qq/hia-rewrite-20261113-e26e-r1/sqlite-btree-cell-native-r1/candidate/reference/native-oracle/oracle-sqlite-3.53.2.c" 3 4
 ((
# 215 "/home/qq/hia-rewrite-20261113-e26e-r1/sqlite-btree-cell-native-r1/candidate/reference/native-oracle/oracle-sqlite-3.53.2.c"
 0xf01fc07f == ((0xfU<<28) | (0x7f<<14) | (0x7f))
# 215 "/home/qq/hia-rewrite-20261113-e26e-r1/sqlite-btree-cell-native-r1/candidate/reference/native-oracle/oracle-sqlite-3.53.2.c" 3 4
 ) ? (void) (0) : __assert_fail (
# 215 "/home/qq/hia-rewrite-20261113-e26e-r1/sqlite-btree-cell-native-r1/candidate/reference/native-oracle/oracle-sqlite-3.53.2.c"
 "SLOT_4_2_0 == ((0xfU<<28) | (0x7f<<14) | (0x7f))"
# 215 "/home/qq/hia-rewrite-20261113-e26e-r1/sqlite-btree-cell-native-r1/candidate/reference/native-oracle/oracle-sqlite-3.53.2.c" 3 4
 , "/home/qq/hia-rewrite-20261113-e26e-r1/sqlite-btree-cell-native-r1/candidate/reference/native-oracle/oracle-sqlite-3.53.2.c", 215, __extension__ __PRETTY_FUNCTION__))
# 215 "/home/qq/hia-rewrite-20261113-e26e-r1/sqlite-btree-cell-native-r1/candidate/reference/native-oracle/oracle-sqlite-3.53.2.c"
                                                           ;

  a = ((u32)p[0])<<14;
  b = p[1];
  p += 2;
  a |= *p;

  if (!(a&0x80))
  {
    a &= 0x001fc07f;
    b &= 0x7f;
    b = b<<7;
    a |= b;
    *v = a;
    return 3;
  }


  a &= 0x001fc07f;
  p++;
  b = b<<14;
  b |= *p;

  if (!(b&0x80))
  {
    b &= 0x001fc07f;


    a = a<<7;
    a |= b;
    *v = a;
    return 4;
  }






  b &= 0x001fc07f;
  s = a;


  p++;
  a = a<<14;
  a |= *p;

  if (!(a&0x80))
  {




    b = b<<7;
    a |= b;
    s = s>>18;
    *v = ((u64)s)<<32 | a;
    return 5;
  }


  s = s<<7;
  s |= b;


  p++;
  b = b<<14;
  b |= *p;

  if (!(b&0x80))
  {


    a &= 0x001fc07f;
    a = a<<7;
    a |= b;
    s = s>>18;
    *v = ((u64)s)<<32 | a;
    return 6;
  }

  p++;
  a = a<<14;
  a |= *p;

  if (!(a&0x80))
  {
    a &= 0xf01fc07f;
    b &= 0x001fc07f;
    b = b<<7;
    a |= b;
    s = s>>11;
    *v = ((u64)s)<<32 | a;
    return 7;
  }


  a &= 0x001fc07f;
  p++;
  b = b<<14;
  b |= *p;

  if (!(b&0x80))
  {
    b &= 0xf01fc07f;


    a = a<<7;
    a |= b;
    s = s>>4;
    *v = ((u64)s)<<32 | a;
    return 8;
  }

  p++;
  a = a<<15;
  a |= *p;




  b &= 0x001fc07f;
  b = b<<8;
  a |= b;

  s = s<<4;
  b = p[-4];
  b &= 0x7f;
  b = b>>3;
  s |= b;

  *v = ((u64)s)<<32 | a;

  return 9;
}

u8 hia_oracle_3532_GetVarint32(const unsigned char *p, u32 *v){
  u64 v64;
  u8 n;



  
# 357 "/home/qq/hia-rewrite-20261113-e26e-r1/sqlite-btree-cell-native-r1/candidate/reference/native-oracle/oracle-sqlite-3.53.2.c" 3 4
 ((
# 357 "/home/qq/hia-rewrite-20261113-e26e-r1/sqlite-btree-cell-native-r1/candidate/reference/native-oracle/oracle-sqlite-3.53.2.c"
 (p[0] & 0x80)!=0
# 357 "/home/qq/hia-rewrite-20261113-e26e-r1/sqlite-btree-cell-native-r1/candidate/reference/native-oracle/oracle-sqlite-3.53.2.c" 3 4
 ) ? (void) (0) : __assert_fail (
# 357 "/home/qq/hia-rewrite-20261113-e26e-r1/sqlite-btree-cell-native-r1/candidate/reference/native-oracle/oracle-sqlite-3.53.2.c"
 "(p[0] & 0x80)!=0"
# 357 "/home/qq/hia-rewrite-20261113-e26e-r1/sqlite-btree-cell-native-r1/candidate/reference/native-oracle/oracle-sqlite-3.53.2.c" 3 4
 , "/home/qq/hia-rewrite-20261113-e26e-r1/sqlite-btree-cell-native-r1/candidate/reference/native-oracle/oracle-sqlite-3.53.2.c", 357, __extension__ __PRETTY_FUNCTION__))
# 357 "/home/qq/hia-rewrite-20261113-e26e-r1/sqlite-btree-cell-native-r1/candidate/reference/native-oracle/oracle-sqlite-3.53.2.c"
                           ;

  if( (p[1] & 0x80)==0 ){

    *v = ((p[0]&0x7f)<<7) | p[1];
    return 2;
  }
  if( (p[2] & 0x80)==0 ){

    *v = ((p[0]&0x7f)<<14) | ((p[1]&0x7f)<<7) | p[2];
    return 3;
  }

  n = hia_oracle_3532_GetVarint(p, &v64);
  
# 371 "/home/qq/hia-rewrite-20261113-e26e-r1/sqlite-btree-cell-native-r1/candidate/reference/native-oracle/oracle-sqlite-3.53.2.c" 3 4
 ((
# 371 "/home/qq/hia-rewrite-20261113-e26e-r1/sqlite-btree-cell-native-r1/candidate/reference/native-oracle/oracle-sqlite-3.53.2.c"
 n>3 && n<=9
# 371 "/home/qq/hia-rewrite-20261113-e26e-r1/sqlite-btree-cell-native-r1/candidate/reference/native-oracle/oracle-sqlite-3.53.2.c" 3 4
 ) ? (void) (0) : __assert_fail (
# 371 "/home/qq/hia-rewrite-20261113-e26e-r1/sqlite-btree-cell-native-r1/candidate/reference/native-oracle/oracle-sqlite-3.53.2.c"
 "n>3 && n<=9"
# 371 "/home/qq/hia-rewrite-20261113-e26e-r1/sqlite-btree-cell-native-r1/candidate/reference/native-oracle/oracle-sqlite-3.53.2.c" 3 4
 , "/home/qq/hia-rewrite-20261113-e26e-r1/sqlite-btree-cell-native-r1/candidate/reference/native-oracle/oracle-sqlite-3.53.2.c", 371, __extension__ __PRETTY_FUNCTION__))
# 371 "/home/qq/hia-rewrite-20261113-e26e-r1/sqlite-btree-cell-native-r1/candidate/reference/native-oracle/oracle-sqlite-3.53.2.c"
                      ;
  if( (v64 & ((((u64)1)<<32)-1))!=v64 ){
    *v = 0xffffffff;
  }else{
    *v = (u32)v64;
  }
  return n;
}



static __attribute__((noinline)) void btreeParseCellAdjustSizeForOverflow(
  MemPage *pPage,
  u8 *pCell,
  CellInfo *pInfo
){
# 396 "/home/qq/hia-rewrite-20261113-e26e-r1/sqlite-btree-cell-native-r1/candidate/reference/native-oracle/oracle-sqlite-3.53.2.c"
  int minLocal;
  int maxLocal;
  int surplus;

  minLocal = pPage->minLocal;
  maxLocal = pPage->maxLocal;
  surplus = minLocal + (pInfo->nPayload - minLocal)%(pPage->pBt->usableSize-4);
  ((void)0);
  ((void)0);
  if( surplus <= maxLocal ){
    pInfo->nLocal = (u16)surplus;
  }else{
    pInfo->nLocal = (u16)minLocal;
  }
  pInfo->nSize = (u16)(&pInfo->pPayload[pInfo->nLocal] - pCell) + 4;
}

static void btreeParseCellPtrNoPayload(
  MemPage *pPage,
  u8 *pCell,
  CellInfo *pInfo
){
  
# 418 "/home/qq/hia-rewrite-20261113-e26e-r1/sqlite-btree-cell-native-r1/candidate/reference/native-oracle/oracle-sqlite-3.53.2.c" 3 4
 ((
# 418 "/home/qq/hia-rewrite-20261113-e26e-r1/sqlite-btree-cell-native-r1/candidate/reference/native-oracle/oracle-sqlite-3.53.2.c"
 oracle_mutex_held(pPage->pBt->mutex)
# 418 "/home/qq/hia-rewrite-20261113-e26e-r1/sqlite-btree-cell-native-r1/candidate/reference/native-oracle/oracle-sqlite-3.53.2.c" 3 4
 ) ? (void) (0) : __assert_fail (
# 418 "/home/qq/hia-rewrite-20261113-e26e-r1/sqlite-btree-cell-native-r1/candidate/reference/native-oracle/oracle-sqlite-3.53.2.c"
 "sqlite3_mutex_held(pPage->pBt->mutex)"
# 418 "/home/qq/hia-rewrite-20261113-e26e-r1/sqlite-btree-cell-native-r1/candidate/reference/native-oracle/oracle-sqlite-3.53.2.c" 3 4
 , "/home/qq/hia-rewrite-20261113-e26e-r1/sqlite-btree-cell-native-r1/candidate/reference/native-oracle/oracle-sqlite-3.53.2.c", 418, __extension__ __PRETTY_FUNCTION__))
# 418 "/home/qq/hia-rewrite-20261113-e26e-r1/sqlite-btree-cell-native-r1/candidate/reference/native-oracle/oracle-sqlite-3.53.2.c"
                                                ;
  
# 419 "/home/qq/hia-rewrite-20261113-e26e-r1/sqlite-btree-cell-native-r1/candidate/reference/native-oracle/oracle-sqlite-3.53.2.c" 3 4
 ((
# 419 "/home/qq/hia-rewrite-20261113-e26e-r1/sqlite-btree-cell-native-r1/candidate/reference/native-oracle/oracle-sqlite-3.53.2.c"
 pPage->leaf==0
# 419 "/home/qq/hia-rewrite-20261113-e26e-r1/sqlite-btree-cell-native-r1/candidate/reference/native-oracle/oracle-sqlite-3.53.2.c" 3 4
 ) ? (void) (0) : __assert_fail (
# 419 "/home/qq/hia-rewrite-20261113-e26e-r1/sqlite-btree-cell-native-r1/candidate/reference/native-oracle/oracle-sqlite-3.53.2.c"
 "pPage->leaf==0"
# 419 "/home/qq/hia-rewrite-20261113-e26e-r1/sqlite-btree-cell-native-r1/candidate/reference/native-oracle/oracle-sqlite-3.53.2.c" 3 4
 , "/home/qq/hia-rewrite-20261113-e26e-r1/sqlite-btree-cell-native-r1/candidate/reference/native-oracle/oracle-sqlite-3.53.2.c", 419, __extension__ __PRETTY_FUNCTION__))
# 419 "/home/qq/hia-rewrite-20261113-e26e-r1/sqlite-btree-cell-native-r1/candidate/reference/native-oracle/oracle-sqlite-3.53.2.c"
                         ;
  
# 420 "/home/qq/hia-rewrite-20261113-e26e-r1/sqlite-btree-cell-native-r1/candidate/reference/native-oracle/oracle-sqlite-3.53.2.c" 3 4
 ((
# 420 "/home/qq/hia-rewrite-20261113-e26e-r1/sqlite-btree-cell-native-r1/candidate/reference/native-oracle/oracle-sqlite-3.53.2.c"
 pPage->childPtrSize==4
# 420 "/home/qq/hia-rewrite-20261113-e26e-r1/sqlite-btree-cell-native-r1/candidate/reference/native-oracle/oracle-sqlite-3.53.2.c" 3 4
 ) ? (void) (0) : __assert_fail (
# 420 "/home/qq/hia-rewrite-20261113-e26e-r1/sqlite-btree-cell-native-r1/candidate/reference/native-oracle/oracle-sqlite-3.53.2.c"
 "pPage->childPtrSize==4"
# 420 "/home/qq/hia-rewrite-20261113-e26e-r1/sqlite-btree-cell-native-r1/candidate/reference/native-oracle/oracle-sqlite-3.53.2.c" 3 4
 , "/home/qq/hia-rewrite-20261113-e26e-r1/sqlite-btree-cell-native-r1/candidate/reference/native-oracle/oracle-sqlite-3.53.2.c", 420, __extension__ __PRETTY_FUNCTION__))
# 420 "/home/qq/hia-rewrite-20261113-e26e-r1/sqlite-btree-cell-native-r1/candidate/reference/native-oracle/oracle-sqlite-3.53.2.c"
                                 ;

  (void)(pPage);

  pInfo->nSize = 4 + hia_oracle_3532_GetVarint(&pCell[4], (u64*)&pInfo->nKey);
  pInfo->nPayload = 0;
  pInfo->nLocal = 0;
  pInfo->pPayload = 0;
  return;
}

static void btreeParseCellPtr(
  MemPage *pPage,
  u8 *pCell,
  CellInfo *pInfo
){
  u8 *pIter;
  u64 nPayload;
  u64 iKey;

  
# 440 "/home/qq/hia-rewrite-20261113-e26e-r1/sqlite-btree-cell-native-r1/candidate/reference/native-oracle/oracle-sqlite-3.53.2.c" 3 4
 ((
# 440 "/home/qq/hia-rewrite-20261113-e26e-r1/sqlite-btree-cell-native-r1/candidate/reference/native-oracle/oracle-sqlite-3.53.2.c"
 oracle_mutex_held(pPage->pBt->mutex)
# 440 "/home/qq/hia-rewrite-20261113-e26e-r1/sqlite-btree-cell-native-r1/candidate/reference/native-oracle/oracle-sqlite-3.53.2.c" 3 4
 ) ? (void) (0) : __assert_fail (
# 440 "/home/qq/hia-rewrite-20261113-e26e-r1/sqlite-btree-cell-native-r1/candidate/reference/native-oracle/oracle-sqlite-3.53.2.c"
 "sqlite3_mutex_held(pPage->pBt->mutex)"
# 440 "/home/qq/hia-rewrite-20261113-e26e-r1/sqlite-btree-cell-native-r1/candidate/reference/native-oracle/oracle-sqlite-3.53.2.c" 3 4
 , "/home/qq/hia-rewrite-20261113-e26e-r1/sqlite-btree-cell-native-r1/candidate/reference/native-oracle/oracle-sqlite-3.53.2.c", 440, __extension__ __PRETTY_FUNCTION__))
# 440 "/home/qq/hia-rewrite-20261113-e26e-r1/sqlite-btree-cell-native-r1/candidate/reference/native-oracle/oracle-sqlite-3.53.2.c"
                                                ;
  
# 441 "/home/qq/hia-rewrite-20261113-e26e-r1/sqlite-btree-cell-native-r1/candidate/reference/native-oracle/oracle-sqlite-3.53.2.c" 3 4
 ((
# 441 "/home/qq/hia-rewrite-20261113-e26e-r1/sqlite-btree-cell-native-r1/candidate/reference/native-oracle/oracle-sqlite-3.53.2.c"
 pPage->leaf==0 || pPage->leaf==1
# 441 "/home/qq/hia-rewrite-20261113-e26e-r1/sqlite-btree-cell-native-r1/candidate/reference/native-oracle/oracle-sqlite-3.53.2.c" 3 4
 ) ? (void) (0) : __assert_fail (
# 441 "/home/qq/hia-rewrite-20261113-e26e-r1/sqlite-btree-cell-native-r1/candidate/reference/native-oracle/oracle-sqlite-3.53.2.c"
 "pPage->leaf==0 || pPage->leaf==1"
# 441 "/home/qq/hia-rewrite-20261113-e26e-r1/sqlite-btree-cell-native-r1/candidate/reference/native-oracle/oracle-sqlite-3.53.2.c" 3 4
 , "/home/qq/hia-rewrite-20261113-e26e-r1/sqlite-btree-cell-native-r1/candidate/reference/native-oracle/oracle-sqlite-3.53.2.c", 441, __extension__ __PRETTY_FUNCTION__))
# 441 "/home/qq/hia-rewrite-20261113-e26e-r1/sqlite-btree-cell-native-r1/candidate/reference/native-oracle/oracle-sqlite-3.53.2.c"
                                           ;
  
# 442 "/home/qq/hia-rewrite-20261113-e26e-r1/sqlite-btree-cell-native-r1/candidate/reference/native-oracle/oracle-sqlite-3.53.2.c" 3 4
 ((
# 442 "/home/qq/hia-rewrite-20261113-e26e-r1/sqlite-btree-cell-native-r1/candidate/reference/native-oracle/oracle-sqlite-3.53.2.c"
 pPage->intKeyLeaf
# 442 "/home/qq/hia-rewrite-20261113-e26e-r1/sqlite-btree-cell-native-r1/candidate/reference/native-oracle/oracle-sqlite-3.53.2.c" 3 4
 ) ? (void) (0) : __assert_fail (
# 442 "/home/qq/hia-rewrite-20261113-e26e-r1/sqlite-btree-cell-native-r1/candidate/reference/native-oracle/oracle-sqlite-3.53.2.c"
 "pPage->intKeyLeaf"
# 442 "/home/qq/hia-rewrite-20261113-e26e-r1/sqlite-btree-cell-native-r1/candidate/reference/native-oracle/oracle-sqlite-3.53.2.c" 3 4
 , "/home/qq/hia-rewrite-20261113-e26e-r1/sqlite-btree-cell-native-r1/candidate/reference/native-oracle/oracle-sqlite-3.53.2.c", 442, __extension__ __PRETTY_FUNCTION__))
# 442 "/home/qq/hia-rewrite-20261113-e26e-r1/sqlite-btree-cell-native-r1/candidate/reference/native-oracle/oracle-sqlite-3.53.2.c"
                            ;
  
# 443 "/home/qq/hia-rewrite-20261113-e26e-r1/sqlite-btree-cell-native-r1/candidate/reference/native-oracle/oracle-sqlite-3.53.2.c" 3 4
 ((
# 443 "/home/qq/hia-rewrite-20261113-e26e-r1/sqlite-btree-cell-native-r1/candidate/reference/native-oracle/oracle-sqlite-3.53.2.c"
 pPage->childPtrSize==0
# 443 "/home/qq/hia-rewrite-20261113-e26e-r1/sqlite-btree-cell-native-r1/candidate/reference/native-oracle/oracle-sqlite-3.53.2.c" 3 4
 ) ? (void) (0) : __assert_fail (
# 443 "/home/qq/hia-rewrite-20261113-e26e-r1/sqlite-btree-cell-native-r1/candidate/reference/native-oracle/oracle-sqlite-3.53.2.c"
 "pPage->childPtrSize==0"
# 443 "/home/qq/hia-rewrite-20261113-e26e-r1/sqlite-btree-cell-native-r1/candidate/reference/native-oracle/oracle-sqlite-3.53.2.c" 3 4
 , "/home/qq/hia-rewrite-20261113-e26e-r1/sqlite-btree-cell-native-r1/candidate/reference/native-oracle/oracle-sqlite-3.53.2.c", 443, __extension__ __PRETTY_FUNCTION__))
# 443 "/home/qq/hia-rewrite-20261113-e26e-r1/sqlite-btree-cell-native-r1/candidate/reference/native-oracle/oracle-sqlite-3.53.2.c"
                                 ;
  pIter = pCell;







  nPayload = *pIter;
  if( nPayload>=0x80 ){
    u8 *pEnd = &pIter[8];
    nPayload &= 0x7f;
    do{
      nPayload = (nPayload<<7) | (*++pIter & 0x7f);
    }while( (*pIter)>=0x80 && pIter<pEnd );
    nPayload &= 0xffffffff;
  }
  pIter++;
# 470 "/home/qq/hia-rewrite-20261113-e26e-r1/sqlite-btree-cell-native-r1/candidate/reference/native-oracle/oracle-sqlite-3.53.2.c"
  iKey = *pIter;
  if( iKey>=0x80 ){
    u8 x;
    iKey = (iKey<<7) ^ (x = *++pIter);
    if( x>=0x80 ){
      iKey = (iKey<<7) ^ (x = *++pIter);
      if( x>=0x80 ){
        iKey = (iKey<<7) ^ 0x10204000 ^ (x = *++pIter);
        if( x>=0x80 ){
          iKey = (iKey<<7) ^ 0x4000 ^ (x = *++pIter);
          if( x>=0x80 ){
            iKey = (iKey<<7) ^ 0x4000 ^ (x = *++pIter);
            if( x>=0x80 ){
              iKey = (iKey<<7) ^ 0x4000 ^ (x = *++pIter);
              if( x>=0x80 ){
                iKey = (iKey<<7) ^ 0x4000 ^ (x = *++pIter);
                if( x>=0x80 ){
                  iKey = (iKey<<8) ^ 0x8000 ^ (*++pIter);
                }
              }
            }
          }
        }
      }else{
        iKey ^= 0x204000;
      }
    }else{
      iKey ^= 0x4000;
    }
  }
  pIter++;

  pInfo->nKey = *(i64*)&iKey;
  pInfo->nPayload = (u32)nPayload;
  pInfo->pPayload = pIter;
  ((void)0);
  ((void)0);
  
# 507 "/home/qq/hia-rewrite-20261113-e26e-r1/sqlite-btree-cell-native-r1/candidate/reference/native-oracle/oracle-sqlite-3.53.2.c" 3 4
 ((
# 507 "/home/qq/hia-rewrite-20261113-e26e-r1/sqlite-btree-cell-native-r1/candidate/reference/native-oracle/oracle-sqlite-3.53.2.c"
 pPage->maxLocal <= 65501
# 507 "/home/qq/hia-rewrite-20261113-e26e-r1/sqlite-btree-cell-native-r1/candidate/reference/native-oracle/oracle-sqlite-3.53.2.c" 3 4
 ) ? (void) (0) : __assert_fail (
# 507 "/home/qq/hia-rewrite-20261113-e26e-r1/sqlite-btree-cell-native-r1/candidate/reference/native-oracle/oracle-sqlite-3.53.2.c"
 "pPage->maxLocal <= BT_MAX_LOCAL"
# 507 "/home/qq/hia-rewrite-20261113-e26e-r1/sqlite-btree-cell-native-r1/candidate/reference/native-oracle/oracle-sqlite-3.53.2.c" 3 4
 , "/home/qq/hia-rewrite-20261113-e26e-r1/sqlite-btree-cell-native-r1/candidate/reference/native-oracle/oracle-sqlite-3.53.2.c", 507, __extension__ __PRETTY_FUNCTION__))
# 507 "/home/qq/hia-rewrite-20261113-e26e-r1/sqlite-btree-cell-native-r1/candidate/reference/native-oracle/oracle-sqlite-3.53.2.c"
                                          ;
  if( nPayload<=pPage->maxLocal ){



    pInfo->nSize = (u16)nPayload + (u16)(pIter - pCell);
    if( pInfo->nSize<4 ) pInfo->nSize = 4;
    pInfo->nLocal = (u16)nPayload;
  }else{
    btreeParseCellAdjustSizeForOverflow(pPage, pCell, pInfo);
  }
}

static void btreeParseCellPtrIndex(
  MemPage *pPage,
  u8 *pCell,
  CellInfo *pInfo
){
  u8 *pIter;
  u32 nPayload;

  
# 528 "/home/qq/hia-rewrite-20261113-e26e-r1/sqlite-btree-cell-native-r1/candidate/reference/native-oracle/oracle-sqlite-3.53.2.c" 3 4
 ((
# 528 "/home/qq/hia-rewrite-20261113-e26e-r1/sqlite-btree-cell-native-r1/candidate/reference/native-oracle/oracle-sqlite-3.53.2.c"
 oracle_mutex_held(pPage->pBt->mutex)
# 528 "/home/qq/hia-rewrite-20261113-e26e-r1/sqlite-btree-cell-native-r1/candidate/reference/native-oracle/oracle-sqlite-3.53.2.c" 3 4
 ) ? (void) (0) : __assert_fail (
# 528 "/home/qq/hia-rewrite-20261113-e26e-r1/sqlite-btree-cell-native-r1/candidate/reference/native-oracle/oracle-sqlite-3.53.2.c"
 "sqlite3_mutex_held(pPage->pBt->mutex)"
# 528 "/home/qq/hia-rewrite-20261113-e26e-r1/sqlite-btree-cell-native-r1/candidate/reference/native-oracle/oracle-sqlite-3.53.2.c" 3 4
 , "/home/qq/hia-rewrite-20261113-e26e-r1/sqlite-btree-cell-native-r1/candidate/reference/native-oracle/oracle-sqlite-3.53.2.c", 528, __extension__ __PRETTY_FUNCTION__))
# 528 "/home/qq/hia-rewrite-20261113-e26e-r1/sqlite-btree-cell-native-r1/candidate/reference/native-oracle/oracle-sqlite-3.53.2.c"
                                                ;
  
# 529 "/home/qq/hia-rewrite-20261113-e26e-r1/sqlite-btree-cell-native-r1/candidate/reference/native-oracle/oracle-sqlite-3.53.2.c" 3 4
 ((
# 529 "/home/qq/hia-rewrite-20261113-e26e-r1/sqlite-btree-cell-native-r1/candidate/reference/native-oracle/oracle-sqlite-3.53.2.c"
 pPage->leaf==0 || pPage->leaf==1
# 529 "/home/qq/hia-rewrite-20261113-e26e-r1/sqlite-btree-cell-native-r1/candidate/reference/native-oracle/oracle-sqlite-3.53.2.c" 3 4
 ) ? (void) (0) : __assert_fail (
# 529 "/home/qq/hia-rewrite-20261113-e26e-r1/sqlite-btree-cell-native-r1/candidate/reference/native-oracle/oracle-sqlite-3.53.2.c"
 "pPage->leaf==0 || pPage->leaf==1"
# 529 "/home/qq/hia-rewrite-20261113-e26e-r1/sqlite-btree-cell-native-r1/candidate/reference/native-oracle/oracle-sqlite-3.53.2.c" 3 4
 , "/home/qq/hia-rewrite-20261113-e26e-r1/sqlite-btree-cell-native-r1/candidate/reference/native-oracle/oracle-sqlite-3.53.2.c", 529, __extension__ __PRETTY_FUNCTION__))
# 529 "/home/qq/hia-rewrite-20261113-e26e-r1/sqlite-btree-cell-native-r1/candidate/reference/native-oracle/oracle-sqlite-3.53.2.c"
                                           ;
  
# 530 "/home/qq/hia-rewrite-20261113-e26e-r1/sqlite-btree-cell-native-r1/candidate/reference/native-oracle/oracle-sqlite-3.53.2.c" 3 4
 ((
# 530 "/home/qq/hia-rewrite-20261113-e26e-r1/sqlite-btree-cell-native-r1/candidate/reference/native-oracle/oracle-sqlite-3.53.2.c"
 pPage->intKeyLeaf==0
# 530 "/home/qq/hia-rewrite-20261113-e26e-r1/sqlite-btree-cell-native-r1/candidate/reference/native-oracle/oracle-sqlite-3.53.2.c" 3 4
 ) ? (void) (0) : __assert_fail (
# 530 "/home/qq/hia-rewrite-20261113-e26e-r1/sqlite-btree-cell-native-r1/candidate/reference/native-oracle/oracle-sqlite-3.53.2.c"
 "pPage->intKeyLeaf==0"
# 530 "/home/qq/hia-rewrite-20261113-e26e-r1/sqlite-btree-cell-native-r1/candidate/reference/native-oracle/oracle-sqlite-3.53.2.c" 3 4
 , "/home/qq/hia-rewrite-20261113-e26e-r1/sqlite-btree-cell-native-r1/candidate/reference/native-oracle/oracle-sqlite-3.53.2.c", 530, __extension__ __PRETTY_FUNCTION__))
# 530 "/home/qq/hia-rewrite-20261113-e26e-r1/sqlite-btree-cell-native-r1/candidate/reference/native-oracle/oracle-sqlite-3.53.2.c"
                               ;
  pIter = pCell + pPage->childPtrSize;
  nPayload = *pIter;
  if( nPayload>=0x80 ){
    u8 *pEnd = &pIter[8];
    nPayload &= 0x7f;
    do{
      nPayload = (nPayload<<7) | (*++pIter & 0x7f);
    }while( *(pIter)>=0x80 && pIter<pEnd );
  }
  pIter++;
  pInfo->nKey = nPayload;
  pInfo->nPayload = nPayload;
  pInfo->pPayload = pIter;
  ((void)0);
  ((void)0);
  
# 546 "/home/qq/hia-rewrite-20261113-e26e-r1/sqlite-btree-cell-native-r1/candidate/reference/native-oracle/oracle-sqlite-3.53.2.c" 3 4
 ((
# 546 "/home/qq/hia-rewrite-20261113-e26e-r1/sqlite-btree-cell-native-r1/candidate/reference/native-oracle/oracle-sqlite-3.53.2.c"
 nPayload>=0
# 546 "/home/qq/hia-rewrite-20261113-e26e-r1/sqlite-btree-cell-native-r1/candidate/reference/native-oracle/oracle-sqlite-3.53.2.c" 3 4
 ) ? (void) (0) : __assert_fail (
# 546 "/home/qq/hia-rewrite-20261113-e26e-r1/sqlite-btree-cell-native-r1/candidate/reference/native-oracle/oracle-sqlite-3.53.2.c"
 "nPayload>=0"
# 546 "/home/qq/hia-rewrite-20261113-e26e-r1/sqlite-btree-cell-native-r1/candidate/reference/native-oracle/oracle-sqlite-3.53.2.c" 3 4
 , "/home/qq/hia-rewrite-20261113-e26e-r1/sqlite-btree-cell-native-r1/candidate/reference/native-oracle/oracle-sqlite-3.53.2.c", 546, __extension__ __PRETTY_FUNCTION__))
# 546 "/home/qq/hia-rewrite-20261113-e26e-r1/sqlite-btree-cell-native-r1/candidate/reference/native-oracle/oracle-sqlite-3.53.2.c"
                      ;
  
# 547 "/home/qq/hia-rewrite-20261113-e26e-r1/sqlite-btree-cell-native-r1/candidate/reference/native-oracle/oracle-sqlite-3.53.2.c" 3 4
 ((
# 547 "/home/qq/hia-rewrite-20261113-e26e-r1/sqlite-btree-cell-native-r1/candidate/reference/native-oracle/oracle-sqlite-3.53.2.c"
 pPage->maxLocal <= 65501
# 547 "/home/qq/hia-rewrite-20261113-e26e-r1/sqlite-btree-cell-native-r1/candidate/reference/native-oracle/oracle-sqlite-3.53.2.c" 3 4
 ) ? (void) (0) : __assert_fail (
# 547 "/home/qq/hia-rewrite-20261113-e26e-r1/sqlite-btree-cell-native-r1/candidate/reference/native-oracle/oracle-sqlite-3.53.2.c"
 "pPage->maxLocal <= BT_MAX_LOCAL"
# 547 "/home/qq/hia-rewrite-20261113-e26e-r1/sqlite-btree-cell-native-r1/candidate/reference/native-oracle/oracle-sqlite-3.53.2.c" 3 4
 , "/home/qq/hia-rewrite-20261113-e26e-r1/sqlite-btree-cell-native-r1/candidate/reference/native-oracle/oracle-sqlite-3.53.2.c", 547, __extension__ __PRETTY_FUNCTION__))
# 547 "/home/qq/hia-rewrite-20261113-e26e-r1/sqlite-btree-cell-native-r1/candidate/reference/native-oracle/oracle-sqlite-3.53.2.c"
                                          ;
  if( nPayload<=pPage->maxLocal ){



    pInfo->nSize = (u16)nPayload + (u16)(pIter - pCell);
    if( pInfo->nSize<4 ) pInfo->nSize = 4;
    pInfo->nLocal = (u16)nPayload;
  }else{
    btreeParseCellAdjustSizeForOverflow(pPage, pCell, pInfo);
  }
}
# 570 "/home/qq/hia-rewrite-20261113-e26e-r1/sqlite-btree-cell-native-r1/candidate/reference/native-oracle/oracle-sqlite-3.53.2.c"
uint32_t oracle_cell(const unsigned char *page, uint64_t page_bytes,
                     uint64_t usable, uint64_t kind, uint64_t cell_offset,
                     uint64_t *out6){
  BtShared shared = {0};
  BtShared *pBt = &shared;
  MemPage page_state = {0};
  MemPage *pPage = &page_state;
  CellInfo info;
  uint64_t key_bits;
  uintptr_t base, payload;

  if( page == 
# 581 "/home/qq/hia-rewrite-20261113-e26e-r1/sqlite-btree-cell-native-r1/candidate/reference/native-oracle/oracle-sqlite-3.53.2.c" 3 4
             ((void *)0) 
# 581 "/home/qq/hia-rewrite-20261113-e26e-r1/sqlite-btree-cell-native-r1/candidate/reference/native-oracle/oracle-sqlite-3.53.2.c"
                  || out6 == 
# 581 "/home/qq/hia-rewrite-20261113-e26e-r1/sqlite-btree-cell-native-r1/candidate/reference/native-oracle/oracle-sqlite-3.53.2.c" 3 4
                             ((void *)0)
      
# 582 "/home/qq/hia-rewrite-20261113-e26e-r1/sqlite-btree-cell-native-r1/candidate/reference/native-oracle/oracle-sqlite-3.53.2.c"
     || page_bytes < 512 || page_bytes > 65536
      || (page_bytes & (page_bytes-1)) != 0
      || usable < 480 || usable > page_bytes || page_bytes-usable > 255
      || (kind != 2 && kind != 5 && kind != 10 && kind != 13)
      || cell_offset > usable-4 ){
    return 1;
  }
  pBt->pageSize = (u32)page_bytes;
  pBt->usableSize = (u32)usable;

  pBt->maxLocal = (u16)((pBt->usableSize-12)*64/255 - 23);
  pBt->minLocal = (u16)((pBt->usableSize-12)*32/255 - 23);
  pBt->maxLeaf = (u16)(pBt->usableSize - 35);
  pBt->minLeaf = (u16)((pBt->usableSize-12)*32/255 - 23);





  pPage->pBt = pBt;
  pPage->isInit = 1;
  pPage->leaf = (kind == 10 || kind == 13);
  pPage->intKey = (kind == 5 || kind == 13);
  pPage->intKeyLeaf = (kind == 13);
  pPage->childPtrSize = pPage->leaf ? 0 : 4;
  pPage->minLocal = pPage->intKey ? pBt->minLeaf : pBt->minLocal;
  pPage->maxLocal = pPage->intKey ? pBt->maxLeaf : pBt->maxLocal;
  pPage->aData = (u8 *)page;
  pPage->aDataEnd = (u8 *)page + page_bytes;
  memset(&info, 0xa5, sizeof(info));

  if( kind == 5 ){
    btreeParseCellPtrNoPayload(pPage, (u8 *)page + cell_offset, &info);
  }else if( kind == 13 ){
    btreeParseCellPtr(pPage, (u8 *)page + cell_offset, &info);
  }else{
    btreeParseCellPtrIndex(pPage, (u8 *)page + cell_offset, &info);
  }

  memcpy(&key_bits, &info.nKey, sizeof(key_bits));
  out6[0] = key_bits;
  out6[1] = info.pPayload == 
# 623 "/home/qq/hia-rewrite-20261113-e26e-r1/sqlite-btree-cell-native-r1/candidate/reference/native-oracle/oracle-sqlite-3.53.2.c" 3 4
                            ((void *)0)
# 623 "/home/qq/hia-rewrite-20261113-e26e-r1/sqlite-btree-cell-native-r1/candidate/reference/native-oracle/oracle-sqlite-3.53.2.c"
                                ;
  out6[2] = info.pPayload == 
# 624 "/home/qq/hia-rewrite-20261113-e26e-r1/sqlite-btree-cell-native-r1/candidate/reference/native-oracle/oracle-sqlite-3.53.2.c" 3 4
                            ((void *)0) 
# 624 "/home/qq/hia-rewrite-20261113-e26e-r1/sqlite-btree-cell-native-r1/candidate/reference/native-oracle/oracle-sqlite-3.53.2.c"
                                 ? 0 : 
# 624 "/home/qq/hia-rewrite-20261113-e26e-r1/sqlite-btree-cell-native-r1/candidate/reference/native-oracle/oracle-sqlite-3.53.2.c" 3 4
                                       (18446744073709551615UL)
# 624 "/home/qq/hia-rewrite-20261113-e26e-r1/sqlite-btree-cell-native-r1/candidate/reference/native-oracle/oracle-sqlite-3.53.2.c"
                                                 ;
  out6[3] = info.nPayload;
  out6[4] = info.nLocal;
  out6[5] = info.nSize;
  if( info.pPayload != 
# 628 "/home/qq/hia-rewrite-20261113-e26e-r1/sqlite-btree-cell-native-r1/candidate/reference/native-oracle/oracle-sqlite-3.53.2.c" 3 4
                      ((void *)0) 
# 628 "/home/qq/hia-rewrite-20261113-e26e-r1/sqlite-btree-cell-native-r1/candidate/reference/native-oracle/oracle-sqlite-3.53.2.c"
                           ){
    base = (uintptr_t)page;
    payload = (uintptr_t)info.pPayload;
    if( base > 
# 631 "/home/qq/hia-rewrite-20261113-e26e-r1/sqlite-btree-cell-native-r1/candidate/reference/native-oracle/oracle-sqlite-3.53.2.c" 3 4
              (18446744073709551615UL)
# 631 "/home/qq/hia-rewrite-20261113-e26e-r1/sqlite-btree-cell-native-r1/candidate/reference/native-oracle/oracle-sqlite-3.53.2.c"
                         -page_bytes || payload < base || payload > base+page_bytes ){
      return 2;
    }
    out6[2] = payload-base;
  }
  return 0;
}
