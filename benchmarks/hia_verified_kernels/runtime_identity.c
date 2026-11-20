/* Observe the actual libc/IFUNC dependency of the native Rust copy arm. */
#define _GNU_SOURCE
#include <dlfcn.h>
#include <gnu/libc-version.h>
#include <inttypes.h>
#include <stdint.h>
#include <stdio.h>

int main(void) {
    void *address = dlsym(RTLD_DEFAULT, "memcpy");
    Dl_info info;
    if (!address || !dladdr(address, &info) || !info.dli_fname || !info.dli_fbase) return 1;
    /* A line-based format avoids interpolating a host pathname into JSON. */
    printf("%s\n%s\n%" PRIuPTR "\n", gnu_get_libc_version(), info.dli_fname,
           (uintptr_t)address - (uintptr_t)info.dli_fbase);
    return 0;
}
