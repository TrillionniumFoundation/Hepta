#include "wrapper_config.h"
extern int hia_asm_goto(int);
extern int hia_inline_asm_output(int);
extern int asm_answer(void);
extern int raw_answer(void);
extern const unsigned char smoke_blob[], module_blob[], inline_blob[];
__asm__(".pushsection .rodata\n.globl module_blob\nmodule_blob:\n"
        ".incbin \"data/module.bin\"\n.popsection\n");
static _Atomic int counter;
__attribute__((noinline)) static void emit_inline_blob(void)
{
    __asm__ volatile(".pushsection .rodata\n.globl inline_blob\ninline_blob:\n"
                     ".incbin \"data/inline.bin\"\n.popsection\n" ::: "memory");
}
__attribute__((noinline)) int ordinary(int n)
{
    int result = CONFIG_SMOKE_BASE;
    for (int i = 0; i < n; ++i)
        result += i;
    __asm__ volatile("" : "+r"(result) :: "memory");
    return result;
}
int main(void)
{
    emit_inline_blob();
    int old = __c11_atomic_fetch_add(&counter, 1, __ATOMIC_RELAXED);
    return old != 0 || ordinary(4) != 12 ||
        hia_asm_goto(0) != 11 || hia_asm_goto(1) != 19 ||
        hia_inline_asm_output(41) != 42 ||
        asm_answer() != 42 || raw_answer() != 13 ||
        smoke_blob[0] != 7 || module_blob[0] != 8 || inline_blob[0] != 9;
}
