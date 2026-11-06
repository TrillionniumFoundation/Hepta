/* Compile this with the pinned Clang frontend. It exercises the actual
 * GNU asm-goto -> callbr + InlineAsm value route used by Linux. */
int hia_asm_goto(int value)
{
    __asm__ goto ("testl %0, %0\n\tjnz %l[nonzero]"
                  : : "r" (value) : "cc", "memory" : nonzero);
    return 11;
nonzero:
    return 19;
}

int hia_inline_asm_output(int value)
{
    __asm__ volatile ("" : "+r" (value) : : "memory");
    return value + 1;
}

int hia_indirect_call(int (*function)(int), int value)
{
    return function(value);
}
