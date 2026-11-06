/* SPDX-License-Identifier: GPL-2.0 */
#include <linux/linkage.h>
#include <linux/objtool.h>
#include <asm/asm.h>

/* Linux's hweight inline asm promises all GPRs except RAX are preserved.
 * Test the eight caller-saved registers which an ordinary C ABI can clobber.
 * Conventional callee-saved registers are not modified by this driver.
 */
SYM_FUNC_START(hia_hweight_abi_probe)
    ANNOTATE_NOENDBR
    movl %edi, %edi
    pushq %rdi
    movl $0x11111111, %esi
    movl $0x22222222, %edx
    movl $0x33333333, %ecx
    movl $0x44444444, %r8d
    movl $0x55555555, %r9d
    movl $0x66666666, %r10d
    movl $0x77777777, %r11d
    call __sw_hweight32
    cmpq (%rsp), %rdi
    jne .Lhia_abi_failed
    cmpq $0x11111111, %rsi
    jne .Lhia_abi_failed
    cmpq $0x22222222, %rdx
    jne .Lhia_abi_failed
    cmpq $0x33333333, %rcx
    jne .Lhia_abi_failed
    cmpq $0x44444444, %r8
    jne .Lhia_abi_failed
    cmpq $0x55555555, %r9
    jne .Lhia_abi_failed
    cmpq $0x66666666, %r10
    jne .Lhia_abi_failed
    cmpq $0x77777777, %r11
    jne .Lhia_abi_failed
    xorl %eax, %eax
    jmp .Lhia_abi_return
.Lhia_abi_failed:
    movl $1, %eax
.Lhia_abi_return:
    popq %rdi
    RET
SYM_FUNC_END(hia_hweight_abi_probe)
