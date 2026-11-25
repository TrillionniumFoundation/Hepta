/* Independent NON-HIA isolated guest observer.
 * Only f0 is the compiler-generated terminal HIA IRETQ subject. */
.set MB_MAGIC,0x1badb002
.set MB_FLAGS,3
.section .multiboot,"a",@progbits
.balign 4
.long MB_MAGIC,MB_FLAGS,-(MB_MAGIC+MB_FLAGS)
.section .text.boot,"ax",@progbits
.code32
.global _start
_start:
    cli
    cld
    cmpl $0x2badb002,%eax
    jne fail32
    lgdt gdt_ptr
    ljmp $0x08,$protected32
protected32:
    movw $0x10,%ax
    movw %ax,%ds
    movw %ax,%es
    movw %ax,%ss
    movl $stack32_top,%esp
    xorl %eax,%eax
    movl $pml4,%edi
    movl $3072,%ecx
    rep stosl
    movl $pdpt,%eax
    orl $7,%eax
    movl %eax,pml4
    movl $pd0,%eax
    orl $7,%eax
    movl %eax,pdpt
    movl $pd0,%edi
    movl $0x83,%eax
    movl $512,%ecx
1:  movl %eax,(%edi)
    movl $0,4(%edi)
    addl $0x200000,%eax
    addl $8,%edi
    loop 1b
    /* User RX code and separate user RW/NX stack. */
    movl $0x400085,pd0+2*8
    movl $0x600087,pd0+3*8
    movl $0x80000000,pd0+3*8+4
    movl $user_payload,%esi
    movl $0x400000,%edi
    movl $(user_end-user_payload),%ecx
    rep movsb
    movl %cr4,%eax
    orl $0x20,%eax
    movl %eax,%cr4
    movl $pml4,%eax
    movl %eax,%cr3
    movl $0xc0000080,%ecx
    rdmsr
    orl $0x901,%eax
    wrmsr
    movl %cr0,%eax
    orl $0x80010000,%eax
    movl %eax,%cr0
    ljmp $0x18,$long64
fail32:
    movl $0x12,%eax
    movw $0xf4,%dx
    outl %eax,%dx
    cli
1:  hlt
    jmp 1b
.code64
.macro put_msr index
    movq %rax,%rdx
    shrq $32,%rdx
    movl $\index,%ecx
    wrmsr
.endm
long64:
    movw $0x10,%ax
    movw %ax,%ds
    movw %ax,%es
    movw %ax,%ss
    leaq stack64_top(%rip),%rsp
    leaq ud_handler(%rip),%rax
    leaq idt+6*16(%rip),%rdi
    movw %ax,(%rdi)
    movw $0x18,2(%rdi)
    movb $0,4(%rdi)
    movb $0x8e,5(%rdi)
    shrq $16,%rax
    movw %ax,6(%rdi)
    shrq $16,%rax
    movl %eax,8(%rdi)
    movl $0,12(%rdi)
    lidt idtr(%rip)
    /* Independent observer owns the syscall return-to-observer mechanism.
     * There is no IRETQ instruction here: only the HIA object owns it. */
    movabsq $0x0000001800000000,%rax
    put_msr 0xc0000081
    movabsq $syscall_entry,%rax
    put_msr 0xc0000082
    movq $0xad5,%rax
    put_msr 0xc0000084
    movq $0x400000,%rdi
    movl $0x2b,%esi
    movl $2,%edx
    movq $0x700000,%rcx
    movl $0x33,%r8d
#ifdef HIA_TEST_IRETQ_SECOND
    movq $(0x400000+user_second-user_payload),%rdi
    movl $0x8d7,%edx
    movq $0x710000,%rcx
#elif defined(HIA_TEST_IRETQ_BAD_RIP)
    movabsq $0x0000800000000000,%rdi
#elif defined(HIA_TEST_IRETQ_BAD_RSP)
    xorl %ecx,%ecx
#elif defined(HIA_TEST_IRETQ_BAD_CS)
    movl $0x18,%esi
#elif defined(HIA_TEST_IRETQ_BAD_SS)
    movl $3,%r8d
#elif defined(HIA_TEST_IRETQ_BAD_FLAGS)
    movl $0x3002,%edx
#elif defined(HIA_TEST_IRETQ_MISSING_BIT)
    xorl %edx,%edx
#endif
    call f0
    jmp abort
syscall_entry:
    /* SYSCALL does not switch stacks; capture actual hardware state before
     * touching memory through RSP. User payload's MOVs do not alter flags. */
    movq %rsp,%r12
    movq %rcx,%r13
    movq %r11,%r14
    leaq stack64_top(%rip),%rsp
    pushfq
    popq %r15
#if defined(HIA_TEST_IRETQ_TRAP_DELTA)
    jmp abort
#endif
    cmpw $0x2b,%dx
    jne abort
    cmpw $0x33,%si
    jne abort
#ifdef HIA_TEST_IRETQ_SECOND
    cmpq $0x2468ace0,%rax
    jne abort
    cmpq $0x710000,%r12
    jne abort
    cmpq $(0x400000+user_second_after-user_payload),%r13
    jne abort
    cmpq $0x8d7,%r14
    jne abort
#else
    cmpq $0x13579bdf,%rax
    jne abort
    cmpq $0x700000,%r12
    jne abort
    cmpq $(0x400000+user_first_after-user_payload),%r13
    jne abort
    cmpq $2,%r14
    jne abort
#endif
    testq $0xad5,%r15
    jnz abort
    xorq %rax,%rax
    movw %cs,%ax
    cmpq $0x18,%rax
    jne abort
    movw %ss,%ax
    cmpq $0x20,%rax
    jne abort
#ifdef HIA_TEST_IRETQ_GUARD_BYPASS
    movb $'N',%bl
#else
    movb $'P',%bl
#endif
    jmp finish
ud_handler:
#ifdef HIA_TEST_IRETQ_TRAP_DELTA
    leaq f0(%rip),%rax
    addq $HIA_TEST_IRETQ_TRAP_DELTA,%rax
    cmpq %rax,(%rsp)
    jne abort
    cmpw $0x18,8(%rsp)
    jne abort
#ifdef HIA_TEST_IRETQ_NOP
    movb $'N',%bl
#else
    movb $'P',%bl
#endif
    jmp finish
#else
    jmp abort
#endif
.global abort
abort:
    movb $'A',%bl
finish:
    movl $0x10,%eax
    cmpb $'P',%bl
    je 1f
    movl $0x11,%eax
    cmpb $'N',%bl
    je 1f
    movl $0x12,%eax
1:  pushq %rax
    movw $0xe9,%dx
    movb %bl,%al
    outb %al,%dx
    popq %rax
    movw $0xf4,%dx
    outl %eax,%dx
    cli
2:  hlt
    jmp 2b
.section .rodata,"a",@progbits
.balign 8
gdt:
    .quad 0,0x00cf9a000000ffff,0x00cf92000000ffff,0x00af9a000000ffff
    .quad 0x00cf92000000ffff,0x00affa000000ffff,0x00cff2000000ffff
gdt_end:
gdt_ptr:
    .word gdt_end-gdt-1
    .long gdt
idtr:
    .word 4095
    .quad idt
user_payload:
    movw %cs,%dx
    movw %ss,%si
    movl $0x13579bdf,%eax
    syscall
user_first_after:
    ud2
user_second:
    movw %cs,%dx
    movw %ss,%si
    movl $0x2468ace0,%eax
    syscall
user_second_after:
    ud2
user_end:
.section .bss,"aw",@nobits
.balign 4096
pml4: .skip 4096
pdpt: .skip 4096
pd0: .skip 4096
.balign 16
stack32: .skip 4096
stack32_top:
stack64: .skip 8192
stack64_top:
idt: .skip 4096
