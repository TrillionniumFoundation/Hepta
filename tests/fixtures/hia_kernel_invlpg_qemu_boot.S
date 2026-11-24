/* Explicit NON-HIA, isolated Multiboot-v1 hardware observer.
 * Only linked f0 is compiled from verified typed HIA Core. Never install on host. */
.set MB_MAGIC, 0x1badb002
.set MB_FLAGS, 0x00000003
.section .multiboot,"a",@progbits
.balign 4
.long MB_MAGIC, MB_FLAGS, -(MB_MAGIC+MB_FLAGS)
.section .text.boot,"ax",@progbits
.code32
.global _start
_start:
    cli
    cld
    cmpl $0x2badb002, %eax
    jne fail32
    lgdt gdt_ptr
    ljmp $0x08, $protected32
protected32:
    movw $0x10, %ax
    movw %ax, %ds
    movw %ax, %es
    movw %ax, %ss
    movl $stack32_top, %esp
    xorl %eax, %eax
    movl $pml4, %edi
    movl $3072, %ecx
    rep stosl
    movl $pdpt, %eax
    orl $3, %eax
    movl %eax, pml4
    movl $pd0, %eax
    orl $3, %eax
    movl %eax, pdpt
    movl $pd0, %edi
    movl $0x83, %eax
    movl $512, %ecx
1:
    movl %eax, (%edi)
    movl $0, 4(%edi)
    addl $0x200000, %eax
    addl $8, %edi
    loop 1b
    movl %cr4, %eax
    orl $0x20, %eax
    movl %eax, %cr4
    movl $pml4, %eax
    movl %eax, %cr3
    movl $0xc0000080, %ecx
    rdmsr
    orl $0x100, %eax
    wrmsr
    movl %cr0, %eax
    orl $0x80000000, %eax
    movl %eax, %cr0
    ljmp $0x18, $long64
fail32:
    movl $0x11, %eax
    movw $0xf4, %dx
    outl %eax, %dx
    cli
1:  hlt
    jmp 1b
.code64
long64:
    movw $0x10, %ax
    movw %ax, %ds
    movw %ax, %es
    movw %ax, %ss
    leaq stack64_top(%rip), %rsp
    /* Only #PF vector 14 is installed; all other faults fail by reset/timeout. */
    leaq pf_handler(%rip), %rax
    leaq idt+14*16(%rip), %rdi
    movw %ax, (%rdi)
    movw $0x18, 2(%rdi)
    movb $0, 4(%rdi)
    movb $0x8e, 5(%rdi)
    shrq $16, %rax
    movw %ax, 6(%rdi)
    shrq $16, %rax
    movl %eax, 8(%rdi)
    movl $0, 12(%rdi)
    lidt idtr(%rip)
#if defined(HIA_TEST_CR0_READ) || defined(HIA_TEST_CR4_READ)
    /* Independent test-only CR writes; subject f0 is a HIA read only.
     * Compare two distinct valid states, then restore the original CR. */
#ifdef HIA_TEST_CR0_READ
#define TEST_CR %cr0
#define TEST_BIT 0x10000
#else
#define TEST_CR %cr4
#define TEST_BIT 0x80
    /* PGE must be available before toggling CR4.PGE. */
    movl $1, %eax
    cpuid
    testl $0x2000, %edx
    jz fail64
#endif
    movq TEST_CR, %r12
    movq %r12, %r13
    andq $~TEST_BIT, %r13
    movq %r13, TEST_CR
    movq $0x1234, %rdi
    call f0
    cmpq %r13, %rax
    jne fail64
    movq TEST_CR, %rcx
    cmpq %r13, %rcx
    jne fail64
    orq $TEST_BIT, %r13
    movq %r13, TEST_CR
    movq $0x5678, %rdi
    call f0
    cmpq %r13, %rax
    jne fail64
    movq TEST_CR, %rcx
    cmpq %r13, %rcx
    jne fail64
    movq %r12, TEST_CR
    movq TEST_CR, %rcx
    cmpq %r12, %rcx
    jne fail64
    movb $'P', %bl
    jmp debug_exit64
#undef TEST_CR
#undef TEST_BIT
#endif
#ifdef HIA_TEST_CR2_READ
    /* Two genuine supervisor non-present reads, not software writes to CR2.
     * The observer owns exception entry/IRET; f0 alone reads CR2 in HIA. */
    andq $-2, pd0+16(%rip)
    andq $-2, pd0+24(%rip)
    mfence
    movq $0x400000, %rax
    invlpg (%rax)
    movq $0x600000, %rax
    invlpg (%rax)
cr2_probe_a:
    movq 0x400000, %rax
    jmp fail64
cr2_probe_b:
    movq 0x600000, %rax
    jmp fail64
#endif
#ifdef HIA_TEST_CR3_WRITE
    /* Test-only root provisioning: A maps VA 4MiB to PA 4MiB;
     * B maps that VA to PA 6MiB. Code and stack mappings are identical.
     * Check hardware CR3 and the data readback after each native call. */
    leaq pml4(%rip), %rsi
    leaq pml4_second(%rip), %rdi
    movl $512, %ecx
    rep movsq
    leaq pdpt(%rip), %rsi
    leaq pdpt_second(%rip), %rdi
    movl $512, %ecx
    rep movsq
    leaq pd0(%rip), %rsi
    leaq pd_second(%rip), %rdi
    movl $512, %ecx
    rep movsq
    leaq pdpt_second(%rip), %rax
    orq $3, %rax
    movq %rax, pml4_second(%rip)
    leaq pd_second(%rip), %rax
    orq $3, %rax
    movq %rax, pdpt_second(%rip)
    movq $0x600083, pd_second+16(%rip)
    movq $0x13579, 0x400000
    movq $0x2468a, 0x600000
    cmpq $0x13579, 0x400000
    jne fail64
    movq %cr3, %rax
    leaq pml4(%rip), %rcx
    cmpq %rcx, %rax
    jne fail64
    leaq pml4_second(%rip), %rdi
    call f0
    leaq pml4_second(%rip), %rcx
    cmpq %rcx, %rax
    jne fail64
    movq %cr3, %rax
    cmpq %rcx, %rax
    jne fail64
    cmpq $0x2468a, 0x400000
    jne fail64
    leaq pml4(%rip), %rdi
    call f0
    leaq pml4(%rip), %rcx
    cmpq %rcx, %rax
    jne fail64
    movq %cr3, %rax
    cmpq %rcx, %rax
    jne fail64
    cmpq $0x13579, 0x400000
    jne fail64
    movb $'P', %bl
    jmp debug_exit64
#endif
#ifdef HIA_TEST_CR3_READ
    /* Independent observer: compare against both the loaded root symbol and
     * hardware readback, then switch to an equivalent but distinct root.
     * Neither root is given to the HIA function as an argument. */
    movq $0x1234, %rdi
    call f0
    leaq pml4(%rip), %rcx
    cmpq %rcx, %rax
    jne fail64
    movq %cr3, %rcx
    cmpq %rcx, %rax
    jne fail64
    leaq pml4(%rip), %rsi
    leaq pml4_second(%rip), %rdi
    movl $512, %ecx
    rep movsq
    leaq pml4_second(%rip), %rax
    movq %rax, %cr3
    movq $0x5678, %rdi
    call f0
    leaq pml4_second(%rip), %rcx
    cmpq %rcx, %rax
    jne fail64
    movq %cr3, %rcx
    cmpq %rcx, %rax
    jne fail64
    movb $'P', %bl
    jmp debug_exit64
#endif
    /* Warm one of the large-page translations, revoke its PRESENT bit,
     * then invoke the HIA-generated INVLPG through the actual f0 symbol. */
    movq $0x400000, %rbx
    movq (%rbx), %r8
    leaq pd0+16(%rip), %r9
    andq $-2, (%r9)
    mfence
#ifdef HIA_TEST_WRONG_VA
    movq $0x600000, %rdi
#else
    movq $0x400000, %rdi
#endif
    call f0
#ifdef HIA_TEST_WRONG_VA
    cmpq $0x600000, %rax
#else
    cmpq $0x400000, %rax
#endif
    jne fail64
#ifdef HIA_TEST_RESTORE
    /* Independent bypass: restoration and another real INVLPG must make
     * the same address accessible, not report a generic #PF as success. */
    /* SysV r9 is caller-saved; derive the actual slot again after f0. */
    leaq pd0+16(%rip), %r9
    orq $1, (%r9)
    movq $0x400000, %rdi
    call f0
    movq (%rbx), %r8
    movl $0x20, %eax
    movb $'R', %bl
    jmp debug_exit64
#endif
probe_read:
    movq (%rbx), %r8
fail64:
    movb $'N', %bl
    jmp debug_exit64
pf_handler:
#ifdef HIA_TEST_CR2_READ
    /* The fault frame, not the HIA return, selects the expected address.
     * Do not supply that address as an argument. */
    cmpq $0, (%rsp)
    jne fail64
    leaq cr2_probe_a(%rip), %rax
    cmpq %rax, 8(%rsp)
    je cr2_fault_a
    leaq cr2_probe_b(%rip), %rax
    cmpq %rax, 8(%rsp)
    jne fail64
    movq $0x600000, %r12
    jmp cr2_check
cr2_fault_a:
    movq $0x400000, %r12
cr2_check:
    movq %rsp, %r13
    andq $-16, %rsp
    movq $0x1234, %rdi
    call f0
    movq %r13, %rsp
    cmpq %r12, %rax
    jne fail64
    movq %cr2, %rcx
    cmpq %r12, %rcx
    jne fail64
    cmpq $0x400000, %r12
    jne cr2_done
    leaq cr2_probe_b(%rip), %rax
    movq %rax, 8(%rsp)
    addq $8, %rsp
    iretq
cr2_done:
    movb $'P', %bl
    jmp debug_exit64
#endif
    movq %cr2, %rax
    cmpq $0x400000, %rax
    jne fail64
    cmpq $0, (%rsp) /* P=0, W=0, U=0, RSVD=0 */
    jne fail64
    leaq probe_read(%rip), %rax
    cmpq %rax, 8(%rsp) /* exact fault RIP */
    jne fail64
    movb $'P', %bl
debug_exit64:
    movw $0xe9, %dx
    movb %bl, %al
    outb %al, %dx
    movw $0xf4, %dx
    movl $0x10, %eax
    cmpb $'N', %bl
    jne 1f
    movl $0x11, %eax
1:
    cmpb $'R', %bl
    jne 2f
    movl $0x20, %eax
2:  outl %eax, %dx
    cli
3:  hlt
    jmp 3b
/* Generated unreachable abort callsite: explicit NON-HIA guest-only sink. */
.global abort
abort:
    movw $0xe9, %dx
    movb $0x41, %al
    outb %al, %dx
    movw $0xf4, %dx
    movl $0x12, %eax
    outl %eax, %dx
    cli
4:  hlt
    jmp 4b

.section .rodata,"a",@progbits
.balign 8
gdt:
    .quad 0
    .quad 0x00cf9a000000ffff
    .quad 0x00cf92000000ffff
    .quad 0x00af9a000000ffff
gdt_end:
gdt_ptr:
    .word gdt_end-gdt-1
    .long gdt
idtr:
    .word 4096-1
    .quad idt
.section .bss,"aw",@nobits
.balign 4096
pml4: .skip 4096
pdpt: .skip 4096
pd0: .skip 4096
#if defined(HIA_TEST_CR3_READ) || defined(HIA_TEST_CR3_WRITE)
pml4_second: .skip 4096
#endif
#ifdef HIA_TEST_CR3_WRITE
pdpt_second: .skip 4096
pd_second: .skip 4096
#endif
.balign 16
stack32: .skip 4096
stack32_top:
stack64: .skip 8192
stack64_top:
.balign 16
idt: .skip 4096
