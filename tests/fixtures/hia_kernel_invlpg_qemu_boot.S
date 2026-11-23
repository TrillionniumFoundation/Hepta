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
.balign 16
stack32: .skip 4096
stack32_top:
stack64: .skip 8192
stack64_top:
.balign 16
idt: .skip 4096
