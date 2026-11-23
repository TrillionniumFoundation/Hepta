.include "race_config.inc"
/* Isolated Multiboot1 x86-64 hardware oracle for staged privileged bytes.
 * Test-only GNU assembly: NOT HIA Core or a production kernel bridge.
 * effect.bin must come from the checked-out upstream staged encoder.
 */
.section .multiboot,"a",@progbits
.align 4
.long 0x1badb002
.long 0
.long -0x1badb002

.section .text,"ax",@progbits
.code32
.global _start
_start:
    cli
    movl $stack_top, %esp
    xorl %eax, %eax
    movl $pml4, %edi
    movl $(4*4096/4), %ecx
    rep stosl
    movl $(pdpt+3), pml4
    movl $(pd+3), pdpt
    movl $0x83, pd
    movl $(pt+3), pd+16
    movl $0x400063, pt
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
    lgdt gdt_ptr
    ljmpl $8, $long_mode

.code64
long_mode:
    movw $0x10, %ax
    movw %ax, %ds
    movw %ax, %es
    movw %ax, %ss
    movabs $stack_top, %rsp
    leaq idt(%rip), %rdi
    leaq handle_ud(%rip), %rax
    movw %ax, (6*16)(%rdi)
    shrq $16, %rax
    movw %ax, (6*16+6)(%rdi)
    shrq $16, %rax
    movl %eax, (6*16+8)(%rdi)
    movw $8, (6*16+2)(%rdi)
    movb $0x8e, (6*16+5)(%rdi)
    leaq handle_pf(%rip), %rax
    movw %ax, (14*16)(%rdi)
    shrq $16, %rax
    movw %ax, (14*16+6)(%rdi)
    shrq $16, %rax
    movl %eax, (14*16+8)(%rdi)
    movw $8, (14*16+2)(%rdi)
    movb $0x8e, (14*16+5)(%rdi)

.if RACE_MODE
    /* Test-only #DB single-step observer: the staged effect bytes are unchanged. */
    leaq handle_db(%rip), %rax
    movw %ax, (1*16)(%rdi)
    shrq $16, %rax
    movw %ax, (1*16+6)(%rdi)
    shrq $16, %rax
    movl %eax, (1*16+8)(%rdi)
    movw $8, (1*16+2)(%rdi)
    movb $0x8e, (1*16+5)(%rdi)
.endif
    lidt idt_ptr(%rip)
    /* Warm this 4KiB translation before native PTE revoke + INVLPG. */
    movl $0x400000, %eax
    movq (%rax), %r9
.if RACE_MODE
    /* Arm TF before the real staged effect. #DB intervenes at the CAS RIP. */
    pushfq
    orq $0x100, (%rsp)
    popfq
.endif
    call effect_start
    movabs $pt, %rax
    movq (%rax), %rbx
    cmpq $0x400062, %rbx
    jne fail
    movl $0x400000, %eax
faulting_read:
    movq (%rax), %r10
    jmp fail

handle_pf:
    movq 8(%rsp), %rax
    leaq faulting_read(%rip), %rdx
    cmpq %rdx, %rax
    jne fail
    movq %cr2, %rax
    cmpq $0x400000, %rax
    jne fail
    movq (%rsp), %rax
    andq $0x1f, %rax
    cmpq $0, %rax
    jne fail
    movabs $pt, %rax
    cmpq $0x400062, (%rax)
    jne fail
    movb $0x50, %al
    outb %al, $0xe9
    movb $0x21, %al
    outb %al, $0xf4
    jmp halt

handle_ud:
    /* Reject only from the emitted UD2, preserving the actual PTE word. */
    movq (%rsp), %rax
    leaq effect_end-2(%rip), %rdx
    cmpq %rdx, %rax
    jne fail
    movabs $pt, %rax
.if RACE_MODE
    /* Must retain the competing writer's word rather than overwrite it. */
    cmpq $0x400023, (%rax)
    jne fail
    cmpl $1, race_seen(%rip)
    jne fail
.else
    cmpq $0x400063, (%rax)
    jne fail
.endif
    movb $0x55, %al
    outb %al, $0xe9
    movb $0x22, %al
    outb %al, $0xf4
    jmp halt

.if RACE_MODE
handle_db:
    /* #DB has RIP, CS, RFLAGS (no error code). Preserve all CAS operands.
     * The RIP proves pre-read/compare and replacement MOV already executed;
     * the next instruction is the original LOCK CMPXCHGQ.
     */
    pushq %rdx
    leaq effect_start+CAS_OFFSET(%rip), %rdx
    cmpq %rdx, 8(%rsp)
    popq %rdx
    jne db_resume
    pushq %rax
    movabs $pt, %rax
    movq $0x400023, (%rax)
    popq %rax
    movl $1, race_seen(%rip)
    /* Resume at the CAS with TF cleared: ZF=0 must branch to original UD2. */
    andq $-257, 16(%rsp)
db_resume:
    iretq
.endif

fail:
    movb $0x46, %al
    outb %al, $0xe9
    movb $0x7f, %al
    outb %al, $0xf4
halt:
    cli
1:  hlt
    jmp 1b

.align 16
.global effect_start, effect_end
effect_start:
.incbin "effect.bin"
effect_end:

.section .rodata,"a",@progbits
.align 8
gdt:
    .quad 0
    .quad 0x00af9a000000ffff
    .quad 0x00cf92000000ffff
gdt_end:
gdt_ptr:
    .word gdt_end-gdt-1
    .long gdt
idt_ptr:
    .word 4096-1
    .quad idt

.section .bss,"aw",@nobits
.align 16
idt:
    .skip 4096
.align 4
race_seen:
    .skip 4

.section .paging,"aw",@nobits
.align 4096
.global pml4, pt, stack_top
pml4:
    .skip 4096
pdpt:
    .skip 4096
pd:
    .skip 4096
pt:
    .skip 4096

.section .stack,"aw",@nobits
.align 16
    .skip 8192
stack_top:
