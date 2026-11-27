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
    /* The new LIDT instruction comes from the isolated native-byte encoder.
     * SIDT is an independent hardware observer, not the operation under test.
     */
    leaq idt_ptr(%rip), %r10
    call descriptor_start
    sidt idtr_readback(%rip)
    cmpw $4095, idtr_readback(%rip)
    jne fail
    leaq idt(%rip), %rax
    cmpq %rax, idtr_readback+2(%rip)
    jne fail
    /* Test-only non-HIA descriptor provisioning, not authority verification:
     * install an actual 64-bit available TSS at GDT selector 0x18.
     * The LTR instruction itself is *only* the staged direct encoder bytes.
     */
    leaq tss(%rip), %rax
    movw $103, gdt+24(%rip)
    movw %ax, gdt+26(%rip)
    shrq $16, %rax
    movb %al, gdt+28(%rip)
    movb $0x89, gdt+29(%rip)
    movb $0, gdt+30(%rip)
    shrq $8, %rax
    movb %al, gdt+31(%rip)
    shrq $8, %rax
    movl %eax, gdt+32(%rip)
    movl $0, gdt+36(%rip)
    movw $0x18, %ax
    call tr_stage_start
    /* Independent CPU-visible TR and GDT descriptor-busy readback.
     * A malicious RET-only LTR stage must fail both hardware checks.
     */
    str %ax
    cmpw $0x18, %ax
    jne fail
    cmpb $0x8b, gdt+29(%rip)
    jne fail
    /* Warm this 4KiB translation before native PTE revoke + INVLPG. */
    movl $0x400000, %eax
    movq (%rax), %r9
.if RACE_MODE
    /* Arm TF before the real staged effect. #DB intervenes at the CAS RIP. */
    pushfq
    orq $0x100, (%rsp)
    popfq
.endif
.if CR4_PGE_MODE
    /* Test-only injection: enable actual CR4.PGE against the owner claim. */
    movq %cr4, %rax
    orq $0x80, %rax
    movq %rax, %cr4
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

.align 16
.global descriptor_start, descriptor_end
descriptor_start:
.incbin "descriptor.bin"
descriptor_end:

.align 16
.global tr_stage_start, tr_stage_end
tr_stage_start:
.incbin "ltr.bin"
tr_stage_end:

.section .rodata,"a",@progbits
.align 8
gdt:
    .quad 0
    .quad 0x00af9a000000ffff
    .quad 0x00cf92000000ffff
    .skip 16  /* TSS64 descriptor, filled by NON-HIA fixture. */
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
.align 8
idtr_readback:
    .skip 16
.align 16
tss:
    .skip 104

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
