/* NON-HIA Multiboot and independent APIC/interrupt observer.
 * HIA f0/f1 calibrate, f2 derives counts, f3 arms, f4 EOIs, f5 stops.
 * Native f7/f8/f9/f10 own reference PIT; f11 composes the whole window. */
.set MB_MAGIC,0x1badb002
.set MB_FLAGS,3
.set APIC,0xfee00000
.set VEC,0x51
.set VBIT,0x20000
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
    movl $4096,%ecx
    rep stosl
    movl $pdpt,%eax
    orl $3,%eax
    movl %eax,pml4
    movl $pd0,%eax
    orl $3,%eax
    movl %eax,pdpt
    movl $pd3,%eax
    orl $3,%eax
    movl %eax,pdpt+3*8
    movl $pd0,%edi
    movl $0x83,%eax
    movl $512,%ecx
1:  movl %eax,(%edi)
    movl $0,4(%edi)
    addl $0x200000,%eax
    addl $8,%edi
    loop 1b
    /* PCD/PWT UC, 2 MiB identity-mapped APIC aperture, supervisor only. */
    movl $0xfee0009b,pd3+503*8
    movl %cr4,%eax
    orl $0x20,%eax
    movl %eax,%cr4
    movl $pml4,%eax
    movl %eax,%cr3
    movl $0xc0000080,%ecx
    rdmsr
    orl $0x100,%eax
    wrmsr
    movl %cr0,%eax
    orl $0x80010000,%eax
    movl %eax,%cr0
    ljmp $0x18,$long64
fail32:
    movl $0x12,%eax
    movw $0xf4,%dx
    outl %eax,%dx
1:  cli
    hlt
    jmp 1b
.code64
long64:
    movw $0x10,%ax
    movw %ax,%ds
    movw %ax,%es
    movw %ax,%ss
    leaq stack64_top(%rip),%rsp
    movb $0xff,%al
    outb %al,$0x21
    outb %al,$0xa1
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
    leaq f0(%rip),%rax
    leaq idt+0x40*16(%rip),%rdi
    movw %ax,(%rdi)
    movw $0x18,2(%rdi)
    movb $0,4(%rdi)
#ifdef HIA_TEST_IRQ_IF
    movb $0x8f,5(%rdi)
#else
    movb $0x8e,5(%rdi)
#endif
    shrq $16,%rax
    movw %ax,6(%rdi)
    shrq $16,%rax
    movl %eax,8(%rdi)
    movl $0,12(%rdi)
    lidt idt_ptr(%rip)
    leaq dispatch(%rip),%rax
#ifdef HIA_TEST_IRQ_NULL_CALLBACK
    xorq %rax,%rax
#elif defined(HIA_TEST_IRQ_HIGH_CALLBACK)
    movabsq $0x0000800000000000,%rax
#endif
    movq %rax,dispatch_slot(%rip)
    leaq dispatch_slot(%rip),%rax
#ifdef HIA_TEST_IRQ_NULL_GS
    xorq %rax,%rax
#endif
    movq %rax,%rdx
    shrq $32,%rdx
    movl $0xc0000101,%ecx
    wrmsr
    movq $0x12345678,irq_stack(%rip)
    movq $0x23456789,irq_stack_top(%rip)
    leaq irq_stack_top(%rip),%rsp
#ifdef HIA_TEST_IRQ_SECOND
    pushq $2263
#elif defined(HIA_TEST_IRQ_IF)
    pushq $514
#elif defined(HIA_TEST_IRQ_DF)
    pushq $1026
#else
    pushq $2
#endif
    popfq
#ifdef HIA_TEST_IRQ_SECOND
    movq $2097153,%rax
    movq $2097426,%rbx
    movq $2097699,%rcx
    movq $2097972,%rdx
    movq $2098245,%rsi
    movq $2098518,%rdi
    movq $2098791,%rbp
    movq $2099064,%r8
    movq $2099337,%r9
    movq $2099610,%r10
    movq $2099883,%r11
    movq $2100156,%r12
    movq $2100429,%r13
    movq $2100702,%r14
    movq $2100975,%r15
#else
    movq $1048577,%rax
    movq $1048850,%rbx
    movq $1049123,%rcx
    movq $1049396,%rdx
    movq $1049669,%rsi
    movq $1049942,%rdi
    movq $1050215,%rbp
    movq $1050488,%r8
    movq $1050761,%r9
    movq $1051034,%r10
    movq $1051307,%r11
    movq $1051580,%r12
    movq $1051853,%r13
    movq $1052126,%r14
    movq $1052399,%r15
#endif
    int $0x40
returned:
    pushfq
    popq observed_flags(%rip)
#ifdef HIA_TEST_IRQ_SECOND
    cmpq $2097153,%rax
    jne abort
    cmpq $2097426,%rbx
    jne abort
    cmpq $2097699,%rcx
    jne abort
    cmpq $2097972,%rdx
    jne abort
    cmpq $2098245,%rsi
    jne abort
    cmpq $2098518,%rdi
    jne abort
    cmpq $2098791,%rbp
    jne abort
    cmpq $2099064,%r8
    jne abort
    cmpq $2099337,%r9
    jne abort
    cmpq $2099610,%r10
    jne abort
    cmpq $2099883,%r11
    jne abort
    cmpq $2100156,%r12
    jne abort
    cmpq $2100429,%r13
    jne abort
    cmpq $2100702,%r14
    jne abort
    cmpq $2100975,%r15
    jne abort
    cmpq $2263,observed_flags(%rip)
#else
    cmpq $1048577,%rax
    jne abort
    cmpq $1048850,%rbx
    jne abort
    cmpq $1049123,%rcx
    jne abort
    cmpq $1049396,%rdx
    jne abort
    cmpq $1049669,%rsi
    jne abort
    cmpq $1049942,%rdi
    jne abort
    cmpq $1050215,%rbp
    jne abort
    cmpq $1050488,%r8
    jne abort
    cmpq $1050761,%r9
    jne abort
    cmpq $1051034,%r10
    jne abort
    cmpq $1051307,%r11
    jne abort
    cmpq $1051580,%r12
    jne abort
    cmpq $1051853,%r13
    jne abort
    cmpq $1052126,%r14
    jne abort
    cmpq $1052399,%r15
    jne abort
    cmpq $2,observed_flags(%rip)
#endif
    jne abort
    cmpq $irq_stack_top,%rsp
    jne abort
    cmpq $1,dispatch_count(%rip)
    jne abort
    cmpq $0x12345678,irq_stack(%rip)
    jne abort
    cmpq $0x23456789,irq_stack_top(%rip)
    jne abort
#if defined(HIA_TEST_IRQ_TRAP_DELTA) || defined(HIA_TEST_IRQ_SAVE_MUTANT)
    jmp abort
#else
    movb $'P',%bl
    jmp finish
#endif
/* Independent frame inspection; no register-saving entry or IRET. */
dispatch:
    incq dispatch_count(%rip)
    movq %rsp,%rax
    andq $15,%rax
    cmpq $8,%rax
    jne abort
    cmpq $irq_stack_top-160,%rdi
    jne abort
    cmpq $returned,120(%rdi)
    jne abort
    cmpq $0x18,128(%rdi)
    jne abort
    cmpq $irq_stack_top,144(%rdi)
    jne abort
    cmpq $0x10,152(%rdi)
    jne abort
#ifdef HIA_TEST_IRQ_SECOND
    cmpq $2263,136(%rdi)
    jne abort
    cmpq $2097153,112(%rdi)
    jne abort
    cmpq $2097426,104(%rdi)
    jne abort
    cmpq $2097699,96(%rdi)
    jne abort
    cmpq $2097972,88(%rdi)
    jne abort
    cmpq $2098245,80(%rdi)
    jne abort
    cmpq $2098518,72(%rdi)
    jne abort
    cmpq $2098791,64(%rdi)
    jne abort
    cmpq $2099064,56(%rdi)
    jne abort
    cmpq $2099337,48(%rdi)
    jne abort
    cmpq $2099610,40(%rdi)
    jne abort
    cmpq $2099883,32(%rdi)
    jne abort
    cmpq $2100156,24(%rdi)
    jne abort
    cmpq $2100429,16(%rdi)
    jne abort
    cmpq $2100702,8(%rdi)
    jne abort
    cmpq $2100975,0(%rdi)
    jne save_mismatch
#else
    cmpq $2,136(%rdi)
    jne abort
    cmpq $1048577,112(%rdi)
    jne abort
    cmpq $1048850,104(%rdi)
    jne abort
    cmpq $1049123,96(%rdi)
    jne abort
    cmpq $1049396,88(%rdi)
    jne abort
    cmpq $1049669,80(%rdi)
    jne abort
    cmpq $1049942,72(%rdi)
    jne abort
    cmpq $1050215,64(%rdi)
    jne abort
    cmpq $1050488,56(%rdi)
    jne abort
    cmpq $1050761,48(%rdi)
    jne abort
    cmpq $1051034,40(%rdi)
    jne abort
    cmpq $1051307,32(%rdi)
    jne abort
    cmpq $1051580,24(%rdi)
    jne abort
    cmpq $1051853,16(%rdi)
    jne abort
    cmpq $1052126,8(%rdi)
    jne abort
    cmpq $1052399,0(%rdi)
    jne save_mismatch
#endif
#ifdef HIA_TEST_IRQ_SAVE_MUTANT
    jmp abort
#endif
    movq %rdi,%rax
#ifdef HIA_TEST_IRQ_NULL_RESULT
    xorq %rax,%rax
#endif
    movq $0x111,%rcx
    movq $0x222,%rdx
    movq $0x333,%rsi
    movq $0x444,%rdi
    movq $0x555,%r8
    movq $0x666,%r9
    movq $0x777,%r10
    movq $0x888,%r11
    ret
save_mismatch:
#ifdef HIA_TEST_IRQ_SAVE_MUTANT
    cmpq $1052126,0(%rdi)
    jne abort
    movb $'N',%bl
    jmp finish
#else
    jmp abort
#endif
ud_handler:
#ifdef HIA_TEST_IRQ_TRAP_DELTA
    leaq f0(%rip),%rax
    addq $HIA_TEST_IRQ_TRAP_DELTA,%rax
    cmpq %rax,(%rsp)
    jne abort
    cmpq $0x18,8(%rsp)
    jne abort
#if defined(HIA_TEST_IRQ_NULL_RESULT) || defined(HIA_TEST_IRQ_IRET_NOP)
    cmpq $1,dispatch_count(%rip)
#else
    cmpq $0,dispatch_count(%rip)
#endif
    jne abort
    movb $'N',%bl
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
gdt_end:
gdt_ptr:
    .word gdt_end-gdt-1
    .long gdt
idt_ptr:
    .word 4095
    .quad idt
.section .bss,"aw",@nobits
.balign 4096
pml4: .skip 4096
pdpt: .skip 4096
pd0: .skip 4096
pd3: .skip 4096
idt: .skip 4096
.balign 16
stack32: .skip 4096
stack32_top:
stack64: .skip 8192
stack64_top:
.balign 16
irq_stack: .skip 8192
irq_stack_top: .skip 8
.balign 8
dispatch_slot: .skip 8
dispatch_count: .skip 8
observed_flags: .skip 8
