/* Explicit NON-HIA, isolated Multiboot-v1 hardware observer.
 * Only linked f0 is compiled from verified typed HIA Core. Never install on host. */
#if defined(HIA_TEST_MMIO_READ32) || defined(HIA_TEST_MMIO_WRITE32)
#define HIA_TEST_MMIO32
#endif
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
#ifdef HIA_TEST_MMIO32
    /* Independent, temporary guest UC mapping of the standard IOAPIC.
     * The subject owns accesses only, not address-space setup. */
    xorl %eax, %eax
    movl $pdmmio, %edi
    movl $1024, %ecx
    rep stosl
    movl $pdmmio, %eax
    orl $3, %eax
    movl %eax, pdpt+24
    movl $0xfec0009b, pdmmio+502*8
#endif
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
#ifdef HIA_TEST_MMIO32
#ifdef HIA_TEST_MMIO_ALIGN
    /* Alignment tests use private RAM, not undefined unaligned device I/O. */
    leaq mmio_ud_handler(%rip), %rax
    leaq idt+6*16(%rip), %rdi
    movw %ax, (%rdi)
    movw $0x18, 2(%rdi)
    movb $0, 4(%rdi)
    movb $0x8e, 5(%rdi)
    shrq $16, %rax
    movw %ax, 6(%rdi)
    shrq $16, %rax
    movl %eax, 8(%rdi)
    movl $0, 12(%rdi)
    movabsq $0x1122334455667788, %rax
    movq %rax, mmio_guard_cell(%rip)
    leaq mmio_guard_cell+1(%rip), %rdi
    movl $0xa1b2c3d4, %esi
    call f0
#ifndef HIA_TEST_MMIO_GUARD_BYPASS
    jmp abort
#else
#ifdef HIA_TEST_MMIO_READ32
    cmpq $0x44556677, %rax
    jne abort
    movabsq $0x1122334455667788, %rcx
#else
    leaq mmio_guard_cell+1(%rip), %rcx
    cmpq %rcx, %rax
    jne abort
    movabsq $0x112233a1b2c3d488, %rcx
#endif
    cmpq %rcx, mmio_guard_cell(%rip)
    jne abort
    movb $'N', %bl
    jmp debug_exit64
#endif
#else
    /* Verify the selected PAT slot is UC before using the device mapping.
     * Do not modify APIC configuration/interrupt routing: only IOREGSEL. */
    movl $1, %eax
    cpuid
    testl $0x10000, %edx
    jz abort
    movl $0x277, %ecx
    rdmsr
    shrl $24, %eax
    testl %eax, %eax
    jne abort
    movl $0xfec00000, %r12d
    movl (%r12), %r14d
    xorl %r15d, %r15d
    .macro mmio_probe initial, target
    movl $\initial, (%r12)
    cmpl $\initial, (%r12)
    jne abort
    movq %r12, %rdi
#ifdef HIA_TEST_MMIO_READ32
    call f0
    cmpq $\initial, %rax
    je mmio_positive\@
    testq %rax, %rax
    jne abort
#else
    movl $\target, %esi
    call f0
    cmpq %r12, %rax
    jne abort
    cmpl $\target, (%r12)
    je mmio_positive\@
    cmpl $\initial, (%r12)
    jne abort
#endif
    orl $2, %r15d
    jmp mmio_done\@
mmio_positive\@:
    orl $1, %r15d
mmio_done\@:
    .endm
    mmio_probe 1, 2
    mmio_probe 2, 1
#ifdef HIA_TEST_MMIO_READ32
    /* A second address: independently read the IOAPIC version window. */
    movl $1, (%r12)
    movl 16(%r12), %r13d
    testl %r13d, %r13d
    jz abort
    cmpl $-1, %r13d
    je abort
    leaq 16(%r12), %rdi
    call f0
    cmpq %r13, %rax
    je mmio_version_positive
    testq %rax, %rax
    jne abort
    orl $2, %r15d
    jmp mmio_version_done
mmio_version_positive:
    orl $1, %r15d
mmio_version_done:
#endif
    movl %r14d, (%r12)
    cmpl %r14d, (%r12)
    jne abort
    cmpl $1, %r15d
    je mmio_device_pass
    cmpl $2, %r15d
    jne abort
    movb $'N', %bl
    jmp debug_exit64
mmio_device_pass:
    movb $'P', %bl
    jmp debug_exit64
#endif
#endif
#ifdef HIA_TEST_CAS64
    /* Aligned guest RAM, deliberately high 64-bit values. */
    leaq cas_cell(%rip), %rdi
    movabsq $0xfedcba9876543210, %r12
    movabsq $0x8765432101234567, %r13
    movq %r12, (%rdi)
    movq %r12, %rsi
    movq %r13, %rdx
    call f0
    cmpq %r12, %rax
    jne abort
    cmpq %r13, cas_cell(%rip)
    je cas_success
    cmpq %r12, cas_cell(%rip)
    jne abort
    leaq cas_cell(%rip), %rdi
    movq %r13, %rsi
    xorl %edx, %edx
    call f0
    cmpq %r13, %rax
    jne abort
    cmpq %r12, cas_cell(%rip)
    jne abort
    movb $'N', %bl
    jmp debug_exit64
cas_success:
    leaq cas_cell(%rip), %rdi
    movq %r12, %rsi
    xorl %edx, %edx
    call f0
    cmpq %r13, %rax
    jne abort
    cmpq %r13, cas_cell(%rip)
    jne abort
    leaq cas_cell(%rip), %rdi
    movq %r13, %rsi
    movq %r12, %rdx
    call f0
    cmpq %r13, %rax
    jne abort
    cmpq %r12, cas_cell(%rip)
    jne abort
    movb $'P', %bl
    jmp debug_exit64
#endif
#if defined(HIA_TEST_IO_IN8) || defined(HIA_TEST_IO_OUT8)
    /* PIC IMR registers on PC/Q35, IRQs disabled throughout. The observer
     * independently establishes and reads each device state and restores
     * the original masks. Only f0 performs the subject operation. */
    cli
    xorl %r15d, %r15d
    .macro io_probe port, initial, target
    movw $\port, %dx
    inb %dx, %al
    movzbl %al, %r12d
    movb $\initial, %al
    outb %al, %dx
    inb %dx, %al
    cmpb $\initial, %al
    jne abort
    movl $\port, %edi
#ifdef HIA_TEST_IO_IN8
    call f0
    cmpq $\initial, %rax
    je io_positive\@
    testq %rax, %rax
    jne abort
#else
    movl $\target, %esi
    call f0
    cmpw $\port, %ax
    jne abort
    movw $\port, %dx
    inb %dx, %al
    cmpb $\target, %al
    je io_positive\@
    cmpb $\initial, %al
    jne abort
#endif
    orl $2, %r15d
    jmp io_restore\@
io_positive\@:
    orl $1, %r15d
io_restore\@:
    movw $\port, %dx
    movb %r12b, %al
    outb %al, %dx
    inb %dx, %al
    cmpb %r12b, %al
    jne abort
    .endm
    io_probe 0x21, 0x5a, 0xa5
    io_probe 0xa1, 0xc3, 0x3c
    cmpl $1, %r15d
    je io_pass
    cmpl $2, %r15d
    jne abort
    movb $'N', %bl
    jmp debug_exit64
io_pass:
    movb $'P', %bl
    jmp debug_exit64
#endif
#if defined(HIA_TEST_IO_IN16) || defined(HIA_TEST_IO_IN32) || defined(HIA_TEST_IO_OUT32)
    /* Independent PCI config-address and host-bridge readback, PC/Q35.
     * Save and restore the address selector. Never write PCI config data. */
    cli
    xorl %r15d, %r15d
    movw $0xcf8, %dx
    inl %dx, %eax
    movl %eax, %r14d
#ifdef HIA_TEST_IO_IN16
    movl $0x80000000, %eax
    outl %eax, %dx
    inl %dx, %eax
    cmpl $0x80000000, %eax
    jne abort
    .macro pci_word_read port
    movw $\port, %dx
    inw %dx, %ax
    movzwl %ax, %r12d
    testl %r12d, %r12d
    jz abort
    cmpl $0xffff, %r12d
    je abort
    movl $\port, %edi
    call f0
    cmpq %r12, %rax
    je pci_word_positive\@
    testq %rax, %rax
    jne abort
    orl $2, %r15d
    jmp pci_word_done\@
pci_word_positive\@:
    orl $1, %r15d
pci_word_done\@:
    .endm
    pci_word_read 0xcfc
    pci_word_read 0xcfe
#else
    .macro pci_dword_probe initial, target
    movw $0xcf8, %dx
    movl $\initial, %eax
    outl %eax, %dx
    inl %dx, %eax
    cmpl $\initial, %eax
    jne abort
    movl $0xcf8, %edi
#ifdef HIA_TEST_IO_IN32
    call f0
    movl $\initial, %r12d
    cmpq %r12, %rax
    je pci_dword_positive\@
    testq %rax, %rax
    jne abort
#else
    movl $\target, %esi
    call f0
    cmpq $0xcf8, %rax
    jne abort
    movw $0xcf8, %dx
    inl %dx, %eax
    cmpl $\target, %eax
    je pci_dword_positive\@
    cmpl $\initial, %eax
    jne abort
#endif
    orl $2, %r15d
    jmp pci_dword_done\@
pci_dword_positive\@:
    orl $1, %r15d
pci_dword_done\@:
    .endm
    pci_dword_probe 0x80000000, 0x80000008
    pci_dword_probe 0x80000008, 0x80000000
#endif
    movw $0xcf8, %dx
    movl %r14d, %eax
    outl %eax, %dx
    inl %dx, %eax
    cmpl %r14d, %eax
    jne abort
    cmpl $1, %r15d
    je wide_pci_pass
    cmpl $2, %r15d
    jne abort
    movb $'N', %bl
    jmp debug_exit64
wide_pci_pass:
    movb $'P', %bl
    jmp debug_exit64
#endif
#ifdef HIA_TEST_IO_OUT16
    /* fw_cfg's x86 I/O selector is a 16-bit write at 0x510.
     * Establish distinct independent first-byte oracles for signature and
     * ID selectors; reset each read cursor before the subject call.
     * A no-op must leave the previous selector's first byte unchanged. */
    cli
    xorl %r15d, %r15d
    .macro fw_probe initial, target
    movw $0x510, %dx
    movw $\initial, %ax
    outw %ax, %dx
    incw %dx
    inb %dx, %al
    movzbl %al, %r12d
    decw %dx
    movw $\target, %ax
    outw %ax, %dx
    incw %dx
    inb %dx, %al
    movzbl %al, %r13d
    cmpl %r12d, %r13d
    je abort
    decw %dx
    movw $\initial, %ax
    outw %ax, %dx
    movl $0x510, %edi
    movl $\target, %esi
    call f0
    cmpq $0x510, %rax
    jne abort
    movw $0x511, %dx
    inb %dx, %al
    cmpb %r13b, %al
    je fw_positive\@
    cmpb %r12b, %al
    jne abort
    orl $2, %r15d
    jmp fw_done\@
fw_positive\@:
    orl $1, %r15d
fw_done\@:
    .endm
    fw_probe 0, 1
    fw_probe 1, 0
    /* Restore the fixture baseline: signature selector at its first byte.
     * Verify all four signature bytes then reset the selector/cursor. */
    movw $0x510, %dx
    xorw %ax, %ax
    outw %ax, %dx
    incw %dx
    inb %dx, %al
    cmpb $'Q', %al
    jne abort
    inb %dx, %al
    cmpb $'E', %al
    jne abort
    inb %dx, %al
    cmpb $'M', %al
    jne abort
    inb %dx, %al
    cmpb $'U', %al
    jne abort
    decw %dx
    xorw %ax, %ax
    outw %ax, %dx
    cmpl $1, %r15d
    je wide_fw_pass
    cmpl $2, %r15d
    jne abort
    movb $'N', %bl
    jmp debug_exit64
wide_fw_pass:
    movb $'P', %bl
    jmp debug_exit64
#endif
#if defined(HIA_TEST_IRQ_DISABLE) || defined(HIA_TEST_IRQ_ENABLE)
    /* Mask both PICs before changing IF; no APIC source is armed. */
    cli
    movb $0xff, %al
    outb %al, $0x21
    outb %al, $0xa1
#ifdef HIA_TEST_IRQ_DISABLE
    sti
    nop
#define IRQ_INITIAL 0x200
#define IRQ_FINAL 0
#else
#define IRQ_INITIAL 0
#define IRQ_FINAL 0x200
#endif
    pushfq
    popq %rcx
    andq $0x200, %rcx
    cmpq $IRQ_INITIAL, %rcx
    jne abort
    movq $0x12345678, %rdi
    call f0
    pushfq
    popq %rcx
    cli
    cmpq $0x12345678, %rax
    jne abort
    andq $0x200, %rcx
    cmpq $IRQ_FINAL, %rcx
    je irq_if_pass
    cmpq $IRQ_INITIAL, %rcx
    jne abort
    movb $'N', %bl
    jmp debug_exit64
irq_if_pass:
    movb $'P', %bl
    jmp debug_exit64
#undef IRQ_INITIAL
#undef IRQ_FINAL
#endif
#if defined(HIA_TEST_CR0_WRITE) || defined(HIA_TEST_CR4_WRITE)
    /* Test-only initial-state provisioning. All subsequent transitions
     * on the success path must be performed by the HIA subject. */
#ifdef HIA_TEST_CR0_WRITE
#define WRITE_CR %cr0
#define WRITE_BIT 0x10000
#else
#define WRITE_CR %cr4
#define WRITE_BIT 0x80
    movl $1, %eax
    cpuid
    testl $0x2000, %edx
    jz abort
#endif
    movq WRITE_CR, %r12
    movq %r12, %r13
    andq $~WRITE_BIT, %r13
    movq %r13, WRITE_CR
    movq WRITE_CR, %rcx
    cmpq %r13, %rcx
    jne abort
    movq %r13, %r14
    orq $WRITE_BIT, %r14
    movq %r14, %rdi
    call f0
    cmpq %r14, %rax
    jne abort
    movq WRITE_CR, %rcx
    cmpq %r14, %rcx
    je write_set_observed
    /* Negative control counts only exact unchanged hardware state,
     * not an exception, malformed return, or arbitrary failure. */
    cmpq %r13, %rcx
    jne abort
    movq %r12, WRITE_CR
    movq WRITE_CR, %rcx
    cmpq %r12, %rcx
    jne abort
    movb $'N', %bl
    jmp debug_exit64
write_set_observed:
    movq %r13, %rdi
    call f0
    cmpq %r13, %rax
    jne abort
    movq WRITE_CR, %rcx
    cmpq %r13, %rcx
    jne abort
    movq %r12, %rdi
    call f0
    cmpq %r12, %rax
    jne abort
    movq WRITE_CR, %rcx
    cmpq %r12, %rcx
    jne abort
    movb $'P', %bl
    jmp debug_exit64
#undef WRITE_CR
#undef WRITE_BIT
#endif
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
#if defined(HIA_TEST_MMIO32) && defined(HIA_TEST_MMIO_ALIGN)
mmio_ud_handler:
#ifdef HIA_TEST_MMIO_GUARD_BYPASS
    jmp abort
#else
    leaq f0(%rip), %rax
    addq $HIA_MMIO_TRAP_DELTA, %rax
    cmpq %rax, (%rsp)
    jne abort
    cmpw $0x18, 8(%rsp)
    jne abort
    movabsq $0x1122334455667788, %rcx
    cmpq %rcx, mmio_guard_cell(%rip)
    jne abort
    movb $'P', %bl
    jmp debug_exit64
#endif
#endif
pf_handler:
#if defined(HIA_TEST_MMIO32) || defined(HIA_TEST_CR0_WRITE) || defined(HIA_TEST_CR4_WRITE) || defined(HIA_TEST_IRQ_DISABLE) || defined(HIA_TEST_IRQ_ENABLE) || defined(HIA_TEST_IO_IN8) || defined(HIA_TEST_IO_OUT8) || defined(HIA_TEST_IO_IN16) || defined(HIA_TEST_IO_OUT16) || defined(HIA_TEST_IO_IN32) || defined(HIA_TEST_IO_OUT32) || defined(HIA_TEST_CAS64)
    jmp abort /* A fault must not masquerade as the write NOP control. */
#endif
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
#ifdef HIA_TEST_MMIO32
pdmmio: .skip 4096
#endif
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
#if defined(HIA_TEST_MMIO32) && defined(HIA_TEST_MMIO_ALIGN)
.balign 8
mmio_guard_cell: .skip 8
#endif
#ifdef HIA_TEST_CAS64
.balign 8
cas_cell: .skip 8
#endif
