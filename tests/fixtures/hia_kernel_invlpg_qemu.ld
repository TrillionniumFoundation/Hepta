/* NON-HIA test-only loader. HIA emitted object is linked unchanged. */
OUTPUT_FORMAT(elf64-x86-64)
OUTPUT_ARCH(i386:x86-64)
ENTRY(_start)
PHDRS { text PT_LOAD FLAGS(5); data PT_LOAD FLAGS(6); }
SECTIONS {
    . = 0x100000;
    .multiboot ALIGN(4) : { KEEP(*(.multiboot)) } :text
    .text ALIGN(16) : { *(.text.boot) *(.text .text.*) } :text
    .rodata ALIGN(16) : { *(.rodata .rodata.*) } :text
    .data ALIGN(4096) : { *(.data .data.*) } :data
    .bss ALIGN(4096) (NOLOAD) : { *(.bss .bss.*) *(COMMON) } :data
    __end = .;
    ASSERT(__end < 0x400000, "test observer overlaps 4MiB probe page")
}
