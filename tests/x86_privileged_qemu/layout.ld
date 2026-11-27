OUTPUT_FORMAT(elf64-x86-64)
ENTRY(_start)
SECTIONS {
 . = 0x100000;
 .multiboot : { KEEP(*(.multiboot)) }
 .text : ALIGN(16) { __text_begin = .; *(.text*) }
 .rodata : ALIGN(16) { *(.rodata*) }
 .data : ALIGN(16) { *(.data*) }
 .bss (NOLOAD) : ALIGN(16) { *(.bss*) *(COMMON) }
 . = 0x180000;
 .paging (NOLOAD) : ALIGN(4096) { *(.paging) }
 . = 0x190000;
 .stack (NOLOAD) : ALIGN(16) { *(.stack) }
 /DISCARD/ : { *(.comment*) *(.note*) *(.eh_frame*) }
}
ASSERT(pml4 == 0x180000, "unexpected PML4 physical address")
ASSERT(pt == 0x183000, "unexpected PTE slot physical address")
ASSERT(stack_top <= 0x192000, "stack exceeds first 2MiB identity mapping")
