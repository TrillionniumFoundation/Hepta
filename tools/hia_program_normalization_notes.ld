ENTRY(hia_cpython_note)
SECTIONS
{
    . = 0;
    .text : { KEEP(*(.text.entry)) *(.text*) *(.rodata*) }
    /DISCARD/ : { *(.comment*) *(.note*) *(.eh_frame*) *(.data*) *(.bss*) }
}
