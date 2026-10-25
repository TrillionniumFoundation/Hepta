ENTRY(Reset)
MEMORY
{
  FLASH (rx) : ORIGIN = 0x00000000, LENGTH = 4M
  RAM (rw) : ORIGIN = 0x20000000, LENGTH = 4M
}
__stack_top = ORIGIN(RAM) + 64K;
SECTIONS
{
  .vector_table ORIGIN(FLASH) : ALIGN(256) { KEEP(*(.vector_table)) } > FLASH
  .text : ALIGN(4) { *(.text .text.*) *(.rodata .rodata.*) . = ALIGN(4); } > FLASH
  .data : ALIGN(4)
  {
    __data_start = .;
    *(.data .data.*)
    . = ALIGN(4);
    __data_end = .;
  } > RAM AT > FLASH
  __data_load = LOADADDR(.data);
  .bss (NOLOAD) : ALIGN(4)
  {
    __bss_start = .;
    *(.bss .bss.*) *(COMMON)
    . = ALIGN(4);
    __bss_end = .;
  } > RAM
  /DISCARD/ : { *(.ARM.exidx*) *(.ARM.extab*) }
  ASSERT(SIZEOF(.vector_table) == 192, "Cortex-M4 16 core plus 32 external vectors required")
  ASSERT(__bss_end < __stack_top - 4096, "Static RAM overlaps the reserved startup stack")
}
