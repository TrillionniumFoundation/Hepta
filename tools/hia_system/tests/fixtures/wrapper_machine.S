#include "wrapper_config.h"
.text
.globl asm_answer
.type asm_answer,@function
asm_answer:
    movl $ASM_VALUE, %eax
    ret
.size asm_answer, .-asm_answer
.pushsection .rodata
.globl smoke_blob
smoke_blob:
    .incbin "data/payload.bin"
.popsection
.section .note.GNU-stack,"",@progbits
