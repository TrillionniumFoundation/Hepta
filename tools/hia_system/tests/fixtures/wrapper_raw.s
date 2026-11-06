.text
.globl raw_answer
.type raw_answer,@function
raw_answer:
    movl $13, %eax
    ret
.size raw_answer, .-raw_answer
.section .note.GNU-stack,"",@progbits
