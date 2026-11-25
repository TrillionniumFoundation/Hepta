/* Six-Q ABI-only status/length adapter. HIA owns all error rendering. */
.intel_syntax noprefix
.text
.global hia_ndu_owner_error, error_call
hia_ndu_owner_error:
    push rbx
    mov rbx,r8
    .byte 0xe8
error_call:.long 0
    test eax,eax
    jnz .Lfailure
    mov rax,[rbx]
    pop rbx
    ret
.Lfailure:
    cmp eax,0xfffffffe
    jne .Linvalid
    mov rax,-2
    pop rbx
    ret
.Linvalid:
    mov rax,-1
    pop rbx
    ret
.section .note.GNU-stack,"",@progbits
