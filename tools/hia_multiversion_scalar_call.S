# Fixed scalar SysV C ABI operation for an HIA-selected, held generation.
# HIA admits argc0..16 and zeroes unused slots before this function is called.
# The actual function pointer comes only from the native loader owner.
.intel_syntax noprefix
.text
.global hia_mv_scalar_call
.type hia_mv_scalar_call,@function
hia_mv_scalar_call:
    push rbx
    push r12
    sub rsp, 88
    mov rbx, rdi
    mov r12, rsi
    mov rax, [r12+48]
    mov [rsp], rax
    mov rax, [r12+56]
    mov [rsp+8], rax
    mov rax, [r12+64]
    mov [rsp+16], rax
    mov rax, [r12+72]
    mov [rsp+24], rax
    mov rax, [r12+80]
    mov [rsp+32], rax
    mov rax, [r12+88]
    mov [rsp+40], rax
    mov rax, [r12+96]
    mov [rsp+48], rax
    mov rax, [r12+104]
    mov [rsp+56], rax
    mov rax, [r12+112]
    mov [rsp+64], rax
    mov rax, [r12+120]
    mov [rsp+72], rax
    mov rdi, [r12]
    mov rsi, [r12+8]
    mov rdx, [r12+16]
    mov rcx, [r12+24]
    mov r8, [r12+32]
    mov r9, [r12+40]
    xor eax, eax
    call rbx
    add rsp, 88
    pop r12
    pop rbx
    ret
.size hia_mv_scalar_call, .-hia_mv_scalar_call
.section .note.GNU-stack,"",@progbits
