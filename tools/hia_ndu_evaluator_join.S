/* Six-word borrowed-view adapter.  All request/numeric semantics are HIA.
 * Main may request one fixed pure-number role, then finish its saved diagnostic.
 * No syscall, allocator, floating instruction or host semantic call occurs. */
.intel_syntax noprefix
.text
.global ndu_join, main_call_1, number_call, main_call_2, debug_call
ndu_join:
    push rbp
    push rbx
    push r12
    push r13
    push r14
    push r15
    sub rsp,24
    mov r12,rdi
    mov r13,rsi
    mov r14,rdx
    mov r15,rcx
    mov rbx,r8
    mov rbp,r9
    cmp rbp,25165824
    jb first
    mov QWORD PTR [rbx+128],0
first:
    .byte 0xe8
main_call_1: .long 0
    cmp eax,0xfffffff7
    je debug
    cmp eax,0xfffffff8
    jne done
    mov rdi,[rbx+136]
    add rdi,r12
    mov rsi,[rbx+104]
    lea rdx,[rbx+1572864]
    mov ecx,96
    lea r8,[rbx+7340032]
    mov r9d,16384
    .byte 0xe8
number_call: .long 0
    jmp resume
debug:
    mov rdi,[rbx+96]
    add rdi,rbx
    mov rsi,[rbx+104]
    lea rdx,[rbx+16777216]
    mov ecx,8388608
    lea r8,[rbx+7340032]
    mov r9d,16384
    .byte 0xe8
debug_call: .long 0
resume:
    mov [rbx+120],rax
    mov QWORD PTR [rbx+128],2
    mov rdi,r12
    mov rsi,r13
    mov rdx,r14
    mov rcx,r15
    mov r8,rbx
    mov r9,rbp
    .byte 0xe8
main_call_2: .long 0
done:
    add rsp,24
    pop r15
    pop r14
    pop r13
    pop r12
    pop rbx
    pop rbp
    ret
.section .note.GNU-stack,"",@progbits
