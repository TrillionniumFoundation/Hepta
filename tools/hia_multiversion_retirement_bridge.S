# Mechanical adapter for the private HIA same-holder retirement owner.
# Only syscall dispatch, a fixed HIA retirement-state call, and dlclose.
.intel_syntax noprefix
.text
.global hia_mv_retire
.type hia_mv_retire,@function
hia_mv_retire:
    push rbx
    push rbp
    push r12
    push r13
    push r14
    push r15
    sub rsp, 136
    mov r12, rdi
    mov r15, rsi
    mov r13, rdx
    mov rbp, rcx
    mov r14, r8
    mov rbx, r9
    mov qword ptr [rsp], 0
    mov [rsp+8], r14
    mov [rsp+16], r12
    mov [rsp+24], r13
.Lpolicy_loop:
    mov rdi, r12
    mov rsi, r15
    mov rdx, r13
    mov rcx, rbp
    mov r8, r14
    mov r9, rbx
    .byte 0xe8
policy_hole:
    .long 0
    test eax, eax
    je .Ldone
    cmp eax, 1
    je .Lsyscall
    cmp eax, 2
    je .Lrole
    cmp eax, 3
    je .Ldlclose
    mov eax, 0xfffffffd
    jmp .Lreturn
.Lsyscall:
    mov r10, [r13+8]
    xor ecx, ecx
.Ltranslate:
    mov rax, [r13+16+rcx*8]
    mov r11, r10
    and r11d, 3
    add rax, [rsp+r11*8]
    mov [rsp+32+rcx*8], rax
    shr r10, 2
    inc ecx
    cmp ecx, 6
    jb .Ltranslate
    mov rdi, [rsp+32]
    mov rsi, [rsp+40]
    mov rdx, [rsp+48]
    mov r10, [rsp+56]
    mov r8, [rsp+64]
    mov r9, [rsp+72]
    mov rax, [r13]
    syscall
    jmp .Lfeedback
.Lrole:
    mov rdi, [r13]
    add rdi, r14
    mov rsi, [r13+8]
    mov rdx, [r13+16]
    add rdx, r14
    mov rcx, [r13+24]
    mov r8, [r13+32]
    add r8, r14
    mov r9, [r13+40]
    .byte 0xe8
state_hole:
    .long 0
    jmp .Lfeedback
.Ldlclose:
    mov rdi, [r13]
    call dlclose@PLT
.Lfeedback:
    mov [r14+8], rax
    jmp .Lpolicy_loop
.Ldone:
    mov eax, dword ptr [r13+8]
.Lreturn:
    add rsp, 136
    pop r15
    pop r14
    pop r13
    pop r12
    pop rbp
    pop rbx
    ret
.size hia_mv_retire, .-hia_mv_retire
.section .note.GNU-stack,"",@progbits
