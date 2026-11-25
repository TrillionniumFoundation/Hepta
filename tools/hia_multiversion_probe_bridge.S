# Fixed probe ABI adapter; HIA owns selection, views, VM steps and equality.
.intel_syntax noprefix
.text
.global hia_mv_probe
.type hia_mv_probe,@function
hia_mv_probe:
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
    jb .Lbad
    cmp eax, 4
    jbe .Lrole
    cmp eax, 5
    je .Lnative
.Lbad:
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
    mov [rsp+80], eax
    mov rdi, [r13]
    add rdi, r14
    mov rsi, [r13+8]
    mov rdx, [r13+16]
    add rdx, r14
    mov rcx, [r13+24]
    mov r8, [r13+32]
    add r8, r14
    mov r9, [r13+40]
    cmp dword ptr [rsp+80], 2
    je .Lsha
    cmp dword ptr [rsp+80], 3
    je .Lelf
    .byte 0xe8
vm_hole:
    .long 0
    jmp .Lfeedback
.Lsha:
    .byte 0xe8
vectors_hole:
    .long 0
    jmp .Lfeedback
.Lelf:
    .byte 0xe8
projector_hole:
    .long 0
    jmp .Lfeedback
.Lnative:
    mov rdi, [r13]
    mov rsi, [r13+8]
    add rsi, r14
    call .Lscalar_inner
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
.size hia_mv_probe, .-hia_mv_probe
.section .note.GNU-stack,"",@progbits

# Fixed scalar SysV C ABI operation for an HIA-selected, held generation.
# HIA admits argc0..16 and zeroes unused slots before this function is called.
# The actual function pointer comes only from the native loader owner.
.intel_syntax noprefix
.text
.type .Lscalar_inner,@function
.Lscalar_inner:
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
.size .Lscalar_inner, .-.Lscalar_inner
.section .note.GNU-stack,"",@progbits
