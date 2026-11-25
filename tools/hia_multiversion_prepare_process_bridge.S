# Mechanical private preparation transport: raw syscalls, fixed HIA entry,
# and one aligned read of the caller's owned cancellation-word capability.
.intel_syntax noprefix
.text
.global hia_mv_prepare_process
.type hia_mv_prepare_process,@function
hia_mv_prepare_process:
    push rbx
    push rbp
    push r12
    push r13
    push r14
    push r15
    sub rsp,136
    mov r12,rdi
    mov r15,rsi
    mov r13,rdx
    mov rbp,rcx
    mov r14,r8
    mov rbx,r9
    cmp rbx,20971520
    jb .Lbad
    cmp rbp,128
    jb .Lbad
    mov qword ptr [r14],0
    mov [r14+16],r14
    mov qword ptr [rsp],0
    mov [rsp+8],r14
    mov [rsp+16],r12
    mov [rsp+24],r13
.Lloop:
    mov rdi,r12
    mov rsi,r15
    mov rdx,r13
    mov rcx,rbp
    mov r8,r14
    mov r9,rbx
    .byte 0xe8
policy_hole:
    .long 0
    test eax,eax
    je .Ldone
    cmp eax,3
    je .Lloop
    cmp eax,1
    je .Lsyscall
    cmp eax,2
    jne .Lreturn
    mov rax,[r14+184]
    test rax,rax
    je .Lfeedback
    mov rax,[rax]
    jmp .Lfeedback
.Lsyscall:
    mov r10,[r13+8]
    xor ecx,ecx
.Ltranslate:
    mov rax,[r13+16+rcx*8]
    mov r11,r10
    and r11d,3
    add rax,[rsp+r11*8]
    mov [rsp+32+rcx*8],rax
    shr r10,2
    inc ecx
    cmp ecx,6
    jb .Ltranslate
    mov rdi,[rsp+32]
    mov rsi,[rsp+40]
    mov rdx,[rsp+48]
    mov r10,[rsp+56]
    mov r8,[rsp+64]
    mov r9,[rsp+72]
    mov rax,[r13]
    syscall
.Lfeedback:
    mov [r14+8],rax
    jmp .Lloop
.Ldone:
    mov eax,[r13+8]
    jmp .Lreturn
.Lbad:
    mov eax,0xfffffffd
.Lreturn:
    add rsp,136
    pop r15
    pop r14
    pop r13
    pop r12
    pop rbp
    pop rbx
    ret
.size hia_mv_prepare_process,.-hia_mv_prepare_process
.section .note.GNU-stack,"",@progbits

