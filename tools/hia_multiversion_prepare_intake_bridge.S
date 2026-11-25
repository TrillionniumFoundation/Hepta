# Mechanical outer intake: fixed HIA roles, raw syscall arguments and one
# caller-owned aligned cancellation capability. No normalization policy here.
.intel_syntax noprefix
.text
.global hia_mv_prepare_intake
.type hia_mv_prepare_intake,@function
hia_mv_prepare_intake:
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
    cmp rbx,268435456
    jb .Lbad
    cmp rbp,320
    jb .Lbad
    mov qword ptr [r14],0
    mov [r14+64],r14
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
    cmp eax,6
    je .Lloop
    cmp eax,1
    je .Lsyscall
    cmp eax,5
    je .Lcancel
    cmp eax,2
    jb .Lreturn
    cmp eax,4
    ja .Lreturn
    mov rdi,[r14+16]
    add rdi,r14
    mov rsi,[r14+24]
    mov rdx,[r14+32]
    add rdx,r14
    mov rcx,[r14+40]
    mov r8,[r14+48]
    add r8,r14
    mov r9,[r14+56]
    cmp eax,2
    je .Lprocess
    cmp eax,3
    je .Lintake
    .byte 0xe8
hash_hole:
    .long 0
    jmp .Lfeedback
.Lprocess:
    .byte 0xe8
process_hole:
    .long 0
    jmp .Lfeedback
.Lintake:
    .byte 0xe8
intake_hole:
    .long 0
    jmp .Lfeedback
.Lcancel:
    mov rax,[r14+72]
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
.size hia_mv_prepare_intake,.-hia_mv_prepare_intake
.section .note.GNU-stack,"",@progbits
