# Fixed Future host facts: syscall, atomic lock word, native node allocation,
# fixed-size metadata copy, and the actual callback selected by the HIA owner.
.intel_syntax noprefix
.text
.global hia_mv_future
.type hia_mv_future,@function
hia_mv_future:
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
    cmp rbp,512
    jb .Lbad
    mov qword ptr [r13+64],0
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
    cmp eax,10
    je .Lloop
    cmp eax,1
    je .Lsyscall
    cmp eax,2
    je .Lcas
    cmp eax,3
    je .Lexchange
    cmp eax,4
    je .Lread_node
    cmp eax,5
    je .Lwrite_node
    cmp eax,6
    je .Lallocate
    cmp eax,7
    je .Lfree
    cmp eax,8
    je .Lcallback
    cmp eax,9
    je .Ldrop
.Lbad:
    mov eax,0xfffffffd
    jmp .Lreturn
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
    jmp .Lfeedback
.Lcas:
    mov rdx,[r13]
    cmp rdx,128
    je .Latomic_ok
    cmp rdx,132
    jne .Lbad
.Latomic_ok:
    add rdx,r14
    mov eax,[r13+8]
    mov ecx,[r13+16]
    lock cmpxchg dword ptr [rdx],ecx
    jmp .Lfeedback
.Lexchange:
    mov rdx,[r13]
    cmp rdx,128
    je .Lexchange_ok
    cmp rdx,132
    jne .Lbad
.Lexchange_ok:
    add rdx,r14
    mov eax,[r13+8]
    xchg dword ptr [rdx],eax
    jmp .Lfeedback
.Lread_node:
    mov rsi,[r13]
    lea rdi,[r13+256]
    mov ecx,8
    cld
    rep movsq
    xor eax,eax
    jmp .Lfeedback
.Lwrite_node:
    mov rdi,[r13]
    lea rsi,[r13+256]
    mov ecx,8
    cld
    rep movsq
    xor eax,eax
    jmp .Lfeedback
.Lallocate:
    mov edi,64
    call malloc
    jmp .Lfeedback
.Lfree:
    mov rdi,[r13]
    call free
    xor eax,eax
    jmp .Lfeedback
.Lcallback:
    mov r11,[r13]
    mov rdi,r14
    mov rsi,[r13+8]
    call r11
    jmp .Lfeedback
.Ldrop:
    mov r11,[r13]
    mov rdi,[r13+8]
    call r11
.Lfeedback:
    mov [r13+448],rax
    jmp .Lloop
.Ldone:
    mov eax,[r13+8]
.Lreturn:
    add rsp,136
    pop r15
    pop r14
    pop r13
    pop r12
    pop rbp
    pop rbx
    ret
.size hia_mv_future, .-hia_mv_future
.section .note.GNU-stack,"",@progbits
