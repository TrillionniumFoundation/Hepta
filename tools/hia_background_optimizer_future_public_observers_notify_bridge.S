# Native Future observer completion policy effects only.
# No allocation, sequence decision, callback selection or lifetime policy.
.intel_syntax noprefix
.text
.global hia_background_optimizer_future_public_observers_notify
.type hia_background_optimizer_future_public_observers_notify,@function
hia_background_optimizer_future_public_observers_notify:
    push rbx
    push rbp
    push r12
    push r13
    push r14
    push r15
    sub rsp,88
    mov r12,rdi
    mov r15,rsi
    mov r13,rdx
    mov rbp,rcx
    mov r14,r8
    mov rbx,r9
    cmp rbp,8192
    jb .Lbad
    cmp rbx,256
    jb .Lbad
    test r13,r13
    je .Lbad
    test r14,r14
    je .Lbad
    mov rax,r13
    add rax,rbp
    jc .Lbad
    mov r10,r14
    add r10,rbx
    jc .Lbad
    cmp r14,rax
    jae .Lowok
    cmp r10,r13
    ja .Lbad
.Lowok:
    mov r11,r12
    add r11,r15
    jc .Lbad
    test r15,r15
    je .Lviews
    test r12,r12
    je .Lbad
    cmp r12,rax
    jae .Lsook
    cmp r11,r13
    ja .Lbad
.Lsook:
    cmp r12,r10
    jae .Lviews
    cmp r11,r14
    ja .Lbad
.Lviews:
    mov qword ptr [r13+128],0
    mov qword ptr [r13+448],0
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
    call policy_body
    test eax,eax
    je .Lreturn
    cmp eax,10
    je .Lloop
    cmp eax,1
    je .Lsyscall
    cmp eax,2
    je .Lcas
    cmp eax,3
    je .Lexchange
    cmp eax,5
    je .Lwaddress
    cmp eax,8
    je .Lcopy
    cmp eax,9
    je .Linvoke
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
.Linvoke:
    mov r10,[r13+8]
    xor ecx,ecx
.Linvoke_translate:
    mov rax,[r13+16+rcx*8]
    mov r11,r10
    and r11d,3
    add rax,[rsp+r11*8]
    mov [rsp+32+rcx*8],rax
    shr r10,2
    inc ecx
    cmp ecx,6
    jb .Linvoke_translate
    mov rdi,[rsp+32]
    mov rsi,[rsp+40]
    mov rdx,[rsp+48]
    mov rcx,[rsp+56]
    mov r8,[rsp+64]
    mov r9,[rsp+72]
    call qword ptr [r13]
    jmp .Lfeedback
.Lcas:
    cmp qword ptr [r13],32
    jne .Lbad
    lea rdx,[r14+32]
    mov eax,[r13+8]
    mov ecx,[r13+16]
    lock cmpxchg dword ptr [rdx],ecx
    jmp .Lfeedback
.Lexchange:
    cmp qword ptr [r13],32
    jne .Lbad
    lea rdx,[r14+32]
    mov eax,[r13+8]
    xchg dword ptr [rdx],eax
    jmp .Lfeedback
.Lwaddress:
    mov rax,[r13]
    cmp rax,rbx
    jae .Lbad
    add rax,r14
    jmp .Lfeedback
.Lcopy:
    mov rax,[r13]
    cmp rax,3
    ja .Lbad
    mov rsi,[r13+8]
    add rsi,[rsp+rax*8]
    mov rax,[r13+16]
    cmp rax,3
    ja .Lbad
    mov rdi,[r13+24]
    add rdi,[rsp+rax*8]
    mov rcx,[r13+32]
    cmp rdi,rsi
    jbe .Lforward
    mov rax,rdi
    sub rax,rsi
    cmp rax,rcx
    jae .Lforward
    test rcx,rcx
    je .Lcopy_done
    lea rsi,[rsi+rcx-1]
    lea rdi,[rdi+rcx-1]
    std
    rep movsb
    cld
    jmp .Lcopy_done
.Lforward:
    cld
    rep movsb
.Lcopy_done:
    xor eax,eax
.Lfeedback:
    mov [r13+448],rax
    jmp .Lloop
.Lreturn:
    add rsp,88
    pop r15
    pop r14
    pop r13
    pop r12
    pop rbp
    pop rbx
    ret
.size hia_background_optimizer_future_public_observers_notify,.-hia_background_optimizer_future_public_observers_notify
policy_body:
.section .note.GNU-stack,"",@progbits
