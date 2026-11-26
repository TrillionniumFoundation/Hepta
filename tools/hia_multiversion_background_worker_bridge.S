# Mechanical continuation adapter for the private HIA background queue.
# Decisions, FIFO/ref ownership and worker identity reside in HIA.
.intel_syntax noprefix
.text
.global hia_mv_background_worker
.type hia_mv_background_worker,@function
hia_mv_background_worker:
.Lentry:
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
    test r12,r12
    jz .Lbad
    test r13,r13
    jz .Lbad
    test r14,r14
    jz .Lbad
    mov rax,r12
    add rax,r15
    jc .Lbad
    mov rax,r13
    add rax,rbp
    jc .Lbad
    mov rax,r14
    add rax,rbx
    jc .Lbad
    cmp rbp,8192
    jb .Lbad
    cmp rbx,512
    jb .Lbad
    mov qword ptr [r13+128],0
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
    je .Lprovider
    cmp eax,6
    je .Lstart
    cmp eax,7
    je .Ljoin
    cmp eax,8
    je .Lfacts
.Lbad:
    mov eax,0xfffffffd
    jmp .Lreturn
.Lsyscall:
    mov qword ptr [rsp+120],0
    jmp .Ltranslate_begin
.Lprovider:
    mov qword ptr [rsp+120],1
.Ltranslate_begin:
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
    mov r8,[rsp+64]
    mov r9,[rsp+72]
    cmp qword ptr [rsp+120],0
    jne .Lcall_provider
    mov r10,[rsp+56]
    mov rax,[r13]
    syscall
    jmp .Lfeedback
.Lcall_provider:
    mov rcx,[rsp+56]
    mov r11,[r13]
    call r11
    mov eax,eax
    jmp .Lfeedback
.Lstart:
    lea rdi,[r14+16]
    xor esi,esi
    lea rdx,[rip+.Lthread]
    mov rcx,r14
    call pthread_create
    mov eax,eax
    jmp .Lfeedback
.Ljoin:
    mov rdi,[r14+16]
    xor esi,esi
    call pthread_join
    mov eax,eax
    jmp .Lfeedback
.Lfacts:
    mov [r13+512],r14
    lea rax,[rip+.Lentry]
    mov [r13+520],rax
    xor eax,eax
    jmp .Lfeedback
.Lcas:
    mov rdx,[r13]
    cmp rdx,128
    jne .Lbad
    add rdx,r14
    mov eax,[r13+8]
    mov ecx,[r13+16]
    lock cmpxchg dword ptr [rdx],ecx
    jmp .Lfeedback
.Lexchange:
    mov rdx,[r13]
    cmp rdx,128
    jne .Lbad
    add rdx,r14
    mov eax,[r13+8]
    xchg dword ptr [rdx],eax
.Lfeedback:
    mov [r13+448],rax
    jmp .Lloop
.Ldone:
    xor eax,eax
.Lreturn:
    add rsp,136
    pop r15
    pop r14
    pop r13
    pop r12
    pop rbp
    pop rbx
    ret
.Lthread:
    push rbx
    mov rbx,rdi
    sub rsp,8320
    xor eax,eax
    mov rdi,rsp
    mov ecx,16
    cld
    rep stosq
    mov rax,3544428870306449736
    mov [rsp],rax
    mov qword ptr [rsp+8],4
    mov rdi,rsp
    mov esi,128
    lea rdx,[rsp+128]
    mov ecx,8192
    mov r8,rbx
    mov r9d,512
    call .Lentry
    add rsp,8320
    pop rbx
    xor eax,eax
    ret
.size hia_mv_background_worker, .-hia_mv_background_worker
.section .note.GNU-stack,"",@progbits
