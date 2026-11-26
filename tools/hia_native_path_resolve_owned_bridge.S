# Fixed six-word views, syscall transport and policy continuation only.
# All path traversal, error ordering and descriptor ownership are HIA policy.
.intel_syntax noprefix
.text
.global hia_native_path_resolve
.type hia_native_path_resolve,@function
hia_native_path_resolve:
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
    cmp rbp,128
    jb .Lbad
    cmp rbx,200704
    jb .Lbad
    test r13,r13
    jz .Lbad
    test r14,r14
    jz .Lbad
    mov rax,r12
    add rax,r15
    jc .Lbad
    mov rdx,r13
    add rdx,rbp
    jc .Lbad
    mov rcx,r14
    add rcx,rbx
    jc .Lbad
    cmp r13,rcx
    jae .Low_ok
    cmp r14,rdx
    jb .Lbad
.Low_ok:
    test r15,r15
    jz .Linput_ok
    test r12,r12
    jz .Lbad
    cmp r12,rdx
    jae .Lso_ok
    cmp r13,rax
    jb .Lbad
.Lso_ok:
    cmp r12,rcx
    jae .Linput_ok
    cmp r14,rax
    jb .Lbad
.Linput_ok:
    cmp r15,32
    jb .Lbad
    mov rax,0x31304f5450414948
    cmp [r12],rax
    jne .Lbad
    cmp QWORD PTR [r12+8],2
    jne .Lbegin_owned
    cmp r15,32
    jne .Lbad
    mov rax,0x3130574f50414948
    cmp [r14+2304],rax
    jne .Lbad
    cmp [r14+2312],r14
    jne .Lbad
    cmp [r14+2328],rbx
    jne .Lbad
    mov eax,39
    syscall
    cmp [r14+2320],rax
    jne .Lbad
.Lbegin_owned:
    mov [r14+16],r14
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
    jz .Lreturn
    cmp eax,3
    je .Lloop
    cmp eax,1
    jne .Lbad
    mov r10,[r13+56]
    xor ecx,ecx
.Ltranslate:
    mov rax,[r13+8+rcx*8]
    mov r11,r10
    and r11d,3
    shr r10,2
    test r11d,r11d
    jz .Largument
    cmp r11d,1
    je .Lsource
    cmp r11d,2
    je .Loutput
    cmp rax,rbx
    ja .Lbad
    add rax,r14
    jc .Lbad
    jmp .Largument
.Lsource:
    cmp rax,r15
    ja .Lbad
    add rax,r12
    jc .Lbad
    jmp .Largument
.Loutput:
    cmp rax,rbp
    ja .Lbad
    add rax,r13
    jc .Lbad
.Largument:
    mov [rsp+32+rcx*8],rax
    inc ecx
    cmp ecx,6
    jb .Ltranslate
    test r10,r10
    jnz .Lbad
    mov rdi,[rsp+32]
    mov rsi,[rsp+40]
    mov rdx,[rsp+48]
    mov r10,[rsp+56]
    mov r8,[rsp+64]
    mov r9,[rsp+72]
    mov rax,[r13]
    syscall
    mov [r14+8],rax
    jmp .Lloop
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
.size hia_native_path_resolve,.-hia_native_path_resolve
.section .note.GNU-stack,"",@progbits
