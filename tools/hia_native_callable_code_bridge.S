/* Fixed six-word transport. HIA owns source admission, code/continuation
 * capability lookup, mappings, pinning, compilation and retirement.
 * Only the private code pointer captured by the native registry is called. */
.intel_syntax noprefix
.text
.global hia_native_callable_code_owner
.type hia_native_callable_code_owner,@function
hia_native_callable_code_owner:
    cmp rcx,8192
    jae .Lmain
    cmp rcx,128
    jb .Lentry_bad
    cmp rsi,128
    jne .Lentry_bad
    test rdi,rdi
    jz .Lentry_bad
    test rdx,rdx
    jz .Lentry_bad
    test r8,r8
    jz .Lentry_bad
    cmp r9,256
    jne .Lentry_bad
    mov rax,0x3151465256414948
    cmp [rdi],rax
    jne .Lentry_bad
    mov rax,rdi
    add rax,rsi
    jc .Lentry_bad
    mov r10,rdx
    add r10,rcx
    jc .Lentry_bad
    cmp rdx,rax
    jae .Lfinalizer_context
    cmp rdi,r10
    jb .Lentry_bad
.Lfinalizer_context:
    mov r11,r8
    add r11,r9
    jc .Lentry_bad
    cmp rdx,r11
    jae .Lfinalizer_stack
    cmp r8,r10
    jb .Lentry_bad
.Lfinalizer_stack:
    push rbx
    push rbp
    push r12
    push r13
    push r14
    push r15
    sub rsp,8200
    mov r13,rdx
    mov rdx,rsp
    mov ecx,8192
    call .Lmain
    test eax,eax
    jne .Lfinalizer_return
    mov rdi,r13
    mov rsi,rsp
    mov ecx,16
    rep movsq
.Lfinalizer_return:
    add rsp,8200
    pop r15
    pop r14
    pop r13
    pop r12
    pop rbp
    pop rbx
    ret
.Lentry_bad:
    mov eax,0xfffffffd
    ret
.Lmain:
    push rbx
    push rbp
    push r12
    push r13
    push r14
    push r15
    sub rsp,152
    mov r12,rdi
    mov r15,rsi
    mov r13,rdx
    mov rbp,rcx
    mov r14,r8
    mov rbx,r9
    cmp rbp,8192
    jb .Lbad
    cmp rbx,256
    jne .Lbad
    test r13,r13
    jz .Lbad
    test r14,r14
    jz .Lbad
    mov rax,r13
    add rax,rbp
    jc .Lbad
    mov [rsp+104],rax
    mov rax,r14
    add rax,rbx
    jc .Lbad
    mov [rsp+112],rax
    cmp r14,[rsp+104]
    jae .Linput
    cmp rax,r13
    ja .Lbad
.Linput:
    mov rax,r12
    add rax,r15
    jc .Lbad
    mov [rsp+96],rax
    test r15,r15
    jz .Lready
    test r12,r12
    jz .Lbad
    cmp r12,[rsp+104]
    jae .Linput_ctx
    cmp rax,r13
    ja .Lbad
.Linput_ctx:
    cmp r12,[rsp+112]
    jae .Lready
    cmp rax,r14
    ja .Lbad
.Lready:
    mov qword ptr [r13+128],0
    mov [r13+144],r14
    mov qword ptr [rsp],0
    mov [rsp+8],r14
    mov [rsp+16],r13
    mov [rsp+24],r12
.Lloop:
    mov rdi,r12
    mov rsi,r15
    mov rdx,r13
    mov rcx,rbp
    mov r8,r14
    mov r9,rbx
    .byte 0xe8
owner_hole: .long 0
    test eax,eax
    jz .Lreturn
    cmp eax,10
    je .Lloop
    cmp eax,1
    je .Lsyscall
    cmp eax,2
    je .Lcas
    cmp eax,3
    je .Lexchange
    cmp eax,4
    je .Lregistry
    cmp eax,5
    je .Lcompiler
    cmp eax,6
    je .Lcompiled
    cmp eax,7
    je .Lbuffers
    jmp .Lreturn
.Lsyscall:
    mov r10,[r13+184]
    xor ecx,ecx
.Largs:
    mov rax,[r13+192+rcx*8]
    mov r11,r10
    and r11d,7
    cmp r11d,3
    ja .Lbad
    add rax,[rsp+r11*8]
    mov [rsp+40+rcx*8],rax
    shr r10,3
    inc ecx
    cmp ecx,6
    jb .Largs
    mov rdi,[rsp+40]
    mov rsi,[rsp+48]
    mov rdx,[rsp+56]
    mov r10,[rsp+64]
    mov r8,[rsp+72]
    mov r9,[rsp+80]
    mov rax,[r13+176]
    syscall
    jmp .Lfeedback
.Lregistry:
    mov rdi,r12
    mov rsi,r15
    mov rdx,r13
    mov rcx,rbp
    mov r8,[r14+16]
    mov r9,[r14+40]
    .byte 0xe8
registry_hole: .long 0
    jmp .Lfeedback
.Lcompiler:
    mov rdi,[r13+312]
    mov rsi,[r13+328]
    mov rdx,[r13+288]
    mov ecx,1048576
    mov r8,[r13+336]
    mov r9d,1048576
    .byte 0xe8
compiler_hole: .long 0
    jmp .Lfeedback
.Lcompiled:
    mov rdi,[r13+496]
    mov rsi,[r13+544]
    lea rdx,[rdi+1048576]
    mov ecx,1048576
    lea r8,[rdi+2097152]
    mov r9d,1048576
    mov rax,[r13+288]
    call rax
    jmp .Lfeedback
.Lbuffers:
    mov rdi,r12
    mov rsi,r15
    mov rdx,r13
    mov rcx,rbp
    mov r8,[r13+552]
    mov r9,[r13+560]
    .byte 0xe8
buffers_hole: .long 0
    jmp .Lfeedback
.Lcas:
    mov r10,[r13+192]
    add r10,r14
    mov rax,[r13+200]
    mov rdx,[r13+208]
    lock cmpxchg qword ptr [r10],rdx
    jmp .Lfeedback
.Lexchange:
    mov r10,[r13+192]
    add r10,r14
    mov rax,[r13+208]
    xchg qword ptr [r10],rax
.Lfeedback:
    mov [r13+136],rax
    jmp .Lloop
.Lbad:
    mov eax,0xfffffffd
.Lreturn:
    add rsp,152
    pop r15
    pop r14
    pop r13
    pop r12
    pop rbp
    pop rbx
    ret
.size hia_native_callable_code_owner,.-hia_native_callable_code_owner
.section .note.GNU-stack,"",@progbits
