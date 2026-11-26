# Fixed kind-6 finalizer calls the native registry owner in the same capsule.
# The private stack preserves only the generated request across the child call.
.intel_syntax noprefix
.text
.global hia_background_native_finalizer
.type hia_background_native_finalizer,@function
hia_background_native_finalizer:
.Lentry:
    push rbx
    push rbp
    push r12
    push r13
    push r14
    push r15
    sub rsp,200
    mov r12,rdi
    mov r15,rsi
    mov r13,rdx
    mov rbp,rcx
    mov r14,r8
    mov rbx,r9
    cmp r15,128
    jne .Lbad
    cmp rbp,1048576
    jb .Lbad
    cmp rbx,512
    jne .Lbad
    test r12,r12
    jz .Lbad
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
    cmp r12,rdx
    jae 1f
    cmp r13,rax
    jb .Lbad
1:
    cmp r14,rdx
    jae 2f
    cmp r13,rcx
    jb .Lbad
2:
    cmp r12,rcx
    jae 3f
    cmp r14,rax
    jb .Lbad
3:
    mov qword ptr [r13+128],0
.Lloop:
    mov rdi,r12
    mov rsi,r15
    mov rdx,r13
    mov rcx,rbp
    mov r8,r14
    mov r9,rbx
    .byte 0xe8
finalizer_policy_hole:
    .long 0
    test eax,eax
    je .Ldone
    cmp eax,16
    jne .Lbad
    lea rsi,[r13+4096]
    mov rdi,rsp
    mov ecx,24
    cld
    rep movsq
    mov rdi,rsp
    mov esi,192
    mov rdx,r13
    mov rcx,rbp
    mov r8,r14
    mov r9,rbx
    .byte 0xe8
objects_hole:
    .long 0
    mov [rsp+192],eax
    mov rsi,r13
    lea rdi,[r13+1024]
    mov ecx,16
    cld
    rep movsq
    mov qword ptr [r13+128],1
    mov eax,[rsp+192]
    mov [r13+136],rax
    jmp .Lloop
.Ldone:
    xor eax,eax
    jmp .Lreturn
.Lbad:
    mov eax,0xfffffffd
.Lreturn:
    add rsp,200
    pop r15
    pop r14
    pop r13
    pop r12
    pop rbp
    pop rbx
    ret
.size hia_background_native_finalizer,.-hia_background_native_finalizer
.section .note.GNU-stack,"",@progbits
