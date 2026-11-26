.intel_syntax noprefix
.text
.global hia_background_native_object_retire
.type hia_background_native_object_retire,@function
hia_background_native_object_retire:
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
    cmp rbp,786432
    jb .Lbad
    cmp rbx,2097152
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
    jae .Lso
    cmp r13,rax
    jb .Lbad
.Lso:
    cmp r12,rcx
    jae .Lsw
    cmp r14,rax
    jb .Lbad
.Lsw:
    cmp r13,rcx
    jae .Low
    cmp r14,rdx
    jb .Lbad
.Low:
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
    je .Lreturn
    cmp eax,10
    je .Lloop
    cmp eax,9
    je .Linvoke

.Lbad:
    mov eax,0xfffffffd
    jmp .Lreturn
.Linvoke:
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
    mov rcx,[rsp+56]
    mov r8,[rsp+64]
    mov r9,[rsp+72]
    mov r11,[r13]
    call r11
    mov eax,eax
    jmp .Lfeedback

.Lfeedback:
    mov [r13+136],rax
    jmp .Lloop
.Lreturn:
    add rsp,136
    pop r15
    pop r14
    pop r13
    pop r12
    pop rbp
    pop rbx
    ret
.size hia_background_native_object_retire,.-hia_background_native_object_retire
.section .note.GNU-stack,"",@progbits
