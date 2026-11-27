# Actual root lock/syscalls and fixed native global/carrier calls.
# Runtime admission, record traversal and ownership transitions are HIA.
.intel_syntax noprefix
.text
.global hia_generation_runtime_borrow
.type hia_generation_runtime_borrow,@function
hia_generation_runtime_borrow:
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
    cmp rbp,262144
    jb .Lbad
    cmp rbx,2048
    jne .Lbad
    cmp r15,128
    jne .Lbad
    test r14,7
    jnz .Lbad
    test r12,r12
    jz .Lbad
    test r13,r13
    jz .Lbad
    test r14,r14
    jz .Lbad
    movabs rax,0x31514c5452414948
    cmp [r12],rax
    jne .Lbad
    mov r10,[r12+8]
    cmp r10,2
    ja .Lbad
    cmp r10,0
    jne .Lframe_fields
    cmp rbp,100696064
    jb .Lbad
.Lframe_fields:
    mov ecx,16
.Lfields:
    cmp r10,0
    jne .Lnot_register
    cmp ecx,24
    jb .Lzero
    cmp ecx,40
    jbe .Lnext_field
.Lnot_register:
    cmp r10,1
    jne .Lzero
    cmp ecx,24
    je .Lnext_field
.Lzero:
    cmp qword ptr [r12+rcx],0
    jne .Lbad
.Lnext_field:
    add ecx,8
    cmp ecx,128
    jb .Lfields
    cmp r10,2
    je .Lhas_cap
    cmp qword ptr [r12+24],0
    je .Lbad
.Lhas_cap:
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
    jae .Lso_ok
    cmp r13,rax
    jb .Lbad
.Lso_ok:
    cmp r12,rcx
    jae .Lsw_ok
    cmp r14,rax
    jb .Lbad
.Lsw_ok:
    cmp r13,rcx
    jae .Low_ok
    cmp r14,rdx
    jb .Lbad
.Low_ok:
    mov [r13+512],r14
    .byte 0x48,0x8d,0x05
root_address_hole:
    .long 0
    mov [r13+520],rax
    .byte 0x48,0x8d,0x05
global_address_hole:
    .long 0
    mov [r13+528],rax
    .byte 0x48,0x8d,0x05
handles_address_hole:
    .long 0
    mov [r13+536],rax
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
    cmp eax,1
    je .Lsyscall
    cmp eax,2
    je .Llock
    cmp eax,3
    je .Lunlock
    cmp eax,12
    je .Lhandles
    cmp eax,8
    je .Lcopy
    cmp eax,9
    je .Lglobal
.Lbad:
    mov eax,0xfffffffd
    jmp .Lreturn
.Llock:
    xor eax,eax
    mov ecx,1
    lock cmpxchg [r14+64],rcx
    pause
    jmp .Lfeedback
.Lunlock:
    xor eax,eax
    xchg [r14+64],rax
    xor eax,eax
    jmp .Lfeedback
.Lglobal:
    lea rdi,[r13+4096]
    mov esi,128
    lea rdx,[r13+32768]
    mov ecx,147456
    mov r8,r14
    mov r9d,2048
    .byte 0xe8
global_call_hole:
    .long 0
    mov eax,eax
    jmp .Lfeedback
.Lhandles:
    lea rdi,[r13+4096]
    mov esi,128
    lea rdx,[r13+32768]
    mov ecx,100663296
    lea r8,[r14+256]
    mov r9d,256
    .byte 0xe8
handles_call_hole:
    .long 0
    mov eax,eax
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
    cld
    rep movsb
    xor eax,eax
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
.size hia_generation_runtime_borrow,.-hia_generation_runtime_borrow
.section .note.GNU-stack,"",@progbits
