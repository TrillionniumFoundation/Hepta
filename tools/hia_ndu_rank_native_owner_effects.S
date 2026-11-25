/* Mechanical six-word effect loop. Every syscall and ownership decision is emitted by HIA. */
.intel_syntax noprefix
.text
.global hia_ndu_effects, effect_policy_call
hia_ndu_effects:
    push rbp
    push rbx
    push r12
    push r13
    push r14
    push r15
    sub rsp,104
    mov r12,rdi
    mov r13,rsi
    mov r14,rdx
    mov r15,r8
    mov [rsp+48],rcx
    mov [rsp+56],r9
    cmp r9,24
    jb .Lbad
    cmp rcx,128
    jb .Lbad
    /* Reject wrapping and overlapping caller views before any store. */
    mov r10,r12
    add r10,r13
    jc .Lbad
    mov r11,r14
    add r11,rcx
    jc .Lbad
    mov rax,r15
    add rax,r9
    jc .Lbad
    cmp r14,rax
    jae .Lno_ow
    cmp r15,r11
    jb .Lbad
.Lno_ow:
    test r13,r13
    jz .Lno_input
    cmp r12,r11
    jae .Lno_so
    cmp r14,r10
    jb .Lbad
.Lno_so:
    cmp r12,rax
    jae .Lno_input
    cmp r15,r10
    jb .Lbad
.Lno_input:
    mov [r15+16],r15
.Lagain:
    mov rdi,r12
    mov rsi,r13
    mov rdx,r14
    mov rcx,[rsp+48]
    mov r8,r15
    mov r9,[rsp+56]
    .byte 0xe8
effect_policy_call: .long 0
    cmp eax,3
    je .Lagain
    test eax,eax
    jz .Lreturn
    cmp eax,1
    jne .Lbad
    xor ebx,ebx
    mov rbp,[r14+56]
.Larg:
    mov rax,[r14+8+rbx*8]
    mov rcx,rbp
    and ecx,3
    shr rbp,2
    test ecx,ecx
    jz .Lready
    cmp ecx,1
    je .Linput
    cmp ecx,2
    je .Loutput
    mov rdx,r15
    mov rsi,[rsp+56]
    jmp .Lview
.Linput:
    mov rdx,r12
    mov rsi,r13
    jmp .Lview
.Loutput:
    mov rdx,r14
    mov rsi,[rsp+48]
.Lview:
    cmp rax,rsi
    ja .Lbad
    add rax,rdx
    jc .Lbad
.Lready:
    mov [rsp+rbx*8],rax
    inc ebx
    cmp ebx,6
    jb .Larg
    test rbp,rbp
    jne .Lbad
    mov rax,[r14]
    mov rdi,[rsp]
    mov rsi,[rsp+8]
    mov rdx,[rsp+16]
    mov r10,[rsp+24]
    mov r8,[rsp+32]
    mov r9,[rsp+40]
    syscall
    mov [r15+8],rax
    jmp .Lagain
.Lbad:
    mov eax,0xfffffffd
.Lreturn:
    add rsp,104
    pop r15
    pop r14
    pop r13
    pop r12
    pop rbx
    pop rbp
    ret
.section .note.GNU-stack,"",@progbits
