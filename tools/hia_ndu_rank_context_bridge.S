# Fixed effect adapter: syscalls, atomic lock word, checked view translation,
# owned byte copies and calls to four source-bound native roles only.
.intel_syntax noprefix
.text
.global hia_ndu_rank_context
.type hia_ndu_rank_context,@function
hia_ndu_rank_context:
    test rdi,rdi
    je .Lguard_bad
    test rdx,rdx
    je .Lguard_bad
    test r8,r8
    je .Lguard_bad
    test r8b,7
    jne .Lguard_bad
    cmp rsi,128
    jb .Lguard_bad
    cmp rcx,512
    jb .Lguard_bad
    cmp r9,131072
    jb .Lguard_bad
    mov rax,rdi
    add rax,rsi
    jc .Lguard_bad
    mov r10,rdx
    add r10,rcx
    jc .Lguard_bad
    mov r11,r8
    add r11,r9
    jc .Lguard_bad
    cmp rdi,r10
    jae .Lso
    cmp rdx,rax
    jb .Lguard_bad
.Lso:
    cmp rdi,r11
    jae .Lsw
    cmp r8,rax
    jb .Lguard_bad
.Lsw:
    cmp rdx,r11
    jae .Low
    cmp r8,r10
    jb .Lguard_bad
.Low:
    jmp .Lgood
.Lguard_bad:
    mov eax,0xfffffffd
    ret
.Lgood:
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
    mov qword ptr [r13+128],0
    mov [r13+480],r12
    mov [r13+488],r13
    mov [r13+496],r14
    mov [r13+504],rbx
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
.global context_policy_hole
context_policy_hole:
    .long 0
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
    cmp eax,6
    je .Lallocate
    cmp eax,7
    je .Lfree
    cmp eax,8
    je .Lcopy
    cmp eax,9
    je .Lpayload
    cmp eax,11
    je .Lsha
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
.Lallocate:
    mov rdi,[r13]
    .byte 0xe8
.global context_malloc_hole
context_malloc_hole:
    .long 0
    jmp .Lfeedback
.Lfree:
    mov rdi,[r13]
    .byte 0xe8
.global context_free_hole
context_free_hole:
    .long 0
    xor eax,eax
    jmp .Lfeedback
.Lcopy:
    mov rax,[r13]
    cmp rax,3
    ja .Lbad
    mov rsi,[r13+8]
    add rsi,[rsp+rax*8]
    jc .Lbad
    mov rax,[r13+16]
    cmp rax,3
    ja .Lbad
    mov rdi,[r13+24]
    add rdi,[rsp+rax*8]
    jc .Lbad
    mov rcx,[r13+32]
    mov rax,rsi
    add rax,rcx
    jc .Lbad
    mov rax,rdi
    add rax,rcx
    jc .Lbad
    cld
    rep movsb
    xor eax,eax
    jmp .Lfeedback
.Lpayload:
    mov rax,[r13]
    cmp rax,3
    ja .Lbad
    mov rdi,[r13+8]
    add rdi,[rsp+rax*8]
    jc .Lbad
    mov rsi,[r13+16]
    mov rax,rdi
    add rax,rsi
    jc .Lbad
    mov r8,[r13+24]
    cmp r8,rbx
    ja .Lbad
    mov rax,rbx
    sub rax,r8
    cmp rax,256
    jb .Lbad
    add r8,r14
    lea rdx,[r14+8704]
    mov ecx,512
    mov r9d,256
    .byte 0xe8
.global context_payload_hole
context_payload_hole:
    .long 0
    jmp .Lfeedback
.Lsha:
    mov rdi,[r13]
    cmp rdi,rbx
    ja .Lbad
    mov rsi,[r13+8]
    mov rax,rbx
    sub rax,rdi
    cmp rsi,rax
    ja .Lbad
    add rdi,r14
    lea rdx,[r14+19000]
    mov ecx,32
    lea r8,[r14+16384]
    mov r9d,1184
    .byte 0xe8
.global context_sha_hole
context_sha_hole:
    .long 0
.Lfeedback:
    mov [r13+448],rax
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
.size hia_ndu_rank_context,.-hia_ndu_rank_context
.section .note.GNU-stack,"",@progbits
