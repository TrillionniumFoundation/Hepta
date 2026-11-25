# Mechanical fixed-role six-word calls. HIA owns all admission, copying,
# ordering, role arguments, identities and output decisions.
.intel_syntax noprefix
.text
.global hia_mv_intake
.type hia_mv_intake,@function
hia_mv_intake:
    push rbx
    push rbp
    push r12
    push r13
    push r14
    push r15
    sub rsp,8
    mov r12,rdi
    mov r15,rsi
    mov r13,rdx
    mov rbp,rcx
    mov r14,r8
    mov rbx,r9
    cmp rbx,167772160
    jb .Lbad
    mov qword ptr [r14],0
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
    cmp eax,2
    jb .Lreturn
    cmp eax,7
    ja .Lreturn
    mov rdi,[r14+16]
    add rdi,r14
    mov rsi,[r14+24]
    mov rdx,[r14+32]
    add rdx,r14
    mov rcx,[r14+40]
    mov r8,[r14+48]
    add r8,r14
    mov r9,[r14+56]
    cmp eax,2
    je .Ladmission
    cmp eax,3
    je .Lcanonical
    cmp eax,4
    je .Lhash
    cmp eax,5
    je .Lprofile
    cmp eax,6
    je .Lscalar
    .byte 0xe8
abi_hole:
    .long 0
    jmp .Lfeedback
.Ladmission:
    .byte 0xe8
admission_hole:
    .long 0
    jmp .Lfeedback
.Lcanonical:
    .byte 0xe8
canonical_hole:
    .long 0
    jmp .Lfeedback
.Lhash:
    .byte 0xe8
hash_hole:
    .long 0
    jmp .Lfeedback
.Lprofile:
    .byte 0xe8
profile_hole:
    .long 0
    jmp .Lfeedback
.Lscalar:
    .byte 0xe8
scalar_hole:
    .long 0
.Lfeedback:
    mov [r14+8],rax
    jmp .Lloop
.Ldone:
    mov eax,[r14+128]
    jmp .Lreturn
.Lbad:
    mov eax,0xfffffffd
.Lreturn:
    add rsp,8
    pop r15
    pop r14
    pop r13
    pop r12
    pop rbp
    pop rbx
    ret
.size hia_mv_intake,.-hia_mv_intake
.section .note.GNU-stack,"",@progbits
