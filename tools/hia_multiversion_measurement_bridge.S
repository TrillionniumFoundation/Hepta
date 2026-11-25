# Fixed pure measurement capture/policy/hash dispatch; no hosted policy.
.intel_syntax noprefix
.text
.global hia_mv_measurement
.type hia_mv_measurement,@function
hia_mv_measurement:
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
    cmp rbp,128
    jb .Lbad
    cmp rbx,65536
    jb .Lbad
    mov qword ptr [r14+4096],0
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
    cmp eax,1
    jb .Lreturn
    cmp eax,2
    ja .Lreturn
    mov rdi,[r13]
    add rdi,r14
    mov rsi,[r13+8]
    mov rdx,[r13+16]
    add rdx,r14
    mov rcx,[r13+24]
    mov r8,[r13+32]
    add r8,r14
    mov r9,[r13+40]
    cmp eax,1
    je .Lmeasurement
    .byte 0xe8
hash_hole:
    .long 0
    jmp .Lfeedback
.Lmeasurement:
    .byte 0xe8
measurement_hole:
    .long 0
.Lfeedback:
    mov [r14+4104],rax
    jmp .Lloop
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
.size hia_mv_measurement,.-hia_mv_measurement
.section .note.GNU-stack,"",@progbits
