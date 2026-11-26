# Fixed effects only: HIA chooses all ownership, operations, extents and roles.
.intel_syntax noprefix
.text
.global hia_result_value
.type hia_result_value,@function
hia_result_value:
.Lvalue_self:
    push rbx
    push rbp
    push r12
    push r13
    push r14
    push r15
    sub rsp,152
    mov qword ptr [rsp+128],0
    mov qword ptr [rsp+136],0
    mov r12,rdi
    mov r15,rsi
    mov r13,rdx
    mov rbp,rcx
    mov r14,r8
    mov rbx,r9
    cmp rbp,8192
    jb .Lbad
    cmp rbx,256
    jb .Lbad
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
    lock inc qword ptr [r14+120]
    mov qword ptr [rsp+128],1
    mov qword ptr [r13+128],0
    mov qword ptr [rsp],0
    mov [rsp+16],r12
    mov [rsp+24],r13
    mov [rsp+32],r14
.Lloop:
    mov rdi,r12
    mov rsi,r15
    mov rdx,r13
    mov rcx,rbp
    mov r8,r14
    mov r9,rbx
    .byte 0xe8
owner_hole:
    .long 0
    test eax,eax
    jz .Lreturn
    cmp eax,10
    je .Lloop
    cmp eax,12
    je .Ldeferred_input
    cmp eax,2
    je .Lcas
    cmp eax,3
    je .Lexchange
    cmp eax,1
    je .Ltranslate
    cmp eax,7
    je .Ltranslate
    cmp eax,8
    je .Ltranslate
    cmp eax,9
    je .Ltranslate
    cmp eax,4
    jne .Lreturn
.Ltranslate:
    mov [rsp+88],rax
    mov rax,[r14+16]
    mov [rsp+8],rax
    mov r10,[r13+200]
    xor ecx,ecx
.Largs:
    mov rax,[r13+208+rcx*8]
    mov r11,r10
    and r11d,7
    cmp r11d,4
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
    mov r8,[rsp+72]
    mov r9,[rsp+80]
    cmp qword ptr [rsp+88],1
    jne .Lrole
    mov r10,[rsp+64]
    mov rax,[r13+192]
    syscall
    jmp .Lfeedback
.Lrole:
    mov rcx,[rsp+64]
    cmp qword ptr [rsp+88],7
    je .Lfinalizer
    cmp qword ptr [rsp+88],8
    je .Lcode_provider
    cmp qword ptr [rsp+88],9
    je .Lvalue_reentry
    mov rax,[r13+192]
    cmp rax,1
    je .Lrole1
    cmp rax,2
    je .Lrole2
    cmp rax,3
    je .Lrole3
    cmp rax,4
    je .Lrole4
    cmp rax,5
    je .Lrole5
    cmp rax,6
    je .Lrole6
    cmp rax,8
    je .Lrole8
    cmp rax,9
    je .Lrole9
    cmp rax,10
    je .Lrole10
    cmp rax,11
    je .Lrole11
    cmp rax,12
    je .Lrole12
    cmp rax,13
    je .Lrole13
    cmp rax,14
    je .Lrole14
    cmp rax,15
    je .Lrole15
    cmp rax,16
    je .Lrole16
    jmp .Lbad
.Lrole1:
    .byte 0xe8
role_1_hole:
    .long 0
    jmp .Lfeedback
.Lrole2:
    .byte 0xe8
role_2_hole:
    .long 0
    jmp .Lfeedback
.Lrole3:
    .byte 0xe8
role_3_hole:
    .long 0
    jmp .Lfeedback
.Lrole4:
    .byte 0xe8
role_4_hole:
    .long 0
    jmp .Lfeedback
.Lrole5:
    .byte 0xe8
role_5_hole:
    .long 0
    jmp .Lfeedback
.Lrole6:
    .byte 0xe8
role_6_hole:
    .long 0
    jmp .Lfeedback
.Lrole8:
    .byte 0xe8
role_8_hole:
    .long 0
    jmp .Lfeedback
.Lrole9:
    .byte 0xe8
role_9_hole:
    .long 0
    jmp .Lfeedback
.Lrole10:
    .byte 0xe8
role_10_hole:
    .long 0
    jmp .Lfeedback
.Lrole11:
    .byte 0xe8
role_11_hole:
    .long 0
    jmp .Lfeedback
.Lrole12:
    .byte 0xe8
role_12_hole:
    .long 0
    jmp .Lfeedback
.Lrole13:
    .byte 0xe8
role_13_hole:
    .long 0
    jmp .Lfeedback
.Lrole14:
    .byte 0xe8
role_14_hole:
    .long 0
    jmp .Lfeedback
.Lrole15:
    .byte 0xe8
role_15_hole:
    .long 0
    jmp .Lfeedback
.Lrole16:
    .byte 0xe8
role_16_hole:
    .long 0
    jmp .Lfeedback
.Lcode_provider:
    mov rax,[r14+192]
    test rax,rax
    jz .Lfinalizer_unbound
    mov r8,[r14+200]
    mov r9,[r14+208]
    call rax
    jmp .Lfeedback
.Lvalue_reentry:
    mov r8,r14
    mov r9,rbx
    call .Lvalue_self
    jmp .Lfeedback
.Lfinalizer:
    mov rax,[r14+128]
    test rax,rax
    jz .Lfinalizer_unbound
    mov r8,[r14+136]
    mov r9,[r14+144]
    call rax
    jmp .Lfeedback
.Lfinalizer_unbound:
    mov eax,0xfffffffd
    jmp .Lfeedback
.Ldeferred_input:
    mov qword ptr [rsp+136],1
    mov rax,[rsp+136]
    mov [r13+8184],rax
    jmp .Lloop
.Lcas:
    mov r10,[r13]
    add r10,r14
    mov rax,[r13+8]
    mov rdx,[r13+16]
    lock cmpxchg qword ptr [r10],rdx
    jmp .Lfeedback
.Lexchange:
    mov r10,[r13]
    add r10,r14
    mov rax,[r13+16]
    xchg qword ptr [r10],rax
.Lfeedback:
    mov [r13+136],rax
    jmp .Lloop
.Lbad:
    mov eax,0xfffffffd
.Lreturn:
    cmp qword ptr [rsp+128],0
    je .Lreturn_unentered
    lock dec qword ptr [r14+120]
.Lreturn_unentered:
    add rsp,152
    pop r15
    pop r14
    pop r13
    pop r12
    pop rbp
    pop rbx
    ret
.size hia_result_value,.-hia_result_value
.section .note.GNU-stack,"",@progbits
