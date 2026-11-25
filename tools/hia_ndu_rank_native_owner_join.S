/* Mechanical fixed-six-word role router. HIA owns identity, paths, budgets and process state. */
.intel_syntax noprefix
.text
.global hia_ndu_owner_join, cancel_sample_call, owner_call, sha_call, identity_call, path_call, pump_call, json_call
hia_ndu_owner_join:
    push rbp
    push rbx
    push r12
    push r13
    push r14
    push r15
    sub rsp,120
    mov r12,rdi
    mov r13,rsi
    mov r14,rdx
    mov r15,r8
    mov [rsp+48],rcx
    mov [rsp+56],r9
    cmp rcx,128
    jb .Lbad
    cmp r9,201326592
    jb .Lbad
    mov rbx,r12
    add rbx,r13
    jc .Lbad
    mov rbp,r14
    add rbp,rcx
    jc .Lbad
    mov r10,r15
    add r10,r9
    jc .Lbad
    cmp r14,r10
    jae .Lno_ow
    cmp r15,rbp
    jb .Lbad
.Lno_ow:
    test r13,r13
    jz .Lno_input
    cmp r12,rbp
    jae .Lno_so
    cmp r14,rbx
    jb .Lbad
.Lno_so:
    cmp r12,r10
    jae .Lno_input
    cmp r15,rbx
    jb .Lbad
.Lno_input:
    mov [r15+16],r15
    cmp QWORD PTR [r15],0
    jne .Lsample
    mov QWORD PTR [r15+1024],0
    jmp .Lresume
/* HIA sampler preserves original parent phase, syscall feedback and nested await.
 * It is advanced before each effect continuation, including nested path/pump. */
.Lsample:
    mov rax,3544418957723257160
    cmp [r15+2256],rax
    jne .Lresume
    cmp QWORD PTR [r15+2424],1
    je .Lsample_call
    mov QWORD PTR [r15+2424],1
    mov QWORD PTR [r15+2432],0
.Lsample_call:
    mov rdi,r12
    mov rsi,r13
    mov rdx,r14
    mov rcx,[rsp+48]
    mov r8,r15
    mov r9,[rsp+56]
    .byte 0xe8
cancel_sample_call:.long 0
    cmp eax,1
    je .Lreturn
    test eax,eax
    jne .Lbad
    mov QWORD PTR [r15+2424],0
.Lresume:
    cmp QWORD PTR [r15+1024],0
    jne .Lnested
.Lowner:
    mov rdi,r12
    mov rsi,r13
    mov rdx,r14
    mov rcx,[rsp+48]
    mov r8,r15
    mov r9,[rsp+56]
    .byte 0xe8
owner_call:.long 0
    cmp eax,2
    je .Linternal
    cmp eax,3
    je .Lreturn
    cmp eax,1
    je .Lreturn
    test eax,eax
    jz .Lreturn
    jmp .Lbad
.Linternal:
    mov rax,[r14]
    cmp rax,1
    jb .Lbad
    cmp rax,5
    ja .Lbad
    mov rsi,r14
    lea rdi,[r15+1024]
    mov ecx,8
    cld
    rep movsq
    mov QWORD PTR [r15+1088],0
    call .Lviews
    cmp QWORD PTR [r15+1024],5
    je .Ljson
    cmp QWORD PTR [r15+1024],3
    jae .Lnested
    cmp QWORD PTR [r15+1024],1
    jne .Lidentity
    .byte 0xe8
sha_call:.long 0
    jmp .Lpure_done
.Lidentity:
    .byte 0xe8
identity_call:.long 0
    jmp .Lpure_done
.Ljson:
    .byte 0xe8
json_call:.long 0
.Lpure_done:
    mov [r15+8],rax
    mov QWORD PTR [r15+1024],0
    jmp .Lowner
.Lnested:
    cmp QWORD PTR [r15+1024],3
    jb .Lbad
    cmp QWORD PTR [r15+1024],4
    ja .Lbad
    call .Lviews
    cmp QWORD PTR [r15+1064],128
    jne .Lbad
    mov rdx,r14
    mov ecx,128
    mov [r8+16],r8
    cmp QWORD PTR [r15+1088],0
    je .Lno_result
    mov rax,[r15+8]
    mov [r8+8],rax
    mov QWORD PTR [r15+1088],0
.Lno_result:
    mov rax,[r15+32]
    cmp QWORD PTR [r15+1024],3
    jne .Lpump
    cmp r9,200704
    jb .Lbad
    mov [r8+544],rax
    .byte 0xe8
path_call:.long 0
    jmp .Lnested_result
.Lpump:
    cmp r9,5242880
    jb .Lbad
    mov [r8+336],rax
    .byte 0xe8
pump_call:.long 0
.Lnested_result:
    cmp eax,1
    je .Lsyscall
    cmp eax,3
    je .Lreturn
    test eax,eax
    jne .Lbad
    mov rdi,[r15+1056]
    add rdi,r15
    mov rsi,r14
    mov ecx,16
    cld
    rep movsq
    mov QWORD PTR [r15+8],0
    mov QWORD PTR [r15+1024],0
    jmp .Lowner
.Lsyscall:
    mov QWORD PTR [r15+1088],1
    xor ebx,ebx
    mov rbp,[r14+56]
    mov QWORD PTR [rsp+64],0
.Larg:
    mov rax,[r14+8+rbx*8]
    mov rdx,rbp
    and edx,3
    shr rbp,2
    test edx,edx
    jz .Larg_ready
    cmp edx,1
    je .Larg_s
    cmp edx,2
    je .Larg_o
    cmp rax,[r15+1080]
    ja .Lbad
    add rax,[r15+1072]
    jc .Lbad
    jmp .Larg_ready
.Larg_s:
    cmp rax,[r15+1048]
    ja .Lbad
    add rax,[r15+1040]
    jc .Lbad
    mov rdx,[r15+1032]
    jmp .Larg_ready
.Larg_o:
    cmp rax,128
    ja .Lbad
.Larg_ready:
    mov [r14+8+rbx*8],rax
    mov ecx,ebx
    add ecx,ecx
    shl rdx,cl
    or [rsp+64],rdx
    inc ebx
    cmp ebx,6
    jb .Larg
    test rbp,rbp
    jne .Lbad
    mov rax,[rsp+64]
    mov [r14+56],rax
    mov eax,1
    jmp .Lreturn
/* Every stored view is a checked subrange of the original six-word views. */
.Lviews:
    mov rax,[r15+1032]
    cmp rax,1
    je .Lsource_s
    cmp rax,3
    jne .Lbad_view
    mov rdi,r15
    mov rsi,[rsp+64]
    jmp .Lsource
.Lsource_s:
    mov rdi,r12
    mov rsi,r13
.Lsource:
    mov rax,[r15+1040]
    cmp rax,rsi
    ja .Lbad_view
    sub rsi,rax
    cmp [r15+1048],rsi
    ja .Lbad_view
    add rdi,rax
    mov rsi,[r15+1048]
    mov rdx,[r15+1056]
    mov rcx,[rsp+64]
    cmp rdx,rcx
    ja .Lbad_view
    sub rcx,rdx
    cmp [r15+1064],rcx
    ja .Lbad_view
    add rdx,r15
    mov rcx,[r15+1064]
    mov r8,[r15+1072]
    mov r9,[rsp+64]
    cmp r8,r9
    ja .Lbad_view
    sub r9,r8
    cmp [r15+1080],r9
    ja .Lbad_view
    add r8,r15
    mov r9,[r15+1080]
    ret
.Lbad_view:
    add rsp,8
.Lbad:
    mov eax,0xfffffffd
.Lreturn:
    add rsp,120
    pop r15
    pop r14
    pop r13
    pop r12
    pop rbx
    pop rbp
    ret
.section .note.GNU-stack,"",@progbits
