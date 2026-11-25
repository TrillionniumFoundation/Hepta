# Fixed mechanical rank engine. All decisions, extents, deadlines and ownership
# are chosen by HIA. Anonymous arena is MAP_PRIVATE, never MAP_SHARED.
# Control O40/O16 return the current arena address/extent for context finish.
.intel_syntax noprefix
.text
.global hia_ndu_rank_engine
.type hia_ndu_rank_engine,@function
hia_ndu_rank_engine:
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
    cmp rbp,65536
    jb .Lbad_buffer
    test r13,r13
    jz .Lbad_buffer
    mov rax,r13
    add rax,rbp
    jc .Lbad_buffer
    mov [rsp+104],rax
    mov rax,r12
    add rax,r15
    jc .Lbad_buffer
    mov [rsp+96],rax
    test r15,r15
    jz .Lcheck_work
    test r12,r12
    jz .Lbad_buffer
    cmp r12,[rsp+104]
    jae .Lcheck_work
    cmp rax,r13
    ja .Lbad_buffer
.Lcheck_work:
    test r14,r14
    jz .Lnew_arena
    test rbx,rbx
    jz .Lbad_buffer
    mov rax,r14
    add rax,rbx
    jc .Lbad_buffer
    mov [rsp+112],rax
    cmp r14,[rsp+104]
    jae .Lwork_input
    cmp rax,r13
    ja .Lbad_buffer
.Lwork_input:
    test r15,r15
    jz .Linitialize
    cmp r14,[rsp+96]
    jae .Linitialize
    cmp r12,[rsp+112]
    jb .Lbad_buffer
    jmp .Linitialize
.Lnew_arena:
    test rbx,rbx
    jnz .Lbad_buffer
    mov eax,9
    xor edi,edi
    mov esi,1048576
    mov edx,3
    mov r10d,34
    mov r8,-1
    xor r9d,r9d
    syscall
    cmp rax,-4095
    jae .Lallocation
    mov r14,rax
    mov ebx,1048576
    jmp .Linitialize
.Linitialize:
    mov qword ptr [rsp],0
    mov [rsp+8],r14
    mov [rsp+16],r12
    mov [rsp+24],r13
    mov [r13+16],rbx
    mov [r13+40],r14
    mov [r13+120],r13
.Lloop:
    mov rdi,r12
    mov rsi,r15
    mov rdx,r13
    mov rcx,rbp
    mov r8,r14
    mov r9,rbx
    .byte 0xe8
main_hole:
    .long 0
    cmp eax,7
    jne .Laction
    mov rdi,r12
    mov rsi,r15
    mov rdx,r13
    mov rcx,rbp
    mov r8,r14
    mov r9,rbx
    .byte 0xe8
tasks_hole:
    .long 0
.Laction:
    test eax,eax
    jz .Ldone
    cmp eax,3
    je .Lloop
    cmp eax,2
    je .Lgrow
    cmp eax,5
    je .Lmove
    cmp eax,1
    je .Ltranslate
    cmp eax,4
    jne .Linternal
.Ltranslate:
    mov [rsp+80],rax
    mov r10,[r13+272]
    xor ecx,ecx
.Larguments:
    mov rax,[r13+280+rcx*8]
    mov r11,r10
    and r11d,3
    add rax,[rsp+r11*8]
    mov [rsp+32+rcx*8],rax
    shr r10,2
    inc ecx
    cmp ecx,6
    jb .Larguments
    mov rdi,[rsp+32]
    mov rsi,[rsp+40]
    mov rdx,[rsp+48]
    mov r8,[rsp+64]
    mov r9,[rsp+72]
    cmp qword ptr [rsp+80],1
    jne .Lrole
    mov r10,[rsp+56]
    mov rax,[r13+264]
    syscall
    jmp .Lfeedback
.Lrole:
    mov rcx,[rsp+56]
    mov rax,[r13+264]
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
    cmp rax,7
    je .Lrole7
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
    cmp rax,17
    je .Lrole17
    cmp rax,19
    je .Lrole19
    cmp rax,20
    je .Lrole20
    jmp .Linternal
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
.Lrole7:
    .byte 0xe8
role_7_hole:
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
.Lrole17:
    .byte 0xe8
role_17_hole:
    .long 0
    jmp .Lfeedback
.Lrole19:
    .byte 0xe8
role_19_hole:
    .long 0
    jmp .Lfeedback
.Lrole20:
    .byte 0xe8
role_20_hole:
    .long 0
    jmp .Lfeedback
.Lfeedback:
    mov [r13+8],rax
    jmp .Lloop
.Lgrow:
    mov rdi,r14
    mov rsi,rbx
    mov rdx,[r13+256]
    mov [rsp+88],rdx
    mov r10d,1
    xor r8d,r8d
    mov eax,25
    syscall
    cmp rax,-4095
    jae .Lgrow_failure
    mov r14,rax
    mov rbx,[rsp+88]
    mov [rsp+8],r14
    mov [r13+16],rbx
    mov [r13+40],r14
    jmp .Lloop
.Lgrow_failure:
    mov qword ptr [r13+112],1
    jmp .Lloop
.Lmove:
    mov rax,[r13+272]
    mov rcx,rax
    and eax,3
    shr rcx,2
    and ecx,3
    mov rdi,[r13+280]
    add rdi,[rsp+rax*8]
    mov rsi,[r13+288]
    add rsi,[rsp+rcx*8]
    mov rcx,[r13+296]
    mov [r13+8],rcx
    cmp rdi,rsi
    jbe .Lforward
    lea rax,[rsi+rcx]
    cmp rdi,rax
    jae .Lforward
    lea rdi,[rdi+rcx-1]
    lea rsi,[rsi+rcx-1]
    std
    rep movsb
    cld
    jmp .Lloop
.Lforward:
    cld
    rep movsb
    jmp .Lloop
.Lallocation:
    mov qword ptr [r13+4000],3
    jmp .Lerror_finish
.Linternal:
    mov qword ptr [r13+4000],4
.Lerror_finish:
    mov qword ptr [r13+4008],2
    mov qword ptr [r13+4024],0
.Ldone:
    xor eax,eax
    jmp .Lreturn
.Lbad_buffer:
    mov eax,0xfffffffd
.Lreturn:
    add rsp,136
    pop r15
    pop r14
    pop r13
    pop r12
    pop rbp
    pop rbx
    ret
.size hia_ndu_rank_engine,.-hia_ndu_rank_engine
.section .note.GNU-stack,"",@progbits
