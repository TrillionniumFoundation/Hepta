# Fixed six-word calls and view movement only. HIA owns all Job decisions.
.intel_syntax noprefix
.text
.global hia_background_job_refs_managed
.type hia_background_job_refs_managed,@function
hia_background_job_refs_managed:
    push rbx
    push rbp
    push r12
    push r13
    push r14
    push r15
    sub rsp,4248
    mov r12,rdi
    mov r15,rsi
    mov [rsp+80],rdx
    mov rbp,rcx
    mov r14,r8
    mov rbx,r9
    cmp r15,64
    jne .Lbad
    cmp rbp,128
    jb .Lbad
    cmp rbx,64
    jb .Lbad
    test r12,r12
    je .Lbad
    test rdx,rdx
    je .Lbad
    test r14,r14
    je .Lbad
    mov rax,r12
    add rax,r15
    jc .Lbad
    mov [rsp+96],rax
    mov rax,rdx
    add rax,rbp
    jc .Lbad
    mov [rsp+104],rax
    mov rax,r14
    add rax,rbx
    jc .Lbad
    mov [rsp+112],rax
    cmp r14,[rsp+104]
    jae .Lcheck_source
    cmp rax,rdx
    ja .Lbad
.Lcheck_source:
    cmp r12,[rsp+104]
    jae .Lsource_work
    cmp [rsp+96],rdx
    ja .Lbad
.Lsource_work:
    cmp r12,[rsp+112]
    jae .Lready
    cmp [rsp+96],r14
    ja .Lbad
.Lready:
    lea r13,[rsp+128]
    mov qword ptr [r13+128],0
    mov qword ptr [rsp],0
    mov [rsp+8],r14
    mov [rsp+16],r12
    mov [rsp+24],r13
.Lloop:
    mov rdi,r12
    mov rsi,r15
    mov rdx,r13
    mov ecx,4096
    mov r8,r14
    mov r9,rbx
    .byte 0xe8
policy_hole:
    .long 0
    test eax,eax
    je .Lcopy
    cmp eax,10
    je .Lloop
    cmp eax,4
    jne .Lbad
    mov r10,[r13+8]
    xor ecx,ecx
.Largs:
    mov rax,[r13+16+rcx*8]
    mov r11,r10
    and r11d,3
    add rax,[rsp+r11*8]
    mov [rsp+32+rcx*8],rax
    shr r10,2
    inc ecx
    cmp ecx,6
    jb .Largs
    mov rdi,[rsp+32]
    mov rsi,[rsp+40]
    mov rdx,[rsp+48]
    mov rcx,[rsp+56]
    mov r8,[rsp+64]
    mov r9,[rsp+72]
    mov r11,[r13]
    call r11
    mov eax,eax
    mov [r13+136],rax
    jmp .Lloop
.Lcopy:
    mov rsi,r13
    mov rdi,[rsp+80]
    mov ecx,128
    cld
    rep movsb
    xor eax,eax
    jmp .Lreturn
.Lbad:
    mov eax,0xfffffffd
.Lreturn:
    add rsp,4248
    pop r15
    pop r14
    pop r13
    pop r12
    pop rbp
    pop rbx
    ret
.size hia_background_job_refs_managed,.-hia_background_job_refs_managed
.section .note.GNU-stack,"",@progbits
