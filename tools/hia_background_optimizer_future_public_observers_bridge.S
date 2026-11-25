# Native Future observer owner policy effects only.
# Only fixed native allocation, invocation, syscalls, atomics and byte transport.
.intel_syntax noprefix
.text
.global hia_background_optimizer_future_public_observers
.type hia_background_optimizer_future_public_observers,@function
hia_background_optimizer_future_public_observers:
    push rbx
    push rbp
    push r12
    push r13
    push r14
    push r15
    sub rsp,88
    mov r12,rdi
    mov r15,rsi
    mov r13,rdx
    mov rbp,rcx
    mov r14,r8
    mov rbx,r9
    cmp rbp,131072
    jb .Lbad
    cmp rbx,256
    jb .Lbad
    test r13,r13
    je .Lbad
    test r14,r14
    je .Lbad
    mov rax,r13
    add rax,rbp
    jc .Lbad
    mov r10,r14
    add r10,rbx
    jc .Lbad
    cmp r14,rax
    jae .Lowok
    cmp r10,r13
    ja .Lbad
.Lowok:
    mov r11,r12
    add r11,r15
    jc .Lbad
    test r15,r15
    je .Lviews
    test r12,r12
    je .Lbad
    cmp r12,rax
    jae .Lsook
    cmp r11,r13
    ja .Lbad
.Lsook:
    cmp r12,r10
    jae .Lviews
    cmp r11,r14
    ja .Lbad
.Lviews:
    mov qword ptr [r13+128],0
    mov qword ptr [r13+448],0
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
main_policy_hole:
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
    cmp eax,5
    je .Lwaddress
    cmp eax,8
    je .Lcopy
    cmp eax,6
    je .Lallocate
    cmp eax,7
    je .Lfree
    cmp eax,9
    je .Lprovider
    cmp eax,11
    je .Lmath
.Lbad:
    mov eax,0xfffffffd
    jmp .Lreturn
.Lmath:
    lea rdi,[r13+74496]
    mov rsi,[r13]
    lea rdx,[r13+75008]
    mov ecx,128
    lea r8,[r13+75264]
    mov r9d,512
    .byte 0xe8
math_policy_hole:
    .long 0
    jmp .Lfeedback
.Lallocate:
    mov rdi,[r13]
    call observer_malloc
    jmp .Lfeedback
.Lfree:
    mov rdi,[r13]
    call observer_deallocate
    xor eax,eax
    jmp .Lfeedback
.Lprovider:
    mov qword ptr [rsp+80],1
    jmp .Ltranslate_start
.Lsyscall:
    mov qword ptr [rsp+80],0
.Ltranslate_start:
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
    cmp qword ptr [rsp+80],0
    jne .Linvoke
    mov rax,[r13]
    syscall
    jmp .Lfeedback
.Linvoke:
    mov rcx,r10
    mov r11,[r13]
    call r11
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
.Lwaddress:
    mov rax,[r13]
    cmp rax,rbx
    jae .Lbad
    add rax,r14
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
    cmp rdi,rsi
    jbe .Lforward
    mov rax,rdi
    sub rax,rsi
    cmp rax,rcx
    jae .Lforward
    test rcx,rcx
    je .Lcopy_done
    lea rsi,[rsi+rcx-1]
    lea rdi,[rdi+rcx-1]
    std
    rep movsb
    cld
    jmp .Lcopy_done
.Lforward:
    cld
    rep movsb
.Lcopy_done:
    xor eax,eax
.Lfeedback:
    mov [r13+448],rax
    jmp .Lloop
.Lreturn:
    add rsp,88
    pop r15
    pop r14
    pop r13
    pop r12
    pop rbp
    pop rbx
    ret
.size hia_background_optimizer_future_public_observers,.-hia_background_optimizer_future_public_observers
.type observer_malloc,@function
observer_malloc:
    push rbx
    mov rbx,rdi
    mov rsi,rdi
    add rsi,32
    jc .La_alloc_fail
    xor edi,edi
    mov edx,3
    mov r10d,34
    mov r8,-1
    xor r9d,r9d
    mov eax,9
    syscall
    cmp rax,-4095
    jae .La_alloc_fail
    mov r10,0x314c414b4e414948
    mov [rax],r10
    lea rcx,[rbx+32]
    mov [rax+8],rcx
    mov [rax+16],rbx
    not rbx
    mov [rax+24],rbx
    add rax,32
    pop rbx
    ret
.La_alloc_fail:
    xor eax,eax
    pop rbx
    ret
.size observer_malloc,.-observer_malloc


.type observer_deallocate,@function
observer_deallocate:
    test rdi,rdi
    je .La_free_done
    test dil,15
    jne .La_invalid
    cmp rdi,32
    jb .La_invalid
    sub rdi,32
    mov rax,0x314c414b4e414948
    cmp [rdi],rax
    jne .La_invalid
    mov rsi,[rdi+8]
    mov rdx,[rdi+16]
    mov rcx,rdx
    not rcx
    cmp [rdi+24],rcx
    jne .La_invalid
    add rdx,32
    jc .La_invalid
    cmp rdx,rsi
    jne .La_invalid
    mov eax,11
    syscall
    test rax,rax
    jne .La_invalid
.La_free_done:
    ret
.La_invalid:
    ud2
.size observer_deallocate,.-observer_deallocate
policy_body:
.section .note.GNU-stack,"",@progbits
