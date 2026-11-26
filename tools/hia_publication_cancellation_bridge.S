# Public cancellation lifecycle over fixed HIA handles and real Future token kernel.
# The source request carries only an operation and opaque registered capability.
# All policy and registry decisions are HIA; this prefix supplies fixed roles.
.intel_syntax noprefix
.text
.global hia_publication_cancellation
.type hia_publication_cancellation,@function
hia_publication_cancellation:
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
 # Reject null, undersized, wrapping and overlapping views before any write.
 test r12,r12
 jz .Lpublic_bad
 test r13,r13
 jz .Lpublic_bad
 test r14,r14
 jz .Lpublic_bad
 cmp r15,64
 jne .Lpublic_bad
 cmp rbp,100679680
 jb .Lpublic_bad
 cmp rbx,256
 jb .Lpublic_bad
 test r14b,7
 jnz .Lpublic_bad
 mov rax,r12
 add rax,r15
 jc .Lpublic_bad
 mov rdx,r13
 add rdx,rbp
 jc .Lpublic_bad
 mov rcx,r14
 add rcx,rbx
 jc .Lpublic_bad
 cmp rax,r13
 jbe .Lpublic_so_ok
 cmp rdx,r12
 ja .Lpublic_bad
.Lpublic_so_ok:
 cmp rax,r14
 jbe .Lpublic_sw_ok
 cmp rcx,r12
 ja .Lpublic_bad
.Lpublic_sw_ok:
 cmp rdx,r14
 jbe .Lpublic_ow_ok
 cmp rcx,r13
 ja .Lpublic_bad
.Lpublic_ow_ok:
 mov qword ptr [r13+256],0
.Lpublic_loop:
 mov rdi,r12
 mov rsi,r15
 mov rdx,r13
 mov rcx,rbp
 mov r8,r14
 mov r9,rbx
 .byte 0xe8
public_policy_hole:
 .long 0
 test eax,eax
 je .Lpublic_return
 cmp eax,10
 je .Lpublic_loop
 cmp eax,12
 jne .Lpublic_return
 lea rdi,[r13+4096]
 mov rsi,[r13]
 lea rdx,[r13+16384]
 mov ecx,100663296
 mov r8,r14
 mov r9,rbx
 call pc_handles_entry
 mov [r13+384],rax
 jmp .Lpublic_loop
.Lpublic_bad:
 mov eax,0xfffffffd
.Lpublic_return:
 add rsp,8
 pop r15
 pop r14
 pop r13
 pop r12
 pop rbp
 pop rbx
 ret
.size hia_publication_cancellation,.-hia_publication_cancellation

.type pc_effects_entry,@function
pc_effects_entry:
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
 cmp r15,256
 jne .Leffects_bad
 cmp rbp,8192
 jb .Leffects_bad
 cmp rbx,512
 jb .Leffects_bad
 mov qword ptr [r13+256],0
.Leffects_loop:
 mov rdi,r12
 mov rsi,r15
 mov rdx,r13
 mov rcx,rbp
 mov r8,r14
 mov r9,rbx
 .byte 0xe8
effects_policy_hole:
 .long 0
 cmp eax,12
 jne .Leffects_return
 lea rdi,[r13+2048]
 mov esi,64
 lea rdx,[r13+4096]
 mov ecx,512
 mov r8,r14
 mov r9,rbx
 call pc_kernel_entry
 mov [r13+384],rax
 jmp .Leffects_loop
.Leffects_bad:
 mov eax,0xfffffffd
.Leffects_return:
 add rsp,8
 pop r15
 pop r14
 pop r13
 pop r12
 pop rbp
 pop rbx
 ret
.size pc_effects_entry,.-pc_effects_entry

# Owned runtime and lease references. All lifecycle decisions are HIA.
.intel_syntax noprefix
.text
.type pc_handles_entry,@function
pc_handles_entry:
 push rbx
 push rbp
 push r12
 push r13
 push r14
 push r15
 sub rsp,152
 mov r12,rdi
 mov r15,rsi
 mov r13,rdx
 mov rbp,rcx
 mov r14,r8
 mov rbx,r9
 cmp rbp,100663296
 jb .Lhandles_bad
 cmp rbx,256
 jb .Lhandles_bad
 mov qword ptr [r13+128],0
 mov qword ptr [rsp],0
 mov [rsp+8],r14
 mov [rsp+16],r12
 mov [rsp+24],r13
.Lhandles_loop:
 mov rdi,r12
 mov rsi,r15
 mov rdx,r13
 mov rcx,rbp
 mov r8,r14
 mov r9,rbx
 .byte 0xe8
 handles_policy_hole:
 .long 0
 test eax,eax
 je .Lhandles_return
 cmp eax,10
 je .Lhandles_loop
 cmp eax,1
 je .Lhandles_syscall
 cmp eax,2
 je .Lhandles_cas
 cmp eax,3
 je .Lhandles_exchange
 cmp eax,4
 je .Lhandles_address
 cmp eax,6
 je .Lhandles_allocate
 cmp eax,7
 je .Lhandles_free
 cmp eax,8
 je .Lhandles_copy
 cmp eax,12
 jne .Lhandles_return
 xor ecx,ecx
.Lhandles_role_translate:
 mov rax,[r13+rcx*8]
 cmp rax,3
 ja .Lhandles_bad
 mov rdx,[r13+8+rcx*8]
 add rdx,[rsp+rax*8]
 mov [rsp+88+rcx*8],rdx
 add ecx,3
 cmp ecx,9
 jb .Lhandles_role_translate
 mov rdi,[rsp+88]
 mov rsi,[r13+16]
 mov rdx,[rsp+112]
 mov rcx,[r13+40]
 mov r8,[rsp+136]
 mov r9,[r13+64]
 call pc_effects_entry
 jmp .Lhandles_feedback
.Lhandles_syscall:
 mov r10,[r13+8]
 xor ecx,ecx
.Lhandles_translate:
 mov rax,[r13+16+rcx*8]
 mov r11,r10
 and r11d,3
 add rax,[rsp+r11*8]
 mov [rsp+32+rcx*8],rax
 shr r10,2
 inc ecx
 cmp ecx,6
 jb .Lhandles_translate
 mov rdi,[rsp+32]
 mov rsi,[rsp+40]
 mov rdx,[rsp+48]
 mov r10,[rsp+56]
 mov r8,[rsp+64]
 mov r9,[rsp+72]
 mov rax,[r13]
 syscall
 jmp .Lhandles_feedback
.Lhandles_cas:
 mov rdx,[r13]
 add rdx,r14
 mov eax,[r13+8]
 mov ecx,[r13+16]
 lock cmpxchg dword ptr [rdx],ecx
 jmp .Lhandles_feedback
.Lhandles_exchange:
 mov rdx,[r13]
 add rdx,r14
 mov eax,[r13+8]
 xchg dword ptr [rdx],eax
 jmp .Lhandles_feedback
.Lhandles_address:
 mov rax,[r13]
 add rax,r13
 jmp .Lhandles_feedback
.Lhandles_allocate:
 mov rdi,[r13]
 call public_malloc
 jmp .Lhandles_feedback
.Lhandles_free:
 mov rdi,[r13]
 call public_deallocate
 xor eax,eax
 jmp .Lhandles_feedback
.Lhandles_copy:
 mov rax,[r13]
 cmp rax,3
 ja .Lhandles_bad
 mov rsi,[r13+8]
 add rsi,[rsp+rax*8]
 mov rax,[r13+16]
 cmp rax,3
 ja .Lhandles_bad
 mov rdi,[r13+24]
 add rdi,[rsp+rax*8]
 mov rcx,[r13+32]
 cld
 rep movsb
 xor eax,eax
.Lhandles_feedback:
 mov [r13+376],rax
 jmp .Lhandles_loop
.Lhandles_bad:
 mov eax,0xfffffffd
.Lhandles_return:
 add rsp,152
 pop r15
 pop r14
 pop r13
 pop r12
 pop rbp
 pop rbx
 ret
.size pc_handles_entry,.-pc_handles_entry


# Fixed Future host facts: syscall, atomic lock word, native node allocation,
# fixed-size metadata copy, and the actual callback selected by the HIA owner.
.intel_syntax noprefix
.text
.type pc_kernel_entry,@function
pc_kernel_entry:
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
    cmp rbp,512
    jb .Lkernel_bad
    mov qword ptr [r13+64],0
    mov qword ptr [rsp],0
    mov [rsp+8],r14
    mov [rsp+16],r12
    mov [rsp+24],r13
.Lkernel_loop:
    mov rdi,r12
    mov rsi,r15
    mov rdx,r13
    mov rcx,rbp
    mov r8,r14
    mov r9,rbx
    .byte 0xe8
kernel_policy_hole:
    .long 0
    test eax,eax
    je .Lkernel_done
    cmp eax,10
    je .Lkernel_loop
    cmp eax,1
    je .Lkernel_syscall
    cmp eax,2
    je .Lkernel_cas
    cmp eax,3
    je .Lkernel_exchange
    cmp eax,4
    je .Lkernel_read_node
    cmp eax,5
    je .Lkernel_write_node
    cmp eax,6
    je .Lkernel_allocate
    cmp eax,7
    je .Lkernel_free
    cmp eax,8
    je .Lkernel_callback
    cmp eax,9
    je .Lkernel_drop
.Lkernel_bad:
    mov eax,0xfffffffd
    jmp .Lkernel_return
.Lkernel_syscall:
    mov r10,[r13+8]
    xor ecx,ecx
.Lkernel_translate:
    mov rax,[r13+16+rcx*8]
    mov r11,r10
    and r11d,3
    add rax,[rsp+r11*8]
    mov [rsp+32+rcx*8],rax
    shr r10,2
    inc ecx
    cmp ecx,6
    jb .Lkernel_translate
    mov rdi,[rsp+32]
    mov rsi,[rsp+40]
    mov rdx,[rsp+48]
    mov r10,[rsp+56]
    mov r8,[rsp+64]
    mov r9,[rsp+72]
    mov rax,[r13]
    syscall
    jmp .Lkernel_feedback
.Lkernel_cas:
    mov rdx,[r13]
    cmp rdx,128
    je .Lkernel_atomic_ok
    cmp rdx,132
    jne .Lkernel_bad
.Lkernel_atomic_ok:
    add rdx,r14
    mov eax,[r13+8]
    mov ecx,[r13+16]
    lock cmpxchg dword ptr [rdx],ecx
    jmp .Lkernel_feedback
.Lkernel_exchange:
    mov rdx,[r13]
    cmp rdx,128
    je .Lkernel_exchange_ok
    cmp rdx,132
    jne .Lkernel_bad
.Lkernel_exchange_ok:
    add rdx,r14
    mov eax,[r13+8]
    xchg dword ptr [rdx],eax
    jmp .Lkernel_feedback
.Lkernel_read_node:
    mov rsi,[r13]
    lea rdi,[r13+256]
    mov ecx,8
    cld
    rep movsq
    xor eax,eax
    jmp .Lkernel_feedback
.Lkernel_write_node:
    mov rdi,[r13]
    lea rsi,[r13+256]
    mov ecx,8
    cld
    rep movsq
    xor eax,eax
    jmp .Lkernel_feedback
.Lkernel_allocate:
    mov edi,64
    call public_malloc
    jmp .Lkernel_feedback
.Lkernel_free:
    mov rdi,[r13]
    call public_deallocate
    xor eax,eax
    jmp .Lkernel_feedback
.Lkernel_callback:
    mov r11,[r13]
    mov rdi,r14
    mov rsi,[r13+8]
    call r11
    jmp .Lkernel_feedback
.Lkernel_drop:
    mov r11,[r13]
    mov rdi,[r13+8]
    call r11
.Lkernel_feedback:
    mov [r13+448],rax
    jmp .Lkernel_loop
.Lkernel_done:
    mov eax,[r13+8]
.Lkernel_return:
    add rsp,136
    pop r15
    pop r14
    pop r13
    pop r12
    pop rbp
    pop rbx
    ret
.size pc_kernel_entry, .-pc_kernel_entry


# Closed allocation adapter copied from the qualified public Future role.

# SysV malloc(size)->pointer or NULL, free(owned_pointer)->void.
# No caller-selected callbacks, libc imports or fixed aggregate byte quota.
# Only pointers minted here and retained by the HIA registry may reach free.
.intel_syntax noprefix
.text

.type public_malloc,@function
public_malloc:
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
.size public_malloc,.-public_malloc


.type public_deallocate,@function
public_deallocate:
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
.size public_deallocate,.-public_deallocate



.section .note.GNU-stack,"",@progbits
