# Fixed six-word dispatch, atomics, syscalls and byte transport.
# Callback selection and lifetime are decided by the HIA policies.
.intel_syntax noprefix
.text
.global hia_background_optimizer_future_public
.type hia_background_optimizer_future_public,@function
hia_background_optimizer_future_public:
public_owner_entry:
    lea r10,[rip+policy_owner]
    mov r11d,65536
    jmp public_generic
public_carrier_entry:
    lea r10,[rip+policy_carrier]
    mov r11d,32768
    jmp public_generic
public_timeout_entry:
    lea r10,[rip+policy_timeout]
    mov r11d,16384
    jmp public_generic
public_log_entry:
    lea r10,[rip+policy_log]
    mov r11d,16384
    jmp public_generic
public_log_small_entry:
    lea r10,[rip+policy_log]
    mov r11d,4096
public_generic:
    push rbx
    push rbp
    push r12
    push r13
    push r14
    push r15
    sub rsp,168
    mov r12,rdi
    mov r15,rsi
    mov r13,rdx
    mov rbp,rcx
    mov r14,r8
    mov rbx,r9
    mov [rsp+120],r10
    cmp rbp,r11
    jb public_bad
    cmp rbx,256
    jb public_bad
    test r13,r13
    je public_bad
    test r14,r14
    je public_bad
    mov rax,r13
    add rax,rbp
    jc public_bad
    mov [rsp+88],rax
    mov rax,r14
    add rax,rbx
    jc public_bad
    mov [rsp+96],rax
    cmp r14,[rsp+88]
    jae public_ow_ok
    cmp rax,r13
    ja public_bad
public_ow_ok:
    mov rax,r12
    add rax,r15
    jc public_bad
    test r15,r15
    je public_views_ok
    test r12,r12
    je public_bad
    cmp r12,[rsp+88]
    jae public_so_ok
    cmp rax,r13
    ja public_bad
public_so_ok:
    cmp r12,[rsp+96]
    jae public_views_ok
    cmp rax,r14
    ja public_bad
public_views_ok:
    lea rax,[rip+kernel_entry]
    mov [r14+64],rax
    lea rax,[rip+fixed_value]
    mov [r14+72],rax
    lea rax,[rip+cell_entry]
    mov [r14+80],rax
    lea rax,[rip+public_owner_entry]
    mov [r14+88],rax
    lea rax,[rip+public_callback]
    mov [r14+96],rax
    lea rax,[rip+public_callback_drop]
    mov [r14+104],rax
    lea rax,[rip+public_carrier_entry]
    mov [r14+152],rax
    lea rax,[rip+public_notify]
    mov [r14+160],rax
    lea rax,[rip+public_timeout_entry]
    mov [r14+168],rax
    lea rax,[rip+public_log_entry]
    mov [r14+176],rax
    lea rax,[rip+fixed_notify]
    mov [r14+184],rax
    lea rax,[rip+public_log_small_entry]
    mov [r14+192],rax
    mov qword ptr [r13+128],0
    mov qword ptr [rsp],0
    mov [rsp+8],r14
    mov [rsp+16],r12
    mov [rsp+24],r13
public_loop:
    mov rdi,r12
    mov rsi,r15
    mov rdx,r13
    mov rcx,rbp
    mov r8,r14
    mov r9,rbx
    call [rsp+120]
    test eax,eax
    je public_return
    cmp eax,10
    je public_loop
    cmp eax,1
    je public_syscall
    cmp eax,2
    je public_cas
    cmp eax,3
    je public_exchange
    cmp eax,4
    je public_address
    cmp eax,5
    je public_waddress
    cmp eax,6
    je public_allocate
    cmp eax,7
    je public_free
    cmp eax,8
    je public_copy
    cmp eax,9
    je public_provider
public_bad:
    mov eax,0xfffffffd
    jmp public_return
public_syscall:
    mov qword ptr [rsp+128],0
    jmp public_translate_begin
public_provider:
    mov qword ptr [rsp+128],1
public_translate_begin:
    mov r10,[r13+8]
    xor ecx,ecx
public_translate:
    mov rax,[r13+16+rcx*8]
    mov r11,r10
    and r11d,3
    add rax,[rsp+r11*8]
    mov [rsp+32+rcx*8],rax
    shr r10,2
    inc ecx
    cmp ecx,6
    jb public_translate
    mov rdi,[rsp+32]
    mov rsi,[rsp+40]
    mov rdx,[rsp+48]
    mov r10,[rsp+56]
    mov r8,[rsp+64]
    mov r9,[rsp+72]
    cmp qword ptr [rsp+128],0
    jne public_invoke
    mov rax,[r13]
    syscall
    jmp public_feedback
public_invoke:
    mov rcx,r10
    mov r11,[r13]
    call r11
    mov eax,eax
    jmp public_feedback
public_cas:
    mov rdx,[r13]
    cmp rdx,32
    je public_cas_ok
    cmp rdx,44
    jne public_bad
public_cas_ok:
    add rdx,r14
    mov eax,[r13+8]
    mov ecx,[r13+16]
    lock cmpxchg dword ptr [rdx],ecx
    jmp public_feedback
public_exchange:
    mov rdx,[r13]
    cmp rdx,32
    je public_exchange_ok
    cmp rdx,44
    jne public_bad
public_exchange_ok:
    add rdx,r14
    mov eax,[r13+8]
    xchg dword ptr [rdx],eax
    jmp public_feedback
public_address:
    mov rax,[r13]
    cmp rax,rbp
    jae public_bad
    add rax,r13
    jmp public_feedback
public_waddress:
    mov rax,[r13]
    cmp rax,rbx
    jae public_bad
    add rax,r14
    jmp public_feedback
public_allocate:
    mov rdi,[r13]
    call public_malloc
    jmp public_feedback
public_free:
    mov rdi,[r13]
    call public_deallocate
    xor eax,eax
    jmp public_feedback
public_copy:
    mov rax,[r13]
    cmp rax,3
    ja public_bad
    mov rsi,[r13+8]
    add rsi,[rsp+rax*8]
    mov rax,[r13+16]
    cmp rax,3
    ja public_bad
    mov rdi,[r13+24]
    add rdi,[rsp+rax*8]
    mov rcx,[r13+32]
    cld
    rep movsb
    xor eax,eax
public_feedback:
    mov [r13+448],rax
    jmp public_loop
public_return:
    add rsp,168
    pop r15
    pop r14
    pop r13
    pop r12
    pop rbp
    pop rbx
    ret

# Two-word callable ABI to fixed native typed-carrier entry.
public_callback:
    push rbx
    mov rbx,rsi
    mov rax,rdi
    lea rdi,[rbx+512]
    xor edx,edx
    mov ecx,24
public_callback_zero:
    mov [rdi],rdx
    add rdi,8
    dec ecx
    jne public_callback_zero
    mov rdx,0x3130434650414948
    mov [rbx+512],rdx
    mov qword ptr [rbx+520],1
    mov [rbx+528],rbx
    mov [rbx+536],rax
    lea rdi,[rbx+512]
    mov esi,192
    lea rdx,[rbx+1024]
    mov ecx,32768
    mov r8,[rbx+184]
    mov r9d,256
    call public_carrier_entry
    test eax,eax
    jne public_callback_bad
    mov eax,[rbx+1048]
    pop rbx
    ret
public_callback_bad:
    mov eax,2
    pop rbx
    ret

public_callback_drop:
    push rbx
    mov rbx,rdi
    lea rdi,[rbx+512]
    xor eax,eax
    mov ecx,24
    cld
    rep stosq
    mov rax,0x3130434650414948
    mov [rbx+512],rax
    mov qword ptr [rbx+520],2
    mov [rbx+528],rbx
    lea rdi,[rbx+512]
    mov esi,192
    lea rdx,[rbx+1024]
    mov ecx,32768
    mov r8,[rbx+184]
    mov r9d,256
    call public_carrier_entry
    test eax,eax
    jne public_drop_return
    cmp [rbx+1088],rbx
    jne public_drop_return
    mov rdi,rbx
    call public_deallocate
public_drop_return:
    xor eax,eax
    pop rbx
    ret

# Fixed 2Q callback adapter to the HIA observer notification owner.
public_notify:
    push rbx
    sub rsp,8256
    mov rbx,rsi
    mov r10,rdi
    mov rdi,rsp
    xor eax,eax
    mov ecx,8
    cld
    rep stosq
    mov rax,0x32304e4642414948
    mov [rsp],rax
    mov [rsp+8],r10
    mov rdi,rsp
    mov esi,64
    lea rdx,[rsp+64]
    mov ecx,8192
    mov r8,rbx
    mov r9d,256
    call fixed_notify
    test eax,eax
    jne public_notify_bad
    cmp qword ptr [rsp+72],0
    jne public_notify_bad
    mov rax,[rsp+96]
    jmp public_notify_return
public_notify_bad:
    mov eax,2
public_notify_return:
    add rsp,8256
    pop rbx
    ret

# Only actual syscall, futex-word atomics, malloc/free, byte copying and fixed
# six-word calls. Decimal arithmetic and ownership transitions are HIA policy.
.intel_syntax noprefix
.text

.type cell_entry,@function
cell_entry:
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
    cmp rbp,16384
    jb .Lcell_bad
    cmp rbx,256
    jb .Lcell_bad
    mov qword ptr [r13+128],0
    mov qword ptr [rsp],0
    mov [rsp+8],r14
    mov [rsp+16],r12
    mov [rsp+24],r13
.Lcell_loop:
    mov rdi,r12
    mov rsi,r15
    mov rdx,r13
    mov rcx,rbp
    mov r8,r14
    mov r9,rbx
    .byte 0xe8
cell_policy_hole:
    .long 0
    test eax,eax
    je .Lcell_return
    cmp eax,10
    je .Lcell_loop
    cmp eax,1
    je .Lcell_syscall
    cmp eax,2
    je .Lcell_cas
    cmp eax,3
    je .Lcell_exchange
    cmp eax,4
    je .Lcell_address
    cmp eax,6
    je .Lcell_allocate
    cmp eax,7
    je .Lcell_free
    cmp eax,8
    je .Lcell_copy
    cmp eax,9
    je .Lcell_provider
.Lcell_bad:
    mov eax,0xfffffffd
    jmp .Lcell_return
.Lcell_syscall:
    mov qword ptr [rsp+120],0
    jmp .Lcell_translate_begin
.Lcell_provider:
    mov qword ptr [rsp+120],1
.Lcell_translate_begin:
    mov r10,[r13+8]
    xor ecx,ecx
.Lcell_translate:
    mov rax,[r13+16+rcx*8]
    mov r11,r10
    and r11d,3
    add rax,[rsp+r11*8]
    mov [rsp+32+rcx*8],rax
    shr r10,2
    inc ecx
    cmp ecx,6
    jb .Lcell_translate
    mov rdi,[rsp+32]
    mov rsi,[rsp+40]
    mov rdx,[rsp+48]
    mov r10,[rsp+56]
    mov r8,[rsp+64]
    mov r9,[rsp+72]
    cmp qword ptr [rsp+120],0
    jne .Lcell_invoke
    mov rax,[r13]
    syscall
    jmp .Lcell_feedback
.Lcell_invoke:
    mov rcx,r10
    mov r11,[r13]
    call r11
    mov eax,eax
    jmp .Lcell_feedback
.Lcell_cas:
    cmp qword ptr [r13],32
    jne .Lcell_bad
    lea rdx,[r14+32]
    mov eax,[r13+8]
    mov ecx,[r13+16]
    lock cmpxchg dword ptr [rdx],ecx
    jmp .Lcell_feedback
.Lcell_exchange:
    cmp qword ptr [r13],32
    jne .Lcell_bad
    lea rdx,[r14+32]
    mov eax,[r13+8]
    xchg dword ptr [rdx],eax
    jmp .Lcell_feedback
.Lcell_address:
    mov rax,[r13]
    cmp rax,rbp
    jae .Lcell_bad
    add rax,r13
    jmp .Lcell_feedback
.Lcell_allocate:
    mov rdi,[r13]
    call public_malloc
    jmp .Lcell_feedback
.Lcell_free:
    mov rdi,[r13]
    call public_deallocate
    xor eax,eax
    jmp .Lcell_feedback
.Lcell_copy:
    mov rax,[r13]
    cmp rax,3
    ja .Lcell_bad
    mov rsi,[r13+8]
    add rsi,[rsp+rax*8]
    mov rax,[r13+16]
    cmp rax,3
    ja .Lcell_bad
    mov rdi,[r13+24]
    add rdi,[rsp+rax*8]
    mov rcx,[r13+32]
    cld
    rep movsb
    xor eax,eax
    jmp .Lcell_feedback
.Lcell_feedback:
    mov [r13+448],rax
    jmp .Lcell_loop
.Lcell_return:
    add rsp,136
    pop r15
    pop r14
    pop r13
    pop r12
    pop rbp
    pop rbx
    ret
.size cell_entry,.-cell_entry


# Fixed Future host facts: syscall, atomic lock word, native node allocation,
# fixed-size metadata copy, and the actual callback selected by the HIA owner.
.intel_syntax noprefix
.text

.type kernel_entry,@function
kernel_entry:
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
.size kernel_entry, .-kernel_entry


# Closed allocation adapter for native rank ownership.
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


.size hia_background_optimizer_future_public,.-hia_background_optimizer_future_public
.section .note.GNU-stack,"",@progbits
