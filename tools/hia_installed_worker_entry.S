/* Linux x86-64 syscall boundary. The HIA entry validates the administrator's
 * argument vector against the immutable installation and identifies the state
 * path. Forward stdin and environment unchanged to the embedded cold launcher. */
.intel_syntax noprefix
.text
.global _start
.global worker_entry_call_hole
_start:
    mov r12,rsp
    mov rax,[r12]
    cmp rax,100
    ja failed
    cmp rax,2
    jb failed
    sub rsp,300000
    and rsp,-16
    mov r15,rsp
    lea rdi,[rsp+512]
    mov r10,rdi
    lea rsi,[r12+16]
    lea r11,[rdi+262144]
next_arg:
    mov r8,[rsi]
    add rsi,8
    test r8,r8
    jz got_args
copy_arg:
    cmp rdi,r11
    jae failed
    mov al,[r8]
    mov [rdi],al
    inc rdi
    inc r8
    test al,al
    jnz copy_arg
    jmp next_arg
got_args:
    sub rdi,r10
    mov [r15+32],rdi
    /* Final config-length word and all literals are part of this ELF's
       read-only LOAD, emitted by the same HIA packer as its code. */
    mov ebx,0x400000
    add rbx,[rbx+96]
    mov r14,[rbx-8]
    cmp r14,104
    jb failed
    cmp r14,1048576
    ja failed
    sub rbx,8
    sub rbx,r14
    /* Read the running file's own directory, never cwd or argv[0]. */
    lea rdi,[rip+self_exe]
    lea rsi,[r15+285000]
    mov edx,4096
    mov eax,89
    syscall
    cmp rax,0
    jle failed
    cmp rax,4096
    jae failed
    mov rcx,rax
parent_component:
    test rcx,rcx
    jz failed
    dec rcx
    cmp byte ptr [r15+285000+rcx],47
    jne parent_component
    inc rcx
    mov [r15+16],rcx
    lea rdi,[r15+270000]
    mov esi,16
    call resolve_installed_path
    lea rdi,[r15+274096]
    mov esi,32
    call resolve_installed_path
    lea rdi,[r15+278192]
    mov esi,40
    call resolve_installed_path
    lea rdi,[r15+512]
    add rdi,[r15+32]
    lea rsi,[r15+270000]
copy_profile_argument:
    lodsb
    stosb
    test al,al
    jne copy_profile_argument
    mov rax,[r15+32]
    stosq
    mov rsi,rdi
    lea rdi,[r15+512]
    sub rsi,rdi
    mov rdx,r15
    mov ecx,8
    mov r8,rbx
    mov r9,r14
    .byte 0xe8
worker_entry_call_hole:
    .long 0
    test eax,eax
    jz failed
    mov r13d,eax
    /* Check the exact installed profile before observing a request. */
    lea rsi,[r15+270000]
    mov edi,-100
    mov edx,0xa0800       /* O_CLOEXEC | O_NOFOLLOW | O_NONBLOCK */
    mov eax,257
    syscall
    test eax,eax
    js failed
    mov ebp,eax
    mov edi,ebp
    lea rsi,[r15+128]
    mov eax,5
    syscall
    test eax,eax
    js failed
    cmp qword ptr [r15+144],1
    jne failed
    mov eax,[r15+152]
    mov ecx,eax
    and eax,0xf000
    cmp eax,0x8000
    jne failed
    test ecx,0x12         /* group/other write */
    jnz failed
    mov eax,107           /* geteuid */
    syscall
    cmp dword ptr [r15+156],0
    je owner_ok
    cmp [r15+156],eax
    jne failed
owner_ok:
    mov r14,[rbx+24]
    lea r14,[rbx+r14]
    mov r8,[r14]
    cmp [r15+176],r8
    jne failed
    add r14,8
    mov r9,r8
read_profile:
    test r9,r9
    jz verified
    mov rdx,r9
    cmp rdx,256
    jbe bounded
    mov edx,256
bounded:
    lea rsi,[r15+256]
    mov edi,ebp
    xor eax,eax
    syscall
    cmp eax,-4
    je read_profile
    test eax,eax
    jle failed
    sub r9,rax
    mov rcx,rax
    mov rdi,r14
    repe cmpsb
    jne failed
    mov r14,rdi
    jmp read_profile
verified:
    mov edi,ebp
    lea rsi,[r15+256]
    mov edx,1
    xor eax,eax
    syscall
    cmp eax,-4
    je verified
    test eax,eax
    jne failed
    mov edi,ebp
    mov eax,3
    syscall
    cmp r13d,2
    jne launch
    mov rsi,[rbx+56]
    lea rsi,[rbx+rsi]
    mov rdx,[rsi]
    add rsi,8
    mov edi,1
    call write_all
    xor edi,edi
    jmp exit_now
launch:
    /* memfd is populated exclusively from the install-time checked ELF. */
    lea rdi,[rip+child_label]
    mov esi,3
    mov eax,319
    syscall
    test eax,eax
    js failed
    mov ebp,eax
    mov rsi,[rbx+48]
    lea rsi,[rbx+rsi]
    mov rdx,[rsi]
    add rsi,8
    mov edi,ebp
    call write_all
    mov edi,ebp
    mov esi,1033
    mov edx,15
    mov eax,72
    syscall
    test eax,eax
    js failed
    lea rax,[rip+child_label]
    mov [r15+64],rax
    mov rax,[r15]
    lea rax,[r15+rax+512]
    mov [r15+72],rax
    lea rax,[r15+274096]
    mov [r15+80],rax
    lea rax,[r15+278192]
    mov [r15+88],rax
    mov rax,[rbx+40]
    lea rax,[rbx+rax+8]
    /* Capsule file and digest are adjacent NUL-terminated strings. */
find_pin:
    cmp byte ptr [rax],0
    lea rax,[rax+1]
    jne find_pin
    mov [r15+96],rax
    mov qword ptr [r15+104],0
    mov rax,[r12]
    lea r10,[r12+rax*8+16]
    lea rdx,[r15+64]
    lea rsi,[rip+empty]
    mov edi,ebp
    mov r8d,4096
    mov eax,322
    syscall
failed:
    mov edi,2
exit_now:
    mov eax,60
    syscall
/* A relative record is inside the install root. The optional absolute form
   is also accepted by the scope binder for independent, already-pinned paths. */
resolve_installed_path:
    mov rsi,[rbx+rsi]
    lea rcx,[rsi+8]
    cmp rcx,r14
    ja failed
    mov r8,[rbx+rsi]
    add rcx,r8
    cmp rcx,r14
    ja failed
    lea rdx,[rbx+rsi+8]
    mov r10,rdi
    cmp byte ptr [rdx],47
    je path_suffix
    lea rsi,[r15+285000]
    mov rcx,[r15+16]
    rep movsb
path_suffix:
    mov rsi,rdx
copy_path:
    test r8,r8
    jz failed
    dec r8
    mov rcx,rdi
    sub rcx,r10
    cmp rcx,4095
    ja failed
    lodsb
    stosb
    test al,al
    jne copy_path
    ret

write_all:
    test rdx,rdx
    jz written
    mov eax,1
    syscall
    cmp eax,-4
    je write_all
    test rax,rax
    jle failed
    add rsi,rax
    sub rdx,rax
    jmp write_all
written:
    ret
child_label: .asciz "hia-agent-evaluate-full-launcher"
self_exe: .asciz "/proc/self/exe"
empty: .byte 0
