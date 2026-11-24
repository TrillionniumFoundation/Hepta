/* Mechanical Linux ABI for the HIA cold master and archive owners.
 * HIA selects every syscall, argument, state transition and terminal result.
 * Buffer selectors only translate bounded HIA offsets to process addresses.
 * No shell, libc, dynamic loader or interpreter runs in this owner. */
.intel_syntax noprefix
.text
.global _start, policy_hole, sha_hole
.equ STATE_BYTES,4194304
.equ PLAN_BYTES,128
_start:
    cmp QWORD PTR [rsp],1
    jne invalid
    sub rsp,160
    mov eax,72
    xor edi,edi
    mov esi,1034
    syscall
    test rax,rax
    js invalid
    and eax,15
    cmp eax,15
    jne invalid
    mov eax,5
    xor edi,edi
    mov rsi,rsp
    syscall
    test rax,rax
    js invalid
    mov eax,[rsp+24]
    and eax,0xf000
    cmp eax,0x8000
    jne invalid
    mov r13,[rsp+48]
    cmp r13,128
    jb invalid
    cmp r13,1048576
    ja invalid
    mov eax,9
    xor edi,edi
    mov rsi,r13
    mov edx,1
    mov r10d,2
    xor r8d,r8d
    xor r9d,r9d
    syscall
    cmp rax,-4095
    jae invalid
    mov r12,rax
    mov eax,9
    xor edi,edi
    mov esi,STATE_BYTES+4096
    mov edx,3
    mov r10d,0x22
    mov r8,-1
    xor r9d,r9d
    syscall
    cmp rax,-4095
    jae invalid
    mov r15,rax
    lea r14,[rax+STATE_BYTES]
advance:
    mov rdi,r12
    mov rsi,r13
    mov rdx,r14
    mov ecx,PLAN_BYTES
    mov r8,r15
    mov r9d,STATE_BYTES
    .byte 0xe8
policy_hole: .long 0
action:
    cmp eax,1
    je syscall_action
    cmp eax,2
    je relocate_action
    cmp eax,3
    je sha_action
    cmp eax,4
    je advance
    jmp invalid
syscall_action:
    xor ebx,ebx
    mov rbp,[r14+56]
argument:
    mov rax,[r14+8+rbx*8]
    mov rcx,rbp
    and ecx,3
    shr rbp,2
    test ecx,ecx
    jz argument_ready
    cmp ecx,1
    jne plan_pointer
    cmp rax,r13
    jae invalid
    add rax,r12
    jmp argument_ready
plan_pointer:
    cmp ecx,2
    jne state_pointer
    cmp rax,PLAN_BYTES
    jae invalid
    add rax,r14
    jmp argument_ready
state_pointer:
    cmp rax,STATE_BYTES
    jae invalid
    add rax,r15
argument_ready:
    mov [rsp+rbx*8],rax
    inc ebx
    cmp ebx,6
    jb argument
    test rbp,rbp
    jne invalid
    mov rax,[r14]
    mov rdi,[rsp]
    mov rsi,[rsp+8]
    mov rdx,[rsp+16]
    mov r10,[rsp+24]
    mov r8,[rsp+32]
    mov r9,[rsp+40]
    syscall
    mov [r15+8],rax
    jmp advance
relocate_action:
    mov rbx,[r14]
    mov rbp,[r14+8]
    mov rdx,[r14+16]
    test rbp,rbp
    jz invalid
    cmp rbp,130
    ja invalid
    lea rax,[rbx+rbp*8]
    cmp rax,STATE_BYTES
    ja invalid
    lea rax,[rdx+rbp*8]
    cmp rax,STATE_BYTES
    ja invalid
    cmp rbx,STATE_BYTES
    jae invalid
    cmp rdx,STATE_BYTES
    jae invalid
relocate_word:
    mov rax,[r15+rbx]
    cmp rax,-1
    je null_word
    cmp rax,STATE_BYTES
    jae invalid
    add rax,r15
    jmp store_word
null_word:
    xor eax,eax
store_word:
    mov [r15+rdx],rax
    add rbx,8
    add rdx,8
    dec rbp
    jne relocate_word
    mov QWORD PTR [r15+8],0
    jmp advance
sha_action:
    mov rsi,[r14]
    cmp rsi,1
    jb invalid
    cmp rsi,65537
    ja invalid
    lea rdi,[r15+65536]
    lea rdx,[r15+4096]
    mov ecx,32
    lea r8,[r15+4160]
    mov r9d,1184
    .byte 0xe8
sha_hole: .long 0
    mov [r15+8],rax
    jmp advance
invalid:
    mov eax,60
    mov edi,65
    syscall
    ud2

