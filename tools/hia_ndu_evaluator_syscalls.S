/* Linux x86-64 transport adapter. HIA owns argv, frames, budgets and decisions. */
.intel_syntax noprefix
.text
.global _start, transport_call, evaluator_call
.equ STATE_BYTES,50331648
.equ INPUT_AT,1048576
.equ INPUT_END,9437184
_start:
    mov r12,rsp
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
    sub rsp,64
    mov rax,[r12]
    test rax,rax
    jz invalid
    dec rax
    mov [r15+16],rax
    xor ebx,ebx
    mov ebp,INPUT_AT
argv_next:
    cmp rbx,[r15+16]
    jae argv_done
    mov rsi,[r12+16+rbx*8]
    xor ecx,ecx
argv_scan:
    lea rax,[rbp+rcx+8]
    cmp rax,INPUT_END
    jae invalid
    cmp BYTE PTR [rsi+rcx],0
    je argv_copy
    inc rcx
    jmp argv_scan
argv_copy:
    mov [r15+rbp],rcx
    lea rdi,[r15+rbp+8]
    lea rbp,[rbp+rcx+8]
    cld
    rep movsb
    inc rbx
    jmp argv_next
argv_done:
    sub rbp,INPUT_AT
    mov [r15+24],rbp
advance:
    lea rdi,[r15+INPUT_AT]
    xor esi,esi
    mov rdx,r14
    mov ecx,128
    mov r8,r15
    mov r9d,STATE_BYTES
    .byte 0xe8
transport_call: .long 0
    cmp eax,1
    je syscall_action
    cmp eax,2
    je evaluate_action
    cmp eax,4
    je advance
    jmp invalid
syscall_action:
    xor ebx,ebx
    mov rbp,[r14+56]
sysarg:
    mov rax,[r14+8+rbx*8]
    mov rcx,rbp
    and ecx,3
    shr rbp,2
    test ecx,ecx
    jz arg_ready
    cmp ecx,3
    jne invalid
    cmp rax,STATE_BYTES
    jae invalid
    add rax,r15
arg_ready:
    mov [rsp+rbx*8],rax
    inc ebx
    cmp ebx,6
    jb sysarg
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
evaluate_action:
    xor ebx,ebx
check_view:
    mov rax,[r14+rbx]
    cmp rax,STATE_BYTES
    ja invalid
    mov rcx,STATE_BYTES
    sub rcx,rax
    cmp [r14+rbx+8],rcx
    ja invalid
    add ebx,16
    cmp ebx,48
    jb check_view
    mov rdi,[r14]
    add rdi,r15
    mov rsi,[r14+8]
    mov rdx,[r14+16]
    add rdx,r15
    mov rcx,[r14+24]
    mov r8,[r14+32]
    add r8,r15
    mov r9,[r14+40]
    .byte 0xe8
evaluator_call: .long 0
    mov [r15+8],rax
    jmp advance
invalid:
    mov eax,60
    mov edi,65
    syscall
    ud2
.section .note.GNU-stack,"",@progbits
