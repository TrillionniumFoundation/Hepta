/* Mechanical Linux argv/syscall transport for the native HIA Worker installation CLI.
 * Policy decisions, path admission, pin checks, capture, request construction
 * and execution selection remain in worker_install_entry.hepta. */
.intel_syntax noprefix
.text
.global _start, policy_hole, sha_hole, entry_pins, entry_metadata
.equ STATE_BYTES,8388608
.equ PLAN_BYTES,67108864
.equ INPUT_BYTES,67108864
_start:
    mov rbp,rsp
    cmp QWORD PTR [rbp],1
    jb invalid
    cmp QWORD PTR [rbp],82
    ja invalid
    mov eax,9
    xor edi,edi
    mov esi,STATE_BYTES+PLAN_BYTES+INPUT_BYTES
    mov edx,3
    mov r10d,0x22
    mov r8,-1
    xor r9d,r9d
    syscall
    cmp rax,-4095
    jae invalid
    mov r15,rax
    lea r14,[rax+STATE_BYTES]
    lea r12,[r14+PLAN_BYTES]
    mov r13d,INPUT_BYTES
    movabs rax,0x3130475241414948
    mov [r12],rax
    mov rax,[rbp]
    mov [r12+8],rax
    lea rsi,[rip+.Lentry_pins]
    lea rdi,[r12+16]
    mov ecx,16
    rep movsq
    mov ebx,144
    xor r9d,r9d
argv_next:
    cmp r9,[rbp]
    jae argv_done
    mov rdx,[rbp+8+r9*8]
    xor r10d,r10d
argv_byte:
    cmp r10,8192
    ja invalid
    lea rax,[rbx+r10+8]
    cmp rax,262144
    jae invalid
    mov cl,[rdx+r10]
    mov [r12+rax],cl
    test cl,cl
    jz argv_end
    inc r10
    jmp argv_byte
argv_end:
    mov [r12+rbx],r10
    lea rbx,[rbx+r10+9]
    inc r9
    jmp argv_next
argv_done:
    sub rsp,160
advance:
    mov rdi,r12
    mov rsi,r13
    mov rdx,r14
    mov ecx,PLAN_BYTES
    mov r8,r15
    mov r9d,STATE_BYTES
    .byte 0xe8
policy_hole: .long 0
    cmp eax,1
    je syscall_action
    cmp eax,2
    je relocate_action
    cmp eax,3
    je sha_action
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

.balign 8
entry_pins:
.Lentry_pins: .zero 128
entry_metadata: .ascii "HIAWEMT1"
.quad 0,0
