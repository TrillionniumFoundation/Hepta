/* Mechanical Linux ABI for the HIA job-observation owner.
 * HIA selects paths, permissions, bindings, limits, syscalls and output bytes.
 * This adapter gathers bounded stdin and translates bounded buffer offsets.
 * The image has no shell, libc, dynamic loader, Python or Rust dependency. */
.intel_syntax noprefix
.text
.global _start, job_observation_policy_hole, job_observation_json_hole
.equ STATE_BYTES,234881024
.equ PLAN_BYTES,128
.equ INPUT_BYTES,65536
_start:
    cmp QWORD PTR [rsp],1
    jne invalid
    sub rsp,160
    mov eax,9
    xor edi,edi
    mov esi,STATE_BYTES+4096+INPUT_BYTES+1
    mov edx,3
    mov r10d,0x22
    mov r8,-1
    xor r9d,r9d
    syscall
    cmp rax,-4095
    jae invalid
    mov r15,rax
    lea r14,[rax+STATE_BYTES]
    lea r12,[r14+4096]
    xor r13d,r13d
read_input:
    xor eax,eax
    xor edi,edi
    lea rsi,[r12+r13]
    mov edx,INPUT_BYTES+1
    sub rdx,r13
    syscall
    cmp rax,-4
    je read_input
    test rax,rax
    js invalid
    jz advance
    add r13,rax
    cmp r13,INPUT_BYTES
    ja invalid
    jmp read_input
advance:
    mov rdi,r12
    mov rsi,r13
    mov rdx,r14
    mov ecx,PLAN_BYTES
    mov r8,r15
    mov r9d,STATE_BYTES
    .byte 0xe8
job_observation_policy_hole: .long 0
    cmp eax,1
    je syscall_action
    cmp eax,4
    je json_action
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
json_action:
    xor ebx,ebx
json_buffer:
    mov rax,[r14+rbx]
    mov rdx,[r14+rbx+8]
    cmp rax,STATE_BYTES
    jae invalid
    add rdx,rax
    jc invalid
    cmp rdx,STATE_BYTES
    ja invalid
    add rax,r15
    mov [rsp+rbx],rax
    add ebx,16
    cmp ebx,48
    jb json_buffer
    mov rdi,[rsp]
    mov rsi,[r14+8]
    mov rdx,[rsp+16]
    mov rcx,[r14+24]
    mov r8,[rsp+32]
    mov r9,[r14+40]
    .byte 0xe8
job_observation_json_hole: .long 0
    mov [r15+8],rax
    jmp advance
invalid:
    mov eax,60
    mov edi,65
    syscall
    ud2
