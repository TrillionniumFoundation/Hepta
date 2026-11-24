/* Mechanical argv/environment, Linux syscall and HIA call transport.
 * HIA owns directory custody, JSON binding, image digests, sealed captures,
 * physical cwd policy, descriptor inheritance and native owner request bytes. */
.intel_syntax noprefix
.text
.global _start, job_submit_policy_hole, job_submit_launch_hole, job_submit_json_hole, job_submit_sha_hole
.equ STATE_BYTES,234881024
.equ PLAN_BYTES,128
.equ INPUT_BYTES,1048576
_start:
    mov rbp,rsp
    cmp QWORD PTR [rbp],1
    jb invalid
    cmp QWORD PTR [rbp],16
    ja invalid
    mov eax,9
    xor edi,edi
    mov esi,STATE_BYTES+4096+INPUT_BYTES
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
    movabs rax,0x3230475241414948
    mov [r12],rax
    mov r8,[rbp]
    mov [r12+8],r8
    mov ebx,32
    xor r9d,r9d
    xor edi,edi
argument_next:
    test edi,edi
    jnz environment_next
    cmp r9,r8
    jb load_argument
    lea rbp,[rbp+16+r8*8]
    xor r9d,r9d
    mov edi,1
environment_next:
    mov rdx,[rbp+r9*8]
    test rdx,rdx
    jz input_done
    cmp r9,128
    jae invalid
    jmp copy_argument
load_argument:
    mov rdx,[rbp+8+r9*8]
copy_argument:
    xor r10d,r10d
argument_byte:
    cmp r10,8192
    ja invalid
    lea rax,[rbx+r10+8]
    cmp rax,INPUT_BYTES
    jae invalid
    mov cl,[rdx+r10]
    mov [r12+rax],cl
    test cl,cl
    jz argument_end
    inc r10
    jmp argument_byte
argument_end:
    mov [r12+rbx],r10
    lea rbx,[rbx+r10+9]
    inc r9
    jmp argument_next
input_done:
    mov [r12+16],r9
    mov [r12+24],rbx
    mov r13,rbx
    sub rsp,160
advance:
    mov rdi,r12
    mov rsi,r13
    mov rdx,r14
    mov ecx,PLAN_BYTES
    mov r8,r15
    mov r9d,STATE_BYTES
    .byte 0xe8
job_submit_policy_hole: .long 0
dispatch_action:
    cmp eax,1
    je syscall_action
    cmp eax,2
    je relocate_action
    cmp eax,3
    je sha_action
    cmp eax,4
    je json_action
    cmp eax,5
    je launch_action
    jmp invalid
launch_action:
    mov rdi,r12
    mov rsi,r13
    mov rdx,r14
    mov ecx,PLAN_BYTES
    mov r8,r15
    mov r9d,STATE_BYTES
    .byte 0xe8
job_submit_launch_hole: .long 0
    jmp dispatch_action
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
job_submit_json_hole: .long 0
    mov [r15+8],rax
    jmp advance
relocate_action:
    mov rbx,[r14]
    mov rbp,[r14+8]
    mov rdx,[r14+16]
    test rbp,rbp
    jz invalid
    cmp rbp,256
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
job_submit_sha_hole: .long 0
    mov [r15+8],rax
    jmp advance
invalid:
    mov eax,60
    mov edi,65
    syscall
    ud2
