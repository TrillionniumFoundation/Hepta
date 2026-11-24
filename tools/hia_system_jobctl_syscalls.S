/* Mechanical argv/environment, Linux syscall and HIA call transport.
 * HIA owns fixed operation admission, streamed image identity, sealed input,
 * fixed argv selection and descriptor inheritance. This adapter dispatches only. */
.intel_syntax noprefix
.text
.global _start, policy_hole, json_hole, request_hole, start_hole, record_hole, process_hole, sha_hole, observation_hole, terminal_hole, canonical_hole
.equ STATE_BYTES,134217728
.equ PLAN_BYTES,128
.equ INPUT_BYTES,4194304
_start:
    mov rbp,rsp
    cmp QWORD PTR [rbp],1
    jb invalid
    cmp QWORD PTR [rbp],65536
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
    cmp r9,65536
    jae invalid
    jmp copy_argument
load_argument:
    mov rdx,[rbp+8+r9*8]
copy_argument:
    xor r10d,r10d
argument_byte:
    cmp r10,131072
    ja invalid
    test edi,edi
    jz argument_size_ready
    cmp r10,131072
    ja invalid
argument_size_ready:
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
policy_hole: .long 0
action_dispatch:
    cmp eax,1
    je syscall_action
    cmp eax,2
    je relocate_action
    cmp eax,4
    je json_action
    cmp eax,5
    je request_action
    cmp eax,6
    je observation_action
    cmp eax,7
    je start_action
    cmp eax,8
    je advance
    cmp eax,9
    je record_action
    cmp eax,10
    je sha_action
    cmp eax,11
    je process_action
    cmp eax,12
    je advance
    cmp eax,13
    je terminal_action
    cmp eax,14
    je canonical_action
    cmp eax,15
    je signal_addresses
    cmp eax,16
    je supervisor_action
    cmp eax,17
    je spec_action
    cmp eax,18
    je spawn_action
    cmp eax,19
    je capture_action
    cmp eax,20
    je publish_action
    cmp eax,21
    je scratch_action
    cmp eax,22
    je scratch_directory_action
    cmp eax,23
    je scratch_group_action
    cmp eax,24
    je vectors_action
    cmp eax,25
    je control_action
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
    cmp rbp,524288
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
json_hole: .long 0
    mov [r15+8],rax
    jmp advance

request_action:
    mov rdi,[r14]
    cmp rdi,STATE_BYTES
    jae invalid
    add rdi,r15
    mov rsi,[r14+8]
    mov rdx,r14
    mov ecx,128
    mov r8,r15
    mov r9d,STATE_BYTES
    .byte 0xe8
request_hole: .long 0
    mov [r15+8],rax
    jmp advance
start_action:
    mov rdi,r12
    mov rsi,r13
    mov rdx,r14
    mov ecx,128
    mov r8,r15
    mov r9d,STATE_BYTES
    .byte 0xe8
start_hole: .long 0
    jmp action_dispatch
record_action:
    mov rdi,[r14]
    cmp rdi,STATE_BYTES
    jae invalid
    mov rsi,[r14+8]
    mov rax,STATE_BYTES
    sub rax,rdi
    cmp rsi,rax
    ja invalid
    add rdi,r15
    mov rdx,r14
    mov ecx,128
    mov r8,r15
    mov r9d,STATE_BYTES
    .byte 0xe8
record_hole: .long 0
    mov [r15+8],rax
    jmp advance
sha_action:
    mov rdi,[r14]
    cmp rdi,STATE_BYTES
    jae invalid
    mov rsi,[r14+8]
    mov rax,STATE_BYTES
    sub rax,rdi
    cmp rsi,rax
    ja invalid
    mov rdx,[r14+16]
    cmp rdx,STATE_BYTES-32
    ja invalid
    mov r8,[r14+24]
    cmp r8,STATE_BYTES-1184
    ja invalid
    add rdi,r15
    add rdx,r15
    add r8,r15
    mov ecx,32
    mov r9d,1184
    .byte 0xe8
sha_hole: .long 0
    mov [r15+8],rax
    jmp advance
process_action:
    mov rdi,r12
    mov rsi,r13
    mov rdx,r14
    mov ecx,128
    mov r8,r15
    mov r9d,STATE_BYTES
    .byte 0xe8
process_hole: .long 0
    jmp action_dispatch
observation_action:
    mov rdi,r12
    mov rsi,r13
    mov rdx,r14
    mov ecx,128
    mov r8,r15
    mov r9d,STATE_BYTES
    .byte 0xe8
observation_hole: .long 0
    jmp action_dispatch
terminal_action:
    mov rdi,[r14]
    cmp rdi,STATE_BYTES
    jae invalid
    mov rsi,[r14+8]
    mov rax,STATE_BYTES
    sub rax,rdi
    cmp rsi,rax
    ja invalid
    add rdi,r15
    mov rdx,r14
    mov ecx,128
    mov r8,r15
    mov r9d,STATE_BYTES
    .byte 0xe8
terminal_hole: .long 0
    mov [r15+8],rax
    jmp advance
canonical_action:
    xor ebx,ebx
canonical_buffer:
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
    jb canonical_buffer
    mov rdi,[rsp]
    mov rsi,[r14+8]
    mov rdx,[rsp+16]
    mov rcx,[r14+24]
    mov r8,[rsp+32]
    mov r9,[r14+40]
    .byte 0xe8
canonical_hole: .long 0
    mov [r15+8],rax
    jmp advance


signal_addresses:
    lea rax,[rip+signal_handler]
    mov [r15+41744],rax
    lea rax,[rip+signal_restorer]
    mov [r15+41752],rax
    mov QWORD PTR [r15+8],0
    jmp advance
signal_handler:
    mov QWORD PTR gs:[41736],1
    ret
signal_restorer:
    mov eax,15
    syscall
    ud2

.global control_hole
control_action:
    mov rdi,r12
    mov rsi,r13
    mov rdx,r14
    mov ecx,128
    mov r8,r15
    mov r9d,STATE_BYTES
    .byte 0xe8
control_hole: .long 0
    jmp action_dispatch

.global supervisor_hole
supervisor_action:
    mov rdi,r12
    mov rsi,r13
    mov rdx,r14
    mov ecx,128
    mov r8,r15
    mov r9d,STATE_BYTES
    .byte 0xe8
supervisor_hole: .long 0
    jmp action_dispatch

.global spawn_hole
spawn_action:
    mov rdi,r12
    mov rsi,r13
    mov rdx,r14
    mov ecx,128
    mov r8,r15
    mov r9d,STATE_BYTES
    .byte 0xe8
spawn_hole: .long 0
    jmp action_dispatch

.global capture_hole
capture_action:
    mov rdi,r12
    mov rsi,r13
    mov rdx,r14
    mov ecx,128
    mov r8,r15
    mov r9d,STATE_BYTES
    .byte 0xe8
capture_hole: .long 0
    jmp action_dispatch

.global publish_hole
publish_action:
    mov rdi,r12
    mov rsi,r13
    mov rdx,r14
    mov ecx,128
    mov r8,r15
    mov r9d,STATE_BYTES
    .byte 0xe8
publish_hole: .long 0
    jmp action_dispatch

.global scratch_hole
scratch_action:
    mov rdi,r12
    mov rsi,r13
    mov rdx,r14
    mov ecx,128
    mov r8,r15
    mov r9d,STATE_BYTES
    .byte 0xe8
scratch_hole: .long 0
    jmp action_dispatch

.global scratch_directory_hole
scratch_directory_action:
    mov rdi,r12
    mov rsi,r13
    mov rdx,r14
    mov ecx,128
    mov r8,r15
    mov r9d,STATE_BYTES
    .byte 0xe8
scratch_directory_hole: .long 0
    jmp action_dispatch

.global scratch_group_hole
scratch_group_action:
    mov rdi,r12
    mov rsi,r13
    mov rdx,r14
    mov ecx,128
    mov r8,r15
    mov r9d,STATE_BYTES
    .byte 0xe8
scratch_group_hole: .long 0
    jmp action_dispatch

.global vectors_hole
vectors_action:
    mov rdi,r12
    mov rsi,r13
    mov rdx,r14
    mov ecx,128
    mov r8,r15
    mov r9d,STATE_BYTES
    .byte 0xe8
vectors_hole: .long 0
    mov [r15+8],rax
    jmp advance

.global spec_hole
spec_action:
    mov rdi,[r14]
    cmp rdi,STATE_BYTES
    jae invalid
    mov rsi,[r14+8]
    mov rax,STATE_BYTES
    sub rax,rdi
    cmp rsi,rax
    ja invalid
    add rdi,r15
    mov rdx,r14
    mov ecx,128
    mov r8,r15
    mov r9d,STATE_BYTES
    .byte 0xe8
spec_hole: .long 0
    mov [r15+8],rax
    jmp advance

invalid:
    mov edi,1
exiting:
    mov eax,60
    syscall
    ud2
