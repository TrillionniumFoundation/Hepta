/* Mechanical Linux ABI for the HIA durable MCP job bridge.
 * HIA selects paths, permissions, bindings, limits, syscalls and output bytes.
 * This adapter gathers bounded stdin and translates bounded buffer offsets.
 * The image has no shell, libc, dynamic loader, Python or Rust dependency. */
.intel_syntax noprefix
.text
.global _start, mcp_job_bridge_bootstrap_hole, mcp_job_bridge_provider_hole, mcp_job_bridge_registry_hole, mcp_job_bridge_process_hole, mcp_job_bridge_transport_hole, mcp_job_bridge_result_hole, mcp_job_bridge_fence_hole, mcp_job_bridge_files_hole, mcp_job_bridge_audit_hole, mcp_job_bridge_json_hole, mcp_job_bridge_sha_hole, mcp_job_bridge_status_hole, mcp_job_bridge_pages_hole, mcp_job_bridge_terminal_hole, mcp_job_bridge_canonical_hole
.global mcp_job_bridge_replay_hole, mcp_job_bridge_compat_hole, mcp_job_bridge_transactions_hole
.equ STATE_BYTES,268435456
.equ PLAN_BYTES,128
.equ INPUT_BYTES,4194304
_start:
    cmp QWORD PTR [rsp],1
    jne invalid
    lea rbx,[rsp+24]
    sub rsp,160
    mov [rsp+80],rbx
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
    mov rbx,[rsp+80]
    xor r8d,r8d
    xor r9d,r9d
environment_entry:
    mov rsi,[rbx]
    test rsi,rsi
    jz environment_done
    cmp r9,128
    jae invalid
    lea rax,[r8+26214400]
    mov [r15+r9*8+53248],rax
    xor ecx,ecx
environment_byte:
    cmp r8,1048576
    jae invalid
    cmp rcx,8192
    jae invalid
    mov al,[rsi]
    mov [r15+r8+26214400],al
    inc rsi
    inc r8
    inc rcx
    test al,al
    jnz environment_byte
    inc r9
    add rbx,8
    jmp environment_entry
environment_done:
    mov QWORD PTR [r15+r9*8+53248],-1
    mov [r15+96],r8
    mov [r15+104],r9
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
    cmp QWORD PTR [r15+16],0
    je module_bootstrap
    cmp QWORD PTR [r15+16],1
    je module_provider
    cmp QWORD PTR [r15+16],2
    je module_registry
    cmp QWORD PTR [r15+16],3
    je module_process
    cmp QWORD PTR [r15+16],4
    je module_transport
    cmp QWORD PTR [r15+16],5
    je module_result
    cmp QWORD PTR [r15+16],6
    je module_fence
    cmp QWORD PTR [r15+16],7
    je module_files
    cmp QWORD PTR [r15+16],8
    je module_audit
    cmp QWORD PTR [r15+16],9
    je module_status
    cmp QWORD PTR [r15+16],10
    je module_pages
    cmp QWORD PTR [r15+16],11
    je module_replay
    cmp QWORD PTR [r15+16],12
    je module_compat
    cmp QWORD PTR [r15+16],13
    je module_transactions
    jmp invalid
module_transactions:
    .byte 0xe8
mcp_job_bridge_transactions_hole: .long 0
    jmp returned
module_compat:
    .byte 0xe8
mcp_job_bridge_compat_hole: .long 0
    jmp returned
module_bootstrap:
    .byte 0xe8
mcp_job_bridge_bootstrap_hole: .long 0
    jmp returned
module_provider:
    .byte 0xe8
mcp_job_bridge_provider_hole: .long 0
    jmp returned
module_registry:
    .byte 0xe8
mcp_job_bridge_registry_hole: .long 0
    jmp returned
module_process:
    .byte 0xe8
mcp_job_bridge_process_hole: .long 0
    jmp returned
module_transport:
    .byte 0xe8
mcp_job_bridge_transport_hole: .long 0
    jmp returned
module_result:
    .byte 0xe8
mcp_job_bridge_result_hole: .long 0
    jmp returned
module_fence:
    .byte 0xe8
mcp_job_bridge_fence_hole: .long 0
    jmp returned
module_files:
    .byte 0xe8
mcp_job_bridge_files_hole: .long 0
    jmp returned
module_audit:
    .byte 0xe8
mcp_job_bridge_audit_hole: .long 0
    jmp returned
module_status:
    .byte 0xe8
mcp_job_bridge_status_hole: .long 0
    jmp returned
module_pages:
    .byte 0xe8
mcp_job_bridge_pages_hole: .long 0
    jmp returned
module_replay:
    .byte 0xe8
mcp_job_bridge_replay_hole: .long 0
    jmp returned
returned:
    cmp eax,6
    je advance
    cmp eax,1
    je syscall_action
    cmp eax,2
    je relocate_action
    cmp eax,3
    je sha_action
    cmp eax,4
    je json_action
    cmp eax,5
    je terminal_action
    cmp eax,7
    je canonical_action
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
    cmp rbp,4099
    ja invalid
    cmp rbx,STATE_BYTES
    jae invalid
    cmp rdx,STATE_BYTES
    jae invalid
    lea rax,[rbx+rbp*8]
    cmp rax,STATE_BYTES
    ja invalid
    lea rax,[rdx+rbp*8]
    cmp rax,STATE_BYTES
    ja invalid
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
    jnz relocate_word
    mov QWORD PTR [r15+8],0
    jmp advance
terminal_action:
    mov ebp,5
    jmp three_buffer_action
canonical_action:
    mov ebp,7
    jmp three_buffer_action
json_action:
    mov ebp,4
three_buffer_action:
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
    cmp ebp,5
    je terminal_call
    cmp ebp,7
    je canonical_call
    .byte 0xe8
mcp_job_bridge_json_hole: .long 0
    jmp buffer_return
terminal_call:
    .byte 0xe8
mcp_job_bridge_terminal_hole: .long 0
    jmp buffer_return
canonical_call:
    .byte 0xe8
mcp_job_bridge_canonical_hole: .long 0
buffer_return:
    mov [r15+8],rax
    jmp advance
sha_action:
    mov rsi,[r14]
    cmp rsi,1
    jb invalid
    cmp rsi,65537
    ja invalid
    lea rdi,[r15+131072]
    lea rdx,[r15+196608]
    mov ecx,32
    lea r8,[r15+200704]
    mov r9d,1184
    .byte 0xe8
mcp_job_bridge_sha_hole: .long 0
    mov [r15+8],rax
    jmp advance
invalid:
    mov eax,60
    mov edi,65
    syscall
    ud2
