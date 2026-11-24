/* Mechanical Linux ABI for the standalone HIA MCP service.
 * HIA owns configuration, custody, limits, files, jobs and protocol semantics.
 * This adapter snapshots bounded argv/env and translates bounded offsets.
 */
.intel_syntax noprefix
.text
.global _start
.equ STATE_BYTES,402653184
.equ PLAN_BYTES,128
.equ BRIDGE_IMAGE,301989888
_start:
    cmp QWORD PTR [rsp],5
    jne invalid
    mov rbx,rsp
    sub rsp,160
    mov [rsp+80],rbx
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
    lea r12,[r14+512]
    xor r13d,r13d
    mov rbx,[rsp+80]
    xor r9d,r9d
    mov r8d,65536
argument_entry:
    mov rsi,[rbx+r9*8+16]
    mov rax,r9
    shl rax,4
    mov [r15+rax+2048],r8
    xor ecx,ecx
argument_byte:
    cmp rcx,4096
    ja invalid
    cmp r8,98304
    jae invalid
    mov al,[rsi]
    mov [r15+r8],al
    inc rsi
    inc r8
    inc rcx
    test al,al
    jnz argument_byte
    dec rcx
    mov rax,r9
    shl rax,4
    mov [r15+rax+2056],rcx
    inc r9
    cmp r9,4
    jb argument_entry
    mov QWORD PTR [r15+112],4
    add rbx,56
    xor r8d,r8d
    xor r9d,r9d
environment_entry:
    mov rsi,[rbx]
    test rsi,rsi
    jz environment_done
    cmp r9,128
    jae invalid
    lea rax,[r8+2097152]
    mov [r15+r9*8+53248],rax
    xor ecx,ecx
environment_byte:
    cmp r8,1048576
    jae invalid
    cmp rcx,8192
    jae invalid
    mov al,[rsi]
    mov [r15+r8+2097152],al
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
    .byte 0xb9
.global mcp_service_bridge_size_hole
mcp_service_bridge_size_hole: .long 0
    cmp ecx,64
    jb invalid
    cmp ecx,16777216
    ja invalid
    mov [r15+120],rcx
    .byte 0x48,0x8d,0x35
.global mcp_service_bridge_hole
mcp_service_bridge_hole: .long 0
    lea rdi,[r15+BRIDGE_IMAGE]
    rep movsb
    lea rsi,[rip+.Lbridge_pin_data]
    lea rdi,[r15+5392]
    mov ecx,32
    rep movsb
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
    je module_setup
    cmp QWORD PTR [r15+16],2
    je module_stream
    cmp QWORD PTR [r15+16],3
    je module_dispatch
    cmp QWORD PTR [r15+16],4
    je module_transport
    cmp QWORD PTR [r15+16],5
    je module_response
    cmp QWORD PTR [r15+16],6
    je module_scheduler
    cmp QWORD PTR [r15+16],7
    je module_files
    cmp QWORD PTR [r15+16],8
    je module_state
    jmp invalid
module_bootstrap:
    .byte 0xe8
.global mcp_service_bootstrap_hole
mcp_service_bootstrap_hole: .long 0
    jmp returned
module_setup:
    .byte 0xe8
.global mcp_service_setup_hole
mcp_service_setup_hole: .long 0
    jmp returned
module_stream:
    .byte 0xe8
.global mcp_service_stream_hole
mcp_service_stream_hole: .long 0
    jmp returned
module_dispatch:
    .byte 0xe8
.global mcp_service_dispatch_hole
mcp_service_dispatch_hole: .long 0
    jmp returned
module_transport:
    .byte 0xe8
.global mcp_service_transport_hole
mcp_service_transport_hole: .long 0
    jmp returned
module_response:
    .byte 0xe8
.global mcp_service_response_hole
mcp_service_response_hole: .long 0
    jmp returned
module_scheduler:
    .byte 0xe8
.global mcp_service_scheduler_hole
mcp_service_scheduler_hole: .long 0
    jmp returned
module_files:
    .byte 0xe8
.global mcp_service_files_hole
mcp_service_files_hole: .long 0
    jmp returned
module_state:
    .byte 0xe8
.global mcp_service_state_hole
mcp_service_state_hole: .long 0
    jmp returned
returned:
    mov eax,eax
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
    je pure_action
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
json_action:
    mov QWORD PTR [rsp+88],4
    xor ebx,ebx
    jmp buffer_action
pure_action:
    mov QWORD PTR [rsp+88],5
    mov ebx,8
buffer_action:
    xor ebp,ebp
buffer_pair:
    mov rax,[r14+rbx]
    mov rcx,[r14+rbx+8]
    cmp rax,STATE_BYTES
    ja invalid
    mov rdx,STATE_BYTES
    sub rdx,rax
    cmp rcx,rdx
    ja invalid
    add rax,r15
    mov [rsp+rbp],rax
    mov [rsp+rbp+8],rcx
    add ebx,16
    add ebp,16
    cmp ebp,48
    jb buffer_pair
    mov rdi,[rsp]
    mov rsi,[rsp+8]
    mov rdx,[rsp+16]
    mov rcx,[rsp+24]
    mov r8,[rsp+32]
    mov r9,[rsp+40]
    cmp QWORD PTR [rsp+88],4
    je call_json
    cmp QWORD PTR [r14],0
    je call_session
    cmp QWORD PTR [r14],1
    je call_reply
    cmp QWORD PTR [r14],2
    je call_canonical
    cmp QWORD PTR [r14],3
    je call_config
    cmp QWORD PTR [r14],4
    je call_admission
    cmp QWORD PTR [r14],5
    je call_catalog
    cmp QWORD PTR [r14],6
    je call_input_schema
    cmp QWORD PTR [r14],7
    je call_controller_json
    cmp QWORD PTR [r14],8
    je call_output_schema
    jmp invalid
call_json:
    .byte 0xe8
.global mcp_service_json_hole
mcp_service_json_hole: .long 0
    jmp buffer_return
call_session:
    .byte 0xe8
.global mcp_service_session_hole
mcp_service_session_hole: .long 0
    jmp buffer_return
call_reply:
    .byte 0xe8
.global mcp_service_reply_hole
mcp_service_reply_hole: .long 0
    jmp buffer_return
call_canonical:
    .byte 0xe8
.global mcp_service_canonical_hole
mcp_service_canonical_hole: .long 0
    jmp buffer_return
call_config:
    .byte 0xe8
.global mcp_service_config_hole
mcp_service_config_hole: .long 0
    jmp buffer_return
call_admission:
    .byte 0xe8
.global mcp_service_admission_hole
mcp_service_admission_hole: .long 0
    jmp buffer_return
call_catalog:
    .byte 0xe8
.global mcp_service_catalog_hole
mcp_service_catalog_hole: .long 0
    jmp buffer_return
call_input_schema:
    .byte 0xe8
.global mcp_service_input_schema_hole
mcp_service_input_schema_hole: .long 0
    jmp buffer_return
call_controller_json:
    .byte 0xe8
.global mcp_service_controller_json_hole
mcp_service_controller_json_hole: .long 0
    jmp buffer_return
call_output_schema:
    .byte 0xe8
.global mcp_service_output_schema_hole
mcp_service_output_schema_hole: .long 0
    jmp buffer_return
buffer_return:
    mov eax,eax
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
.global mcp_service_sha_hole
mcp_service_sha_hole: .long 0
    mov eax,eax
    mov [r15+8],rax
    jmp advance
invalid:
    mov eax,60
    mov edi,65
    syscall
    ud2
.global mcp_service_bridge_pin
.Lbridge_pin_data:
mcp_service_bridge_pin: .zero 32
.section .note.GNU-stack,"",@progbits
