/* Mechanical Linux syscall/byte-ABI translation. All request,
 * ownership, retention and durable-publication policy is emitted HIA. */
.intel_syntax noprefix
.text
.global _start
.equ STATE_BYTES,33554432
.equ PLAN_BYTES,128
_start:
    sub rsp,160
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
advance:
    mov rdi,r12
    mov rsi,r13
    mov rdx,r14
    mov ecx,PLAN_BYTES
    mov r8,r15
    mov r9d,STATE_BYTES
    cmp QWORD PTR [r15+16],0
    je module_session
    cmp QWORD PTR [r15+16],1
    je module_files
    cmp QWORD PTR [r15+16],2
    je module_records
    cmp QWORD PTR [r15+16],3
    je module_archive
    cmp QWORD PTR [r15+16],4
    je module_layout
    cmp QWORD PTR [r15+16],5
    je module_retention
    cmp QWORD PTR [r15+16],6
    je module_root
    cmp QWORD PTR [r15+16],7
    je module_scan
    cmp QWORD PTR [r15+16],8
    je module_write
    cmp QWORD PTR [r15+16],9
    je module_recovery
    cmp QWORD PTR [r15+16],10
    je module_leases
    cmp QWORD PTR [r15+16],11
    je module_open
    cmp QWORD PTR [r15+16],12
    je module_response
    cmp QWORD PTR [r15+16],13
    je module_metadata
    cmp QWORD PTR [r15+16],14
    je module_intent
    cmp QWORD PTR [r15+16],15
    je module_history
    cmp QWORD PTR [r15+16],16
    je module_archive_query
    cmp QWORD PTR [r15+16],17
    je module_batch
    jmp invalid
module_session:
    .byte 0xe8
.global audit_session_hole
audit_session_hole: .long 0
    jmp returned
module_files:
    .byte 0xe8
.global audit_files_hole
audit_files_hole: .long 0
    jmp returned
module_records:
    .byte 0xe8
.global audit_records_hole
audit_records_hole: .long 0
    jmp returned
module_archive:
    .byte 0xe8
.global audit_archive_hole
audit_archive_hole: .long 0
    jmp returned
module_layout:
    .byte 0xe8
.global audit_layout_hole
audit_layout_hole: .long 0
    jmp returned
module_retention:
    .byte 0xe8
.global audit_retention_hole
audit_retention_hole: .long 0
    jmp returned
module_root:
    .byte 0xe8
.global audit_root_hole
audit_root_hole: .long 0
    jmp returned
module_scan:
    .byte 0xe8
.global audit_scan_hole
audit_scan_hole: .long 0
    jmp returned
module_write:
    .byte 0xe8
.global audit_write_hole
audit_write_hole: .long 0
    jmp returned
module_recovery:
    .byte 0xe8
.global audit_recovery_hole
audit_recovery_hole: .long 0
    jmp returned
module_leases:
    .byte 0xe8
.global audit_leases_hole
audit_leases_hole: .long 0
    jmp returned
module_open:
    .byte 0xe8
.global audit_open_hole
audit_open_hole: .long 0
    jmp returned
module_response:
    .byte 0xe8
.global audit_response_hole
audit_response_hole: .long 0
    jmp returned
module_metadata:
    .byte 0xe8
.global audit_metadata_hole
audit_metadata_hole: .long 0
    jmp returned
module_intent:
    .byte 0xe8
.global audit_intent_hole
audit_intent_hole: .long 0
    jmp returned
module_history:
    .byte 0xe8
.global audit_history_hole
audit_history_hole: .long 0
    jmp returned
module_archive_query:
    .byte 0xe8
.global audit_archive_query_hole
audit_archive_query_hole: .long 0
    jmp returned
module_batch:
    .byte 0xe8
.global audit_batch_hole
audit_batch_hole: .long 0
    jmp returned
returned:
    mov eax,eax
    cmp eax,6
    je advance
    cmp eax,1
    je syscall_action
    cmp eax,2
    je relocate_action
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
    xor ebx,ebx
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
    .byte 0xe8
.global audit_json_hole
audit_json_hole: .long 0
    mov eax,eax
    mov [r15+8],rax
    jmp advance
invalid:
    mov eax,60
    mov edi,65
    syscall
    ud2
.section .note.GNU-stack,"",@progbits
