/* NEW INACTIVE native UnixOpen issuance capsule mechanics, source r1.
 * Not assembled or executed. This fragment has no standalone entry point.
 * Fixed parent dispatcher role9 must own the three exact context pointers.
 * No public input can provide a context pointer, capsule, completion or ACK.
 * Existing FS9 carrier byte base: ceb21c40b4287b1eff4e998d61fdfcfa59fb3110.
 *
 * Every helper runs with r15=the private role9 context and r13=a fixed member.
 * begin takes rcx=requesting call, rdx=requesting action after the carrier has
 * installed a new immutable REQUEST and before its first actual entry.
 * complete is called only from the actual native terminal edge, never USER.
 * capture takes rdi=one of the three owned capture descriptors below.
 *
 * Fields88/96 encode original entry operand permissions, not the physical
 * snapshot's protection: every captured mapping is RO at capture time.
 * R/R/W role8 has input2 flag1; R/W/W roles6/7 have input2 flag0.
 */
.intel_syntax noprefix
.equ UI_MASTER,2496
.equ UI_ACTUAL_ID,2504
.equ UI_SOURCE_LEASE,2512
.equ UI_REQUEST_CALL,2520
.equ UI_REQUEST_ACTION,2528
.equ UI_COMPLETION_SERIAL,2536
.equ UI_COMPLETION_RETURN,2544
.equ UI_COMPLETION_VALID,2552
.equ UI_FIXED_FS,2560
.equ UI_FIXED_PARENT,2568
.equ UI_FIXED_FRAMER,2576
.equ UI_PROCESS,2584
.equ UI_NEXT_INPUT_LEASE,2592
.equ UI_ROOT_CALL,2600
.equ UI_RETURN_EDGE,2608
.equ UI_INFLIGHT,2616
.equ UI_BEGIN_SERIAL,2624
.equ UI_CAP_PARENT,1200
.equ UI_CAP_FS,1240
.equ UI_CAP_CHILD,1280
.equ UI_CAPSULE_MAGIC,0x3130434955414948
.equ UI_CAPSULE_TRACE,0x3130544955414948

/* Validate identity through the fixed live registry, before following any
 * supplied context descriptor. r13 is a native dispatcher register only. */
.Lnamespace_uij_member:
    test r15,r15
    jz protocol_failure
    cmp qword ptr [r15+ROLE],9
    jne protocol_failure
    cmp [r15+ROOT_LINK],r15
    jne protocol_failure
    cmp qword ptr [r15+UI_PROCESS],0
    je protocol_failure
    test r13,r13
    jz protocol_failure
    cmp r13,[r15+UI_FIXED_FS]
    je .Luij_member_fs
    cmp r13,[r15+UI_FIXED_PARENT]
    je .Luij_member_parent
    cmp r13,[r15+UI_FIXED_FRAMER]
    jne protocol_failure
    mov eax,8
    jmp .Luij_member_selected
.Luij_member_fs:
    mov eax,6
    jmp .Luij_member_selected
.Luij_member_parent:
    mov eax,7
.Luij_member_selected:
    cmp [r13+ROLE],rax
    jne protocol_failure
    cmp [r13+UI_ACTUAL_ID],rax
    jne protocol_failure
    cmp [r13+UI_MASTER],r15
    jne protocol_failure
    cmp qword ptr [r13+CONTEXT_SEQUENCE],0
    je protocol_failure
    cmp qword ptr [r13+CONTEXT_RETIRED],0
    jne protocol_failure
    ret

/* Request copy and RO protection precede begin. Replacing REQUEST while
 * UI_INFLIGHT=1 is forbidden by the caller and detected by its active lease.
 * GROW repeats the same actual call without entering begin a second time. */
.Lnamespace_uij_begin:
    push rbx
    push r12
    mov rbx,rcx
    mov r12,rdx
    call .Lnamespace_uij_member
    cmp qword ptr [r13+UI_INFLIGHT],0
    jne protocol_failure
    lea rax,[r13+REQUEST]
    cmp [r13+CURRENT_DESC],rax
    jne protocol_failure
    cmp qword ptr [r13+REQUEST+32],1
    jne protocol_failure
    cmp qword ptr [r13+REQUEST+16],0
    je protocol_failure
    mov rax,[r13+REQUEST+16]
    cmp [r13+CURRENT_LENGTH],rax
    jne protocol_failure
    lea rdi,[r13+REQUEST]
    call check_descriptor
    mov rax,[r15+UI_NEXT_INPUT_LEASE]
    cmp rax,-1
    je protocol_failure
    inc rax
    mov [r15+UI_NEXT_INPUT_LEASE],rax
    mov [r13+UI_SOURCE_LEASE],rax
    mov [r13+UI_REQUEST_CALL],rbx
    mov [r13+UI_REQUEST_ACTION],r12
    mov rax,[r13+ENTRY_SERIAL]
    mov [r13+UI_BEGIN_SERIAL],rax
    mov qword ptr [r13+UI_COMPLETION_SERIAL],0
    mov qword ptr [r13+UI_COMPLETION_RETURN],0
    mov qword ptr [r13+UI_COMPLETION_VALID],0
    mov qword ptr [r13+UI_INFLIGHT],1
    pop r12
    pop rbx
    ret

/* A completion is issued once for a real returned call. Role6's last inner
 * native input may be ACK; original REQUEST remains separately owned/RO.
 * All three exact logical operands are frozen before any capture is allowed. */
.Lnamespace_uij_complete:
    call .Lnamespace_uij_member
    cmp qword ptr [r13+UI_INFLIGHT],1
    jne protocol_failure
    cmp qword ptr [r13+UI_COMPLETION_VALID],0
    jne protocol_failure
    mov rax,[r13+ENTRY_SERIAL]
    cmp rax,[r13+UI_BEGIN_SERIAL]
    jbe protocol_failure
    mov rdx,[r13+ENTRY_RETURN]
    mov ecx,edx
    cmp rcx,rdx
    jne protocol_failure
    cmp qword ptr [r13+UI_SOURCE_LEASE],0
    je protocol_failure
    call .Lnamespace_uij_frozen_operands
    mov rax,[r13+ENTRY_SERIAL]
    mov [r13+UI_COMPLETION_SERIAL],rax
    mov rax,[r13+ENTRY_RETURN]
    mov [r13+UI_COMPLETION_RETURN],rax
    mov qword ptr [r13+UI_INFLIGHT],0
    mov qword ptr [r13+UI_COMPLETION_VALID],1
    ret

.Lnamespace_uij_frozen_operands:
    cmp qword ptr [r13+REQUEST],0
    je protocol_failure
    cmp qword ptr [r13+OUTPUT],0
    je protocol_failure
    cmp qword ptr [r13+WORK],0
    je protocol_failure
    cmp qword ptr [r13+REQUEST+32],1
    jne protocol_failure
    cmp qword ptr [r13+OUTPUT+32],1
    jne protocol_failure
    cmp qword ptr [r13+WORK+32],1
    jne protocol_failure
    lea rdi,[r13+REQUEST]
    call check_descriptor
    lea rdi,[r13+OUTPUT]
    call check_descriptor
    lea rdi,[r13+WORK]
    call check_descriptor
    ret

/* Produce exact128B header + full original REQUEST + full OUTPUT + full WORK.
 * No parsed projection, payload cap, syscall policy or state interpretation.
 * Destination must be a descriptor owned by this same native dispatcher.
 * Each copied byte has an actual guarded source mapping and exact logical span.
 */
.Lnamespace_uij_capture:
    push rbx
    push r12
    mov rbx,rdi
    call .Lnamespace_uij_member
    lea rax,[r15+UI_CAP_PARENT]
    cmp rbx,rax
    je .Luij_capture_destination
    lea rax,[r15+UI_CAP_FS]
    cmp rbx,rax
    je .Luij_capture_destination
    lea rax,[r15+UI_CAP_CHILD]
    cmp rbx,rax
    jne protocol_failure
.Luij_capture_destination:
    cmp qword ptr [r13+UI_INFLIGHT],0
    jne protocol_failure
    cmp qword ptr [r13+UI_COMPLETION_VALID],1
    jne protocol_failure
    mov rax,[r13+ENTRY_SERIAL]
    test rax,rax
    jz protocol_failure
    cmp [r13+UI_COMPLETION_SERIAL],rax
    jne protocol_failure
    mov rax,[r13+ENTRY_RETURN]
    cmp [r13+UI_COMPLETION_RETURN],rax
    jne protocol_failure
    cmp qword ptr [r13+UI_SOURCE_LEASE],0
    je protocol_failure
    call .Lnamespace_uij_frozen_operands
    mov r12,128
    add r12,[r13+REQUEST+16]
    jc allocation_failure
    add r12,[r13+OUTPUT+16]
    jc allocation_failure
    add r12,[r13+WORK+16]
    jc allocation_failure
    mov rdi,rbx
    call release_descriptor
    mov rdi,rbx
    mov rsi,r12
    call allocate_descriptor
    mov r12,[rbx+8]
    mov rax,UI_CAPSULE_MAGIC
    mov [r12],rax
    mov rax,[r13+ROLE]
    mov [r12+8],rax
    mov rax,[r13+UI_ACTUAL_ID]
    mov [r12+16],rax
    mov rax,[r13+CONTEXT_SEQUENCE]
    mov [r12+24],rax
    mov rax,[r13+UI_COMPLETION_SERIAL]
    mov [r12+32],rax
    mov rax,[r13+UI_COMPLETION_RETURN]
    mov [r12+40],rax
    mov rax,[r13+REQUEST+16]
    mov [r12+48],rax
    mov rax,[r13+OUTPUT+16]
    mov [r12+56],rax
    mov rax,[r13+WORK+16]
    mov [r12+64],rax
    mov rax,[r13+UI_SOURCE_LEASE]
    mov [r12+72],rax
    mov qword ptr [r12+80],1
    xor eax,eax
    cmp qword ptr [r13+ROLE],8
    sete al
    mov [r12+88],rax
    mov qword ptr [r12+96],0
    mov rax,[r15+UI_PROCESS]
    mov [r12+104],rax
    mov rax,[r13+UI_REQUEST_ACTION]
    mov [r12+112],rax
    mov rax,[r13+UI_REQUEST_CALL]
    mov [r12+120],rax
    lea rdi,[r12+128]
    mov rsi,[r13+REQUEST+8]
    mov rcx,[r13+REQUEST+16]
    rep movsb
    mov rsi,[r13+OUTPUT+8]
    mov rcx,[r13+OUTPUT+16]
    rep movsb
    mov rsi,[r13+WORK+8]
    mov rcx,[r13+WORK+16]
    rep movsb
    mov rax,[rbx+8]
    add rax,[rbx+16]
    jc protocol_failure
    cmp rdi,rax
    jne protocol_failure
    mov rdi,rbx
    call check_descriptor
    mov rdi,rbx
    mov esi,1
    call protect_descriptor
    /* A new trace kind records these complete actual bytes. Old BEFORE/AFTER
     * image traces remain unchanged and must be correlated by the reader. */
    mov rax,UI_CAPSULE_TRACE
    mov [r15+TRACE_HEADER],rax
    mov qword ptr [r15+TRACE_HEADER+8],5
    mov rax,[r13+UI_COMPLETION_SERIAL]
    mov [r15+TRACE_HEADER+16],rax
    mov rax,[rbx+16]
    mov [r15+TRACE_HEADER+24],rax
    mov rax,[r13+ROLE]
    mov [r15+TRACE_HEADER+32],rax
    mov rax,[r13+UI_ACTUAL_ID]
    mov [r15+TRACE_HEADER+40],rax
    mov rax,[r13+UI_COMPLETION_RETURN]
    mov [r15+TRACE_HEADER+48],rax
    mov rax,[r13+UI_SOURCE_LEASE]
    mov [r15+TRACE_HEADER+56],rax
    mov rax,[r13+UI_REQUEST_ACTION]
    mov [r15+TRACE_HEADER+64],rax
    mov rax,[r13+UI_REQUEST_CALL]
    mov [r15+TRACE_HEADER+72],rax
    mov rax,[r13+CONTEXT_SEQUENCE]
    mov [r15+TRACE_HEADER+80],rax
    mov qword ptr [r15+TRACE_HEADER+88],0
    call trace_header_write
    mov edi,2
    mov rsi,[rbx+8]
    mov rdx,[rbx+16]
    call write_all
    pop r12
    pop rbx
    ret
