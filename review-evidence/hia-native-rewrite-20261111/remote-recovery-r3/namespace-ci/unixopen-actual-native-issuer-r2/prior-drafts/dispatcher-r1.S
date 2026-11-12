
/* NEW fixed live UnixOpen issuance dispatcher r1; not assembled/executed.
 * The transport exposes only an original role6 USER input or role7 BEGIN.
 * Completed capsules, role8/9 inputs and parent ACKs have no external route.
 * These two entry inputs remain explicit private development predecessors;
 * no ordinary Store, complete unixOpen, SQL31 or installed authority is claimed.
 */
.equ UI_SCOPE_A,2632
.equ UI_SCOPE_B,2640
.equ UI_TRANSPORT_CALL,2648
.equ UI_USER_KIND,2656
.equ UI_PENDING_MEMBER,2664
.equ UI_EVENT_ACTION,2672
.equ UI_PARENT_ACTIVE,2680
.equ UI_USER,1320
.equ UI_TRANSPORT_MAGIC,0x3130504955414948
.equ UI_EVENT_MAGIC,0x3130454955414948
.equ UI_CHANNEL_MAGIC,0x3130584955414948
.equ UI_PARENT_MAGIC,0x31304f554e414948
.equ UI_BOOT_MAGIC,0x3130424955414948
.equ UI_PARENT_TRACE,0x3130545550414948
.equ UI_FRAMER_TRACE,0x3130544655414948
.equ UI_ISSUER_TRACE,0x3130544a55414948

/* Existing r15 is the real shared role6 context. Its ROOT_LINK remains self;
 * all old DMS/FS/DB/memory paths and their metadata relationships remain exact.
 * The new link is private metadata, never a value supplied by transport input.
 */
.Luij_boot:
    mov r14,r15
    xor edi,edi
    mov esi,12288
    mov edx,3
    mov r10d,34
    mov r8,-1
    xor r9d,r9d
    mov eax,9
    syscall
    cmp rax,-4095
    jae allocation_failure
    mov r15,rax
    mov [r15+ROOT_LINK],rax
    mov [r15+UI_MASTER],rax
    mov qword ptr [r15+ROLE],9
    mov qword ptr [r15+UI_ACTUAL_ID],9
    mov qword ptr [r15+CONTEXT_SEQUENCE],1
    mov [r15+UI_FIXED_FS],r14
    mov [r14+UI_MASTER],r15
    mov qword ptr [r14+UI_ACTUAL_ID],6
    mov rax,[r14+CONTROL_FD]
    mov [r15+CONTROL_FD],rax
    mov rax,[r14+PARENT_PID]
    mov [r15+PARENT_PID],rax
    mov rax,[r14+NSML_PAGE]
    mov [r15+NSML_PAGE],rax
    mov rax,UI_ISSUER_TRACE
    mov [r15+TRACE_ID],rax
    mov eax,39
    syscall
    test rax,rax
    jle protocol_failure
    mov [r15+UI_PROCESS],rax
    mov [r15+UI_SCOPE_A],rax
    mov qword ptr [r15+UI_SCOPE_B],9
    lea r13,[r15+4096]
    mov [r15+UI_FIXED_PARENT],r13
    mov [r13+UI_MASTER],r15
    mov [r13+ROOT_LINK],r15
    mov qword ptr [r13+ROLE],7
    mov qword ptr [r13+UI_ACTUAL_ID],7
    mov qword ptr [r13+CONTEXT_SEQUENCE],1
    mov rax,UI_PARENT_TRACE
    mov [r13+TRACE_ID],rax
    lea r13,[r15+8192]
    mov [r15+UI_FIXED_FRAMER],r13
    mov [r13+UI_MASTER],r15
    mov [r13+ROOT_LINK],r15
    mov qword ptr [r13+ROLE],8
    mov qword ptr [r13+UI_ACTUAL_ID],8
    mov qword ptr [r13+CONTEXT_SEQUENCE],1
    mov rax,UI_FRAMER_TRACE
    mov [r13+TRACE_ID],rax
    mov esi,1024
    call initialize_context
    mov rbx,r15
    mov r15,[rbx+UI_FIXED_PARENT]
    mov esi,4096
    call initialize_context
    lea rdi,[r15+OUTPUT]
    mov esi,1024
    call grow_descriptor
    mov r15,[rbx+UI_FIXED_FRAMER]
    mov esi,512
    call initialize_context
    mov r15,rbx
    /* This boot record exposes actual process/context identities only. It is
     * never accepted back as a capability, completion, raw FD, or ACK. */
    lea rdi,[r15+ACK]
    mov esi,3
    call protect_descriptor
    mov r12,[r15+ACK+8]
    mov rax,UI_BOOT_MAGIC
    mov [r12],rax
    mov rax,[r15+UI_PROCESS]
    mov [r12+8],rax
    mov qword ptr [r12+16],6
    mov qword ptr [r12+24],7
    mov qword ptr [r12+32],8
    mov qword ptr [r12+40],9
    mov qword ptr [r12+48],1
    mov qword ptr [r12+56],4096
    lea rdi,[r15+ACK]
    mov esi,1
    call protect_descriptor
    mov qword ptr [r15+IO_LENGTH],64
    mov edi,1
    lea rsi,[r15+IO_LENGTH]
    mov edx,8
    call write_all
    mov edi,1
    mov rsi,[r15+ACK+8]
    mov edx,64
    call write_all
    jmp .Luij_next_user

/* A frame is u64 byte length, then exactly64B HIAUIP01 header + original USER.
 * command1 is role6 original USER; command2 is role7 BEGIN, never an ACK.
 * Caller-supplied process identity is required to be zero and is replaced
 * with the actual captured getpid at the one new role7 BEGIN copy boundary.
 */
.Luij_next_user:
    cmp qword ptr [r15+ROLE],9
    jne protocol_failure
    mov rdi,[r15+CONTROL_FD]
    lea rsi,[r15+IO_LENGTH]
    mov edx,8
    mov r10d,1
    call read_exact
    test eax,eax
    jnz normal_exit
    cmp qword ptr [r15+UI_PARENT_ACTIVE],0
    jne protocol_failure
    cmp qword ptr [r15+IO_LENGTH],64
    jb protocol_failure
    lea rdi,[r15+UI_USER]
    call release_descriptor
    lea rdi,[r15+UI_USER]
    mov rsi,[r15+IO_LENGTH]
    call allocate_descriptor
    mov rdi,[r15+CONTROL_FD]
    mov rsi,[r15+UI_USER+8]
    mov rdx,[r15+IO_LENGTH]
    xor r10d,r10d
    call read_exact
    lea rdi,[r15+UI_USER]
    call check_descriptor
    mov r12,[r15+UI_USER+8]
    mov rax,UI_TRANSPORT_MAGIC
    cmp [r12],rax
    jne protocol_failure
    mov rax,[r15+UI_USER+16]
    sub rax,64
    cmp [r12+16],rax
    jne protocol_failure
    xor eax,eax
    mov ecx,24
.Luij_user_reserved:
    or rax,[r12+rcx]
    add rcx,8
    cmp rcx,64
    jb .Luij_user_reserved
    test rax,rax
    jnz protocol_failure
    mov rax,[r12+8]
    cmp rax,1
    je .Luij_user_kind_valid
    cmp rax,2
    jne protocol_failure
.Luij_user_kind_valid:
    mov [r15+UI_USER_KIND],rax
    cmp qword ptr [r15+UI_TRANSPORT_CALL],-1
    je protocol_failure
    inc qword ptr [r15+UI_TRANSPORT_CALL]
    lea rdi,[r15+UI_USER]
    mov esi,1
    call protect_descriptor
    cmp qword ptr [r15+UI_USER_KIND],1
    je .Luij_user_fs
    jmp .Luij_user_parent

.Luij_user_fs:
    mov r13,[r15+UI_FIXED_FS]
    call .Lnamespace_uij_member
    cmp qword ptr [r13+UI_INFLIGHT],0
    jne protocol_failure
    mov r12,[r15+UI_USER+8]
    mov rbx,[r12+16]
    add rbx,128
    jc allocation_failure
    lea rdi,[r13+REQUEST]
    call release_descriptor
    lea rdi,[r13+REQUEST]
    mov rsi,rbx
    call allocate_descriptor
    mov rbx,[r13+REQUEST+8]
    mov rax,JOIN_CHANNEL
    mov [rbx],rax
    mov qword ptr [rbx+8],1
    mov rcx,[r12+16]
    mov [rbx+32],rcx
    mov rax,[r15+NSML_PAGE]
    mov [rbx+88],rax
    lea rdi,[rbx+128]
    lea rsi,[r12+64]
    rep movsb
    lea rdi,[r13+REQUEST]
    mov esi,1
    call protect_descriptor
    call .Luij_member_current_request
    mov rcx,[r15+UI_TRANSPORT_CALL]
    xor edx,edx
    call .Lnamespace_uij_begin
    mov qword ptr [r13+UI_RETURN_EDGE],1
    mov r15,r13
    jmp outer_invoke

.Luij_user_parent:
    mov r12,[r15+UI_USER+8]
    cmp qword ptr [r12+16],512
    jb protocol_failure
    mov rax,UI_PARENT_MAGIC
    cmp [r12+64],rax
    jne protocol_failure
    cmp qword ptr [r12+72],1
    jne protocol_failure
    cmp qword ptr [r12+248],0
    jne protocol_failure
    mov r13,[r15+UI_FIXED_PARENT]
    call .Lnamespace_uij_member
    cmp qword ptr [r13+UI_INFLIGHT],0
    jne protocol_failure
    lea rdi,[r13+REQUEST]
    lea rsi,[r15+UI_USER]
    mov edx,64
    mov rcx,[r12+16]
    call .Luij_copy_view
    lea rdi,[r13+REQUEST]
    mov esi,3
    call protect_descriptor
    mov rax,[r15+UI_PROCESS]
    mov rbx,[r13+REQUEST+8]
    mov [rbx+184],rax
    lea rdi,[r13+REQUEST]
    call check_descriptor
    lea rdi,[r13+REQUEST]
    mov esi,1
    call protect_descriptor
    call .Luij_member_current_request
    mov rcx,[r15+UI_TRANSPORT_CALL]
    xor edx,edx
    call .Lnamespace_uij_begin
    mov qword ptr [r15+UI_PARENT_ACTIVE],1
    mov r15,r13
    jmp .Luij_parent_invoke

.Luij_parent_invoke:
    call invoke_image
    cmp qword ptr [r15+OUTPUT+16],256
    jb protocol_failure
    mov r12,[r15+OUTPUT+8]
    mov rax,UI_PARENT_MAGIC
    cmp [r12],rax
    jne protocol_failure
    mov rax,[r15+ENTRY_RETURN]
    cmp [r12+8],rax
    jne protocol_failure
    cmp eax,2
    je .Luij_parent_grow
    cmp eax,1
    je .Luij_parent_pending
    test eax,eax
    je .Luij_parent_terminal
    cmp eax,0xfffffffd
    jne protocol_failure
.Luij_parent_terminal:
    mov r13,r15
    mov r15,[r13+UI_MASTER]
    call .Lnamespace_uij_complete
    mov qword ptr [r15+UI_PARENT_ACTIVE],0
    jmp .Luij_publish_member_output

.Luij_parent_grow:
    lea rax,[r15+REQUEST]
    cmp [r15+CURRENT_DESC],rax
    jne protocol_failure
    mov r13,[r12+136]
    mov r14,[r12+144]
    cmp r13,4096
    jb protocol_failure
    cmp r14,256
    jb protocol_failure
    cmp r13,[r15+WORK+16]
    ja .Luij_parent_growth_progress
    cmp r14,[r15+OUTPUT+16]
    jbe protocol_failure
.Luij_parent_growth_progress:
    lea rdi,[r15+WORK]
    mov rsi,r13
    call grow_descriptor
    lea rdi,[r15+OUTPUT]
    mov rsi,r14
    call grow_descriptor
    jmp .Luij_parent_invoke

.Luij_parent_pending:
    mov r13,r15
    mov r15,[r13+UI_MASTER]
    call .Lnamespace_uij_complete
    lea rdi,[r15+UI_CAP_PARENT]
    call .Lnamespace_uij_capture
    mov r13,[r15+UI_FIXED_FS]
    lea rdi,[r15+UI_CAP_FS]
    call .Lnamespace_uij_capture
    cmp qword ptr [r15+UI_ROOT_CALL],-1
    je protocol_failure
    inc qword ptr [r15+UI_ROOT_CALL]
    mov qword ptr [r15+UI_EVENT_ACTION],0
    mov rbx,256
    add rbx,[r15+UI_CAP_PARENT+16]
    jc allocation_failure
    add rbx,[r15+UI_CAP_FS+16]
    jc allocation_failure
    lea rdi,[r15+REQUEST]
    call release_descriptor
    lea rdi,[r15+REQUEST]
    mov rsi,rbx
    call allocate_descriptor
    mov r12,[r15+REQUEST+8]
    mov rax,UI_CHANNEL_MAGIC
    mov [r12],rax
    mov qword ptr [r12+8],1
    call .Luij_root_header
    mov r13,[r15+UI_FIXED_FRAMER]
    call .Lnamespace_uij_member
    mov rax,[r13+UI_ACTUAL_ID]
    mov [r12+64],rax
    mov rax,[r13+CONTEXT_SEQUENCE]
    mov [r12+72],rax
    mov rax,[r13+ENTRY_SERIAL]
    mov [r12+80],rax
    mov rax,[r15+UI_CAP_PARENT+16]
    mov [r12+88],rax
    mov rax,[r15+UI_CAP_FS+16]
    mov [r12+96],rax
    lea rdi,[r12+256]
    mov rsi,[r15+UI_CAP_PARENT+8]
    mov rcx,[r15+UI_CAP_PARENT+16]
    rep movsb
    mov rsi,[r15+UI_CAP_FS+8]
    mov rcx,[r15+UI_CAP_FS+16]
    rep movsb
    call .Luij_root_request_ready
    jmp .Luij_root_invoke

/* Called only by the actual old outer terminal. The old nested context
 * machinery has finished, with the original REQUEST and actual O/W frozen. */
.Luij_fs_terminal:
    mov r13,r15
    mov r15,[r13+UI_MASTER]
    call .Lnamespace_uij_complete
    mov rax,[r13+UI_RETURN_EDGE]
    mov qword ptr [r13+UI_RETURN_EDGE],0
    cmp rax,1
    je .Luij_publish_member_output
    cmp rax,2
    jne protocol_failure
    cmp [r15+UI_PENDING_MEMBER],r13
    jne protocol_failure
    jmp .Luij_child_capture

/* The exposed development response is the exact actual member output only.
 * A non-raw parent pending stays active. No new input can resume it as an ACK. */
.Luij_publish_member_output:
    call .Lnamespace_uij_member
    call .Lnamespace_uij_frozen_operands
    mov rax,[r13+OUTPUT+16]
    mov [r15+IO_LENGTH],rax
    mov edi,1
    lea rsi,[r15+IO_LENGTH]
    mov edx,8
    call write_all
    mov edi,1
    mov rsi,[r13+OUTPUT+8]
    mov rdx,[r13+OUTPUT+16]
    call write_all
    jmp .Luij_next_user

.Luij_root_invoke:
    call invoke_image
    cmp qword ptr [r15+OUTPUT+16],256
    jne protocol_failure
    mov r12,[r15+OUTPUT+8]
    mov rax,UI_EVENT_MAGIC
    cmp [r12],rax
    jne protocol_failure
    mov rax,[r15+ENTRY_RETURN]
    cmp [r12+8],rax
    jne protocol_failure
    cmp qword ptr [r12+248],0
    jne protocol_failure
    mov rax,[r15+UI_SCOPE_A]
    cmp [r12+16],rax
    jne protocol_failure
    mov rax,[r15+UI_SCOPE_B]
    cmp [r12+24],rax
    jne protocol_failure
    mov rax,[r15+UI_ROOT_CALL]
    cmp [r12+32],rax
    jne protocol_failure
    mov rax,[r15+UI_ACTUAL_ID]
    cmp [r12+40],rax
    jne protocol_failure
    mov rax,[r15+CONTEXT_SEQUENCE]
    cmp [r12+48],rax
    jne protocol_failure
    mov rax,[r15+UI_PROCESS]
    cmp [r12+56],rax
    jne protocol_failure
    mov rax,[r15+ENTRY_RETURN]
    cmp eax,2
    je .Luij_root_grow
    call .Luij_live_parent
    mov rax,[r15+ENTRY_RETURN]
    cmp eax,1
    je .Luij_dispatch_child
    test eax,eax
    je .Luij_parent_ack
    cmp eax,3
    jne protocol_failure
    /* No implementation or fabricated ACK for the other ten parent effects. */
    cmp qword ptr [r12+72],6
    jne protocol_failure
    mov r13,[r15+UI_FIXED_PARENT]
    jmp .Luij_publish_member_output

.Luij_root_grow:
    lea rax,[r15+REQUEST]
    cmp [r15+CURRENT_DESC],rax
    jne protocol_failure
    mov r13,[r12+160]
    mov r14,[r12+168]
    cmp r13,1024
    jb protocol_failure
    cmp r14,256
    jne protocol_failure
    cmp r13,[r15+WORK+16]
    ja .Luij_root_growth_progress
    cmp r14,[r15+OUTPUT+16]
    jbe protocol_failure
.Luij_root_growth_progress:
    lea rdi,[r15+WORK]
    mov rsi,r13
    call grow_descriptor
    lea rdi,[r15+OUTPUT]
    mov rsi,r14
    call grow_descriptor
    jmp .Luij_root_invoke

/* HIA's binding refers to this still-live completed parent entry. These fixed
 * metadata/value comparisons do not assign a semantic operation or syscall. */
.Luij_live_parent:
    mov r13,[r15+UI_FIXED_PARENT]
    call .Lnamespace_uij_member
    cmp qword ptr [r13+UI_COMPLETION_VALID],1
    jne protocol_failure
    cmp qword ptr [r13+UI_INFLIGHT],0
    jne protocol_failure
    cmp qword ptr [r13+ENTRY_RETURN],1
    jne protocol_failure
    cmp qword ptr [r13+OUTPUT+32],1
    jne protocol_failure
    cmp qword ptr [r13+OUTPUT+16],512
    jb protocol_failure
    lea rdi,[r13+OUTPUT]
    call check_descriptor
    mov rax,[r13+UI_ACTUAL_ID]
    cmp [r12+208],rax
    jne protocol_failure
    mov rax,[r13+CONTEXT_SEQUENCE]
    cmp [r12+216],rax
    jne protocol_failure
    mov rax,[r13+ENTRY_SERIAL]
    cmp [r12+224],rax
    jne protocol_failure
    cmp [r13+UI_COMPLETION_SERIAL],rax
    jne protocol_failure
    mov rbx,[r13+OUTPUT+8]
    mov rax,[rbx+32]
    cmp [r12+232],rax
    jne protocol_failure
    mov rax,[rbx+40]
    cmp [r12+240],rax
    jne protocol_failure
    ret

.Luij_dispatch_child:
    mov rax,[r15+UI_EVENT_ACTION]
    cmp rax,-1
    je protocol_failure
    inc rax
    cmp [r12+64],rax
    jne protocol_failure
    mov [r15+UI_EVENT_ACTION],rax
    mov rax,[r12+80]
    cmp rax,6
    je .Luij_select_shared_fs
    cmp rax,8
    jne protocol_failure
    mov r13,[r15+UI_FIXED_FRAMER]
    jmp .Luij_selected_member
.Luij_select_shared_fs:
    mov r13,[r15+UI_FIXED_FS]
.Luij_selected_member:
    call .Lnamespace_uij_member
    cmp qword ptr [r13+UI_INFLIGHT],0
    jne protocol_failure
    mov rax,[r13+UI_ACTUAL_ID]
    cmp [r12+120],rax
    jne protocol_failure
    mov rax,[r13+CONTEXT_SEQUENCE]
    cmp [r12+128],rax
    jne protocol_failure
    mov rax,[r13+ENTRY_SERIAL]
    cmp [r12+136],rax
    jne protocol_failure
    mov [r15+UI_PENDING_MEMBER],r13
    cmp qword ptr [r12+96],0
    je protocol_failure
    lea rdi,[r15+WORK]
    mov rsi,[r12+88]
    mov rdx,[r12+96]
    call .Luij_view_check
    cmp qword ptr [r13+ROLE],6
    je .Luij_check_shared_shape
    lea rdi,[r15+WORK]
    mov rsi,[r12+104]
    mov rdx,[r12+112]
    call .Luij_view_check
    mov rax,[r12+112]
    test rax,rax
    jz protocol_failure
    cmp [r12+144],rax
    jne protocol_failure
    cmp qword ptr [r12+152],512
    jb protocol_failure
    jmp .Luij_copy_child_inputs
.Luij_check_shared_shape:
    mov rax,[r12+104]
    or rax,[r12+112]
    jnz protocol_failure
    cmp qword ptr [r12+144],256
    jb protocol_failure
    cmp qword ptr [r12+152],4096
    jb protocol_failure
.Luij_copy_child_inputs:
    lea rdi,[r13+REQUEST]
    lea rsi,[r15+WORK]
    mov rdx,[r12+88]
    mov rcx,[r12+96]
    call .Luij_copy_view
    cmp qword ptr [r13+ROLE],6
    je .Luij_grow_child_output
    lea rdi,[r13+OUTPUT]
    lea rsi,[r15+WORK]
    mov rdx,[r12+104]
    mov rcx,[r12+112]
    call .Luij_copy_view
    jmp .Luij_grow_child_work
.Luij_grow_child_output:
    lea rdi,[r13+OUTPUT]
    mov rsi,[r12+144]
    call grow_descriptor
.Luij_grow_child_work:
    lea rdi,[r13+WORK]
    mov rsi,[r12+152]
    call grow_descriptor
    call .Luij_member_current_request
    mov rcx,[r15+UI_ROOT_CALL]
    mov rdx,[r15+UI_EVENT_ACTION]
    call .Lnamespace_uij_begin
    cmp qword ptr [r13+ROLE],6
    je .Luij_enter_shared_fs
    mov r15,r13
    call invoke_image
    mov r13,r15
    mov r15,[r13+UI_MASTER]
    call .Lnamespace_uij_complete
    jmp .Luij_child_capture
.Luij_enter_shared_fs:
    mov qword ptr [r13+UI_RETURN_EDGE],2
    mov r15,r13
    jmp outer_invoke

.Luij_child_capture:
    cmp [r15+UI_PENDING_MEMBER],r13
    jne protocol_failure
    mov rax,[r15+UI_ROOT_CALL]
    cmp [r13+UI_REQUEST_CALL],rax
    jne protocol_failure
    mov rax,[r15+UI_EVENT_ACTION]
    cmp [r13+UI_REQUEST_ACTION],rax
    jne protocol_failure
    lea rdi,[r15+UI_CAP_CHILD]
    call .Lnamespace_uij_capture
    mov rbx,[r15+UI_CAP_CHILD+16]
    add rbx,256
    jc allocation_failure
    lea rdi,[r15+REQUEST]
    call release_descriptor
    lea rdi,[r15+REQUEST]
    mov rsi,rbx
    call allocate_descriptor
    mov r12,[r15+REQUEST+8]
    mov rax,UI_CHANNEL_MAGIC
    mov [r12],rax
    mov qword ptr [r12+8],2
    call .Luij_root_header
    mov rax,[r15+UI_EVENT_ACTION]
    mov [r12+64],rax
    mov rax,[r15+UI_CAP_CHILD+16]
    mov [r12+72],rax
    lea rdi,[r12+256]
    mov rsi,[r15+UI_CAP_CHILD+8]
    mov rcx,[r15+UI_CAP_CHILD+16]
    rep movsb
    mov qword ptr [r15+UI_PENDING_MEMBER],0
    call .Luij_root_request_ready
    jmp .Luij_root_invoke

.Luij_parent_ack:
    cmp qword ptr [r12+72],5
    jne protocol_failure
    mov rax,[r15+UI_EVENT_ACTION]
    cmp [r12+64],rax
    jne protocol_failure
    cmp qword ptr [r12+184],512
    jne protocol_failure
    lea rdi,[r15+WORK]
    mov rsi,[r12+176]
    mov edx,512
    call .Luij_view_check
    mov r13,[r15+UI_FIXED_PARENT]
    lea rdi,[r13+REQUEST]
    lea rsi,[r15+WORK]
    mov rdx,[r12+176]
    mov ecx,512
    call .Luij_copy_view
    call .Luij_member_current_request
    mov rcx,[r15+UI_ROOT_CALL]
    mov rdx,[r15+UI_EVENT_ACTION]
    call .Lnamespace_uij_begin
    mov r15,r13
    jmp .Luij_parent_invoke

.Luij_root_header:
    mov rax,[r15+UI_SCOPE_A]
    mov [r12+16],rax
    mov rax,[r15+UI_SCOPE_B]
    mov [r12+24],rax
    mov rax,[r15+UI_ROOT_CALL]
    mov [r12+32],rax
    mov rax,[r15+UI_ACTUAL_ID]
    mov [r12+40],rax
    mov rax,[r15+CONTEXT_SEQUENCE]
    mov [r12+48],rax
    mov rax,[r15+UI_PROCESS]
    mov [r12+56],rax
    ret

.Luij_root_request_ready:
    lea rdi,[r15+REQUEST]
    call check_descriptor
    lea rdi,[r15+REQUEST]
    mov esi,1
    call protect_descriptor
    lea rax,[r15+REQUEST]
    mov [r15+CURRENT_DESC],rax
    mov rax,[r15+REQUEST+16]
    mov [r15+CURRENT_LENGTH],rax
    ret

.Luij_member_current_request:
    lea rax,[r13+REQUEST]
    mov [r13+CURRENT_DESC],rax
    mov rax,[r13+REQUEST+16]
    mov [r13+CURRENT_LENGTH],rax
    ret

/* Full logical range and readonly source permission precede any copy/free.
 * Inputs: RDI is an internally selected descriptor, RSI offset, RDX length.
 * Callee saves every input register other than RAX; no OS side effect. */
.Luij_view_check:
    push rcx
    push rdx
    push rsi
    cmp qword ptr [rdi],0
    je protocol_failure
    cmp qword ptr [rdi+32],1
    jne protocol_failure
    cmp rsi,[rdi+16]
    ja protocol_failure
    mov rax,[rdi+16]
    sub rax,rsi
    cmp rdx,rax
    ja protocol_failure
    mov rax,[rdi+8]
    add rax,rsi
    jc protocol_failure
    add rax,rdx
    jc protocol_failure
    call check_descriptor
    pop rsi
    pop rdx
    pop rcx
    ret

/* Copy a complete issued logical view into a distinct owned descriptor.
 * RDI target, RSI private source descriptor, RDX offset, RCX length.
 * No caller-supplied pointer enters this helper. Each caller fixes the target
 * to REQUEST or the role8 readonly second operand, with no inflight member.
 */
.Luij_copy_view:
    push rbx
    push r12
    push r13
    push r14
    mov rbx,rdi
    mov r12,rsi
    mov r13,rdx
    mov r14,rcx
    cmp rbx,r12
    je protocol_failure
    mov rdi,r12
    mov rsi,r13
    mov rdx,r14
    call .Luij_view_check
    mov rdi,rbx
    call release_descriptor
    mov rdi,rbx
    mov rsi,r14
    call allocate_descriptor
    mov rsi,[r12+8]
    add rsi,r13
    jc protocol_failure
    mov rdi,[rbx+8]
    mov rcx,r14
    rep movsb
    mov rdi,rbx
    call check_descriptor
    mov rdi,rbx
    mov esi,1
    call protect_descriptor
    pop r14
    pop r13
    pop r12
    pop rbx
    ret
