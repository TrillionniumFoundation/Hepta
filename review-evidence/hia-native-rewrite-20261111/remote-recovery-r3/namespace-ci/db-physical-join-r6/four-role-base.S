/* NEW fixed DMS7 + Map3 + memory1 + FS5 join carrier, source r1.
 * Four private RWW roles: FS1, Map2, memory3 and DMS4. DMS HIA creates and
 * retires dynamic per-node contexts and owns all database/WAL/map policy.
 * Actual immutable completed REQUEST/O/W capsules alone enter child channels.
 * Raw stdin can supply USER only; no external ACK, node pointer or address.
 * The lower memory registry protects actual extents/context lifetimes only.
 * No SQL/root/migration/full DB inode/deferred-close policy is added here.
 * Source-only until its own assembler, B3, VM and physical controls complete.
 */
.intel_syntax noprefix
.section .text
.global executor_start,image_table,executor_end

/* Descriptor: raw mapping, logical address, logical capacity, mapping bytes,
 * mprotect flags. Guard pages surround a page-rounded area with 16-byte
 * canaries immediately before and after the logical data. */
.equ REQUEST,0
.equ OUTPUT,40
.equ WORK,80
.equ ACK,120
.equ TEMP,160
.equ CONTROL_FD,256
.equ CURRENT_DESC,264
.equ CURRENT_LENGTH,272
.equ ENTRY_SERIAL,280
.equ ENTRY_RETURN,288
.equ ACK_LENGTH,296
.equ PRIMITIVE_NUMBER,304
.equ PRIMITIVE_RETURN,312
.equ PRIMITIVE_PAYLOAD,320
.equ PRIMITIVE_OP,328
.equ PARENT_PID,336
.equ LAST_SYSSEQ,344
.equ ROLE,352
.equ ROOT_LINK,360
.equ TRACE_ID,368
.equ SELECTED_CHILD,376
.equ IO_LENGTH,384
.equ USER_LENGTH,392
.equ LAST_ACTION,400
.equ CHILD_REPLY_SIZE,408
.equ LAST_MEMORY_CALL,2480
.equ DMS_MAGIC,0x33304d444e414948
.equ MAP_MAGIC,0x3130504d53414948
.equ MEM_MAGIC,0x31304c4d4e414948
.equ MEM_CHANNEL,0x3130584d4e414948
.equ CHANNEL_MAGIC,0x333058444e414948
.equ DMS_TRACE,0x333054444e414948
.equ MAP_TRACE,0x3130544d53414948
.equ MEM_TRACE,0x3130544d4e414948
.equ PENDING_ROLE,416
.equ PENDING_NODE,424
.equ PENDING_CREATE,432
.equ PENDING_STAGE,440
.equ PENDING_SOURCE,448
.equ PENDING_LEASE,456
.equ RETIRE_COUNT,464
.equ RETIRE_QUARANTINE,472
.equ RETIRE_MASK,480
.equ RETIRE_NODE,488
.equ CONTEXT_NODE,2400
.equ CONTEXT_SEQUENCE,2408
.equ CONTEXT_NEXT,2416
.equ CONTEXT_RETIRED,2424
.equ CONTEXT_HEAD,2432
.equ NEXT_CONTEXT_SEQUENCE,2440
.equ RETIRE_SEQUENCE,2448
.equ CONTEXT_QUARANTINE,2456
.equ TRACE_HEADER,512
.equ SYSCALL_SCRATCH,640
.equ HIA_MAGIC,0x333052464e414948
.equ TRACE_MAGIC,0x333054464e414948
.equ CANARY,0x7a19b5d3e6824c0f

executor_start:
    /* Kernel-issued AT_PAGESZ is captured before changing the initial stack.
     * This immutable x86-64 Linux template uses 4096-byte guard pages. */
    mov rbx,rsp
    mov rcx,[rbx]
    lea rbx,[rbx+rcx*8+16]
find_environment_end:
    cmp qword ptr [rbx],0
    je environment_end
    add rbx,8
    jmp find_environment_end
environment_end:
    add rbx,8
    xor r13d,r13d
find_auxiliary_page:
    mov rax,[rbx]
    test rax,rax
    jz auxiliary_page_ready
    cmp rax,6
    jne next_auxiliary
    test r13,r13
    jnz early_allocation_failure
    mov r13,[rbx+8]
next_auxiliary:
    add rbx,16
    jmp find_auxiliary_page
auxiliary_page_ready:
    cmp r13,4096
    jne early_allocation_failure
    and rsp,-16
    cld
    /* The root DMS and one FS context are fixed. Map/memory contexts are
     * unbounded linked allocations created only by an actual HIA request. */
    xor edi,edi
    mov esi,8192
    mov edx,3
    mov r10d,0x22
    mov r8,-1
    xor r9d,r9d
    mov eax,9
    syscall
    cmp rax,-4095
    jae early_allocation_failure
    mov r15,rax
    mov [r15+ROOT_LINK],rax
    mov [r15+NSML_PAGE],r13
    mov qword ptr [r15+ROLE],4
    mov qword ptr [r15+CONTEXT_SEQUENCE],1
    mov qword ptr [r15+NEXT_CONTEXT_SEQUENCE],2
    mov rax,DMS_TRACE
    mov [r15+TRACE_ID],rax
    mov eax,110
    syscall
    cmp rax,1
    jbe protocol_failure
    mov [r15+PARENT_PID],rax
    mov edi,1
    mov esi,9
    xor edx,edx
    xor r10d,r10d
    xor r8d,r8d
    mov eax,157
    syscall
    test rax,rax
    jne protocol_failure
    mov eax,110
    syscall
    cmp rax,[r15+PARENT_PID]
    jne protocol_failure
    xor edi,edi
    mov esi,1030
    mov edx,3
    mov eax,72
    syscall
    cmp rax,-4095
    jae transport_failure
    mov [r15+CONTROL_FD],rax
    xor edi,edi
    mov eax,3
    syscall
    test rax,rax
    jne transport_failure
    mov r14,r15
    lea r15,[r14+4096]
    mov [r15+ROOT_LINK],r14
    mov qword ptr [r15+ROLE],1
    mov qword ptr [r15+CONTEXT_SEQUENCE],2
    mov rax,TRACE_MAGIC
    mov [r15+TRACE_ID],rax
    mov esi,512
    call initialize_context
    mov r15,r14
    mov esi,8192
    call initialize_context
    lea rdi,[r15+OUTPUT]
    mov esi,1280
    call grow_descriptor

next_request:
    mov rdi,[r15+CONTROL_FD]
    lea rsi,[r15+IO_LENGTH]
    mov edx,8
    mov r10d,1
    call read_exact
    test eax,eax
    jnz normal_exit
    mov rax,[r15+IO_LENGTH]
    mov [r15+USER_LENGTH],rax
    add rax,64
    jc allocation_failure
    mov [r15+IO_LENGTH],rax
    lea rdi,[r15+REQUEST]
    call release_descriptor
    lea rdi,[r15+REQUEST]
    mov rsi,[r15+IO_LENGTH]
    call allocate_descriptor
    mov r12,[r15+REQUEST+8]
    mov rax,CHANNEL_MAGIC
    mov [r12],rax
    mov qword ptr [r12+8],1
    mov rax,[r15+USER_LENGTH]
    mov [r12+32],rax
    mov rax,[r15+NSML_PAGE]
    mov [r12+48],rax
    mov rdi,[r15+CONTROL_FD]
    lea rsi,[r12+64]
    mov rdx,[r15+USER_LENGTH]
    xor r10d,r10d
    call read_exact
    lea rdi,[r15+REQUEST]
    mov esi,1
    call protect_descriptor
    lea rax,[r15+REQUEST]
    mov [r15+CURRENT_DESC],rax
    mov rax,[r15+REQUEST+16]
    mov [r15+CURRENT_LENGTH],rax

invoke_coordinator:
    call invoke_image
    mov r12,[r15+OUTPUT+8]
    mov rax,DMS_MAGIC
    cmp [r12],rax
    jne protocol_failure
    mov rax,[r15+ENTRY_RETURN]
    cmp [r12+8],rax
    jne protocol_failure
    cmp qword ptr [r12+176],3
    jne protocol_failure
    mov rdx,[r15+OUTPUT+16]
    sub rdx,256
    jc protocol_failure
    cmp [r12+128],rdx
    ja protocol_failure
    cmp eax,2
    je coordinator_grow
    cmp eax,1
    je coordinator_filesystem
    cmp eax,5
    je coordinator_private_child
    cmp eax,6
    je coordinator_retire
    test eax,eax
    je coordinator_return
    cmp eax,0xfffffffd
    jne protocol_failure
coordinator_return:
    mov rax,[r15+OUTPUT+16]
    mov [r15+IO_LENGTH],rax
    mov edi,1
    lea rsi,[r15+IO_LENGTH]
    mov edx,8
    call write_all
    mov edi,1
    mov rsi,[r15+OUTPUT+8]
    mov rdx,[r15+OUTPUT+16]
    call write_all
    jmp next_request

coordinator_grow:
    /* Replay precisely the same actual immutable input, including a complete
     * child capsule. Neither an image producer nor a syscall is repeated. */
    mov r13,[r12+80]
    mov r14,[r12+88]
    cmp r13,[r15+WORK+16]
    ja coordinator_growth_progress
    cmp r14,[r15+OUTPUT+16]
    jbe protocol_failure
coordinator_growth_progress:
    lea rdi,[r15+WORK]
    mov rsi,r13
    call grow_descriptor
    lea rdi,[r15+OUTPUT]
    mov rsi,r14
    call grow_descriptor
    jmp invoke_coordinator

check_root_action:
    mov rax,[r12+40]
    cmp rax,[r15+LAST_ACTION]
    jbe protocol_failure
    mov [r15+LAST_ACTION],rax
    ret

coordinator_filesystem:
    call check_root_action
    cmp qword ptr [r12+48],1
    jne protocol_failure
    mov qword ptr [r15+PENDING_ROLE],1
    mov qword ptr [r15+PENDING_NODE],0
    mov qword ptr [r15+PENDING_CREATE],0
    mov rax,[r12+56]
    mov [r15+PENDING_STAGE],rax
    mov rax,[r12+72]
    mov [r15+PENDING_LEASE],rax
    lea r13,[r15+4096]
    jmp selected_child

coordinator_private_child:
    call check_root_action
    mov rax,[r12+48]
    cmp rax,2
    jb protocol_failure
    cmp rax,3
    ja protocol_failure
    mov [r15+PENDING_ROLE],rax
    mov rdx,[r12+56]
    test rdx,rdx
    jz protocol_failure
    mov [r15+PENDING_NODE],rdx
    mov rax,[r12+88]
    cmp rax,1
    ja protocol_failure
    mov [r15+PENDING_CREATE],rax
    mov rax,[r12+112]
    mov [r15+PENDING_STAGE],rax
    mov rax,[r12+120]
    mov [r15+PENDING_LEASE],rax
    mov rax,[r15+PENDING_ROLE]
    call find_context
    cmp qword ptr [r15+PENDING_CREATE],0
    jne create_selected_context
    test r13,r13
    jz protocol_failure
    jmp selected_child
create_selected_context:
    test r13,r13
    jnz protocol_failure
    cmp qword ptr [r12+72],1536
    jb protocol_failure
    mov rax,[r12+80]
    cmp rax,256
    jb protocol_failure
    cmp qword ptr [r15+PENDING_ROLE],2
    jne create_output_valid
    cmp rax,257
    jb protocol_failure
create_output_valid:
    cmp qword ptr [r15+NEXT_CONTEXT_SEQUENCE],-1
    je protocol_failure
    xor edi,edi
    mov esi,4096
    mov edx,3
    mov r10d,34
    mov r8,-1
    xor r9d,r9d
    mov eax,9
    syscall
    cmp rax,-4095
    jae allocation_failure
    mov r13,rax
    mov [r13+ROOT_LINK],r15
    mov rax,[r15+PENDING_ROLE]
    mov [r13+ROLE],rax
    mov rax,[r15+PENDING_NODE]
    mov [r13+CONTEXT_NODE],rax
    inc qword ptr [r15+NEXT_CONTEXT_SEQUENCE]
    mov rax,[r15+NEXT_CONTEXT_SEQUENCE]
    mov [r13+CONTEXT_SEQUENCE],rax
    mov rax,[r15+CONTEXT_HEAD]
    mov [r13+CONTEXT_NEXT],rax
    mov [r15+CONTEXT_HEAD],r13
    mov rax,MAP_TRACE
    cmp qword ptr [r13+ROLE],2
    je create_trace_ready
    mov rax,MEM_TRACE
create_trace_ready:
    mov [r13+TRACE_ID],rax
    mov [r15+SELECTED_CHILD],r13
    mov r14,r15
    mov r15,r13
    mov rsi,[r12+72]
    call initialize_context
    lea rdi,[r15+OUTPUT]
    mov rsi,[r12+80]
    call grow_descriptor
    mov r13,r15
    mov r15,r14

selected_child:
    mov rax,[r12+64]
    cmp rax,[r12+128]
    jne protocol_failure
    cmp rax,256
    jb protocol_failure
    mov [r15+PENDING_SOURCE],rax
    mov [r15+SELECTED_CHILD],r13
    lea rdi,[r13+REQUEST]
    call release_descriptor
    lea rdi,[r13+REQUEST]
    mov rsi,[r12+128]
    call allocate_descriptor
    mov rdi,[r13+REQUEST+8]
    lea rsi,[r12+256]
    mov rcx,[r12+128]
    rep movsb
    lea rdi,[r13+REQUEST]
    mov esi,1
    call protect_descriptor
    lea rax,[r13+REQUEST]
    mov [r13+CURRENT_DESC],rax
    mov rax,[r13+REQUEST+16]
    mov [r13+CURRENT_LENGTH],rax
    mov r15,r13
    cmp qword ptr [r15+ROLE],1
    je call_filesystem
    cmp qword ptr [r15+ROLE],2
    je call_map
    call run_memory
    jmp child_completed
call_map:
    call run_map
    jmp child_completed
call_filesystem:
    call run_filesystem
child_completed:
    /* Original issued REQUEST and actual completed O/W are independently
     * immutable. Internal primitive ACKs are not substituted for REQUEST. */
    call check_all_descriptors
    mov r13,r15
    mov r15,[r15+ROOT_LINK]
    cmp r13,[r15+SELECTED_CHILD]
    jne protocol_failure
    cmp qword ptr [r13+REQUEST+32],1
    jne protocol_failure
    cmp qword ptr [r13+OUTPUT+32],1
    jne protocol_failure
    cmp qword ptr [r13+WORK+32],1
    jne protocol_failure
    mov rax,[r13+REQUEST+16]
    cmp rax,[r15+PENDING_SOURCE]
    jne protocol_failure
    add rax,320
    jc allocation_failure
    add rax,[r13+OUTPUT+16]
    jc allocation_failure
    add rax,[r13+WORK+16]
    jc allocation_failure
    mov [r15+CHILD_REPLY_SIZE],rax
    lea rdi,[r15+ACK]
    mov rsi,rax
    call grow_descriptor
    lea rdi,[r15+ACK]
    mov esi,3
    call protect_descriptor
    mov rdi,[r15+ACK+8]
    mov rcx,[r15+ACK+16]
    xor eax,eax
    rep stosb
    mov r12,[r15+ACK+8]
    mov r13,[r15+SELECTED_CHILD]
    mov rax,CHANNEL_MAGIC
    mov [r12],rax
    mov rax,[r13+ROLE]
    mov [r12+16],rax
    mov edx,2
    cmp rax,1
    je child_origin_ready
    lea rdx,[rax+3]
child_origin_ready:
    mov [r12+8],rdx
    mov rax,[r13+ENTRY_RETURN]
    mov [r12+24],rax
    mov [r12+152],rax
    mov rax,[r15+CHILD_REPLY_SIZE]
    sub rax,64
    mov [r12+32],rax
    mov rax,[r13+ENTRY_SERIAL]
    mov [r12+40],rax
    mov [r12+160],rax
    mov rax,[r15+NSML_PAGE]
    mov [r12+48],rax
    mov rax,DMS_MAGIC
    mov [r12+64],rax
    mov rax,[r13+ROLE]
    mov [r12+120],rax
    mov edx,8
    cmp rax,1
    je child_command_ready
    lea rdx,[rax+15]
child_command_ready:
    mov [r12+72],rdx
    mov rbx,[r15+OUTPUT+8]
    mov rax,[rbx+16]
    mov [r12+80],rax
    mov rax,[rbx+24]
    mov [r12+88],rax
    mov rax,[rbx+32]
    mov [r12+96],rax
    mov rax,[rbx+40]
    mov [r12+104],rax
    mov rax,[r15+PENDING_LEASE]
    mov [r12+112],rax
    mov rax,[r13+REQUEST+16]
    mov [r12+128],rax
    mov rax,[r13+OUTPUT+16]
    mov [r12+136],rax
    mov rax,[r13+WORK+16]
    mov [r12+144],rax
    cmp qword ptr [r13+ROLE],1
    je child_metadata_ready
    mov rax,[r15+PENDING_NODE]
    cmp rax,[r13+CONTEXT_NODE]
    jne protocol_failure
    mov [r12+168],rax
    mov rax,[r15+PENDING_CREATE]
    mov [r12+176],rax
    mov rax,[r15+PENDING_STAGE]
    mov [r12+184],rax
child_metadata_ready:
    mov rax,[r15+CHILD_REPLY_SIZE]
    sub rax,320
    mov [r12+192],rax
    lea rdi,[r12+320]
    mov rsi,[r13+REQUEST+8]
    mov rcx,[r13+REQUEST+16]
    rep movsb
    mov rsi,[r13+OUTPUT+8]
    mov rcx,[r13+OUTPUT+16]
    rep movsb
    mov rsi,[r13+WORK+8]
    mov rcx,[r13+WORK+16]
    rep movsb
    call root_ack_ready
    jmp invoke_coordinator

root_ack_ready:
    call check_all_descriptors
    lea rdi,[r15+ACK]
    mov esi,1
    call protect_descriptor
    lea rax,[r15+ACK]
    mov [r15+CURRENT_DESC],rax
    mov rax,[r15+CHILD_REPLY_SIZE]
    mov [r15+CURRENT_LENGTH],rax
    ret

/* Root r15; actual role RAX and HIA-issued node identity RDX.
 * Only this private metadata registry chooses an already-created context.
 * No contents of a user header become an actual context address. */
find_context:
    mov r13,[r15+CONTEXT_HEAD]
find_context_next:
    test r13,r13
    jz find_context_done
    cmp qword ptr [r13+CONTEXT_RETIRED],0
    jne protocol_failure
    cmp [r13+ROLE],rax
    jne find_context_advance
    cmp [r13+CONTEXT_NODE],rdx
    je find_context_done
find_context_advance:
    mov r13,[r13+CONTEXT_NEXT]
    jmp find_context_next
find_context_done:
    ret

/* Called on the active context. Work capacity is the only supplied argument. */
initialize_context:
    push rbx
    mov rbx,rsi
    lea rdi,[r15+OUTPUT]
    mov esi,256
    call allocate_descriptor
    lea rdi,[r15+WORK]
    mov rsi,rbx
    call allocate_descriptor
    lea rdi,[r15+ACK]
    mov esi,512
    call allocate_descriptor
    pop rbx
    ret

/* One actual direct RWW image entry. Images are fixed at HIA publication.
 * The invocation has the original System V stack alignment at CALL. */
invoke_image:
    sub rsp,8
    inc qword ptr [r15+ENTRY_SERIAL]
    jz protocol_failure
    call check_all_descriptors
    lea rdi,[r15+OUTPUT]
    mov esi,3
    call protect_descriptor
    lea rdi,[r15+WORK]
    mov esi,3
    call protect_descriptor
    call trace_before
    mov rax,[r15+CURRENT_DESC]
    cmp qword ptr [rax+32],1
    jne protocol_failure
    mov rdi,[rax+8]
    mov rsi,[r15+CURRENT_LENGTH]
    cmp rsi,[rax+16]
    ja protocol_failure
    mov rdx,[r15+OUTPUT+8]
    mov rcx,[r15+OUTPUT+16]
    mov r8,[r15+WORK+8]
    mov r9,[r15+WORK+16]
    mov r10,[r15+ROLE]
    cmp r10,1
    jb protocol_failure
    cmp r10,4
    ja protocol_failure
    lea rax,[rip+.Limage_table]
    call qword ptr [rax+r10*8]
    mov eax,eax
    mov [r15+ENTRY_RETURN],rax
    call check_all_descriptors
    lea rdi,[r15+OUTPUT]
    mov esi,1
    call protect_descriptor
    lea rdi,[r15+WORK]
    mov esi,1
    call protect_descriptor
    call trace_after
    add rsp,8
    ret

run_map:
    sub rsp,8
invoke_map:
    call invoke_image
    mov r12,[r15+OUTPUT+8]
    mov rax,MAP_MAGIC
    cmp [r12],rax
    jne protocol_failure
    mov rax,[r15+ENTRY_RETURN]
    cmp [r12+8],rax
    jne protocol_failure
    cmp qword ptr [r12+184],1
    jne protocol_failure
    mov rdx,[r15+OUTPUT+16]
    sub rdx,256
    jc protocol_failure
    cmp [r12+128],rdx
    ja protocol_failure
    cmp eax,2
    je map_grow
    test eax,eax
    je map_return
    cmp eax,1
    je map_return
    cmp eax,0xfffffffd
    jne protocol_failure
map_return:
    add rsp,8
    ret
map_grow:
    lea rax,[r15+REQUEST]
    cmp [r15+CURRENT_DESC],rax
    jne protocol_failure
    mov r13,[r12+96]
    mov r14,[r12+104]
    cmp r13,[r15+WORK+16]
    ja map_growth_progress
    cmp r14,[r15+OUTPUT+16]
    jbe protocol_failure
map_growth_progress:
    lea rdi,[r15+WORK]
    mov rsi,r13
    call grow_descriptor
    lea rdi,[r15+OUTPUT]
    mov rsi,r14
    call grow_descriptor
    jmp invoke_map

run_memory:
    sub rsp,8
invoke_memory:
    call invoke_image
    mov r12,[r15+OUTPUT+8]
    mov rax,MEM_MAGIC
    cmp [r12],rax
    jne protocol_failure
    mov rax,[r15+ENTRY_RETURN]
    cmp [r12+8],rax
    jne protocol_failure
    /* The actual current context node must agree with the actual HIA event.
     * Invalid private frames are refused before any memory primitive. */
    mov rdx,[r15+CONTEXT_NODE]
    cmp [r12+56],rdx
    jne protocol_failure
    cmp eax,2
    je memory_grow
    cmp eax,1
    je memory_primitive
    test eax,eax
    je memory_return
    cmp eax,0xfffffffd
    jne protocol_failure
memory_return:
    add rsp,8
    ret
memory_grow:
    lea rax,[r15+REQUEST]
    cmp [r15+CURRENT_DESC],rax
    jne protocol_failure
    cmp qword ptr [r12+160],3
    jne protocol_failure
    mov r13,[r12+64]
    mov r14,[r12+72]
    cmp r13,[r15+WORK+16]
    ja memory_growth_progress
    cmp r14,[r15+OUTPUT+16]
    jbe protocol_failure
memory_growth_progress:
    lea rdi,[r15+WORK]
    mov rsi,r13
    call grow_descriptor
    lea rdi,[r15+OUTPUT]
    mov rsi,r14
    call grow_descriptor
    jmp invoke_memory

memory_primitive:
    cmp qword ptr [r12+160],2
    jne protocol_failure
    /* Action is local to one HIA memory call. The completed-call sequence is
     * monotone, while every new call starts its first primitive at action 1.
     * Calls without primitives may create gaps; old calls and repeated actions
     * remain rejected before any memory syscall or registry operation. */
    mov rdx,[r12+32]
    test rdx,rdx
    jz protocol_failure
    cmp rdx,[r15+LAST_MEMORY_CALL]
    jb protocol_failure
    ja memory_first_primitive_of_call
    mov rax,[r12+40]
    cmp rax,[r15+LAST_ACTION]
    jbe protocol_failure
    jmp memory_primitive_correlated
memory_first_primitive_of_call:
    cmp qword ptr [r12+40],1
    jne protocol_failure
memory_primitive_correlated:
    mov [r15+LAST_MEMORY_CALL],rdx
    mov rax,[r12+40]
    mov [r15+LAST_ACTION],rax
    cmp qword ptr [r15+LAST_SYSSEQ],-1
    je protocol_failure
    mov rax,[r12+64]
    cmp rax,1
    jb protocol_failure
    cmp rax,4
    ja protocol_failure
    mov [r15+PRIMITIVE_OP],rax
    lea rdi,[r15+ACK]
    mov esi,576
    call grow_descriptor
    lea rdi,[r15+ACK]
    mov esi,3
    call protect_descriptor
    mov rdi,[r15+ACK+8]
    mov rcx,[r15+ACK+16]
    xor eax,eax
    rep stosb
    inc qword ptr [r15+LAST_SYSSEQ]
    mov r13,[r15+OUTPUT+8]
    /* The helper gets actual metadata pointers; no HIA bytes are pointers to
     * metadata. Its immutable event remains the original O mapping. */
    mov r14,r15
    mov r15,[r15+ROOT_LINK]
    call namespace_memory_primitive
    mov r15,r14
    mov [r15+PRIMITIVE_RETURN],rax
    mov rbx,rax
    mov r12,[r15+OUTPUT+8]
    mov r13,[r15+ACK+8]
    mov rax,MEM_CHANNEL
    mov [r13],rax
    mov qword ptr [r13+8],2
    mov rax,[r15+PRIMITIVE_OP]
    mov [r13+16],rax
    mov [r13+128],rax
    mov qword ptr [r13+32],512
    mov rax,[r15+LAST_SYSSEQ]
    mov [r13+40],rax
    mov [r13+160],rax
    mov rax,MEM_MAGIC
    mov [r13+64],rax
    mov qword ptr [r13+72],3
    mov rax,[r12+16]
    mov [r13+80],rax
    mov rax,[r12+24]
    mov [r13+88],rax
    mov rax,[r12+32]
    mov [r13+96],rax
    mov rax,[r12+40]
    mov [r13+104],rax
    mov rax,[r12+48]
    mov [r13+112],rax
    mov rax,[r12+56]
    mov [r13+120],rax
    mov qword ptr [r13+168],256
    cmp rbx,-4095
    jae memory_primitive_error
    mov [r13+144],rbx
    jmp memory_primitive_ack
memory_primitive_error:
    neg rbx
    mov [r13+136],rbx
memory_primitive_ack:
    lea rdi,[r13+320]
    mov rsi,r12
    mov ecx,256
    rep movsb
    mov qword ptr [r15+ACK_LENGTH],576
    mov rax,[r15+PRIMITIVE_OP]
    mov qword ptr [r15+PRIMITIVE_NUMBER],0
    cmp rax,1
    jne memory_not_mmap
    mov qword ptr [r15+PRIMITIVE_NUMBER],9
memory_not_mmap:
    cmp rax,3
    jne memory_trace_ready
    mov qword ptr [r15+PRIMITIVE_NUMBER],11
memory_trace_ready:
    call check_all_descriptors
    lea rdi,[r15+ACK]
    mov esi,1
    call protect_descriptor
    call trace_primitive
    lea rax,[r15+ACK]
    mov [r15+CURRENT_DESC],rax
    mov qword ptr [r15+CURRENT_LENGTH],576
    jmp invoke_memory

run_filesystem:
    sub rsp,8
invoke_fs:
    call invoke_image
    mov r12,[r15+OUTPUT+8]
    mov rax,HIA_MAGIC
    cmp [r12],rax
    jne protocol_failure
    mov rax,[r15+ENTRY_RETURN]
    cmp [r12+8],rax
    jne protocol_failure
    cmp qword ptr [r12+176],3
    jne protocol_failure
    mov rcx,200
event_reserved:
    cmp qword ptr [r12+rcx],0
    jne protocol_failure
    add rcx,8
    cmp rcx,256
    jb event_reserved
    mov rdx,[r15+OUTPUT+16]
    sub rdx,256
    jc protocol_failure
    cmp [r12+128],rdx
    ja protocol_failure
    cmp eax,2
    je fs_grow
    cmp eax,1
    je fs_syscall
    test eax,eax
    je fs_return
    cmp eax,0xfffffffd
    jne protocol_failure

fs_return:
    add rsp,8
    ret

fs_grow:
    /* No primitive has run for this source. ACK-triggered growth is forbidden. */
    lea rax,[r15+REQUEST]
    cmp [r15+CURRENT_DESC],rax
    jne protocol_failure
    cmp qword ptr [r12+120],3
    jne protocol_failure
    mov rax,[r12+136]
    mov rdx,[r12+144]
    cmp rax,[r15+WORK+16]
    ja grow_progress
    cmp rdx,[r15+OUTPUT+16]
    jbe protocol_failure
grow_progress:
    mov r13,rax
    mov r14,rdx
    lea rdi,[r15+WORK]
    mov rsi,r13
    call grow_descriptor
    lea rdi,[r15+OUTPUT]
    mov rsi,r14
    call grow_descriptor
    /* Original request remains the same read-only mapping and exact extent. */
    jmp invoke_fs

fs_syscall:
    cmp qword ptr [r12+120],2
    jne protocol_failure
    mov rax,[r12+40]
    cmp rax,[r15+LAST_SYSSEQ]
    jbe protocol_failure
    mov [r15+LAST_SYSSEQ],rax
    mov rax,[r12+48]
    test rax,rax
    jz protocol_failure
    cmp rax,24
    ja protocol_failure
    mov [r15+PRIMITIVE_OP],rax
    /* Output capacity already covers the exact HIA-requested primitive result. */
    lea rdi,[r15+ACK]
    mov rsi,[r15+OUTPUT+16]
    cmp rsi,512
    jae ack_capacity_ready
    mov esi,512
ack_capacity_ready:
    call grow_descriptor
    lea rdi,[r15+ACK]
    mov esi,3
    call protect_descriptor
    mov rdi,[r15+ACK+8]
    mov rcx,[r15+ACK+16]
    xor eax,eax
    rep stosb
    mov r12,[r15+OUTPUT+8]
    mov r13,[r15+ACK+8]
    mov rax,HIA_MAGIC
    mov [r13],rax
    mov qword ptr [r13+8],3
    mov rax,[r12+16]
    mov [r13+16],rax
    mov rax,[r12+24]
    mov [r13+24],rax
    mov rax,[r12+32]
    mov [r13+32],rax
    mov rax,[r12+40]
    mov [r13+40],rax
    mov rax,[r12+48]
    mov [r13+48],rax
    mov rax,[r12+112]
    mov [r13+104],rax
    mov rax,[r15+PRIMITIVE_OP]
    cmp eax,1
    je primitive_openat
    cmp eax,2
    je primitive_pread
    cmp eax,3
    je primitive_pwrite
    cmp eax,4
    je primitive_fstat
    cmp eax,5
    je primitive_ftruncate
    cmp eax,6
    je primitive_fsync
    cmp eax,7
    je primitive_renameat
    cmp eax,8
    je primitive_close
    cmp eax,9
    je primitive_unlinkat
    cmp eax,10
    je primitive_mkdirat
    cmp eax,11
    je primitive_flock
    cmp eax,12
    je primitive_clock
    cmp eax,13
    je primitive_sleep
    cmp eax,14
    je primitive_random
    cmp eax,15
    je primitive_fstat
    cmp eax,16
    je primitive_geteuid
    cmp eax,17
    je primitive_setlk
    cmp eax,18
    je primitive_statat
    cmp eax,19
    je primitive_readlinkat
    cmp eax,20
    je primitive_getcwd
    cmp eax,21
    je primitive_fchmod
    cmp eax,22
    je primitive_fchmodat
    cmp eax,23
    je primitive_getlk
    jmp primitive_fchown

primitive_openat:
    call check_path_payload
    mov rdi,[r12+64]
    lea rsi,[r12+256]
    mov rdx,[r12+72]
    mov r10,[r12+80]
    mov eax,257
    jmp perform_primitive
primitive_pread:
    mov rax,[r12+72]
    call check_ack_extent
    mov rdi,[r12+64]
    lea rsi,[r13+256]
    mov rdx,[r12+72]
    mov r10,[r12+80]
    mov eax,17
    jmp perform_primitive
primitive_pwrite:
    mov rax,[r12+80]
    cmp rax,[r12+128]
    ja protocol_failure
    mov rdi,[r12+64]
    lea rsi,[r12+256]
    mov rdx,[r12+80]
    mov r10,[r12+72]
    mov eax,18
    jmp perform_primitive
primitive_fstat:
    mov eax,144
    call check_ack_extent
    mov rdi,[r12+64]
    lea rsi,[r13+256]
    mov eax,5
    jmp perform_primitive
primitive_ftruncate:
    mov rdi,[r12+64]
    mov rsi,[r12+72]
    mov eax,77
    jmp perform_primitive
primitive_fsync:
    mov rdi,[r12+64]
    mov eax,74
    jmp perform_primitive
primitive_renameat:
    call check_path_payload
    mov rax,[r12+80]
    cmp rax,[r12+128]
    jae protocol_failure
    cmp byte ptr [r12+rax+256],0
    jne protocol_failure
    inc rax
    jz protocol_failure
    cmp rax,[r12+128]
    jae protocol_failure
    lea r10,[r12+rax+256]
    mov rdi,[r12+64]
    lea rsi,[r12+256]
    mov rdx,[r12+72]
    mov eax,264
    jmp perform_primitive
primitive_close:
    mov rdi,[r12+64]
    mov eax,3
    jmp perform_primitive
primitive_unlinkat:
    call check_path_payload
    mov rdi,[r12+64]
    lea rsi,[r12+256]
    mov rdx,[r12+72]
    mov eax,263
    jmp perform_primitive
primitive_mkdirat:
    call check_path_payload
    mov rdi,[r12+64]
    lea rsi,[r12+256]
    mov rdx,[r12+72]
    mov eax,258
    jmp perform_primitive
primitive_flock:
    mov rdi,[r12+64]
    mov rsi,[r12+72]
    mov eax,73
    jmp perform_primitive
primitive_clock:
    mov eax,16
    call check_ack_extent
    mov edi,1
    lea rsi,[r13+256]
    mov eax,228
    jmp perform_primitive
primitive_sleep:
    mov rax,[r12+64]
    mov [r15+SYSCALL_SCRATCH],rax
    mov rax,[r12+72]
    mov [r15+SYSCALL_SCRATCH+8],rax
    lea rdi,[r15+SYSCALL_SCRATCH]
    xor esi,esi
    mov eax,35
    jmp perform_primitive
primitive_random:
    mov rax,[r12+64]
    call check_ack_extent
    lea rdi,[r13+256]
    mov rsi,[r12+64]
    mov rdx,[r12+72]
    mov eax,318
    jmp perform_primitive
primitive_geteuid:
    mov eax,107
    jmp perform_primitive
primitive_setlk:
    /* x86-64 struct flock: short type, short SEEK_SET, off_t start/len, pid. */
    lea rdi,[r15+SYSCALL_SCRATCH]
    mov ecx,4
    xor eax,eax
    rep stosq
    mov rax,[r12+72]
    mov word ptr [r15+SYSCALL_SCRATCH],ax
    mov rax,[r12+80]
    mov [r15+SYSCALL_SCRATCH+8],rax
    mov rax,[r12+88]
    mov [r15+SYSCALL_SCRATCH+16],rax
    mov rdi,[r12+64]
    mov esi,6
    lea rdx,[r15+SYSCALL_SCRATCH]
    mov eax,72
    jmp perform_primitive
primitive_getlk:
    /* Actual x86-64 F_GETLK writes this complete 32-byte, initially zeroed view.
     * No conflict/locking policy is interpreted in the mechanical executor. */
    mov eax,32
    call check_ack_extent
    lea rdi,[r13+256]
    mov ecx,4
    xor eax,eax
    rep stosq
    mov rax,[r12+72]
    mov word ptr [r13+256],ax
    mov rax,[r12+80]
    mov [r13+264],rax
    mov rax,[r12+88]
    mov [r13+272],rax
    mov rdi,[r12+64]
    mov esi,5
    lea rdx,[r13+256]
    mov eax,72
    jmp perform_primitive
primitive_statat:
    call check_path_payload
    mov eax,144
    call check_ack_extent
    mov rdi,[r12+64]
    lea rsi,[r12+256]
    lea rdx,[r13+256]
    mov r10,[r12+72]
    mov eax,262
    jmp perform_primitive
primitive_readlinkat:
    call check_path_payload
    mov rax,[r12+72]
    call check_ack_extent
    mov rdi,[r12+64]
    lea rsi,[r12+256]
    lea rdx,[r13+256]
    mov r10,[r12+72]
    mov eax,267
    jmp perform_primitive
primitive_getcwd:
    mov rax,[r12+64]
    call check_ack_extent
    lea rdi,[r13+256]
    mov rsi,[r12+64]
    mov eax,79
    jmp perform_primitive
primitive_fchmod:
    mov rdi,[r12+64]
    mov rsi,[r12+72]
    mov eax,91
    jmp perform_primitive
primitive_fchmodat:
    call check_path_payload
    mov rdi,[r12+64]
    lea rsi,[r12+256]
    mov rdx,[r12+72]
    mov eax,268
    jmp perform_primitive

primitive_fchown:
    mov rdi,[r12+64]
    mov rsi,[r12+72]
    mov rdx,[r12+80]
    mov eax,0xffffffff
    cmp rsi,rax
    ja protocol_failure
    cmp rdx,rax
    ja protocol_failure
    mov eax,93
    jmp perform_primitive

/* Check mechanical syscall spans before the kernel can touch memory.
 * These are actual allocated-view bounds, not new namespace quotas. */
check_ack_extent:
    mov rcx,[r15+ACK+16]
    sub rcx,256
    jc protocol_failure
    cmp rax,rcx
    ja protocol_failure
    ret
check_path_payload:
    mov rax,[r12+128]
    test rax,rax
    jz protocol_failure
    /* Event payload <= logical output capacity was checked before dispatch. */
    cmp byte ptr [r12+rax+255],0
    jne protocol_failure
    ret

perform_primitive:
    mov [r15+PRIMITIVE_NUMBER],rax
    /* Exactly one actual namespace primitive. EINTR is an actual result. */
    syscall
    mov [r15+PRIMITIVE_RETURN],rax
    mov [r13+56],rax
    xor edx,edx
    cmp rax,-4095
    jae primitive_extent_ready
    mov rcx,[r15+PRIMITIVE_OP]
    cmp ecx,2
    je primitive_variable_extent
    cmp ecx,14
    je primitive_variable_extent
    cmp ecx,19
    je primitive_variable_extent
    cmp ecx,20
    je primitive_variable_extent
    test rax,rax
    jne primitive_extent_ready
    cmp ecx,4
    je primitive_stat_extent
    cmp ecx,15
    je primitive_stat_extent
    cmp ecx,18
    je primitive_stat_extent
    cmp ecx,23
    je primitive_getlk_extent
    cmp ecx,12
    jne primitive_extent_ready
    mov edx,16
    jmp primitive_extent_ready
primitive_getlk_extent:
    mov edx,32
    jmp primitive_extent_ready
primitive_stat_extent:
    mov edx,144
    jmp primitive_extent_ready
primitive_variable_extent:
    mov rdx,rax
primitive_extent_ready:
    mov rcx,[r15+ACK+16]
    sub rcx,256
    jc protocol_failure
    cmp rdx,rcx
    ja protocol_failure
    mov [r15+PRIMITIVE_PAYLOAD],rdx
    mov [r13+96],rdx
    add rdx,256
    jc protocol_failure
    mov [r15+ACK_LENGTH],rdx
    call check_all_descriptors
    lea rdi,[r15+ACK]
    mov esi,1
    call protect_descriptor
    call trace_primitive
    lea rax,[r15+ACK]
    mov [r15+CURRENT_DESC],rax
    mov rax,[r15+ACK_LENGTH]
    mov [r15+CURRENT_LENGTH],rax
    jmp invoke_fs

coordinator_retire:
    call check_root_action
    mov rax,[r12+48]
    test rax,rax
    jz protocol_failure
    cmp rax,3
    ja protocol_failure
    mov [r15+RETIRE_MASK],rax
    mov rax,[r12+56]
    test rax,rax
    jz protocol_failure
    mov [r15+RETIRE_NODE],rax
    cmp qword ptr [r12+80],0
    jne protocol_failure
    mov rax,[r15+RETIRE_SEQUENCE]
    cmp rax,-1
    je protocol_failure
    inc rax
    cmp [r12+88],rax
    jne protocol_failure
    mov qword ptr [r15+RETIRE_COUNT],0
    mov qword ptr [r15+RETIRE_QUARANTINE],0
    /* Allocate the complete actual ACK before retiring any context. */
    lea rdi,[r15+ACK]
    mov esi,576
    call grow_descriptor
    lea rdi,[r15+ACK]
    mov esi,3
    call protect_descriptor
    mov rdi,[r15+ACK+8]
    mov rcx,[r15+ACK+16]
    xor eax,eax
    rep stosb
    mov eax,2
    mov rdx,[r15+RETIRE_NODE]
    call find_context
    test qword ptr [r15+RETIRE_MASK],1
    jnz retire_map_present
    test r13,r13
    jnz protocol_failure
    jmp retire_memory_lookup
retire_map_present:
    test r13,r13
    jz protocol_failure
    mov rdi,r13
    call retire_actual_context
    inc qword ptr [r15+RETIRE_COUNT]
retire_memory_lookup:
    mov eax,3
    mov rdx,[r15+RETIRE_NODE]
    call find_context
    test qword ptr [r15+RETIRE_MASK],2
    jnz retire_memory_present
    test r13,r13
    jnz protocol_failure
    cmp qword ptr [r12+72],0
    jne protocol_failure
    jmp retire_complete
retire_memory_present:
    test r13,r13
    jz protocol_failure
    mov rdi,r13
    call namespace_memory_context_counts
    test r8,r8
    jnz protocol_failure
    cmp r9,[r12+72]
    jne protocol_failure
    mov [r15+RETIRE_QUARANTINE],r9
    mov rdi,r13
    call retire_actual_context
    inc qword ptr [r15+RETIRE_COUNT]
retire_complete:
    inc qword ptr [r15+RETIRE_SEQUENCE]
    mov r13,[r15+ACK+8]
    mov rax,CHANNEL_MAGIC
    mov [r13],rax
    mov qword ptr [r13+8],7
    mov qword ptr [r13+16],4
    mov qword ptr [r13+32],512
    mov rax,[r15+RETIRE_SEQUENCE]
    mov [r13+40],rax
    mov [r13+160],rax
    mov rax,[r15+NSML_PAGE]
    mov [r13+48],rax
    mov rax,DMS_MAGIC
    mov [r13+64],rax
    mov qword ptr [r13+72],19
    mov rax,[r12+16]
    mov [r13+80],rax
    mov rax,[r12+24]
    mov [r13+88],rax
    mov rax,[r12+32]
    mov [r13+96],rax
    mov rax,[r12+40]
    mov [r13+104],rax
    mov rax,[r12+64]
    mov [r13+112],rax
    mov qword ptr [r13+120],4
    mov rax,[r15+RETIRE_NODE]
    mov [r13+128],rax
    mov rax,[r15+RETIRE_MASK]
    mov [r13+136],rax
    mov rax,[r15+RETIRE_COUNT]
    mov [r13+144],rax
    mov rax,[r15+RETIRE_QUARANTINE]
    mov [r13+152],rax
    mov qword ptr [r13+168],256
    mov qword ptr [r13+192],256
    lea rdi,[r13+320]
    mov rsi,r12
    mov ecx,256
    rep movsb
    mov qword ptr [r15+CHILD_REPLY_SIZE],576
    call root_ack_ready
    jmp invoke_coordinator

/* RDI is an actual private context metadata pointer, r15 the actual root.
 * Count its actual live/quarantine mappings before retiring metadata. */
namespace_memory_context_counts:
    xor r8d,r8d
    xor r9d,r9d
    mov r10,[r15+NSML_HEAD]
memory_counts_block:
    test r10,r10
    jz memory_counts_done
    lea rdx,[r10+32]
    mov ecx,63
memory_counts_record:
    cmp [rdx+32],rdi
    jne memory_counts_next
    cmp qword ptr [rdx+40],1
    jne memory_counts_quarantine
    inc r8
    jmp memory_counts_next
memory_counts_quarantine:
    cmp qword ptr [rdx+40],2
    jne memory_counts_next
    inc r9
memory_counts_next:
    add rdx,64
    dec ecx
    jnz memory_counts_record
    mov r10,[r10]
    jmp memory_counts_block
memory_counts_done:
    ret

/* Retire only the issued context, after all its dependent child views have
 * been copied to immutable owned capsules. No live mapping can be abandoned.
 * Actual quarantine retains the metadata allocation until process exit;
 * its address is never inserted into the active context registry again. */
retire_actual_context:
    push rbx
    push r14
    mov rbx,rdi
    cmp qword ptr [rbx+CONTEXT_RETIRED],0
    jne protocol_failure
    cmp [rbx+ROOT_LINK],r15
    jne protocol_failure
    call namespace_memory_context_counts
    test r8,r8
    jnz protocol_failure
    mov [rbx+CONTEXT_QUARANTINE],r9
    lea rdx,[r15+CONTEXT_HEAD]
retire_context_find:
    mov rax,[rdx]
    test rax,rax
    jz protocol_failure
    cmp rax,rbx
    je retire_context_unlink
    lea rdx,[rax+CONTEXT_NEXT]
    jmp retire_context_find
retire_context_unlink:
    mov rax,[rbx+CONTEXT_NEXT]
    mov [rdx],rax
    mov qword ptr [rbx+CONTEXT_NEXT],0
    mov qword ptr [rbx+CONTEXT_RETIRED],1
    mov r14,r15
    mov r15,rbx
    call check_all_descriptors
    lea rdi,[r15+REQUEST]
    call release_descriptor
    lea rdi,[r15+OUTPUT]
    call release_descriptor
    lea rdi,[r15+WORK]
    call release_descriptor
    lea rdi,[r15+ACK]
    call release_descriptor
    cmp qword ptr [r15+TEMP],0
    jne protocol_failure
    mov r15,r14
    cmp qword ptr [rbx+CONTEXT_QUARANTINE],0
    jne retire_context_done
    mov rdi,rbx
    mov esi,4096
    mov eax,11
    syscall
    test rax,rax
    jne allocation_failure
retire_context_done:
    pop r14
    pop rbx
    ret

/* Allocate a NEW descriptor; the entire middle mapping initially contains
 * zeroes. Natural size_t/virtual-memory failures end this process. */
allocate_descriptor:
    push rbx
    push r12
    push r13
    mov rbx,rdi
    mov r12,rsi
    cmp qword ptr [rbx],0
    jne protocol_failure
    mov r13,rsi
    add r13,32
    jc allocation_failure
    add r13,4095
    jc allocation_failure
    and r13,-4096
    add r13,8192
    jc allocation_failure
    xor edi,edi
    mov rsi,r13
    xor edx,edx
    mov r10d,0x22
    mov r8,-1
    xor r9d,r9d
    mov eax,9
    syscall
    cmp rax,-4095
    jae allocation_failure
    mov [rbx],rax
    lea rdi,[rax+4096]
    mov rsi,r13
    sub rsi,8192
    mov edx,3
    mov eax,10
    syscall
    test rax,rax
    jne allocation_failure
    mov rax,[rbx]
    lea rcx,[rax+4112]
    mov [rbx+8],rcx
    mov [rbx+16],r12
    mov [rbx+24],r13
    mov qword ptr [rbx+32],3
    mov rax,CANARY
    mov [rcx-16],rax
    mov [rcx-8],rax
    mov [rcx+r12],rax
    mov [rcx+r12+8],rax
    pop r13
    pop r12
    pop rbx
    ret

protect_descriptor:
    push rbx
    mov rbx,rdi
    cmp rsi,[rbx+32]
    je protect_done
    cmp esi,1
    je protect_allowed
    cmp esi,3
    jne protocol_failure
protect_allowed:
    mov edx,esi
    mov rdi,[rbx]
    test rdi,rdi
    jz protocol_failure
    add rdi,4096
    mov rsi,[rbx+24]
    sub rsi,8192
    mov eax,10
    syscall
    test rax,rax
    jne allocation_failure
    mov [rbx+32],rdx
protect_done:
    pop rbx
    ret

check_descriptor:
    cmp qword ptr [rdi],0
    je descriptor_checked
    mov rcx,[rdi+8]
    mov rdx,[rdi+16]
    mov rax,CANARY
    cmp [rcx-16],rax
    jne guard_failure
    cmp [rcx-8],rax
    jne guard_failure
    cmp [rcx+rdx],rax
    jne guard_failure
    cmp [rcx+rdx+8],rax
    jne guard_failure
descriptor_checked:
    ret

check_all_descriptors:
    push rbx
    xor ebx,ebx
check_descriptor_loop:
    lea rdi,[r15+rbx]
    call check_descriptor
    add rbx,40
    cmp rbx,160
    jb check_descriptor_loop
    pop rbx
    ret

release_descriptor:
    push rbx
    mov rbx,rdi
    cmp qword ptr [rbx],0
    je release_done
    call check_descriptor
    mov rdi,[rbx]
    mov rsi,[rbx+24]
    mov eax,11
    syscall
    test rax,rax
    jne allocation_failure
    mov rdi,rbx
    mov ecx,5
    xor eax,eax
    rep stosq
release_done:
    pop rbx
    ret

grow_descriptor:
    cmp rsi,[rdi+16]
    jbe growth_done
    push rbx
    push r12
    push r13
    mov rbx,rdi
    mov r13,rsi
    call check_descriptor
    lea rdi,[r15+TEMP]
    mov rsi,r13
    call allocate_descriptor
    mov rsi,[rbx+8]
    mov rdi,[r15+TEMP+8]
    mov rcx,[rbx+16]
    rep movsb
    mov rdi,rbx
    call release_descriptor
    lea rsi,[r15+TEMP]
    mov rdi,rbx
    mov ecx,5
    rep movsq
    lea rdi,[r15+TEMP]
    mov ecx,5
    xor eax,eax
    rep stosq
    pop r13
    pop r12
    pop rbx
growth_done:
    ret

/* Transport alone retries EINTR and partial I/O; namespace primitives never do.
 * read_exact returns 1 only for EOF before any byte of an allowed prefix. */
read_exact:
    push rbx
    mov rbx,rdx
    mov r8,rsi
    mov r9,rdx
read_loop:
    test r9,r9
    jz read_done
    mov rsi,r8
    mov rdx,r9
    xor eax,eax
    syscall
    cmp rax,-4
    je read_loop
    test rax,rax
    js transport_failure
    jz read_eof
    cmp rax,r9
    ja transport_failure
    add r8,rax
    sub r9,rax
    jmp read_loop
read_eof:
    test r10,r10
    jz transport_failure
    cmp r9,rbx
    jne transport_failure
    mov eax,1
    pop rbx
    ret
read_done:
    xor eax,eax
    pop rbx
    ret

write_all:
    mov r8,rsi
    mov r9,rdx
write_loop:
    test r9,r9
    jz write_done
    mov rsi,r8
    mov rdx,r9
    mov eax,1
    syscall
    cmp rax,-4
    je write_loop
    test rax,rax
    jle transport_failure
    cmp rax,r9
    ja transport_failure
    add r8,rax
    sub r9,rax
    jmp write_loop
write_done:
    ret

/* Trace header is twelve u64s:
 * magic, kind, entry serial, source/ACK extent, output cap or syscall number,
 * workspace cap or op, actual HIA/syscall result, extra(0 or syscall sequence),
 * actual HIA-issued node, actual never-reused context sequence, role, zero.
 * BEFORE payload: current exact input + entire output + entire workspace.
 * AFTER payload: entire output + entire workspace.
 * PRIMITIVE payload: the exact real ACK about to become read-only HIA input.
 */
trace_header_common:
    mov rax,[r15+TRACE_ID]
    mov [r15+TRACE_HEADER],rax
    mov [r15+TRACE_HEADER+8],rdi
    mov rax,[r15+ENTRY_SERIAL]
    mov [r15+TRACE_HEADER+16],rax
    mov rax,[r15+CURRENT_LENGTH]
    mov [r15+TRACE_HEADER+24],rax
    mov rax,[r15+OUTPUT+16]
    mov [r15+TRACE_HEADER+32],rax
    mov rax,[r15+WORK+16]
    mov [r15+TRACE_HEADER+40],rax
    mov qword ptr [r15+TRACE_HEADER+48],0
    mov qword ptr [r15+TRACE_HEADER+56],0
    mov rax,[r15+CONTEXT_NODE]
    mov [r15+TRACE_HEADER+64],rax
    mov rax,[r15+CONTEXT_SEQUENCE]
    mov [r15+TRACE_HEADER+72],rax
    mov rax,[r15+ROLE]
    mov [r15+TRACE_HEADER+80],rax
    mov qword ptr [r15+TRACE_HEADER+88],0
    ret

trace_header_write:
    mov edi,2
    lea rsi,[r15+TRACE_HEADER]
    mov edx,96
    jmp write_all

trace_output_work:
    mov edi,2
    mov rsi,[r15+OUTPUT+8]
    mov rdx,[r15+OUTPUT+16]
    call write_all
    mov edi,2
    mov rsi,[r15+WORK+8]
    mov rdx,[r15+WORK+16]
    jmp write_all

trace_before:
    mov edi,1
    call trace_header_common
    call trace_header_write
    mov rax,[r15+CURRENT_DESC]
    mov edi,2
    mov rsi,[rax+8]
    mov rdx,[r15+CURRENT_LENGTH]
    call write_all
    jmp trace_output_work

trace_after:
    mov edi,2
    call trace_header_common
    mov rax,[r15+ENTRY_RETURN]
    mov [r15+TRACE_HEADER+48],rax
    call trace_header_write
    jmp trace_output_work

trace_primitive:
    mov edi,3
    call trace_header_common
    mov rax,[r15+ACK_LENGTH]
    mov [r15+TRACE_HEADER+24],rax
    mov rax,[r15+PRIMITIVE_NUMBER]
    mov [r15+TRACE_HEADER+32],rax
    mov rax,[r15+PRIMITIVE_OP]
    mov [r15+TRACE_HEADER+40],rax
    mov rax,[r15+PRIMITIVE_RETURN]
    mov [r15+TRACE_HEADER+48],rax
    mov rax,[r15+LAST_SYSSEQ]
    mov [r15+TRACE_HEADER+56],rax
    call trace_header_write
    mov edi,2
    mov rsi,[r15+ACK+8]
    mov rdx,[r15+ACK_LENGTH]
    jmp write_all

normal_exit:
    xor edi,edi
    mov eax,231
    syscall
    ud2
protocol_failure:
    mov ebx,110
    jmp fatal_exit
transport_failure:
    mov ebx,111
    jmp fatal_exit
allocation_failure:
    mov ebx,112
    jmp fatal_exit
guard_failure:
    mov ebx,113
fatal_exit:
    /* Best effort only: never recurse through trace I/O on a transport error. */
    mov rax,[r15+TRACE_ID]
    mov [r15+TRACE_HEADER],rax
    mov qword ptr [r15+TRACE_HEADER+8],4
    mov rax,[r15+ENTRY_SERIAL]
    mov [r15+TRACE_HEADER+16],rax
    mov qword ptr [r15+TRACE_HEADER+24],0
    mov qword ptr [r15+TRACE_HEADER+32],0
    mov qword ptr [r15+TRACE_HEADER+40],0
    mov [r15+TRACE_HEADER+48],rbx
    mov qword ptr [r15+TRACE_HEADER+56],0
    mov rax,[r15+CONTEXT_NODE]
    mov [r15+TRACE_HEADER+64],rax
    mov rax,[r15+CONTEXT_SEQUENCE]
    mov [r15+TRACE_HEADER+72],rax
    mov rax,[r15+ROLE]
    mov [r15+TRACE_HEADER+80],rax
    mov qword ptr [r15+TRACE_HEADER+88],0
    mov edi,2
    lea rsi,[r15+TRACE_HEADER]
    mov edx,96
    mov eax,1
    syscall
    mov edi,ebx
    mov eax,231
    syscall
    ud2
early_allocation_failure:
    mov edi,112
    mov eax,231
    syscall
    ud2

/* NEW fixed DMS+Map join mechanical memory fragment, source r2 integrated.
 *
 * NOT a standalone executable and NOT yet assembled/executed.
 * Caller: r14 current memory-image context metadata, r15 root metadata,
 * r13 read-only actual 256-byte HIA memory event.
 *
 * HIA owns logical operations, tokens, node identity, source/FD leases and
 * cleanup policy. This fragment owns only actual mapping extents and raw
 * address safety. It never parses SQL, selects a node, retries a user syscall,
 * issues a namespace authority, or converts an error to successful retirement.
 *
 * Caller allocates ACK storage before entering, pins the current context and
 * supplies the original read-only event. On return RAX is the actual signed
 * primitive result (mmap address or0, or negative errno). Caller wraps that
 * result in the private actual ACK exactly once. Internal registry allocation
 * failure is fatal/UNKNOWN, not fabricated success or a second user syscall.
 *
 * The process-global registry and lock are fixed metadata, never image
 * operands. Context metadata remains alive through process exit and is not
 * reused while any live/quarantined mapping references it.
 */
.global namespace_memory_primitive
.global namespace_memory_registry_context_empty

/* Must be initialized from real auxv AT_PAGESZ by the final fixed executor. */
.equ NSML_HEAD,2304
.equ NSML_MAP_SEQUENCE,2312
.equ NSML_MUTEX,2320
.equ NSML_PAGE,2328
/* Per memory-image context scratch, disjoint from the image operands. */
.equ NSML_PENDING_RECORD,2344
.equ NSML_DEST_RECORD,2352
.equ NSML_SOURCE_RECORD,2360
.equ NSML_ROUNDED_SIZE,2376
.equ NSML_EVENT_MAGIC,0x31304c4d4e414948
/* A raw registry block has32 bytes of linkage then63 records of64 bytes.
 * This is block granularity, not a global mapping-count limit.
 * Record: base,logical bytes,rounded bytes,prot,actual context,state,serial,0.
 * state0free,1live,2quarantine. Quarantine is never reusable/borrowable.
 */

namespace_memory_primitive:
    mov rax,NSML_EVENT_MAGIC
    cmp [r13],rax
    jne namespace_memory_bad
    cmp qword ptr [r13+8],1
    jne namespace_memory_bad
    mov rax,[r15+NSML_PAGE]
    test rax,rax
    jz namespace_memory_bad
    cmp rax,1073741824
    ja namespace_memory_bad
    lea rdx,[rax-1]
    test rax,rdx
    jnz namespace_memory_bad
    cmp [r13+152],rax
    jne namespace_memory_bad
    cmp qword ptr [r13+128],0
    jne namespace_memory_bad
    mov rax,[r13+64]
    cmp rax,1
    je namespace_memory_mmap
    cmp rax,2
    je namespace_memory_copy
    cmp rax,3
    je namespace_memory_unmap
    cmp rax,4
    je namespace_memory_barrier
    jmp namespace_memory_bad

namespace_memory_mmap:
    cmp qword ptr [r13+72],0
    jne namespace_memory_bad
    mov rax,[r13+80]
    test rax,rax
    jz namespace_memory_bad
    mov rcx,[r15+NSML_PAGE]
    dec rcx
    add rax,rcx
    jc namespace_memory_bad
    not rcx
    and rax,rcx
    mov [r14+NSML_ROUNDED_SIZE],rax
    mov rax,[r13+88]
    cmp rax,1
    je namespace_memory_mmap_prot
    cmp rax,3
    jne namespace_memory_bad
namespace_memory_mmap_prot:
    mov rax,[r13+96]
    cmp rax,1
    je namespace_memory_mmap_file
    cmp rax,34
    jne namespace_memory_bad
    cmp qword ptr [r13+88],3
    jne namespace_memory_bad
    cmp qword ptr [r13+104],-1
    jne namespace_memory_bad
    cmp qword ptr [r13+112],0
    jne namespace_memory_bad
    jmp namespace_memory_mmap_ready
namespace_memory_mmap_file:
    mov rax,[r13+104]
    cmp rax,2147483647
    ja namespace_memory_bad
    mov rax,[r13+112]
    test rax,rax
    js namespace_memory_bad
    mov rcx,[r15+NSML_PAGE]
    dec rcx
    test rax,rcx
    jnz namespace_memory_bad
namespace_memory_mmap_ready:
    cmp qword ptr [r15+NSML_MAP_SEQUENCE],-1
    je namespace_memory_bad
    call namespace_memory_reserve_record
    mov [r14+NSML_PENDING_RECORD],rdx
    /* Exactly one requested user mmap, no EINTR retry. */
    mov eax,9
    xor edi,edi
    mov rsi,[r13+80]
    mov rdx,[r13+88]
    mov r10,[r13+96]
    mov r8,[r13+104]
    mov r9,[r13+112]
    syscall
    cmp rax,-4095
    jae namespace_memory_return
    mov rcx,[r15+NSML_PAGE]
    dec rcx
    test rax,rcx
    jnz namespace_memory_bad
    mov rcx,rax
    add rcx,[r14+NSML_ROUNDED_SIZE]
    jc namespace_memory_bad
    mov rdx,[r14+NSML_PENDING_RECORD]
    mov [rdx],rax
    mov rcx,[r13+80]
    mov [rdx+8],rcx
    mov rcx,[r14+NSML_ROUNDED_SIZE]
    mov [rdx+16],rcx
    mov rcx,[r13+88]
    mov [rdx+24],rcx
    mov [rdx+32],r14
    mov qword ptr [rdx+40],1
    inc qword ptr [r15+NSML_MAP_SEQUENCE]
    mov rcx,[r15+NSML_MAP_SEQUENCE]
    mov [rdx+48],rcx
    mov qword ptr [rdx+56],0
    ret

namespace_memory_copy:
    cmp qword ptr [r13+96],0
    jne namespace_memory_bad
    cmp qword ptr [r13+104],0
    jne namespace_memory_bad
    cmp qword ptr [r13+112],0
    jne namespace_memory_bad
    mov rax,[r13+72]
    call namespace_memory_find_live
    test rdx,rdx
    jz namespace_memory_bad
    test qword ptr [rdx+24],2
    jz namespace_memory_bad
    mov rax,[r13+80]
    cmp rax,[rdx+8]
    ja namespace_memory_bad
    mov [r14+NSML_DEST_RECORD],rdx
    mov rax,[r13+88]
    call namespace_memory_find_live
    test rdx,rdx
    jz namespace_memory_bad
    test qword ptr [rdx+24],1
    jz namespace_memory_bad
    mov rax,[r13+80]
    cmp rax,[rdx+8]
    ja namespace_memory_bad
    mov [r14+NSML_SOURCE_RECORD],rdx
    /* Both full actual ranges and permissions precede every memory access. */
    mov rdi,[r13+72]
    mov rsi,[r13+88]
    mov rcx,[r13+80]
    test rcx,rcx
    jz namespace_memory_zero_return
    cmp rdi,rsi
    jbe namespace_memory_copy_forward
    lea rax,[rsi+rcx]
    cmp rdi,rax
    jae namespace_memory_copy_forward
    lea rdi,[rdi+rcx-1]
    lea rsi,[rsi+rcx-1]
    std
    rep movsb
    cld
    jmp namespace_memory_zero_return
namespace_memory_copy_forward:
    cld
    rep movsb
    jmp namespace_memory_zero_return

namespace_memory_unmap:
    cmp qword ptr [r13+88],0
    jne namespace_memory_bad
    cmp qword ptr [r13+96],0
    jne namespace_memory_bad
    cmp qword ptr [r13+104],0
    jne namespace_memory_bad
    cmp qword ptr [r13+112],0
    jne namespace_memory_bad
    mov rax,[r13+72]
    call namespace_memory_find_live
    test rdx,rdx
    jz namespace_memory_bad
    mov [r14+NSML_PENDING_RECORD],rdx
    mov rax,[r13+80]
    test rax,rax
    jz namespace_memory_bad
    mov rcx,[r15+NSML_PAGE]
    dec rcx
    add rax,rcx
    jc namespace_memory_bad
    not rcx
    and rax,rcx
    cmp rax,[rdx+16]
    jne namespace_memory_bad
    /* Consume the mechanically borrowable mapping before issuing close.
     * Negative result leaves quarantine; no caller can retry by raw address. */
    mov qword ptr [rdx+40],2
    mov eax,11
    mov rdi,[r13+72]
    mov rsi,[r13+80]
    syscall
    cmp rax,-4095
    jae namespace_memory_return
    test rax,rax
    jnz namespace_memory_bad
    mov rdx,[r14+NSML_PENDING_RECORD]
    mov qword ptr [rdx],0
    mov qword ptr [rdx+8],0
    mov qword ptr [rdx+16],0
    mov qword ptr [rdx+24],0
    mov qword ptr [rdx+32],0
    mov qword ptr [rdx+40],0
    mov qword ptr [rdx+48],0
    mov qword ptr [rdx+56],0
    jmp namespace_memory_zero_return

namespace_memory_barrier:
    lea rdx,[r13+72]
    mov ecx,6
namespace_memory_barrier_args:
    cmp qword ptr [rdx],0
    jne namespace_memory_bad
    add rdx,8
    dec ecx
    jnz namespace_memory_barrier_args
    /* The fixed executor invokes images on one thread. Acquire/release the
     * actual shared process-local mutex word around the hardware full fence.
     * A nonzero owner here is a mechanical reentrancy/corruption fault. */
    cmp qword ptr [r15+NSML_MUTEX],0
    jne namespace_memory_bad
    lock bts qword ptr [r15+NSML_MUTEX],0
    jc namespace_memory_bad
    mfence
    lock btr qword ptr [r15+NSML_MUTEX],0
namespace_memory_zero_return:
    xor eax,eax
namespace_memory_return:
    cld
    ret

/* Return the record for exact live mapping base RAX owned by current actual
 * context, or RDX=0. Raw integers from another context are not borrowed views. */
namespace_memory_find_live:
    mov r8,[r15+NSML_HEAD]
namespace_memory_find_block:
    test r8,r8
    jz namespace_memory_find_none
    lea rdx,[r8+32]
    mov ecx,63
namespace_memory_find_row:
    cmp qword ptr [rdx+40],1
    jne namespace_memory_find_next
    cmp [rdx+32],r14
    jne namespace_memory_find_next
    cmp [rdx],rax
    je namespace_memory_find_done
namespace_memory_find_next:
    add rdx,64
    dec ecx
    jnz namespace_memory_find_row
    mov r8,[r8]
    jmp namespace_memory_find_block
namespace_memory_find_none:
    xor edx,edx
namespace_memory_find_done:
    ret

/* Reserve a free bookkeeping record before user mmap. The auxiliary metadata
 * mmap is not reported as the requested primitive, and failure exits UNKNOWN.
 * There is no fixed total number of blocks or resources. */
namespace_memory_reserve_record:
    mov r8,[r15+NSML_HEAD]
namespace_memory_reserve_block:
    test r8,r8
    jz namespace_memory_reserve_allocate
    lea rdx,[r8+32]
    mov ecx,63
namespace_memory_reserve_row:
    cmp qword ptr [rdx+40],0
    je namespace_memory_reserve_done
    add rdx,64
    dec ecx
    jnz namespace_memory_reserve_row
    mov r8,[r8]
    jmp namespace_memory_reserve_block
namespace_memory_reserve_allocate:
    mov eax,9
    xor edi,edi
    mov esi,4096
    mov edx,3
    mov r10d,34
    mov r8,-1
    xor r9d,r9d
    syscall
    cmp rax,-4095
    jae namespace_memory_allocation_failure
    mov rdx,[r15+NSML_HEAD]
    mov [rax],rdx
    mov qword ptr [rax+8],63
    mov qword ptr [rax+16],0
    mov qword ptr [rax+24],0
    mov [r15+NSML_HEAD],rax
    lea rdx,[rax+32]
namespace_memory_reserve_done:
    ret

/* Before the final executor frees/reuses context metadata, this pure check
 * must return1. Quarantine intentionally keeps a context alive to exit.
 * Input RDI actual context metadata pointer. No raw unmap is done here. */
namespace_memory_registry_context_empty:
    mov r8,[r15+NSML_HEAD]
namespace_memory_context_block:
    test r8,r8
    jz namespace_memory_context_yes
    lea rdx,[r8+32]
    mov ecx,63
namespace_memory_context_row:
    cmp qword ptr [rdx+40],0
    je namespace_memory_context_next
    cmp [rdx+32],rdi
    je namespace_memory_context_no
namespace_memory_context_next:
    add rdx,64
    dec ecx
    jnz namespace_memory_context_row
    mov r8,[r8]
    jmp namespace_memory_context_block
namespace_memory_context_yes:
    mov eax,1
    ret
namespace_memory_context_no:
    xor eax,eax
    ret
namespace_memory_allocation_failure:
    mov r15,r14
    jmp allocation_failure
namespace_memory_bad:
    cld
    mov r15,r14
    jmp protocol_failure

.balign 16
image_table:
.Limage_table:
    .zero 40
executor_end:
.section .note.GNU-stack,"",@progbits
