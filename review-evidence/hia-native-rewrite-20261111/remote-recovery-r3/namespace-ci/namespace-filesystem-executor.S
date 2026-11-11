/* Fixed Linux x86-64 HIANFR03 syscall carrier, new source revision 4.
 *
 * AUTHORING ONLY until separately assembled, HIA-packed and executed.
 * The HIA image owns descriptor tokens, operation selection, shape/errno
 * interpretation, continuation identity, GROW and permanent refusal.
 *
 * This process has one private owner. stdin is a length-prefixed request
 * transport, stdout returns full output buffers, stderr is a lossless binary
 * entry/primitive trace. It is not an installed AgentStore or a reusable nested
 * context carrier. Fatal paths terminate the process, so the kernel releases
 * all its descriptors/locks; they do not fabricate a successful HIA ACK.
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
.equ IO_LENGTH,384
.equ TRACE_HEADER,512
.equ SYSCALL_SCRATCH,640
.equ HIA_MAGIC,0x333052464e414948
.equ TRACE_MAGIC,0x333054464e414948
.equ CANARY,0x7a19b5d3e6824c0f

executor_start:
    and rsp,-16
    cld
    /* The carrier's metadata is never passed to an HIA image. */
    xor edi,edi
    mov esi,4096
    mov edx,3
    mov r10d,0x22
    mov r8,-1
    xor r9d,r9d
    mov eax,9
    syscall
    cmp rax,-4095
    jae early_allocation_failure
    mov r15,rax

    /* Bind this direct child to its actual parent, including the setup race. */
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

    /* Keep transport ownership separate, making actual descriptor 0 available.
     * F_DUPFD_CLOEXEC does not close or reuse any unrelated descriptor. */
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

    lea rdi,[r15+OUTPUT]
    mov esi,256
    call allocate_descriptor
    lea rdi,[r15+WORK]
    mov esi,512
    call allocate_descriptor
    lea rdi,[r15+ACK]
    mov esi,512
    call allocate_descriptor

next_request:
    mov rdi,[r15+CONTROL_FD]
    lea rsi,[r15+IO_LENGTH]
    mov edx,8
    mov r10d,1
    call read_exact
    test eax,eax
    jnz normal_exit
    lea rdi,[r15+REQUEST]
    call release_descriptor
    lea rdi,[r15+REQUEST]
    mov rsi,[r15+IO_LENGTH]
    call allocate_descriptor
    mov rdi,[r15+CONTROL_FD]
    mov rsi,[r15+REQUEST+8]
    mov rdx,[r15+REQUEST+16]
    xor r10d,r10d
    call read_exact
    lea rdi,[r15+REQUEST]
    mov esi,1
    call protect_descriptor
    lea rax,[r15+REQUEST]
    mov [r15+CURRENT_DESC],rax
    mov rax,[r15+REQUEST+16]
    mov [r15+CURRENT_LENGTH],rax

invoke_owner:
    inc qword ptr [r15+ENTRY_SERIAL]
    jz protocol_failure
    call check_all_descriptors
    lea rdi,[r15+OUTPUT]
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
    call qword ptr [rip+.Limage_table+8]
    mov eax,eax
    mov [r15+ENTRY_RETURN],rax
    call check_all_descriptors
    lea rdi,[r15+OUTPUT]
    mov esi,1
    call protect_descriptor
    call trace_after

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
    je owner_grow
    cmp eax,1
    je owner_syscall
    test eax,eax
    je return_event
    cmp eax,0xfffffffd
    jne protocol_failure

return_event:
    /* Preserve every output byte, including unused capacity, for comparison. */
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

owner_grow:
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
    jmp invoke_owner

owner_syscall:
    cmp qword ptr [r12+120],2
    jne protocol_failure
    mov rax,[r12+40]
    cmp rax,[r15+LAST_SYSSEQ]
    jbe protocol_failure
    mov [r15+LAST_SYSSEQ],rax
    mov rax,[r12+48]
    test rax,rax
    jz protocol_failure
    cmp rax,22
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
    jmp primitive_fchmodat

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
    cmp ecx,12
    jne primitive_extent_ready
    mov edx,16
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
    jmp invoke_owner

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

/* Trace header is eight u64s:
 * magic, kind, entry serial, source/ACK extent, output cap or syscall number,
 * workspace cap or op, actual HIA/syscall result, extra(0 or syscall sequence).
 * BEFORE payload: current exact input + entire output + entire workspace.
 * AFTER payload: entire output + entire workspace.
 * PRIMITIVE payload: the exact real ACK about to become read-only HIA input.
 */
trace_header_common:
    mov rax,TRACE_MAGIC
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
    ret

trace_header_write:
    mov edi,2
    lea rsi,[r15+TRACE_HEADER]
    mov edx,64
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
    mov rax,TRACE_MAGIC
    mov [r15+TRACE_HEADER],rax
    mov qword ptr [r15+TRACE_HEADER+8],4
    mov rax,[r15+ENTRY_SERIAL]
    mov [r15+TRACE_HEADER+16],rax
    mov qword ptr [r15+TRACE_HEADER+24],0
    mov qword ptr [r15+TRACE_HEADER+32],0
    mov qword ptr [r15+TRACE_HEADER+40],0
    mov [r15+TRACE_HEADER+48],rbx
    mov qword ptr [r15+TRACE_HEADER+56],0
    mov edi,2
    lea rsi,[r15+TRACE_HEADER]
    mov edx,64
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

.balign 16
image_table:
.Limage_table:
    .zero 16
executor_end:
.section .note.GNU-stack,"",@progbits
