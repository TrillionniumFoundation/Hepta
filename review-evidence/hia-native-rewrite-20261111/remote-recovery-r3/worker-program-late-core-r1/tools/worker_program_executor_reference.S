/* Fixed Linux x86-64 descriptor/syscall executor. No JSON/value/semantic policy.
 * The HIA controller owns every call, allocation, continuation and late gate.
 * This literal template is embedded and linked by the native HIA ELF packer.
 * GNU as is development authoring only; the resulting executable has no loader,
 * interpreter, libc, external files, child processes or exec syscall.
 */
.intel_syntax noprefix
.section .text
.global executor_start
.equ ROLE,2048
.equ LEASE,2056
.equ SEQ,2064
.equ CMDLEN,2072
.equ CMDPTR,2080
.equ CMDMAP,2088
.equ FRAMEMAP,2096
.equ FDS,2112
.equ POSITIONS,2128
.equ SEALED,2144
.equ FIRST_RO,2160
.equ SECOND_RO,2168
.equ RESULT,2176
.equ IO_PTR,2184
.equ IO_LEFT,2192
.equ IO_AT,2200
.equ IO_FILE,2208
.equ IO_END,2216
.equ RAW_LEN,2224
.equ EVENT,0x3130454443414948
.equ ACK,0x3130414443414948
.equ CTOR_INIT,0x3130494443414948
.equ RAW_CONFIG,0x3130434e52414948
.equ TWO_READ_MASK,0xe0bf80bee2ac0462
.equ RUN_MODE,2232
.equ PUB_ROLE,2240
.equ PARENT,2248
.equ CHILD_TARGET,2256
.equ LEGACY,2264
.equ BORROWED,8192
.equ PROGRAM_INIT,0x3130494150414948
.equ DIGITS,2272
.equ KIND,2280
.equ DEPTH,2288

executor_start:
    cmp qword ptr [rsp],1
    jne early_usage
    and rsp,-16
    cld
    lea r14,[rip+image_table]
    xor edi,edi
    mov esi,16384
    mov edx,3
    mov r10d,0x22
    mov r8,-1
    xor r9d,r9d
    mov eax,9
    syscall
    cmp rax,-4095
    jae early_io
    mov r15,rax
    mov qword ptr [r15+FDS],-1
    mov qword ptr [r15+FDS+8],-1
    xor edi,edi
    mov esi,4096
    mov edx,3
    mov r10d,0x22
    mov r8,-1
    xor r9d,r9d
    mov eax,9
    syscall
    cmp rax,-4095
    jae early_io
    mov [r15+CMDMAP],rax
    mov r13,rax
    xor edi,edi
    mov esi,4096
    mov edx,3
    mov r10d,0x22
    mov r8,-1
    xor r9d,r9d
    mov eax,9
    syscall
    cmp rax,-4095
    jae early_io
    mov [r15+FRAMEMAP],rax
    mov r12,rax
    xor edi,edi
    mov esi,1
    call resize_slot
    xor edi,edi
    mov esi,1
    call protect_slot
    mov edi,2
    mov esi,1048576
    call resize_slot
    /* Exact immutable byte framing. HIA interprets JSON and public policy. */
    cmp qword ptr [rip+executable_policy],4
    jne abi_error
    mov rsi,r13
    mov edx,64
    call input_exact
    mov rax,0x31304e4945414948
    cmp [r13],rax
    je input_magic_checked
    mov rax,0x31304e4a45414948
    cmp [r13],rax
    jne abi_error
input_magic_checked:
    cmp qword ptr [r13+56],0
    jne abi_error
    mov rax,[r13+8]
    test rax,rax
    jz abi_error
    cmp rax,-1
    je abi_error
    mov [r15+LEASE],rax
    mov rax,[r13+24]
    mov [r15+DIGITS],rax
    mov qword ptr [r15+KIND],2
    mov qword ptr [r15+DEPTH],0
    mov edi,1
    mov rsi,[r13+32]
    call resize_slot
    mov rsi,[r15+1*32]
    mov rdx,[r15+1*32+8]
    call input_exact
    mov edi,1
    mov esi,1
    call protect_slot
    mov edi,4
    mov rsi,[r13+40]
    call resize_slot
    mov rsi,[r15+4*32]
    mov rdx,[r15+4*32+8]
    call input_exact
    mov edi,4
    mov esi,1
    call protect_slot
    mov edi,5
    mov rsi,[r13+48]
    call resize_slot
    mov rsi,[r15+5*32]
    mov rdx,[r15+5*32+8]
    call input_exact
    mov edi,5
    mov esi,1
    call protect_slot
input_end:
    xor eax,eax
    xor edi,edi
    lea rsi,[r15+4096]
    mov edx,1
    syscall
    cmp rax,-4
    je input_end
    test rax,rax
    js io_error
    jnz abi_error
    mov rbx,[r15+2*32]
    mov qword ptr [rbx+4096],1
    mov qword ptr [rbx+4096+16],1048576
    mov rax,[r15+1*32+8]
    mov [rbx+4096+1*8],rax
    mov rax,[r15+4*32+8]
    mov [rbx+4096+4*8],rax
    mov rax,[r15+5*32+8]
    mov [rbx+4096+5*8],rax
    mov rdx,0x31304e4a45414948
    mov rax,0x3130494345414948
    cmp [r13],rdx
    jne input_init_selected
    mov rax,0x3130494a45414948
input_init_selected:
    mov [r13],rax
    mov qword ptr [r15+ROLE],56
    mov [r15+CMDPTR],r13
    mov qword ptr [r15+CMDLEN],64
    jmp controller_entry
input_exact:
    mov [r15+IO_PTR],rsi
    mov [r15+IO_LEFT],rdx
input_exact_loop:
    cmp qword ptr [r15+IO_LEFT],0
    je input_exact_done
    xor eax,eax
    xor edi,edi
    mov rsi,[r15+IO_PTR]
    mov rdx,[r15+IO_LEFT]
    syscall
    cmp rax,-4
    je input_exact_loop
    test rax,rax
    js io_error
    jz abi_error
    cmp rax,[r15+IO_LEFT]
    ja abi_error
    add [r15+IO_PTR],rax
    sub [r15+IO_LEFT],rax
    jmp input_exact_loop
input_exact_done:
    ret

controller_entry:
    mov rdi,[r15+CMDPTR]
    cmp rdi,r13
    jne command_already_readonly
    mov esi,4096
    mov edx,1
    mov eax,10
    syscall
    test rax,rax
    jnz io_error
command_already_readonly:
    mov rax,[r15+ROLE]
    cmp qword ptr [r15+KIND],2
    je entry_edit_role
    cmp qword ptr [r15+KIND],1
    je entry_program_role
    cmp qword ptr [r15+KIND],0
    jne abi_error
    cmp rax,40
    jb abi_error
    cmp rax,45
    ja abi_error
    jmp entry_role_checked
entry_program_role:
    cmp rax,44
    je entry_role_checked
    cmp rax,46
    jne abi_error
    jmp entry_role_checked
entry_edit_role:
    cmp rax,56
    jb abi_error
    cmp rax,59
    ja abi_error
entry_role_checked:
    mov rax,[r14+rax*8]
    test rax,rax
    jz abi_error
    mov rdi,[r15+CMDPTR]
    mov rsi,[r15+CMDLEN]
    mov rdx,r12
    mov ecx,128
    mov r8,[r15+2*32]
    mov r9d,1048576
    call rax
    cmp eax,128
    jne abi_error
    mov rdi,[r15+CMDPTR]
    cmp rdi,r13
    jne command_writable
    mov esi,4096
    mov edx,3
    mov eax,10
    syscall
    test rax,rax
    jnz io_error
command_writable:
    mov rax,EVENT
    cmp [r12],rax
    jne abi_error
    mov rax,[r15+LEASE]
    cmp [r12+16],rax
    jne abi_error
    cmp qword ptr [r12+8],7
    je terminal_event
    mov rax,[r15+SEQ]
    add rax,1
    jc abi_error
    cmp [r12+24],rax
    jne abi_error
    mov [r15+SEQ],rax
    mov rdi,r13
    xor eax,eax
    mov ecx,40
    rep stosq
    mov rax,ACK
    mov [r13],rax
    mov rax,[r15+LEASE]
    mov [r13+8],rax
    mov rax,[r15+SEQ]
    mov [r13+16],rax
    mov rax,[r12+8]
    mov [r13+24],rax
    mov [r15+CMDPTR],r13
    mov qword ptr [r15+CMDLEN],64
    cmp rax,1
    je op_call
    cmp rax,2
    je op_grow
    cmp rax,3
    je op_zero
    cmp rax,4
    je op_copy
    cmp rax,5
    je op_release
    cmp rax,6
    je op_protect
    cmp rax,8
    je op_switch
    cmp rax,10
    je op_create
    cmp rax,11
    je op_append
    cmp rax,12
    je op_read
    cmp rax,13
    je op_seal
    cmp rax,14
    je op_view
    cmp rax,15
    je op_run_child
    jmp abi_error

op_call:
    cmp qword ptr [r12+120],0
    jne abi_error
    mov rax,[r12+32]
    cmp rax,1
    jb abi_error
    cmp qword ptr [r15+KIND],2
    je component_edit_roles
    cmp rax,55
    je component_role_checked
    cmp rax,28
    ja abi_error
    jmp component_role_checked
component_edit_roles:
    cmp rax,63
    ja abi_error
    cmp rax,40
    jb component_role_checked
    cmp rax,46
    jbe abi_error
    cmp rax,56
    jb component_role_checked
    cmp rax,59
    jbe abi_error
component_role_checked:
    cmp qword ptr [r14+rax*8],0
    je abi_error
    mov rax,[r12+40]
    cmp rax,[r12+64]
    je abi_error
    cmp rax,[r12+80]
    je abi_error
    mov rax,[r12+64]
    cmp rax,[r12+80]
    je abi_error
    mov rdi,[r12+40]
    mov rsi,[r12+48]
    mov rdx,[r12+56]
    call range_view
    mov rax,[rcx+24]
    mov [r15+FIRST_RO],rax
    mov rdi,[r12+64]
    xor esi,esi
    mov rdx,[r12+72]
    call range_view
    mov rax,[rcx+24]
    mov [r15+SECOND_RO],rax
    mov rdi,[r12+80]
    xor esi,esi
    mov rdx,[r12+88]
    call range_view
    cmp qword ptr [rcx+24],0
    jne abi_error
    mov rdi,[r12+40]
    mov esi,1
    call protect_slot
    mov rcx,[r12+32]
    mov rax,TWO_READ_MASK
    bt rax,rcx
    jnc call_second_writable
    mov rdi,[r12+64]
    mov esi,1
    call protect_slot
    jmp actual_component_call
call_second_writable:
    cmp qword ptr [r15+SECOND_RO],0
    jne abi_error
actual_component_call:
    mov rax,[r12+40]
    shl rax,5
    mov rdi,[r15+rax]
    add rdi,[r12+48]
    mov rsi,[r12+56]
    mov rax,[r12+64]
    shl rax,5
    mov rdx,[r15+rax]
    mov rcx,[r12+72]
    mov rax,[r12+80]
    shl rax,5
    mov r8,[r15+rax]
    mov r9,[r12+88]
    mov rax,[r12+32]
    call qword ptr [r14+rax*8]
    mov eax,eax
    mov [r15+RESULT],rax
    cmp eax,0xfffffffd
    je abi_error
    mov rdi,[r12+40]
    mov rsi,[r15+FIRST_RO]
    call protect_slot
    mov rcx,[r12+32]
    mov rax,TWO_READ_MASK
    bt rax,rcx
    jnc call_rights_restored
    mov rdi,[r12+64]
    mov rsi,[r15+SECOND_RO]
    call protect_slot
call_rights_restored:
    mov rax,[r15+RESULT]
    mov [r13+40],rax
    mov rdi,[r12+96]
    mov rsi,[r12+104]
    mov rdx,[r12+112]
    jmp copy_observation

op_grow:
    mov edi,6
    call reserved_tail
    mov rdi,[r12+32]
    cmp rdi,4
    jb abi_error
    mov rsi,[r12+40]
    test rsi,rsi
    jz abi_error
    call resize_slot
    jmp controller_entry

op_zero:
    mov edi,7
    call reserved_tail
    mov rdi,[r12+32]
    mov rsi,[r12+40]
    mov rdx,[r12+48]
    call range_view
    cmp qword ptr [rcx+24],0
    jne abi_error
    mov rdi,rax
    mov rcx,rdx
    xor eax,eax
    rep stosb
    jmp controller_entry

op_copy:
    mov edi,9
    call reserved_tail
    mov rax,[r12+32]
    cmp rax,[r12+48]
    je abi_error
    mov rdi,[r12+32]
    mov rsi,[r12+40]
    mov rdx,[r12+64]
    call range_view
    mov [r15+IO_PTR],rax
    mov rdi,[r12+48]
    mov rsi,[r12+56]
    mov rdx,[r12+64]
    call range_view
    cmp qword ptr [rcx+24],0
    jne abi_error
    mov rdi,rax
    mov rsi,[r15+IO_PTR]
    mov rcx,[r12+64]
    rep movsb
    jmp controller_entry

op_release:
    mov edi,5
    call reserved_tail
    mov rax,[r12+32]
    cmp rax,4
    jb abi_error
    cmp rax,63
    ja abi_error
    shl rax,5
    lea rbx,[r15+rax]
    mov rdi,[rbx]
    test rdi,rdi
    jz abi_error
    mov rcx,[r12+32]
    cmp qword ptr [r15+BORROWED+rcx*8],0
    jne release_borrowed
    mov rsi,[rbx+16]
    mov eax,11
    syscall
    test rax,rax
    jnz io_error
release_borrowed:
    mov rcx,[r12+32]
    mov qword ptr [r15+BORROWED+rcx*8],0
    mov rdi,rbx
    xor eax,eax
    mov ecx,4
    rep stosq
    jmp controller_entry

op_protect:
    mov edi,6
    call reserved_tail
    mov rdi,[r12+32]
    cmp rdi,4
    jb abi_error
    mov rsi,[r12+40]
    call protect_slot
    jmp controller_entry

op_switch:
    mov edi,5
    call reserved_tail
    mov rax,[r12+32]
    cmp qword ptr [r15+KIND],2
    je switch_edit_role
    cmp qword ptr [r15+KIND],0
    jne abi_error
    cmp rax,40
    jb abi_error
    cmp rax,42
    ja abi_error
    jmp switch_role_checked
switch_edit_role:
    cmp rax,56
    jb abi_error
    cmp rax,59
    ja abi_error
switch_role_checked:
    cmp rax,[r15+ROLE]
    je abi_error
    mov [r15+ROLE],rax
    jmp controller_entry

op_create:
    mov edi,5
    call reserved_tail
    mov rbx,[r12+32]
    cmp rbx,1
    ja abi_error
    cmp qword ptr [r15+FDS+rbx*8],-1
    jne abi_error
    lea rdi,[rip+spool_name]
    mov esi,3
    mov eax,319
    syscall
    test rax,rax
    js io_error
    mov [r15+FDS+rbx*8],rax
    jmp controller_entry

op_append:
    mov edi,9
    call reserved_tail
    mov rbx,[r12+32]
    cmp rbx,1
    ja abi_error
    cmp qword ptr [r15+FDS+rbx*8],0
    jl abi_error
    cmp qword ptr [r15+SEALED+rbx*8],0
    jne abi_error
    mov rax,[r12+40]
    cmp rax,[r15+POSITIONS+rbx*8]
    jne abi_error
    test rax,rax
    js abi_error
    add rax,[r12+64]
    jc abi_error
    test rax,rax
    js abi_error
    mov [r15+IO_END],rax
    mov rdi,[r12+48]
    mov rsi,[r12+56]
    mov rdx,[r12+64]
    call range_view
    mov [r15+IO_PTR],rax
    mov rax,[r12+64]
    mov [r15+IO_LEFT],rax
    mov rax,[r12+40]
    mov [r15+IO_AT],rax
    mov [r15+IO_FILE],rbx
append_loop:
    cmp qword ptr [r15+IO_LEFT],0
    je append_done
    mov rbx,[r15+IO_FILE]
    mov rdi,[r15+FDS+rbx*8]
    mov rsi,[r15+IO_PTR]
    mov rdx,[r15+IO_LEFT]
    mov r10,[r15+IO_AT]
    mov eax,18
    syscall
    cmp rax,-4
    je append_loop
    test rax,rax
    jle io_error
    cmp rax,[r15+IO_LEFT]
    ja abi_error
    add [r15+IO_PTR],rax
    add [r15+IO_AT],rax
    sub [r15+IO_LEFT],rax
    jmp append_loop
append_done:
    mov rax,[r15+IO_END]
    mov [r15+POSITIONS+rbx*8],rax
    jmp controller_entry

op_read:
    mov edi,9
    call reserved_tail
    mov rbx,[r12+32]
    cmp rbx,1
    ja abi_error
    cmp qword ptr [r15+SEALED+rbx*8],1
    jne abi_error
    mov rax,[r12+40]
    mov rcx,[r15+POSITIONS+rbx*8]
    cmp rax,rcx
    ja abi_error
    sub rcx,rax
    cmp [r12+64],rcx
    ja abi_error
    mov rdi,[r12+48]
    mov rsi,[r12+56]
    mov rdx,[r12+64]
    call range_view
    cmp qword ptr [rcx+24],0
    jne abi_error
    mov [r15+IO_PTR],rax
    mov rax,[r12+64]
    mov [r15+IO_LEFT],rax
    mov rax,[r12+40]
    mov [r15+IO_AT],rax
    mov [r15+IO_FILE],rbx
read_spool_loop:
    cmp qword ptr [r15+IO_LEFT],0
    je controller_entry
    mov rbx,[r15+IO_FILE]
    mov rdi,[r15+FDS+rbx*8]
    mov rsi,[r15+IO_PTR]
    mov rdx,[r15+IO_LEFT]
    mov r10,[r15+IO_AT]
    mov eax,17
    syscall
    cmp rax,-4
    je read_spool_loop
    test rax,rax
    jle io_error
    cmp rax,[r15+IO_LEFT]
    ja abi_error
    add [r15+IO_PTR],rax
    add [r15+IO_AT],rax
    sub [r15+IO_LEFT],rax
    jmp read_spool_loop

op_seal:
    mov edi,5
    call reserved_tail
    mov rbx,[r12+32]
    cmp rbx,1
    ja abi_error
    cmp qword ptr [r15+FDS+rbx*8],0
    jl abi_error
    cmp qword ptr [r15+SEALED+rbx*8],0
    jne abi_error
    mov rdi,[r15+FDS+rbx*8]
    mov esi,1033
    mov edx,15
    mov eax,72
    syscall
    test rax,rax
    jnz io_error
    mov rdi,[r15+FDS+rbx*8]
    mov esi,1034
    mov eax,72
    syscall
    cmp rax,15
    jne io_error
    mov qword ptr [r15+SEALED+rbx*8],1
    jmp controller_entry

op_view:
    mov edi,7
    call reserved_tail
    mov rdi,[r12+32]
    mov rsi,[r12+40]
    mov rdx,[r12+48]
copy_observation:
    cmp rdx,256
    ja abi_error
    call range_view
    mov [r13+48],rdx
    lea rcx,[rdx+64]
    mov [r15+CMDLEN],rcx
    mov rsi,rax
    lea rdi,[r13+64]
    mov rcx,rdx
    rep movsb
    jmp controller_entry

terminal_event:
    mov rax,[r15+SEQ]
    cmp [r12+24],rax
    jne abi_error
    cmp qword ptr [r15+KIND],2
    je edit_publication
    cmp qword ptr [r15+ROLE],44
    je raw_handoff
    cmp qword ptr [r15+ROLE],43
    je ctor_handoff
    cmp qword ptr [r15+ROLE],40
    je lowering_handoff
    cmp qword ptr [r15+ROLE],45
    je final_publication
    cmp qword ptr [r15+ROLE],46
    jne abi_error
final_publication:
    cmp qword ptr [r12+32],0
    jne semantic_error
    cmp qword ptr [r12+40],0
    jne abi_error
    cmp qword ptr [r15+PARENT],0
    jne child_complete

    /* The HIA result supplies a complete readonly receipt and Core view.
     * A consumer must require successful exit and both complete extents. */
    cmp qword ptr [r15+ROLE],46
    jne abi_error
    cmp qword ptr [r12+48],56
    jne abi_error
    cmp qword ptr [r12+56],256
    jne abi_error
    cmp qword ptr [r15+56*32+24],1
    jne abi_error
    mov edi,56
    xor esi,esi
    mov edx,256
    call range_view
    mov [r15+IO_PTR],rax
    mov [r15+IO_LEFT],rdx
receipt_loop:
    cmp qword ptr [r15+IO_LEFT],0
    je receipt_complete
    mov edi,2
    mov rsi,[r15+IO_PTR]
    mov rdx,[r15+IO_LEFT]
    mov eax,1
    syscall
    cmp rax,-4
    je receipt_loop
    test rax,rax
    jle io_error
    cmp rax,[r15+IO_LEFT]
    ja abi_error
    add [r15+IO_PTR],rax
    sub [r15+IO_LEFT],rax
    jmp receipt_loop
receipt_complete:
    cmp qword ptr [r15+45*32+24],1
    jne abi_error
    mov edi,45
    xor esi,esi
    mov rdx,[r12+88]
    call range_view
    test rdx,rdx
    jz abi_error
    mov [r15+IO_PTR],rax
    mov [r15+IO_LEFT],rdx
publish_loop:
    cmp qword ptr [r15+IO_LEFT],0
    je success
    mov edi,1
    mov rsi,[r15+IO_PTR]
    mov rdx,[r15+IO_LEFT]
    mov eax,1
    syscall
    cmp rax,-4
    je publish_loop
    test rax,rax
    jle io_error
    cmp rax,[r15+IO_LEFT]
    ja abi_error
    add [r15+IO_PTR],rax
    sub [r15+IO_LEFT],rax
    jmp publish_loop

edit_publication:
    cmp qword ptr [r15+KIND],2
    jne abi_error
    cmp qword ptr [r15+DEPTH],0
    jne abi_error
    cmp qword ptr [r15+PARENT],0
    jne abi_error
    mov qword ptr [r15+IO_FILE],1
    mov qword ptr [r15+IO_END],0
    cmp qword ptr [r12+32],0
    jne edit_refusal_view
    cmp qword ptr [r12+40],0
    jne abi_error
    jmp edit_declared_view
edit_refusal_view:
    mov qword ptr [r15+IO_FILE],2
    mov qword ptr [r15+IO_END],2
    cmp qword ptr [r12+64],0
    jne edit_declared_view
    cmp qword ptr [r12+48],0
    jne abi_error
    cmp qword ptr [r12+56],0
    jne abi_error
    mov qword ptr [r15+IO_PTR],0
    mov qword ptr [r15+IO_LEFT],0
    jmp edit_write_terminal
edit_declared_view:
    mov rdi,[r12+48]
    mov rsi,[r12+56]
    mov rdx,[r12+64]
    call range_view
    cmp qword ptr [rcx+24],1
    jne abi_error
    mov [r15+IO_PTR],rax
    mov [r15+IO_LEFT],rdx
edit_write_terminal:
    mov rsi,r12
    mov edx,128
edit_terminal_write:
    mov edi,2
    mov eax,1
    syscall
    cmp rax,-4
    je edit_terminal_write
    test rax,rax
    jle io_error
    cmp rax,rdx
    ja abi_error
    add rsi,rax
    sub rdx,rax
    jne edit_terminal_write
edit_payload_write:
    cmp qword ptr [r15+IO_LEFT],0
    je edit_result_exit
    mov rdi,[r15+IO_FILE]
    mov rsi,[r15+IO_PTR]
    mov rdx,[r15+IO_LEFT]
    mov eax,1
    syscall
    cmp rax,-4
    je edit_payload_write
    test rax,rax
    jle io_error
    cmp rax,[r15+IO_LEFT]
    ja abi_error
    add [r15+IO_PTR],rax
    sub [r15+IO_LEFT],rax
    jmp edit_payload_write
edit_result_exit:
    mov rdi,[r15+IO_END]
    jmp terminate

raw_handoff:
    cmp qword ptr [r12+32],7
    je semantic_error
    mov rax,CTOR_INIT
    cmp [r12+32],rax
    jne abi_error
    mov rax,[r15+LEASE]
    add rax,1
    jc abi_error
    cmp [r12+40],rax
    jne abi_error
    mov rax,[r15+LEGACY]
    cmp [r12+48],rax
    jne abi_error
    cmp qword ptr [r12+64],48
    jne abi_error
    mov edi,9
    call reserved_tail
    xor ecx,ecx
raw_pool_check:
    cmp ecx,0
    je raw_pool_next
    cmp ecx,2
    je raw_pool_next
    cmp ecx,48
    je raw_pool_next
    mov rax,rcx
    shl rax,5
    cmp qword ptr [r15+rax],0
    jne abi_error
raw_pool_next:
    inc ecx
    cmp ecx,64
    jb raw_pool_check
    cmp qword ptr [r15+48*32+24],1
    jne abi_error
    mov rax,[r12+56]
    cmp [r15+48*32+8],rax
    jne abi_error
    lea rsi,[r15+48*32]
    lea rdi,[r15+1*32]
    mov ecx,4
    rep movsq
    lea rdi,[r15+48*32]
    xor eax,eax
    mov ecx,4
    rep stosq
    mov rax,[r12+40]
    mov [r15+LEASE],rax
    mov qword ptr [r15+SEQ],0
    mov qword ptr [r15+ROLE],43
    cmp qword ptr [r15+KIND],0
    je raw_target_selected
    mov qword ptr [r15+ROLE],46
raw_target_selected:
    mov rdi,r13
    xor eax,eax
    mov ecx,8
    rep stosq
    mov rax,CTOR_INIT
    cmp qword ptr [r15+KIND],0
    je raw_command_selected
    mov rax,PROGRAM_INIT
raw_command_selected:
    mov [r13],rax
    mov rax,[r12+40]
    mov [r13+8],rax
    mov rax,[r12+48]
    mov [r13+16],rax
    mov rax,[r12+56]
    mov [r13+24],rax
    mov [r15+CMDPTR],r13
    mov qword ptr [r15+CMDLEN],64
    jmp controller_entry

ctor_handoff:
    mov qword ptr [r15+ROLE],40
    jmp copy_handoff
lowering_handoff:
    cmp qword ptr [r12+32],0
    jne semantic_error
    cmp qword ptr [r12+40],0
    jne abi_error
    mov rax,[r15+PUB_ROLE]
    cmp rax,45
    jne abi_error
selected_publication:
    mov [r15+ROLE],rax
copy_handoff:
    mov rsi,r12
    mov rdi,r13
    mov ecx,16
    rep movsq
    mov [r15+CMDPTR],r13
    mov qword ptr [r15+CMDLEN],128
    jmp controller_entry


/* HIA chooses a complete fixed child invocation. No value is decoded here. */
op_run_child:
    /* Only edit -> program -> ordinary. No arbitrary recursion. */
    cmp qword ptr [r15+KIND],2
    je child_from_edit
    cmp qword ptr [r15+KIND],1
    jne abi_error
    cmp qword ptr [r15+ROLE],46
    jne abi_error
    cmp qword ptr [r15+DEPTH],1
    jne abi_error
    mov rax,[r15+PARENT]
    test rax,rax
    jz abi_error
    cmp qword ptr [rax+KIND],2
    jne abi_error
    cmp qword ptr [rax+DEPTH],0
    jne abi_error
    cmp qword ptr [rax+PARENT],0
    jne abi_error
    cmp qword ptr [r12+32],0
    jne abi_error
    cmp qword ptr [r12+80],0
    jne abi_error
    jmp child_mode_checked
child_from_edit:
    cmp qword ptr [r15+DEPTH],0
    jne abi_error
    cmp qword ptr [r15+PARENT],0
    jne abi_error
    cmp qword ptr [r15+ROLE],56
    jb abi_error
    cmp qword ptr [r15+ROLE],59
    ja abi_error
    cmp qword ptr [r12+32],2
    jne abi_error
child_mode_checked:
    mov edi,11
    call reserved_tail
    cmp qword ptr [r12+48],0
    jne abi_error
    mov rax,[r12+40]
    cmp rax,[r12+64]
    je abi_error
    mov rdi,rax
    xor esi,esi
    mov rdx,[r12+56]
    cmp qword ptr [r12+32],2
    je child_input_view
    test rdx,rdx
    jz abi_error
    call range_view
    cmp [rcx+8],rdx
    jne abi_error
    jmp child_input_checked
child_input_view:
    call range_view
child_input_checked:
    cmp qword ptr [rcx+24],1
    jne abi_error
    mov rax,[r12+64]
    cmp rax,4
    jb abi_error
    cmp rax,63
    ja abi_error
    shl rax,5
    cmp qword ptr [r15+rax],0
    jne abi_error
    mov rax,[r12+72]
    test rax,rax
    jz abi_error
    cmp rax,-1
    je abi_error
    xor edi,edi
    mov esi,16384
    mov edx,3
    mov r10d,0x22
    mov r8,-1
    xor r9d,r9d
    mov eax,9
    syscall
    cmp rax,-4095
    jae io_error
    mov r10,rax
    mov [r10+PARENT],r15
    mov qword ptr [r10+FDS],-1
    mov qword ptr [r10+FDS+8],-1
    mov rax,[r12+32]
    mov [r10+RUN_MODE],rax
    mov qword ptr [r10+LEGACY],0
    mov rcx,[r15+DEPTH]
    add rcx,1
    cmp rcx,2
    ja abi_error
    mov [r10+DEPTH],rcx
    mov rcx,[r15+DIGITS]
    mov [r10+DIGITS],rcx
    mov qword ptr [r10+KIND],0
    mov qword ptr [r10+PUB_ROLE],45
    test rax,rax
    jz child_kind_selected
    mov qword ptr [r10+KIND],1
    mov qword ptr [r10+PUB_ROLE],46
    mov rcx,[r12+80]
    mov [r10+DIGITS],rcx
child_kind_selected:
    mov rax,[r12+64]
    mov [r10+CHILD_TARGET],rax
    mov rax,[r12+72]
    mov [r10+LEASE],rax
    mov rax,[r12+56]
    mov [r10+RAW_LEN],rax
    mov edx,44
    mov qword ptr [r10+BORROWED+rdx*8],1
    shl rdx,5
    lea rdi,[r10+rdx]
    mov rsi,[r12+40]
    shl rsi,5
    add rsi,r15
    mov ecx,4
    rep movsq
    mov rax,[r10+RAW_LEN]
    mov [r10+44*32+8],rax
    mov r15,r10
    xor edi,edi
    mov esi,4096
    mov edx,3
    mov r10d,0x22
    mov r8,-1
    xor r9d,r9d
    mov eax,9
    syscall
    cmp rax,-4095
    jae io_error
    mov [r15+CMDMAP],rax
    mov r13,rax
    xor edi,edi
    mov esi,4096
    mov edx,3
    mov r10d,0x22
    mov r8,-1
    xor r9d,r9d
    mov eax,9
    syscall
    cmp rax,-4095
    jae io_error
    mov [r15+FRAMEMAP],rax
    mov r12,rax
    xor edi,edi
    mov esi,1
    call resize_slot
    xor edi,edi
    mov esi,1
    call protect_slot
    mov edi,2
    mov esi,1048576
    call resize_slot
    mov rbx,[r15+2*32]
    mov qword ptr [rbx+4096],1
    mov qword ptr [rbx+4096+16],1048576
    mov rax,[r15+RAW_LEN]
    mov [rbx+4096+44*8],rax
    mov rax,RAW_CONFIG
    mov [rbx+12288],rax
    mov qword ptr [rbx+12296],0
    mov rax,[r15+DIGITS]
    mov [rbx+12304],rax
    mov rax,[r15+LEASE]
    mov [rbx+12312],rax
    mov qword ptr [r15+ROLE],44
    mov rax,[r15+44*32]
    mov [r15+CMDPTR],rax
    mov rax,[r15+RAW_LEN]
    mov [r15+CMDLEN],rax
    jmp controller_entry
/* Copy only actual terminal bytes and transfer one actual readonly mapping.
 * The parent ACK is inaccessible to HIA child kernels. Its private context
 * and pending sequence remain live and immutable throughout this invocation.
 */
child_complete:
    /* Rejoin exactly the suspended bounded parent invocation. */
    mov rbx,[r15+PARENT]
    test rbx,rbx
    jz abi_error
    cmp qword ptr [r15+RUN_MODE],2
    je return_program_child
    cmp qword ptr [r15+RUN_MODE],0
    jne abi_error
    cmp qword ptr [r15+KIND],0
    jne abi_error
    cmp qword ptr [r15+DEPTH],2
    jne abi_error
    cmp qword ptr [rbx+KIND],1
    jne abi_error
    cmp qword ptr [rbx+DEPTH],1
    jne abi_error
    cmp qword ptr [rbx+ROLE],46
    jne abi_error
    mov rax,[rbx+PARENT]
    test rax,rax
    jz abi_error
    cmp qword ptr [rax+KIND],2
    jne abi_error
    cmp qword ptr [rax+DEPTH],0
    jne abi_error
    cmp qword ptr [rax+PARENT],0
    jne abi_error
    jmp return_parent_checked
return_program_child:
    cmp qword ptr [r15+KIND],1
    jne abi_error
    cmp qword ptr [r15+DEPTH],1
    jne abi_error
    cmp qword ptr [rbx+KIND],2
    jne abi_error
    cmp qword ptr [rbx+DEPTH],0
    jne abi_error
    cmp qword ptr [rbx+PARENT],0
    jne abi_error
    cmp qword ptr [rbx+ROLE],56
    jb abi_error
    cmp qword ptr [rbx+ROLE],59
    ja abi_error
return_parent_checked:
    mov rax,[rbx+FRAMEMAP]
    mov rcx,[rax+32]
    cmp [r15+RUN_MODE],rcx
    jne abi_error
    mov rax,[rbx+FRAMEMAP]
    cmp qword ptr [rax+8],15
    jne abi_error
    mov rcx,[r15+CHILD_TARGET]
    cmp [rax+64],rcx
    jne abi_error
    mov rdi,[rbx+CMDMAP]
    cmp qword ptr [rdi+24],15
    jne abi_error
    mov qword ptr [rdi+40],128
    mov qword ptr [rdi+48],160
    mov qword ptr [rdi+192],0
    mov [rdi+200],rcx
    mov rax,[r15+ROLE]
    mov [rdi+208],rax
    mov qword ptr [rdi+216],0
    add rdi,64
    mov rsi,r12
    mov ecx,16
    rep movsq
    mov qword ptr [rbx+CMDLEN],224
    cmp qword ptr [r12+32],0
    jne child_diagnostic_transfer
    cmp qword ptr [r12+40],0
    jne abi_error
    mov rax,[r15+ROLE]
    cmp [r15+PUB_ROLE],rax
    jne abi_error
    cmp qword ptr [r15+45*32+24],1
    jne abi_error
    mov edi,45
    xor esi,esi
    mov rdx,[r12+88]
    test rdx,rdx
    jz abi_error
    call range_view
    cmp qword ptr [r15+RUN_MODE],2
    je child_frame_copy
    mov rax,[r15+CHILD_TARGET]
    shl rax,5
    lea rdi,[rbx+rax]
    cmp qword ptr [rdi],0
    jne abi_error
    lea rsi,[r15+45*32]
    mov ecx,4
    rep movsq
    mov rax,[r15+45*32+8]
    mov rdi,[rbx+CMDMAP]
    mov [rdi+192],rax
    lea rdi,[r15+45*32]
    xor eax,eax
    mov ecx,4
    rep stosq
    jmp child_cleanup
child_frame_copy:
    /* Exact actual receipt + exact actual Core. No header is rebuilt. */
    mov [r15+IO_PTR],rax
    mov [r15+IO_LEFT],rdx
    cmp qword ptr [r12+48],56
    jne abi_error
    cmp qword ptr [r12+56],256
    jne abi_error
    cmp qword ptr [r15+56*32+24],1
    jne abi_error
    mov edi,56
    xor esi,esi
    mov edx,256
    call range_view
    mov [r15+IO_AT],rax
    mov rax,[r15+IO_LEFT]
    add rax,256
    jc abi_error
    test rax,rax
    js abi_error
    mov [r15+IO_END],rax
    mov rcx,[r15+CHILD_TARGET]
    shl rcx,5
    cmp qword ptr [rbx+rcx],0
    jne abi_error
    push r15
    mov rdi,[r15+CHILD_TARGET]
    mov rsi,[r15+IO_END]
    mov r15,rbx
    call resize_slot
    pop r15
    mov rcx,[r15+CHILD_TARGET]
    shl rcx,5
    mov rdi,[rbx+rcx]
    mov rsi,[r15+IO_AT]
    mov ecx,256
    rep movsb
    mov rsi,[r15+IO_PTR]
    mov rcx,[r15+IO_LEFT]
    rep movsb
    push r15
    mov rdi,[r15+CHILD_TARGET]
    mov esi,1
    mov r15,rbx
    call protect_slot
    pop r15
    mov rdi,[rbx+CMDMAP]
    mov rax,[r15+IO_END]
    mov [rdi+192],rax
    jmp child_cleanup
child_diagnostic_transfer:
    /* No diagnostic text/header is interpreted by the fixed executor. */
    cmp qword ptr [r12+32],8
    jne child_cleanup
    mov rax,[r15+ROLE]
    cmp [r15+PUB_ROLE],rax
    jne abi_error
    cmp qword ptr [r15+57*32],0
    je abi_error
    cmp qword ptr [r15+57*32+8],65
    jb abi_error
    cmp qword ptr [r15+57*32+24],1
    jne abi_error
    cmp qword ptr [r15+BORROWED+57*8],0
    jne abi_error
    mov rax,[r15+CHILD_TARGET]
    shl rax,5
    lea rdi,[rbx+rax]
    cmp qword ptr [rdi],0
    jne abi_error
    lea rsi,[r15+57*32]
    mov ecx,4
    rep movsq
    mov rax,[r15+57*32+8]
    mov rdi,[rbx+CMDMAP]
    mov [rdi+192],rax
    lea rdi,[r15+57*32]
    xor eax,eax
    mov ecx,4
    rep stosq
    jmp child_cleanup
child_cleanup:
    xor r8d,r8d
child_cleanup_maps:
    cmp qword ptr [r15+BORROWED+r8*8],0
    jne child_cleanup_next
    mov r9,r8
    shl r9,5
    mov rdi,[r15+r9]
    test rdi,rdi
    jz child_cleanup_next
    mov rsi,[r15+r9+16]
    mov eax,11
    syscall
    test rax,rax
    jnz io_error
child_cleanup_next:
    inc r8d
    cmp r8d,64
    jb child_cleanup_maps
    xor r8d,r8d
child_cleanup_files:
    mov rdi,[r15+FDS+r8*8]
    test rdi,rdi
    js child_cleanup_file_next
    mov eax,3
    syscall
    test rax,rax
    jnz io_error
child_cleanup_file_next:
    inc r8d
    cmp r8d,2
    jb child_cleanup_files
    mov rdi,r13
    mov esi,4096
    mov eax,11
    syscall
    test rax,rax
    jnz io_error
    mov rdi,r12
    mov esi,4096
    mov eax,11
    syscall
    test rax,rax
    jnz io_error
    mov rdi,r15
    mov esi,16384
    mov eax,11
    syscall
    test rax,rax
    jnz early_io
    mov r15,rbx
    mov r12,[r15+FRAMEMAP]
    mov r13,[r15+CMDMAP]
    jmp controller_entry

/* Leaf helpers. All quantities are exact unsigned buffer extents, never values. */
reserved_tail:
    cmp edi,16
    jae tail_done
    cmp qword ptr [r12+rdi*8],0
    jne abi_error
    inc edi
    jmp reserved_tail
tail_done:
    ret

range_view:
    cmp rdi,63
    ja abi_error
    mov rcx,rdi
    shl rcx,5
    add rcx,r15
    mov rax,[rcx]
    test rax,rax
    jz abi_error
    mov r8,[rcx+8]
    cmp rsi,r8
    ja abi_error
    sub r8,rsi
    cmp rdx,r8
    ja abi_error
    add rax,rsi
    ret

protect_slot:
    cmp rdi,63
    ja abi_error
    cmp rsi,1
    ja abi_error
    cmp qword ptr [r15+BORROWED+rdi*8],0
    je protection_owned
    cmp rsi,1
    jne abi_error
protection_owned:
    shl rdi,5
    lea r9,[r15+rdi]
    cmp qword ptr [r9],0
    je abi_error
    cmp [r9+24],rsi
    je protect_done
    mov r8,rsi
    mov rdi,[r9]
    mov rsi,[r9+16]
    mov edx,3
    test r8,r8
    jz protect_call
    mov edx,1
protect_call:
    mov eax,10
    syscall
    test rax,rax
    jnz io_error
    mov [r9+24],r8
protect_done:
    ret

resize_slot:
    cmp rdi,63
    ja abi_error
    test rsi,rsi
    js abi_error
    push rbx
    push r12
    push r13
    mov rbx,rdi
    shl rbx,5
    add rbx,r15
    mov r12,rsi
    cmp qword ptr [rbx],0
    je resize_allowed
    cmp qword ptr [rbx+24],0
    jne abi_error
    cmp r12,[rbx+8]
    jbe abi_error
resize_allowed:
    mov r13,r12
    add r13,4095
    jc abi_error
    and r13,-4096
    jnz resize_map
    mov r13d,4096
resize_map:
    xor edi,edi
    mov rsi,r13
    mov edx,3
    mov r10d,0x22
    mov r8,-1
    xor r9d,r9d
    mov eax,9
    syscall
    cmp rax,-4095
    jae io_error
    mov r8,rax
    cmp qword ptr [rbx],0
    je resize_store
    mov rdi,r8
    mov rsi,[rbx]
    mov rcx,[rbx+8]
    rep movsb
    mov rdi,[rbx]
    mov rsi,[rbx+16]
    mov eax,11
    syscall
    test rax,rax
    jnz io_error
resize_store:
    mov [rbx],r8
    mov [rbx+8],r12
    mov [rbx+16],r13
    mov qword ptr [rbx+24],0
    pop r13
    pop r12
    pop rbx
    ret

semantic_error:
    cmp qword ptr [r15+PARENT],0
    jne child_complete
    mov rsi,r12
    mov edx,128
semantic_write:
    mov edi,2
    mov eax,1
    syscall
    cmp rax,-4
    je semantic_write
    test rax,rax
    jle early_io
    add rsi,rax
    sub rdx,rax
    jne semantic_write
    mov edi,2
    jmp terminate

abi_error:
    mov ebx,3
    jmp execution_error
io_error:
    mov ebx,4
execution_error:
    mov rax,0x3130524558414948
    mov [r15+4096],rax
    mov [r15+4104],rbx
    mov rax,[r15+ROLE]
    mov [r15+4112],rax
    mov rax,[r15+SEQ]
    mov [r15+4120],rax
    mov edi,2
    lea rsi,[r15+4096]
    mov edx,32
error_write:
    mov eax,1
    syscall
    cmp rax,-4
    je error_write
    test rax,rax
    jle error_exit
    add rsi,rax
    sub rdx,rax
    jne error_write
error_exit:
    mov edi,ebx
    jmp terminate
success:
    xor edi,edi
    jmp terminate
early_usage:
    mov edi,64
    jmp terminate
early_io:
    mov edi,4
terminate:
    mov eax,60
    syscall
    ud2

spool_name:
    .asciz "hia-private-spool"
    .p2align 3
image_table:
    .zero 512
executable_policy:
    .quad 4,4300
executor_end:
.section .note.GNU-stack,"",@progbits
