/* Fixed Linux x86-64 CLI and finite service-context mechanics, new development.
 * Captures all argv/env C-string bytes and the actual stdout TIOCGWINSZ result.
 * HIA owns decoding, option parsing, environment policy, file admission and
 * output selection. No JSON, CLI option or business-service parser is here.
 * Forked descriptor mechanics from native-edit-executor-next; this standalone
 * process owns one requested input fd and relies on Linux exit cleanup on fatal
 * allocation/protocol failure. Service lifetimes use the explicit finite ABI.
 */
.intel_syntax noprefix
.section .text
.global executor_start
.equ LEASE,2056
.equ SEQ,2064
.equ CMDLEN,2072
.equ CMDMAP,2088
.equ FRAMEMAP,2096
.equ FD,2112
.equ FIRST_RO,2160
.equ SECOND_RO,2168
.equ RESULT,2176
.equ IO_PTR,2184
.equ IO_LEFT,2192
.equ IO_FILE,2208
.equ ARG_STACK,2280
.equ ARGC,2288
.equ ARGV,2296
.equ ENVC,2304
.equ ENVP,2312
.equ STRBYTES,2320
.equ ROW_CURSOR,2328
.equ SCALAR_CURSOR,2336
.equ WIN,2400
.equ EVENT,0x3130454443414948
.equ ACK,0x3130414443414948
.equ TWO_READ_MASK,0x78

executor_start:
    mov rbx,rsp
    and rsp,-16
    cld
    lea r14,[rip+image_table]
    xor edi,edi
    mov esi,16384
    call map_rw
    mov r15,rax
    mov [r15+ARG_STACK],rbx
    mov qword ptr [r15+FD],-1
    mov qword ptr [r15+LEASE],1
    xor edi,edi
    mov esi,4096
    call map_rw
    mov r13,rax
    mov [r15+CMDMAP],rax
    xor edi,edi
    mov esi,4096
    call map_rw
    mov r12,rax
    mov [r15+FRAMEMAP],rax
    xor edi,edi
    xor esi,esi
    call resize_slot
    xor edi,edi
    mov esi,1
    call protect_slot
    mov edi,2
    mov esi,65536
    call resize_slot
    mov edi,3
    mov esi,128
    call resize_slot

    mov rbx,[r15+ARG_STACK]
    mov rax,[rbx]
    mov [r15+ARGC],rax
    lea rsi,[rbx+8]
    mov [r15+ARGV],rsi
    mov rcx,rax
    shr rcx,61
    jnz abi_error
    shl rax,3
    add rax,16
    jc abi_error
    add rax,rbx
    jc abi_error
    mov [r15+ENVP],rax
    mov rsi,rax
    xor ecx,ecx
env_count:
    cmp qword ptr [rsi],0
    je env_counted
    add rsi,8
    jc abi_error
    inc rcx
    jz abi_error
    jmp env_count
env_counted:
    mov [r15+ENVC],rcx
    mov rsi,[r15+ENVP]
    call count_strings
    mov rsi,[r15+ARGV]
    mov rcx,[r15+ARGC]
    call count_strings
    mov rax,[r15+ARGC]
    add rax,[r15+ENVC]
    jc abi_error
    mov rcx,rax
    shr rcx,60
    jnz abi_error
    shl rax,4
    add rax,96
    jc abi_error
    mov [r15+SCALAR_CURSOR],rax
    mov qword ptr [r15+ROW_CURSOR],96
    mov rsi,rax
    add rsi,[r15+STRBYTES]
    jc abi_error
    mov edi,1
    call resize_slot
    mov rbx,[r15+32]
    mov rax,0x3130534f43414948
    mov [rbx],rax
    mov qword ptr [rbx+8],1
    mov rax,[r15+ARGC]
    mov [rbx+16],rax
    mov rax,[r15+ENVC]
    mov [rbx+24],rax
    mov qword ptr [rbx+32],96
    mov rax,[r15+SCALAR_CURSOR]
    mov [rbx+40],rax
    mov rax,[r15+40]
    mov [rbx+48],rax
    mov edi,1
    mov esi,0x5413
    lea rdx,[r15+WIN]
    mov eax,16
    syscall
    test rax,rax
    js tty_error
    movzx eax,word ptr [r15+WIN+2]
    mov [rbx+56],rax
    movzx eax,word ptr [r15+WIN]
    mov [rbx+64],rax
    jmp tty_done
tty_error:
    neg rax
    mov [rbx+72],rax
tty_done:
    mov rsi,[r15+ARGV]
    mov rcx,[r15+ARGC]
    call capture_strings
    mov rsi,[r15+ENVP]
    mov rcx,[r15+ENVC]
    call capture_strings
    mov rax,[r15+SCALAR_CURSOR]
    cmp rax,[r15+40]
    jne abi_error
    mov edi,1
    mov esi,1
    call protect_slot
    mov rax,0x3130494c43414948
    mov [r13],rax
    mov qword ptr [r13+8],1
    mov rax,[r15+40]
    mov [r13+16],rax
    mov qword ptr [r15+CMDLEN],64
    jmp controller_entry

count_strings:
    test rcx,rcx
    jz count_done
    mov rdx,[rsi]
    test rdx,rdx
    jz abi_error
    xor eax,eax
count_char:
    cmp byte ptr [rdx+rax],0
    je count_next
    inc rax
    jz abi_error
    jmp count_char
count_next:
    add [r15+STRBYTES],rax
    jc abi_error
    add rsi,8
    dec rcx
    jmp count_strings
count_done:
    ret

capture_strings:
    test rcx,rcx
    jz capture_done
    mov rdx,[rsi]
    mov r8,[r15+ROW_CURSOR]
    mov r9,[r15+SCALAR_CURSOR]
    mov rax,[r15+32]
    mov [rax+r8],r9
    xor edi,edi
capture_char:
    mov r10b,[rdx+rdi]
    test r10b,r10b
    jz capture_next
    cmp r9,[r15+40]
    jae abi_error
    mov [rax+r9],r10b
    inc r9
    inc rdi
    jmp capture_char
capture_next:
    mov [rax+r8+8],rdi
    add r8,16
    mov [r15+ROW_CURSOR],r8
    mov [r15+SCALAR_CURSOR],r9
    add rsi,8
    dec rcx
    jmp capture_strings
capture_done:
    ret

controller_entry:
    mov rdi,r13
    mov esi,4096
    mov edx,1
    mov eax,10
    syscall
    test rax,rax
    jnz io_error
    mov rdi,r13
    mov rsi,[r15+CMDLEN]
    mov rdx,r12
    mov ecx,128
    mov r8,[r15+64]
    mov r9d,65536
    call qword ptr [r14+7*8]
    cmp eax,128
    jne abi_error
    mov rdi,r13
    mov esi,4096
    mov edx,3
    mov eax,10
    syscall
    test rax,rax
    jnz io_error
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
    cmp rax,14
    je op_view
    cmp rax,16
    je op_primitive
    cmp rax,17
    je op_business
    jmp abi_error

op_call:
    cmp qword ptr [r12+120],0
    jne abi_error
    mov rax,[r12+32]
    cmp rax,1
    jb abi_error
    cmp rax,6
    ja abi_error
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
    cmp rdi,4
    jb abi_error
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
    /* Slot 3 is a dedicated 128-byte RWW output, not the event mapping. */
    cmp qword ptr [r12+64],3
    jne abi_error
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
    cmp rdi,4
    jb abi_error
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
    cmp rdi,4
    jb abi_error
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
    mov rcx,[r15+BUS_PINNED]
    bt rcx,rax
    jc abi_error
    shl rax,5
    lea rbx,[r15+rax]
    mov rdi,[rbx]
    test rdi,rdi
    jz abi_error
    mov rsi,[rbx+16]
    mov eax,11
    syscall
    test rax,rax
    jnz io_error
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

/* args: primitive, fd, buffer slot/offset/extent, flags, observation
 * slot/offset/extent, three reserved zeros. Raw negative errno is never
 * reinterpreted as a language error by this carrier. */
op_primitive:
    mov edi,13
    call reserved_tail
    mov rax,[r12+32]
    cmp rax,1
    jb abi_error
    cmp rax,4
    ja abi_error
    mov rdi,[r12+48]
    mov rsi,[r12+56]
    mov rdx,[r12+64]
    call range_view
    mov [r15+IO_PTR],rax
    cmp qword ptr [r12+32],1
    je primitive_open
    cmp qword ptr [r12+72],0
    jne abi_error
    mov rdi,[r12+40]
    cmp rdi,[r15+FD]
    jne abi_error
    test rdi,rdi
    js abi_error
    cmp qword ptr [r12+32],2
    je primitive_stat
    cmp qword ptr [r12+32],3
    je primitive_read
    cmp qword ptr [r12+64],0
    jne abi_error
    mov qword ptr [r15+FD],-1
    mov eax,3
    syscall
    jmp primitive_result
primitive_open:
    cmp qword ptr [r15+FD],-1
    jne abi_error
    cmp qword ptr [r12+40],0
    jne abi_error
    test rdx,rdx
    jz abi_error
    cmp byte ptr [rax+rdx-1],0
    jne abi_error
    mov rsi,rax
    mov rdi,-100
    mov rdx,[r12+72]
    xor r10d,r10d
    mov eax,257
    syscall
    test rax,rax
    js primitive_result
    mov [r15+FD],rax
    jmp primitive_result
primitive_stat:
    cmp qword ptr [r12+48],4
    jb abi_error
    cmp qword ptr [rcx+24],0
    jne abi_error
    cmp qword ptr [r12+64],144
    jne abi_error
    mov rsi,[r15+IO_PTR]
    mov eax,5
    syscall
    jmp primitive_result
primitive_read:
    cmp qword ptr [r12+48],4
    jb abi_error
    cmp qword ptr [rcx+24],0
    jne abi_error
    mov rsi,[r15+IO_PTR]
    mov rdx,[r12+64]
    xor eax,eax
    syscall
primitive_result:
    mov [r13+40],rax
    mov rdi,[r12+80]
    mov rsi,[r12+88]
    mov rdx,[r12+96]
    jmp copy_observation

terminal_event:
    mov rax,[r15+SEQ]
    cmp [r12+24],rax
    jne abi_error
    mov edi,11
    call reserved_tail
    cmp qword ptr [r12+32],255
    ja abi_error
    /* Both complete readonly views are admitted before either stream writes. */
    mov rdi,[r12+40]
    mov rsi,[r12+48]
    mov rdx,[r12+56]
    call range_view
    cmp qword ptr [rcx+24],1
    jne abi_error
    mov rdi,[r12+64]
    mov rsi,[r12+72]
    mov rdx,[r12+80]
    call range_view
    cmp qword ptr [rcx+24],1
    jne abi_error
    mov rdi,[r12+40]
    mov rsi,[r12+48]
    mov rdx,[r12+56]
    call range_view
    mov rsi,rax
    mov edi,1
    call write_all
    mov rdi,[r12+64]
    mov rsi,[r12+72]
    mov rdx,[r12+80]
    call range_view
    mov rsi,rax
    mov edi,2
    call write_all
    mov rdi,[r12+32]
    jmp terminate

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
    cmp rsi,1
    je parent_protection_checked
    mov rax,[r15+BUS_PINNED]
    bt rax,rdi
    jc abi_error
parent_protection_checked:
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
    mov rax,[r15+BUS_PINNED]
    bt rax,rdi
    jc abi_error
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
    call map_rw
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
map_rw:
    mov edx,3
    mov r10d,0x22
    mov r8,-1
    xor r9d,r9d
    mov eax,9
    syscall
    cmp rax,-4095
    jae io_error
    ret
write_all:
    test rdx,rdx
    jz write_done
    mov eax,1
    syscall
    cmp rax,-4
    je write_all
    test rax,rax
    jle io_error
    cmp rax,rdx
    ja abi_error
    add rsi,rax
    sub rdx,rax
    jmp write_all
write_done:
    ret
abi_error:
    mov edi,126
    jmp terminate
io_error:
    mov edi,74
terminate:
    mov eax,60
    syscall
    ud2


/* Private outer service contexts. The service interpreter's original internal
 * KIND/DEPTH/PARENT graph remains unchanged; SERVICE_HOST is a separate edge. */
.equ BUS_CHILD,2464
.equ BUS_ID,2472
.equ BUS_LEASE,2480
.equ BUS_SEQ,2488
.equ BUS_LIFECYCLE,2496
.equ BUS_TARGET,2504
.equ BUS_PINNED,2512
.equ BUS_PIN_TEMP,2520
.equ BUS_COMMAND_PTR,2528
.equ BUS_COMMAND_LEN,2536
.equ BUS_TABLE_PTR,2544
.equ BUS_TABLE_COUNT,2552
.equ BUS_VERB,2560
.equ BUS_MASK,2568
.equ BUS_MASK_TEMP,2576
.equ BUS_ROW_TARGET,2584
.equ BUS_ROW_SOURCE,2592
.equ SVC_HOST,2304
.equ SVC_SERVICE_ID,2312
.equ SVC_SERVICE_LEASE,2320
.equ SVC_WAITING,2328
.equ SVC_TABLE_PTR,2336

op_business:
    cmp qword ptr [r15+FD],-1
    jne abi_error
    cmp qword ptr [r12+120],0
    jne abi_error
    mov rax,[r12+32]
    cmp rax,1
    jb abi_error
    cmp rax,3
    ja abi_error
    mov [r15+BUS_VERB],rax
    mov rcx,[r12+40]
    cmp rcx,1
    jb abi_error
    cmp rcx,2
    ja abi_error
    cmp qword ptr [r12+48],0
    je abi_error
    cmp rax,1
    je business_new
    cmp qword ptr [r15+BUS_CHILD],0
    je abi_error
    cmp rcx,[r15+BUS_ID]
    jne abi_error
    mov rcx,[r12+48]
    cmp rcx,[r15+BUS_LEASE]
    jne abi_error
    mov rcx,[r12+112]
    cmp rcx,[r15+BUS_SEQ]
    jne abi_error
    cmp rax,3
    je business_retire
    cmp qword ptr [r15+BUS_LIFECYCLE],0
    jne abi_error
    mov rcx,[r15+BUS_CHILD]
    cmp qword ptr [rcx+SVC_WAITING],1
    jne abi_error
    jmp business_inputs
business_new:
    cmp qword ptr [r15+BUS_CHILD],0
    jne abi_error
    cmp qword ptr [r12+112],0
    jne abi_error
business_inputs:
    mov rax,[r12+104]
    cmp rax,4
    jb abi_error
    cmp rax,63
    ja abi_error
    mov rcx,[r15+BUS_PINNED]
    bt rcx,rax
    jc abi_error
    shl rax,5
    cmp qword ptr [r15+rax],0
    jne abi_error
    cmp qword ptr [r12+72],128
    jne abi_error
    mov rdi,[r12+56]
    mov rsi,[r12+64]
    mov rdx,[r12+72]
    call range_view
    cmp qword ptr [rcx+24],1
    jne abi_error
    mov [r15+BUS_COMMAND_PTR],rax
    mov [r15+BUS_COMMAND_LEN],rdx
    mov rdi,[r12+80]
    mov rsi,[r12+88]
    mov rdx,[r12+96]
    call range_view
    cmp qword ptr [rcx+24],1
    jne abi_error
    cmp rdx,32
    jb abi_error
    mov [r15+BUS_TABLE_PTR],rax
    mov rcx,0x313056534c414948
    cmp [rax],rcx
    jne abi_error
    cmp qword ptr [rax+8],1
    jne abi_error
    mov rcx,[rax+16]
    cmp rcx,4
    ja abi_error
    mov [r15+BUS_TABLE_COUNT],rcx
    shl rcx,5
    add rcx,32
    cmp rcx,rdx
    jne abi_error
    cmp [rax+24],rdx
    jne abi_error
    mov qword ptr [r15+BUS_MASK_TEMP],0
    mov qword ptr [r15+BUS_PIN_TEMP],0
    xor ebx,ebx
business_validate_rows:
    cmp rbx,[r15+BUS_TABLE_COUNT]
    jae business_rows_validated
    mov rax,rbx
    shl rax,5
    add rax,[r15+BUS_TABLE_PTR]
    add rax,32
    mov rdi,[rax]
    cmp rdi,63
    ja abi_error
    mov [r15+BUS_ROW_SOURCE],rdi
    mov rsi,[rax+8]
    mov rdx,[rax+16]
    mov rcx,[rax+24]
    cmp rcx,63
    ja abi_error
    mov [r15+BUS_ROW_TARGET],rcx
    cmp qword ptr [r15+BUS_VERB],1
    je business_validate_initial_target
    cmp rcx,4
    jb abi_error
    mov r8,[r15+BUS_MASK]
    bt r8,rcx
    jnc abi_error
    mov r8,[r15+BUS_CHILD]
    mov r9,rcx
    shl r9,5
    cmp qword ptr [r8+r9],0
    jne abi_error
    jmp business_target_valid
business_validate_initial_target:
    cmp rcx,1
    je business_target_valid
    cmp rcx,4
    je business_target_valid
    cmp rcx,5
    jne abi_error
business_target_valid:
    mov r8,[r15+BUS_MASK_TEMP]
    bts r8,rcx
    jc abi_error
    mov [r15+BUS_MASK_TEMP],r8
    call range_view
    cmp qword ptr [rcx+24],1
    jne abi_error
    mov rcx,[r15+BUS_ROW_SOURCE]
    mov r8,[r15+BUS_PIN_TEMP]
    bts r8,rcx
    mov [r15+BUS_PIN_TEMP],r8
    inc rbx
    jmp business_validate_rows
business_rows_validated:
    mov rax,[r15+BUS_MASK_TEMP]
    cmp qword ptr [r15+BUS_VERB],1
    jne business_resume_mask
    cmp rax,0x32
    jne abi_error
    jmp business_validated
business_resume_mask:
    cmp rax,[r15+BUS_MASK]
    jne abi_error
business_validated:
    mov rax,[r12+104]
    mov [r15+BUS_TARGET],rax
    mov rax,[r15+BUS_PIN_TEMP]
    or [r15+BUS_PINNED],rax
    cmp qword ptr [r15+BUS_VERB],1
    jne business_install_rows
    mov rax,[r12+40]
    mov [r15+BUS_ID],rax
    mov rax,[r12+48]
    mov [r15+BUS_LEASE],rax
    xor edi,edi
    mov esi,16384
    call map_rw
    mov [r15+BUS_CHILD],rax
    mov [rax+SVC_HOST],r15
    mov rdx,[r15+BUS_ID]
    mov [rax+SVC_SERVICE_ID],rdx
    mov rdx,[r15+BUS_LEASE]
    mov [rax+SVC_SERVICE_LEASE],rdx
    mov [rax+svc_LEASE],rdx
    mov qword ptr [rax+svc_FDS],-1
    mov qword ptr [rax+svc_FDS+8],-1
    mov qword ptr [rax+svc_KIND],2
    mov qword ptr [rax+svc_DEPTH],0
    mov qword ptr [rax+svc_PARENT],0
    mov qword ptr [rax+svc_ROLE],56
    lea rdx,[rip+service_image_table_1]
    cmp qword ptr [r15+BUS_ID],1
    je business_table_selected
    lea rdx,[rip+service_image_table_2]
business_table_selected:
    mov [rax+SVC_TABLE_PTR],rdx
    xor edi,edi
    mov esi,4096
    call map_rw
    mov rdx,[r15+BUS_CHILD]
    mov [rdx+svc_CMDMAP],rax
    mov [rdx+svc_CMDPTR],rax
    xor edi,edi
    mov esi,4096
    call map_rw
    mov rdx,[r15+BUS_CHILD]
    mov [rdx+svc_FRAMEMAP],rax
    push r15
    mov r15,rdx
    xor edi,edi
    mov esi,1
    call svc_resize_slot
    xor edi,edi
    mov esi,1
    call svc_protect_slot
    mov edi,2
    mov esi,1048576
    call svc_resize_slot
    mov rax,[r15+2*32]
    mov qword ptr [rax+4096],1
    mov qword ptr [rax+4096+2*8],1048576
    pop r15
business_install_rows:
    xor ebx,ebx
business_install_loop:
    cmp rbx,[r15+BUS_TABLE_COUNT]
    jae business_command_install
    mov rax,rbx
    shl rax,5
    add rax,[r15+BUS_TABLE_PTR]
    add rax,32
    mov r9,[rax+24]
    mov r8,[r15+BUS_CHILD]
    mov qword ptr [r8+svc_BORROWED+r9*8],1
    mov r10,r9
    shl r10,5
    lea rdi,[r8+r10]
    mov rsi,[rax]
    shl rsi,5
    add rsi,r15
    mov ecx,4
    rep movsq
    mov rcx,[rax+8]
    add [r8+r10],rcx
    mov rcx,[rax+16]
    mov [r8+r10+8],rcx
    /* BEGIN alone initializes the fixed HIA capacity inventory. RESUME
     * installs descriptors only; HIA commits its capacity after checking ACK. */
    cmp qword ptr [r15+BUS_VERB],1
    jne business_install_next
    mov rdx,[r8+2*32]
    mov [rdx+4096+r9*8],rcx
business_install_next:
    inc rbx
    jmp business_install_loop
business_command_install:
    mov rbx,[r15+BUS_CHILD]
    mov rdi,[rbx+svc_CMDMAP]
    cmp qword ptr [r15+BUS_VERB],1
    je business_initial_command
    /* The parent ACK is already defined; avoid a forward absolute-equate
     * operand that GNU as selects as a 32-bit displacement before resolution. */
    mov rax,ACK
    mov [rdi],rax
    mov rax,[rbx+svc_LEASE]
    mov [rdi+8],rax
    mov rax,[rbx+svc_SEQ]
    cmp rax,[r15+BUS_SEQ]
    jne abi_error
    mov [rdi+16],rax
    mov qword ptr [rdi+24],18
    mov qword ptr [rdi+32],0
    mov qword ptr [rdi+40],0
    mov qword ptr [rdi+48],128
    mov qword ptr [rdi+56],0
    add rdi,64
business_initial_command:
    mov rsi,[r15+BUS_COMMAND_PTR]
    mov rcx,[r15+BUS_COMMAND_LEN]
    rep movsb
    mov rax,[rbx+svc_CMDMAP]
    mov [rbx+svc_CMDPTR],rax
    mov rax,[r15+BUS_COMMAND_LEN]
    cmp qword ptr [r15+BUS_VERB],1
    je business_command_size_ready
    add rax,64
business_command_size_ready:
    mov [rbx+svc_CMDLEN],rax
    mov qword ptr [rbx+SVC_WAITING],0
    mov r15,rbx
    mov r13,[r15+svc_CMDMAP]
    mov r12,[r15+svc_FRAMEMAP]
    mov r14,[r15+SVC_TABLE_PTR]
    jmp svc_controller_entry

business_retire:
    mov edi,7
business_retire_zero:
    cmp edi,14
    jae business_retire_begin
    cmp qword ptr [r12+rdi*8],0
    jne abi_error
    inc edi
    jmp business_retire_zero
business_retire_begin:
    mov rbx,r15
    mov r15,[r15+BUS_CHILD]
    cmp qword ptr [r15+SVC_WAITING],1
    jne abi_error
    xor r8d,r8d
business_retire_maps:
    cmp qword ptr [r15+svc_BORROWED+r8*8],0
    jne business_retire_next
    mov r9,r8
    shl r9,5
    mov rdi,[r15+r9]
    test rdi,rdi
    jz business_retire_next
    mov rsi,[r15+r9+16]
    mov eax,11
    syscall
    test rax,rax
    jnz io_error
business_retire_next:
    inc r8
    cmp r8,64
    jb business_retire_maps
    xor r8d,r8d
business_retire_files:
    mov rdi,[r15+svc_FDS+r8*8]
    mov qword ptr [r15+svc_FDS+r8*8],-1
    test rdi,rdi
    js business_retire_file_next
    mov eax,3
    syscall
    test rax,rax
    jnz io_error
business_retire_file_next:
    inc r8
    cmp r8,2
    jb business_retire_files
    mov rdi,[r15+svc_CMDMAP]
    mov esi,4096
    mov eax,11
    syscall
    test rax,rax
    jnz io_error
    mov rdi,[r15+svc_FRAMEMAP]
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
    jnz io_error
    mov r15,rbx
    mov r13,[r15+CMDMAP]
    mov r12,[r15+FRAMEMAP]
    mov qword ptr [r15+BUS_CHILD],0
    mov qword ptr [r15+BUS_ID],0
    mov qword ptr [r15+BUS_LEASE],0
    mov qword ptr [r15+BUS_SEQ],0
    mov qword ptr [r15+BUS_LIFECYCLE],0
    mov qword ptr [r15+BUS_MASK],0
    mov qword ptr [r15+BUS_PINNED],0
    jmp controller_entry

.equ svc_ROLE,2048
.equ svc_LEASE,2056
.equ svc_SEQ,2064
.equ svc_CMDLEN,2072
.equ svc_CMDPTR,2080
.equ svc_CMDMAP,2088
.equ svc_FRAMEMAP,2096
.equ svc_FDS,2112
.equ svc_POSITIONS,2128
.equ svc_SEALED,2144
.equ svc_FIRST_RO,2160
.equ svc_SECOND_RO,2168
.equ svc_RESULT,2176
.equ svc_IO_PTR,2184
.equ svc_IO_LEFT,2192
.equ svc_IO_AT,2200
.equ svc_IO_FILE,2208
.equ svc_IO_END,2216
.equ svc_RAW_LEN,2224
.equ svc_EVENT,0x3130454443414948
.equ svc_ACK,0x3130414443414948
.equ svc_CTOR_INIT,0x3130494443414948
.equ svc_RAW_CONFIG,0x3130434e52414948
.equ svc_TWO_READ_MASK,0xe0bf80bee2ac0462
.equ svc_RUN_MODE,2232
.equ svc_PUB_ROLE,2240
.equ svc_PARENT,2248
.equ svc_CHILD_TARGET,2256
.equ svc_LEGACY,2264
.equ svc_BORROWED,8192
.equ svc_PROGRAM_INIT,0x3130494150414948
.equ svc_DIGITS,2272
.equ svc_KIND,2280
.equ svc_DEPTH,2288
svc_controller_entry:
    mov rdi,[r15+svc_CMDPTR]
    cmp rdi,r13
    jne svc_command_already_readonly
    mov esi,4096
    mov edx,1
    mov eax,10
    syscall
    test rax,rax
    jnz svc_io_error
svc_command_already_readonly:
    mov rax,[r15+svc_ROLE]
    cmp qword ptr [r15+svc_KIND],2
    je svc_entry_edit_role
    cmp qword ptr [r15+svc_KIND],1
    je svc_entry_program_role
    cmp qword ptr [r15+svc_KIND],0
    jne svc_abi_error
    cmp rax,40
    jb svc_abi_error
    cmp rax,45
    ja svc_abi_error
    jmp svc_entry_role_checked
svc_entry_program_role:
    cmp rax,44
    je svc_entry_role_checked
    cmp rax,46
    jne svc_abi_error
    jmp svc_entry_role_checked
svc_entry_edit_role:
    cmp rax,56
    jb svc_abi_error
    cmp rax,59
    ja svc_abi_error
svc_entry_role_checked:
    mov rax,[r14+rax*8]
    test rax,rax
    jz svc_abi_error
    mov rdi,[r15+svc_CMDPTR]
    mov rsi,[r15+svc_CMDLEN]
    mov rdx,r12
    mov ecx,128
    mov r8,[r15+2*32]
    mov r9d,1048576
    call rax
    cmp eax,128
    jne svc_abi_error
    mov rdi,[r15+svc_CMDPTR]
    cmp rdi,r13
    jne svc_command_writable
    mov esi,4096
    mov edx,3
    mov eax,10
    syscall
    test rax,rax
    jnz svc_io_error
svc_command_writable:
    mov rax,svc_EVENT
    cmp [r12],rax
    jne svc_abi_error
    mov rax,[r15+svc_LEASE]
    cmp [r12+16],rax
    jne svc_abi_error
    cmp qword ptr [r12+8],7
    je svc_terminal_event
    mov rax,[r15+svc_SEQ]
    add rax,1
    jc svc_abi_error
    cmp [r12+24],rax
    jne svc_abi_error
    mov [r15+svc_SEQ],rax
    mov rdi,r13
    xor eax,eax
    mov ecx,40
    rep stosq
    mov rax,svc_ACK
    mov [r13],rax
    mov rax,[r15+svc_LEASE]
    mov [r13+8],rax
    mov rax,[r15+svc_SEQ]
    mov [r13+16],rax
    mov rax,[r12+8]
    mov [r13+24],rax
    mov [r15+svc_CMDPTR],r13
    mov qword ptr [r15+svc_CMDLEN],64
    cmp rax,1
    je svc_op_call
    cmp rax,2
    je svc_op_grow
    cmp rax,3
    je svc_op_zero
    cmp rax,4
    je svc_op_copy
    cmp rax,5
    je svc_op_release
    cmp rax,6
    je svc_op_protect
    cmp rax,8
    je svc_op_switch
    cmp rax,10
    je svc_op_create
    cmp rax,11
    je svc_op_append
    cmp rax,12
    je svc_op_read
    cmp rax,13
    je svc_op_seal
    cmp rax,14
    je svc_op_view
    cmp rax,15
    je svc_op_run_child
    cmp rax,18
    je svc_op_yield
    jmp svc_abi_error

svc_op_call:
    cmp qword ptr [r12+120],0
    jne svc_abi_error
    mov rax,[r12+32]
    cmp rax,1
    jb svc_abi_error
    cmp qword ptr [r15+svc_KIND],2
    je svc_component_edit_roles
    cmp rax,55
    je svc_component_role_checked
    cmp rax,28
    ja svc_abi_error
    jmp svc_component_role_checked
svc_component_edit_roles:
    cmp rax,63
    ja svc_abi_error
    cmp rax,40
    jb svc_component_role_checked
    cmp rax,46
    jbe svc_abi_error
    cmp rax,56
    jb svc_component_role_checked
    cmp rax,59
    jbe svc_abi_error
svc_component_role_checked:
    cmp qword ptr [r15+svc_KIND],2
    jne svc_service_component_identity_checked
    cmp qword ptr [r15+SVC_SERVICE_ID],1
    jne svc_service_component_identity_checked
    cmp rax,60
    jne svc_service_component_identity_checked
    cmp qword ptr [r15+svc_ROLE],56
    jne svc_abi_error
svc_service_component_identity_checked:
    cmp qword ptr [r14+rax*8],0
    je svc_abi_error
    mov rax,[r12+40]
    cmp rax,[r12+64]
    je svc_abi_error
    cmp rax,[r12+80]
    je svc_abi_error
    mov rax,[r12+64]
    cmp rax,[r12+80]
    je svc_abi_error
    mov rdi,[r12+40]
    mov rsi,[r12+48]
    mov rdx,[r12+56]
    call svc_range_view
    mov rax,[rcx+24]
    mov [r15+svc_FIRST_RO],rax
    mov rdi,[r12+64]
    xor esi,esi
    mov rdx,[r12+72]
    call svc_range_view
    mov rax,[rcx+24]
    mov [r15+svc_SECOND_RO],rax
    mov rdi,[r12+80]
    xor esi,esi
    mov rdx,[r12+88]
    call svc_range_view
    cmp qword ptr [rcx+24],0
    jne svc_abi_error
    mov rdi,[r12+40]
    mov esi,1
    call svc_protect_slot
    mov rcx,[r12+32]
    call svc_service_two_read_mask
    bt rax,rcx
    jnc svc_call_second_writable
    mov rdi,[r12+64]
    mov esi,1
    call svc_protect_slot
    jmp svc_actual_component_call
svc_call_second_writable:
    cmp qword ptr [r15+svc_SECOND_RO],0
    jne svc_abi_error
svc_actual_component_call:
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
    mov [r15+svc_RESULT],rax
    cmp eax,0xfffffffd
    je svc_abi_error
    mov rdi,[r12+40]
    mov rsi,[r15+svc_FIRST_RO]
    call svc_protect_slot
    mov rcx,[r12+32]
    call svc_service_two_read_mask
    bt rax,rcx
    jnc svc_call_rights_restored
    mov rdi,[r12+64]
    mov rsi,[r15+svc_SECOND_RO]
    call svc_protect_slot
svc_call_rights_restored:
    mov rax,[r15+svc_RESULT]
    mov [r13+40],rax
    mov rdi,[r12+96]
    mov rsi,[r12+104]
    mov rdx,[r12+112]
    jmp svc_copy_observation

svc_op_grow:
    mov edi,6
    call svc_reserved_tail
    mov rdi,[r12+32]
    cmp rdi,4
    jb svc_abi_error
    mov rsi,[r12+40]
    test rsi,rsi
    jz svc_abi_error
    call svc_resize_slot
    jmp svc_controller_entry

svc_op_zero:
    mov edi,7
    call svc_reserved_tail
    mov rdi,[r12+32]
    mov rsi,[r12+40]
    mov rdx,[r12+48]
    call svc_range_view
    cmp qword ptr [rcx+24],0
    jne svc_abi_error
    mov rdi,rax
    mov rcx,rdx
    xor eax,eax
    rep stosb
    jmp svc_controller_entry

svc_op_copy:
    mov edi,9
    call svc_reserved_tail
    mov rax,[r12+32]
    cmp rax,[r12+48]
    je svc_abi_error
    mov rdi,[r12+32]
    mov rsi,[r12+40]
    mov rdx,[r12+64]
    call svc_range_view
    mov [r15+svc_IO_PTR],rax
    mov rdi,[r12+48]
    mov rsi,[r12+56]
    mov rdx,[r12+64]
    call svc_range_view
    cmp qword ptr [rcx+24],0
    jne svc_abi_error
    mov rdi,rax
    mov rsi,[r15+svc_IO_PTR]
    mov rcx,[r12+64]
    rep movsb
    jmp svc_controller_entry

svc_op_release:
    mov edi,5
    call svc_reserved_tail
    mov rax,[r12+32]
    cmp rax,4
    jb svc_abi_error
    cmp rax,63
    ja svc_abi_error
    shl rax,5
    lea rbx,[r15+rax]
    mov rdi,[rbx]
    test rdi,rdi
    jz svc_abi_error
    mov rcx,[r12+32]
    cmp qword ptr [r15+svc_BORROWED+rcx*8],0
    jne svc_release_borrowed
    mov rsi,[rbx+16]
    mov eax,11
    syscall
    test rax,rax
    jnz svc_io_error
svc_release_borrowed:
    mov rcx,[r12+32]
    mov qword ptr [r15+svc_BORROWED+rcx*8],0
    mov rdi,rbx
    xor eax,eax
    mov ecx,4
    rep stosq
    jmp svc_controller_entry

svc_op_protect:
    mov edi,6
    call svc_reserved_tail
    mov rdi,[r12+32]
    cmp rdi,4
    jb svc_abi_error
    mov rsi,[r12+40]
    call svc_protect_slot
    jmp svc_controller_entry

svc_op_switch:
    mov edi,5
    call svc_reserved_tail
    mov rax,[r12+32]
    cmp qword ptr [r15+svc_KIND],2
    je svc_switch_edit_role
    cmp qword ptr [r15+svc_KIND],0
    jne svc_abi_error
    cmp rax,40
    jb svc_abi_error
    cmp rax,42
    ja svc_abi_error
    jmp svc_switch_role_checked
svc_switch_edit_role:
    cmp rax,56
    jb svc_abi_error
    cmp rax,59
    ja svc_abi_error
svc_switch_role_checked:
    cmp rax,[r15+svc_ROLE]
    je svc_abi_error
    mov [r15+svc_ROLE],rax
    jmp svc_controller_entry

svc_op_create:
    mov edi,5
    call svc_reserved_tail
    mov rbx,[r12+32]
    cmp rbx,1
    ja svc_abi_error
    cmp qword ptr [r15+svc_FDS+rbx*8],-1
    jne svc_abi_error
    lea rdi,[rip+svc_spool_name]
    mov esi,3
    mov eax,319
    syscall
    test rax,rax
    js svc_io_error
    mov [r15+svc_FDS+rbx*8],rax
    jmp svc_controller_entry

svc_op_append:
    mov edi,9
    call svc_reserved_tail
    mov rbx,[r12+32]
    cmp rbx,1
    ja svc_abi_error
    cmp qword ptr [r15+svc_FDS+rbx*8],0
    jl svc_abi_error
    cmp qword ptr [r15+svc_SEALED+rbx*8],0
    jne svc_abi_error
    mov rax,[r12+40]
    cmp rax,[r15+svc_POSITIONS+rbx*8]
    jne svc_abi_error
    test rax,rax
    js svc_abi_error
    add rax,[r12+64]
    jc svc_abi_error
    test rax,rax
    js svc_abi_error
    mov [r15+svc_IO_END],rax
    mov rdi,[r12+48]
    mov rsi,[r12+56]
    mov rdx,[r12+64]
    call svc_range_view
    mov [r15+svc_IO_PTR],rax
    mov rax,[r12+64]
    mov [r15+svc_IO_LEFT],rax
    mov rax,[r12+40]
    mov [r15+svc_IO_AT],rax
    mov [r15+svc_IO_FILE],rbx
svc_append_loop:
    cmp qword ptr [r15+svc_IO_LEFT],0
    je svc_append_done
    mov rbx,[r15+svc_IO_FILE]
    mov rdi,[r15+svc_FDS+rbx*8]
    mov rsi,[r15+svc_IO_PTR]
    mov rdx,[r15+svc_IO_LEFT]
    mov r10,[r15+svc_IO_AT]
    mov eax,18
    syscall
    cmp rax,-4
    je svc_append_loop
    test rax,rax
    jle svc_io_error
    cmp rax,[r15+svc_IO_LEFT]
    ja svc_abi_error
    add [r15+svc_IO_PTR],rax
    add [r15+svc_IO_AT],rax
    sub [r15+svc_IO_LEFT],rax
    jmp svc_append_loop
svc_append_done:
    mov rax,[r15+svc_IO_END]
    mov [r15+svc_POSITIONS+rbx*8],rax
    jmp svc_controller_entry

svc_op_read:
    mov edi,9
    call svc_reserved_tail
    mov rbx,[r12+32]
    cmp rbx,1
    ja svc_abi_error
    cmp qword ptr [r15+svc_SEALED+rbx*8],1
    jne svc_abi_error
    mov rax,[r12+40]
    mov rcx,[r15+svc_POSITIONS+rbx*8]
    cmp rax,rcx
    ja svc_abi_error
    sub rcx,rax
    cmp [r12+64],rcx
    ja svc_abi_error
    mov rdi,[r12+48]
    mov rsi,[r12+56]
    mov rdx,[r12+64]
    call svc_range_view
    cmp qword ptr [rcx+24],0
    jne svc_abi_error
    mov [r15+svc_IO_PTR],rax
    mov rax,[r12+64]
    mov [r15+svc_IO_LEFT],rax
    mov rax,[r12+40]
    mov [r15+svc_IO_AT],rax
    mov [r15+svc_IO_FILE],rbx
svc_read_spool_loop:
    cmp qword ptr [r15+svc_IO_LEFT],0
    je svc_controller_entry
    mov rbx,[r15+svc_IO_FILE]
    mov rdi,[r15+svc_FDS+rbx*8]
    mov rsi,[r15+svc_IO_PTR]
    mov rdx,[r15+svc_IO_LEFT]
    mov r10,[r15+svc_IO_AT]
    mov eax,17
    syscall
    cmp rax,-4
    je svc_read_spool_loop
    test rax,rax
    jle svc_io_error
    cmp rax,[r15+svc_IO_LEFT]
    ja svc_abi_error
    add [r15+svc_IO_PTR],rax
    add [r15+svc_IO_AT],rax
    sub [r15+svc_IO_LEFT],rax
    jmp svc_read_spool_loop

svc_op_seal:
    mov edi,5
    call svc_reserved_tail
    mov rbx,[r12+32]
    cmp rbx,1
    ja svc_abi_error
    cmp qword ptr [r15+svc_FDS+rbx*8],0
    jl svc_abi_error
    cmp qword ptr [r15+svc_SEALED+rbx*8],0
    jne svc_abi_error
    mov rdi,[r15+svc_FDS+rbx*8]
    mov esi,1033
    mov edx,15
    mov eax,72
    syscall
    test rax,rax
    jnz svc_io_error
    mov rdi,[r15+svc_FDS+rbx*8]
    mov esi,1034
    mov eax,72
    syscall
    cmp rax,15
    jne svc_io_error
    mov qword ptr [r15+svc_SEALED+rbx*8],1
    jmp svc_controller_entry

svc_op_view:
    mov edi,7
    call svc_reserved_tail
    mov rdi,[r12+32]
    mov rsi,[r12+40]
    mov rdx,[r12+48]
svc_copy_observation:
    cmp rdx,256
    ja svc_abi_error
    call svc_range_view
    mov [r13+48],rdx
    lea rcx,[rdx+64]
    mov [r15+svc_CMDLEN],rcx
    mov rsi,rax
    lea rdi,[r13+64]
    mov rcx,rdx
    rep movsb
    jmp svc_controller_entry

svc_terminal_event:
    mov rax,[r15+svc_SEQ]
    cmp [r12+24],rax
    jne svc_abi_error
    cmp qword ptr [r15+svc_KIND],2
    je svc_edit_publication
    cmp qword ptr [r15+svc_ROLE],44
    je svc_raw_handoff
    cmp qword ptr [r15+svc_ROLE],43
    je svc_ctor_handoff
    cmp qword ptr [r15+svc_ROLE],40
    je svc_lowering_handoff
    cmp qword ptr [r15+svc_ROLE],45
    je svc_final_publication
    cmp qword ptr [r15+svc_ROLE],46
    jne svc_abi_error
svc_final_publication:
    cmp qword ptr [r12+32],0
    jne svc_semantic_error
    cmp qword ptr [r12+40],0
    jne svc_abi_error
    cmp qword ptr [r15+svc_PARENT],0
    jne svc_child_complete

    /* The HIA result supplies a complete readonly receipt and Core view.
     * A consumer must require successful exit and both complete extents. */
    cmp qword ptr [r15+svc_ROLE],46
    jne svc_abi_error
    cmp qword ptr [r12+48],56
    jne svc_abi_error
    cmp qword ptr [r12+56],256
    jne svc_abi_error
    cmp qword ptr [r15+56*32+24],1
    jne svc_abi_error
    mov edi,56
    xor esi,esi
    mov edx,256
    call svc_range_view
    mov [r15+svc_IO_PTR],rax
    mov [r15+svc_IO_LEFT],rdx
svc_receipt_loop:
    cmp qword ptr [r15+svc_IO_LEFT],0
    je svc_receipt_complete
    mov edi,2
    mov rsi,[r15+svc_IO_PTR]
    mov rdx,[r15+svc_IO_LEFT]
    mov eax,1
    syscall
    cmp rax,-4
    je svc_receipt_loop
    test rax,rax
    jle svc_io_error
    cmp rax,[r15+svc_IO_LEFT]
    ja svc_abi_error
    add [r15+svc_IO_PTR],rax
    sub [r15+svc_IO_LEFT],rax
    jmp svc_receipt_loop
svc_receipt_complete:
    cmp qword ptr [r15+45*32+24],1
    jne svc_abi_error
    mov edi,45
    xor esi,esi
    mov rdx,[r12+88]
    call svc_range_view
    test rdx,rdx
    jz svc_abi_error
    mov [r15+svc_IO_PTR],rax
    mov [r15+svc_IO_LEFT],rdx
svc_publish_loop:
    cmp qword ptr [r15+svc_IO_LEFT],0
    je svc_success
    mov edi,1
    mov rsi,[r15+svc_IO_PTR]
    mov rdx,[r15+svc_IO_LEFT]
    mov eax,1
    syscall
    cmp rax,-4
    je svc_publish_loop
    test rax,rax
    jle svc_io_error
    cmp rax,[r15+svc_IO_LEFT]
    ja svc_abi_error
    add [r15+svc_IO_PTR],rax
    sub [r15+svc_IO_LEFT],rax
    jmp svc_publish_loop

svc_edit_publication:
    /* The CLI service root must yield; it never writes process streams. */
    jmp svc_abi_error

svc_raw_handoff:
    cmp qword ptr [r12+32],7
    je svc_semantic_error
    mov rax,svc_CTOR_INIT
    cmp [r12+32],rax
    jne svc_abi_error
    mov rax,[r15+svc_LEASE]
    add rax,1
    jc svc_abi_error
    cmp [r12+40],rax
    jne svc_abi_error
    mov rax,[r15+svc_LEGACY]
    cmp [r12+48],rax
    jne svc_abi_error
    cmp qword ptr [r12+64],48
    jne svc_abi_error
    mov edi,9
    call svc_reserved_tail
    xor ecx,ecx
svc_raw_pool_check:
    cmp ecx,0
    je svc_raw_pool_next
    cmp ecx,2
    je svc_raw_pool_next
    cmp ecx,48
    je svc_raw_pool_next
    mov rax,rcx
    shl rax,5
    cmp qword ptr [r15+rax],0
    jne svc_abi_error
svc_raw_pool_next:
    inc ecx
    cmp ecx,64
    jb svc_raw_pool_check
    cmp qword ptr [r15+48*32+24],1
    jne svc_abi_error
    mov rax,[r12+56]
    cmp [r15+48*32+8],rax
    jne svc_abi_error
    lea rsi,[r15+48*32]
    lea rdi,[r15+1*32]
    mov ecx,4
    rep movsq
    lea rdi,[r15+48*32]
    xor eax,eax
    mov ecx,4
    rep stosq
    mov rax,[r12+40]
    mov [r15+svc_LEASE],rax
    mov qword ptr [r15+svc_SEQ],0
    mov qword ptr [r15+svc_ROLE],43
    cmp qword ptr [r15+svc_KIND],0
    je svc_raw_target_selected
    mov qword ptr [r15+svc_ROLE],46
svc_raw_target_selected:
    mov rdi,r13
    xor eax,eax
    mov ecx,8
    rep stosq
    mov rax,svc_CTOR_INIT
    cmp qword ptr [r15+svc_KIND],0
    je svc_raw_command_selected
    mov rax,svc_PROGRAM_INIT
svc_raw_command_selected:
    mov [r13],rax
    mov rax,[r12+40]
    mov [r13+8],rax
    mov rax,[r12+48]
    mov [r13+16],rax
    mov rax,[r12+56]
    mov [r13+24],rax
    mov [r15+svc_CMDPTR],r13
    mov qword ptr [r15+svc_CMDLEN],64
    jmp svc_controller_entry

svc_ctor_handoff:
    mov qword ptr [r15+svc_ROLE],40
    jmp svc_copy_handoff
svc_lowering_handoff:
    cmp qword ptr [r12+32],0
    jne svc_semantic_error
    cmp qword ptr [r12+40],0
    jne svc_abi_error
    mov rax,[r15+svc_PUB_ROLE]
    cmp rax,45
    jne svc_abi_error
svc_selected_publication:
    mov [r15+svc_ROLE],rax
svc_copy_handoff:
    mov rsi,r12
    mov rdi,r13
    mov ecx,16
    rep movsq
    mov [r15+svc_CMDPTR],r13
    mov qword ptr [r15+svc_CMDLEN],128
    jmp svc_controller_entry


/* HIA chooses a complete fixed child invocation. No value is decoded here. */
svc_op_run_child:
    /* Only edit -> program -> ordinary. No arbitrary recursion. */
    cmp qword ptr [r15+svc_KIND],2
    je svc_child_from_edit
    cmp qword ptr [r15+svc_KIND],1
    jne svc_abi_error
    cmp qword ptr [r15+svc_ROLE],46
    jne svc_abi_error
    cmp qword ptr [r15+svc_DEPTH],1
    jne svc_abi_error
    mov rax,[r15+svc_PARENT]
    test rax,rax
    jz svc_abi_error
    cmp qword ptr [rax+svc_KIND],2
    jne svc_abi_error
    cmp qword ptr [rax+svc_DEPTH],0
    jne svc_abi_error
    cmp qword ptr [rax+svc_PARENT],0
    jne svc_abi_error
    cmp qword ptr [r12+32],0
    jne svc_abi_error
    cmp qword ptr [r12+80],0
    jne svc_abi_error
    jmp svc_child_mode_checked
svc_child_from_edit:
    cmp qword ptr [r15+svc_DEPTH],0
    jne svc_abi_error
    cmp qword ptr [r15+svc_PARENT],0
    jne svc_abi_error
    cmp qword ptr [r15+svc_ROLE],56
    jb svc_abi_error
    cmp qword ptr [r15+svc_ROLE],59
    ja svc_abi_error
    cmp qword ptr [r12+32],2
    jne svc_abi_error
svc_child_mode_checked:
    mov edi,11
    call svc_reserved_tail
    cmp qword ptr [r12+48],0
    jne svc_abi_error
    mov rax,[r12+40]
    cmp rax,[r12+64]
    je svc_abi_error
    mov rdi,rax
    xor esi,esi
    mov rdx,[r12+56]
    cmp qword ptr [r12+32],2
    je svc_child_input_view
    test rdx,rdx
    jz svc_abi_error
    call svc_range_view
    cmp [rcx+8],rdx
    jne svc_abi_error
    jmp svc_child_input_checked
svc_child_input_view:
    call svc_range_view
svc_child_input_checked:
    cmp qword ptr [rcx+24],1
    jne svc_abi_error
    mov rax,[r12+64]
    cmp rax,4
    jb svc_abi_error
    cmp rax,63
    ja svc_abi_error
    shl rax,5
    cmp qword ptr [r15+rax],0
    jne svc_abi_error
    mov rax,[r12+72]
    test rax,rax
    jz svc_abi_error
    cmp rax,-1
    je svc_abi_error
    xor edi,edi
    mov esi,16384
    mov edx,3
    mov r10d,0x22
    mov r8,-1
    xor r9d,r9d
    mov eax,9
    syscall
    cmp rax,-4095
    jae svc_io_error
    mov r10,rax
    mov [r10+svc_PARENT],r15
    mov qword ptr [r10+svc_FDS],-1
    mov qword ptr [r10+svc_FDS+8],-1
    mov rax,[r12+32]
    mov [r10+svc_RUN_MODE],rax
    mov qword ptr [r10+svc_LEGACY],0
    mov rcx,[r15+svc_DEPTH]
    add rcx,1
    cmp rcx,2
    ja svc_abi_error
    mov [r10+svc_DEPTH],rcx
    mov rcx,[r15+svc_DIGITS]
    mov [r10+svc_DIGITS],rcx
    mov qword ptr [r10+svc_KIND],0
    mov qword ptr [r10+svc_PUB_ROLE],45
    test rax,rax
    jz svc_child_kind_selected
    mov qword ptr [r10+svc_KIND],1
    mov qword ptr [r10+svc_PUB_ROLE],46
    mov rcx,[r12+80]
    mov [r10+svc_DIGITS],rcx
svc_child_kind_selected:
    mov rax,[r12+64]
    mov [r10+svc_CHILD_TARGET],rax
    mov rax,[r12+72]
    mov [r10+svc_LEASE],rax
    mov rax,[r12+56]
    mov [r10+svc_RAW_LEN],rax
    mov edx,44
    mov qword ptr [r10+svc_BORROWED+rdx*8],1
    shl rdx,5
    lea rdi,[r10+rdx]
    mov rsi,[r12+40]
    shl rsi,5
    add rsi,r15
    mov ecx,4
    rep movsq
    mov rax,[r10+svc_RAW_LEN]
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
    jae svc_io_error
    mov [r15+svc_CMDMAP],rax
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
    jae svc_io_error
    mov [r15+svc_FRAMEMAP],rax
    mov r12,rax
    xor edi,edi
    mov esi,1
    call svc_resize_slot
    xor edi,edi
    mov esi,1
    call svc_protect_slot
    mov edi,2
    mov esi,1048576
    call svc_resize_slot
    mov rbx,[r15+2*32]
    mov qword ptr [rbx+4096],1
    mov qword ptr [rbx+4096+16],1048576
    mov rax,[r15+svc_RAW_LEN]
    mov [rbx+4096+44*8],rax
    mov rax,svc_RAW_CONFIG
    mov [rbx+12288],rax
    mov qword ptr [rbx+12296],0
    mov rax,[r15+svc_DIGITS]
    mov [rbx+12304],rax
    mov rax,[r15+svc_LEASE]
    mov [rbx+12312],rax
    mov qword ptr [r15+svc_ROLE],44
    mov rax,[r15+44*32]
    mov [r15+svc_CMDPTR],rax
    mov rax,[r15+svc_RAW_LEN]
    mov [r15+svc_CMDLEN],rax
    jmp svc_controller_entry
/* Copy only actual terminal bytes and transfer one actual readonly mapping.
 * The parent svc_ACK is inaccessible to HIA child kernels. Its private context
 * and pending sequence remain live and immutable throughout this invocation.
 */
svc_child_complete:
    /* Rejoin exactly the suspended bounded parent invocation. */
    mov rbx,[r15+svc_PARENT]
    test rbx,rbx
    jz svc_abi_error
    cmp qword ptr [r15+svc_RUN_MODE],2
    je svc_return_program_child
    cmp qword ptr [r15+svc_RUN_MODE],0
    jne svc_abi_error
    cmp qword ptr [r15+svc_KIND],0
    jne svc_abi_error
    cmp qword ptr [r15+svc_DEPTH],2
    jne svc_abi_error
    cmp qword ptr [rbx+svc_KIND],1
    jne svc_abi_error
    cmp qword ptr [rbx+svc_DEPTH],1
    jne svc_abi_error
    cmp qword ptr [rbx+svc_ROLE],46
    jne svc_abi_error
    mov rax,[rbx+svc_PARENT]
    test rax,rax
    jz svc_abi_error
    cmp qword ptr [rax+svc_KIND],2
    jne svc_abi_error
    cmp qword ptr [rax+svc_DEPTH],0
    jne svc_abi_error
    cmp qword ptr [rax+svc_PARENT],0
    jne svc_abi_error
    jmp svc_return_parent_checked
svc_return_program_child:
    cmp qword ptr [r15+svc_KIND],1
    jne svc_abi_error
    cmp qword ptr [r15+svc_DEPTH],1
    jne svc_abi_error
    cmp qword ptr [rbx+svc_KIND],2
    jne svc_abi_error
    cmp qword ptr [rbx+svc_DEPTH],0
    jne svc_abi_error
    cmp qword ptr [rbx+svc_PARENT],0
    jne svc_abi_error
    cmp qword ptr [rbx+svc_ROLE],56
    jb svc_abi_error
    cmp qword ptr [rbx+svc_ROLE],59
    ja svc_abi_error
svc_return_parent_checked:
    mov rax,[rbx+svc_FRAMEMAP]
    mov rcx,[rax+32]
    cmp [r15+svc_RUN_MODE],rcx
    jne svc_abi_error
    mov rax,[rbx+svc_FRAMEMAP]
    cmp qword ptr [rax+8],15
    jne svc_abi_error
    mov rcx,[r15+svc_CHILD_TARGET]
    cmp [rax+64],rcx
    jne svc_abi_error
    mov rdi,[rbx+svc_CMDMAP]
    cmp qword ptr [rdi+24],15
    jne svc_abi_error
    mov qword ptr [rdi+40],128
    mov qword ptr [rdi+48],160
    mov qword ptr [rdi+192],0
    mov [rdi+200],rcx
    mov rax,[r15+svc_ROLE]
    mov [rdi+208],rax
    mov qword ptr [rdi+216],0
    add rdi,64
    mov rsi,r12
    mov ecx,16
    rep movsq
    mov qword ptr [rbx+svc_CMDLEN],224
    cmp qword ptr [r12+32],0
    jne svc_child_diagnostic_transfer
    cmp qword ptr [r12+40],0
    jne svc_abi_error
    mov rax,[r15+svc_ROLE]
    cmp [r15+svc_PUB_ROLE],rax
    jne svc_abi_error
    cmp qword ptr [r15+45*32+24],1
    jne svc_abi_error
    mov edi,45
    xor esi,esi
    mov rdx,[r12+88]
    test rdx,rdx
    jz svc_abi_error
    call svc_range_view
    cmp qword ptr [r15+svc_RUN_MODE],2
    je svc_child_frame_copy
    mov rax,[r15+svc_CHILD_TARGET]
    shl rax,5
    lea rdi,[rbx+rax]
    cmp qword ptr [rdi],0
    jne svc_abi_error
    lea rsi,[r15+45*32]
    mov ecx,4
    rep movsq
    mov rax,[r15+45*32+8]
    mov rdi,[rbx+svc_CMDMAP]
    mov [rdi+192],rax
    lea rdi,[r15+45*32]
    xor eax,eax
    mov ecx,4
    rep stosq
    jmp svc_child_cleanup
svc_child_frame_copy:
    /* Exact actual receipt + exact actual Core. No header is rebuilt. */
    mov [r15+svc_IO_PTR],rax
    mov [r15+svc_IO_LEFT],rdx
    cmp qword ptr [r12+48],56
    jne svc_abi_error
    cmp qword ptr [r12+56],256
    jne svc_abi_error
    cmp qword ptr [r15+56*32+24],1
    jne svc_abi_error
    mov edi,56
    xor esi,esi
    mov edx,256
    call svc_range_view
    mov [r15+svc_IO_AT],rax
    mov rax,[r15+svc_IO_LEFT]
    add rax,256
    jc svc_abi_error
    test rax,rax
    js svc_abi_error
    mov [r15+svc_IO_END],rax
    mov rcx,[r15+svc_CHILD_TARGET]
    shl rcx,5
    cmp qword ptr [rbx+rcx],0
    jne svc_abi_error
    push r15
    mov rdi,[r15+svc_CHILD_TARGET]
    mov rsi,[r15+svc_IO_END]
    mov r15,rbx
    call svc_resize_slot
    pop r15
    mov rcx,[r15+svc_CHILD_TARGET]
    shl rcx,5
    mov rdi,[rbx+rcx]
    mov rsi,[r15+svc_IO_AT]
    mov ecx,256
    rep movsb
    mov rsi,[r15+svc_IO_PTR]
    mov rcx,[r15+svc_IO_LEFT]
    rep movsb
    push r15
    mov rdi,[r15+svc_CHILD_TARGET]
    mov esi,1
    mov r15,rbx
    call svc_protect_slot
    pop r15
    mov rdi,[rbx+svc_CMDMAP]
    mov rax,[r15+svc_IO_END]
    mov [rdi+192],rax
    jmp svc_child_cleanup
svc_child_diagnostic_transfer:
    /* No diagnostic text/header is interpreted by the fixed executor. */
    cmp qword ptr [r12+32],8
    jne svc_child_cleanup
    mov rax,[r15+svc_ROLE]
    cmp [r15+svc_PUB_ROLE],rax
    jne svc_abi_error
    cmp qword ptr [r15+57*32],0
    je svc_abi_error
    cmp qword ptr [r15+57*32+8],65
    jb svc_abi_error
    cmp qword ptr [r15+57*32+24],1
    jne svc_abi_error
    cmp qword ptr [r15+svc_BORROWED+57*8],0
    jne svc_abi_error
    mov rax,[r15+svc_CHILD_TARGET]
    shl rax,5
    lea rdi,[rbx+rax]
    cmp qword ptr [rdi],0
    jne svc_abi_error
    lea rsi,[r15+57*32]
    mov ecx,4
    rep movsq
    mov rax,[r15+57*32+8]
    mov rdi,[rbx+svc_CMDMAP]
    mov [rdi+192],rax
    lea rdi,[r15+57*32]
    xor eax,eax
    mov ecx,4
    rep stosq
    jmp svc_child_cleanup
svc_child_cleanup:
    xor r8d,r8d
svc_child_cleanup_maps:
    cmp qword ptr [r15+svc_BORROWED+r8*8],0
    jne svc_child_cleanup_next
    mov r9,r8
    shl r9,5
    mov rdi,[r15+r9]
    test rdi,rdi
    jz svc_child_cleanup_next
    mov rsi,[r15+r9+16]
    mov eax,11
    syscall
    test rax,rax
    jnz svc_io_error
svc_child_cleanup_next:
    inc r8d
    cmp r8d,64
    jb svc_child_cleanup_maps
    xor r8d,r8d
svc_child_cleanup_files:
    mov rdi,[r15+svc_FDS+r8*8]
    test rdi,rdi
    js svc_child_cleanup_file_next
    mov eax,3
    syscall
    test rax,rax
    jnz svc_io_error
svc_child_cleanup_file_next:
    inc r8d
    cmp r8d,2
    jb svc_child_cleanup_files
    mov rdi,r13
    mov esi,4096
    mov eax,11
    syscall
    test rax,rax
    jnz svc_io_error
    mov rdi,r12
    mov esi,4096
    mov eax,11
    syscall
    test rax,rax
    jnz svc_io_error
    mov rdi,r15
    mov esi,16384
    mov eax,11
    syscall
    test rax,rax
    jnz svc_early_io
    mov r15,rbx
    mov r12,[r15+svc_FRAMEMAP]
    mov r13,[r15+svc_CMDMAP]
    jmp svc_controller_entry

/* Leaf helpers. All quantities are exact unsigned buffer extents, never values. */
svc_reserved_tail:
    cmp edi,16
    jae svc_tail_done
    cmp qword ptr [r12+rdi*8],0
    jne svc_abi_error
    inc edi
    jmp svc_reserved_tail
svc_tail_done:
    ret

svc_range_view:
    cmp rdi,63
    ja svc_abi_error
    mov rcx,rdi
    shl rcx,5
    add rcx,r15
    mov rax,[rcx]
    test rax,rax
    jz svc_abi_error
    mov r8,[rcx+8]
    cmp rsi,r8
    ja svc_abi_error
    sub r8,rsi
    cmp rdx,r8
    ja svc_abi_error
    add rax,rsi
    ret

svc_protect_slot:
    cmp rdi,63
    ja svc_abi_error
    cmp rsi,1
    ja svc_abi_error
    cmp qword ptr [r15+svc_BORROWED+rdi*8],0
    je svc_protection_owned
    cmp rsi,1
    jne svc_abi_error
svc_protection_owned:
    shl rdi,5
    lea r9,[r15+rdi]
    cmp qword ptr [r9],0
    je svc_abi_error
    cmp [r9+24],rsi
    je svc_protect_done
    mov r8,rsi
    mov rdi,[r9]
    mov rsi,[r9+16]
    mov edx,3
    test r8,r8
    jz svc_protect_call
    mov edx,1
svc_protect_call:
    mov eax,10
    syscall
    test rax,rax
    jnz svc_io_error
    mov [r9+24],r8
svc_protect_done:
    ret

svc_resize_slot:
    cmp rdi,63
    ja svc_abi_error
    test rsi,rsi
    js svc_abi_error
    push rbx
    push r12
    push r13
    mov rbx,rdi
    shl rbx,5
    add rbx,r15
    mov r12,rsi
    cmp qword ptr [rbx],0
    je svc_resize_allowed
    cmp qword ptr [rbx+24],0
    jne svc_abi_error
    cmp r12,[rbx+8]
    jbe svc_abi_error
svc_resize_allowed:
    mov r13,r12
    add r13,4095
    jc svc_abi_error
    and r13,-4096
    jnz svc_resize_map
    mov r13d,4096
svc_resize_map:
    xor edi,edi
    mov rsi,r13
    mov edx,3
    mov r10d,0x22
    mov r8,-1
    xor r9d,r9d
    mov eax,9
    syscall
    cmp rax,-4095
    jae svc_io_error
    mov r8,rax
    cmp qword ptr [rbx],0
    je svc_resize_store
    mov rdi,r8
    mov rsi,[rbx]
    mov rcx,[rbx+8]
    rep movsb
    mov rdi,[rbx]
    mov rsi,[rbx+16]
    mov eax,11
    syscall
    test rax,rax
    jnz svc_io_error
svc_resize_store:
    mov [rbx],r8
    mov [rbx+8],r12
    mov [rbx+16],r13
    mov qword ptr [rbx+24],0
    pop r13
    pop r12
    pop rbx
    ret

svc_semantic_error:
    cmp qword ptr [r15+svc_PARENT],0
    jne svc_child_complete
    /* A service-root result must be a typed private yield, never process I/O. */
    jmp svc_abi_error

svc_abi_error:
    jmp abi_error
svc_io_error:
    jmp io_error
svc_early_io:
    jmp io_error
svc_early_usage:
    jmp abi_error
svc_success:
    jmp abi_error
svc_terminate:
    jmp abi_error
svc_service_two_read_mask:
    mov rax,svc_TWO_READ_MASK
    cmp qword ptr [r15+svc_KIND],2
    jne svc_service_mask_ready
    cmp qword ptr [r15+SVC_SERVICE_ID],1
    jne svc_service_mask_ready
    bts rax,60
svc_service_mask_ready:
    ret
svc_spool_name:
    .asciz "hia-private-spool"


/* The external CLI edge is independent of the existing internal child edge. */
svc_op_yield:
    cmp qword ptr [r15+svc_KIND],2
    jne svc_abi_error
    cmp qword ptr [r15+svc_DEPTH],0
    jne svc_abi_error
    cmp qword ptr [r15+svc_PARENT],0
    jne svc_abi_error
    cmp qword ptr [r15+svc_ROLE],56
    jne svc_abi_error
    cmp qword ptr [r15+SVC_WAITING],0
    jne svc_abi_error
    mov rbx,[r15+SVC_HOST]
    test rbx,rbx
    jz svc_abi_error
    cmp [rbx+BUS_CHILD],r15
    jne svc_abi_error
    mov rax,[r15+SVC_SERVICE_ID]
    cmp [rbx+BUS_ID],rax
    jne svc_abi_error
    mov rax,[r15+SVC_SERVICE_LEASE]
    cmp [rbx+BUS_LEASE],rax
    jne svc_abi_error
    cmp [r12+32],rax
    jne svc_abi_error
    cmp [r15+svc_LEASE],rax
    jne svc_abi_error
    mov rax,[rbx+FRAMEMAP]
    cmp qword ptr [rax+8],17
    jne svc_abi_error
    mov rcx,[rbx+BUS_VERB]
    cmp [rax+32],rcx
    jne svc_abi_error
    mov rcx,[rbx+SEQ]
    cmp [rax+24],rcx
    jne svc_abi_error
    mov edi,10
    call svc_reserved_tail
    cmp qword ptr [r12+40],1
    ja svc_abi_error
    mov rax,[r12+72]
    test al,15
    jnz svc_abi_error
    cmp qword ptr [r12+40],0
    je svc_yield_mask_count
    test rax,rax
    jnz svc_abi_error
svc_yield_mask_count:
    mov rcx,rax
    xor edx,edx
svc_yield_mask_loop:
    test rcx,rcx
    jz svc_yield_mask_valid
    lea r8,[rcx-1]
    and rcx,r8
    inc edx
    cmp edx,4
    ja svc_abi_error
    jmp svc_yield_mask_loop
svc_yield_mask_valid:
    mov rdi,[r12+48]
    mov rsi,[r12+56]
    mov rdx,[r12+64]
    call svc_range_view
    cmp qword ptr [rcx+24],1
    jne svc_abi_error
    mov [r15+svc_IO_PTR],rax
    mov [r15+svc_IO_LEFT],rdx
    mov rax,[rbx+BUS_TARGET]
    cmp rax,4
    jb svc_abi_error
    cmp rax,63
    ja svc_abi_error
    mov rcx,[rbx+BUS_PINNED]
    bt rcx,rax
    jc svc_abi_error
    shl rax,5
    cmp qword ptr [rbx+rax],0
    jne svc_abi_error
    push r15
    mov rdi,[rbx+BUS_TARGET]
    mov rsi,[r15+svc_IO_LEFT]
    mov r15,rbx
    call resize_slot
    pop r15
    mov rax,[rbx+BUS_TARGET]
    shl rax,5
    mov rdi,[rbx+rax]
    mov rsi,[r15+svc_IO_PTR]
    mov rcx,[r15+svc_IO_LEFT]
    rep movsb
    push r15
    mov rdi,[rbx+BUS_TARGET]
    mov esi,1
    mov r15,rbx
    call protect_slot
    pop r15
    mov rax,[r15+svc_SEQ]
    cmp rax,[rbx+BUS_SEQ]
    jbe svc_abi_error
    mov [rbx+BUS_SEQ],rax
    mov rcx,[r12+40]
    mov [rbx+BUS_LIFECYCLE],rcx
    mov rcx,[r12+72]
    mov [rbx+BUS_MASK],rcx
    mov qword ptr [r15+SVC_WAITING],1
    mov rdi,[rbx+CMDMAP]
    mov qword ptr [rdi+40],0
    mov qword ptr [rdi+48],128
    mov rax,0x3130414243414948
    mov [rdi+64],rax
    mov qword ptr [rdi+72],1
    mov rax,[rbx+BUS_ID]
    mov [rdi+80],rax
    mov rax,[rbx+BUS_LEASE]
    mov [rdi+88],rax
    mov rax,[r15+svc_LEASE]
    mov [rdi+96],rax
    mov rax,[r15+svc_SEQ]
    mov [rdi+104],rax
    mov rax,[r15+svc_ROLE]
    mov [rdi+112],rax
    mov rax,[rbx+BUS_LIFECYCLE]
    mov [rdi+120],rax
    mov rax,[rbx+BUS_TARGET]
    mov [rdi+128],rax
    mov rax,[r15+svc_IO_LEFT]
    mov [rdi+136],rax
    mov rax,[rbx+BUS_VERB]
    mov [rdi+144],rax
    mov rax,[rbx+SEQ]
    mov [rdi+152],rax
    mov qword ptr [rdi+160],0
    mov qword ptr [rdi+168],0
    mov qword ptr [rdi+176],0
    mov qword ptr [rdi+184],0
    mov qword ptr [rbx+CMDLEN],192
    mov r15,rbx
    mov r13,[r15+CMDMAP]
    mov r12,[r15+FRAMEMAP]
    lea r14,[rip+image_table]
    jmp controller_entry

    .p2align 3
service_image_table_1:
    .zero 512
service_image_table_2:
    .zero 512

    .p2align 3
image_table:
    .zero 512
executor_end:
.section .note.GNU-stack,"",@progbits
