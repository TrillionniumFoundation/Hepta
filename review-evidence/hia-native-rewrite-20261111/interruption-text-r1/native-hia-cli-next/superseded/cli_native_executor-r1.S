/* Fixed Linux x86-64 CLI mechanics, new development source.
 * Captures all argv/env C-string bytes and the actual stdout TIOCGWINSZ result.
 * HIA owns decoding, option parsing, environment policy, file admission and
 * output selection. No JSON, CLI option or business-service parser is here.
 * Forked descriptor mechanics from native-edit-executor-next; this standalone
 * process owns one requested input fd and relies on Linux exit cleanup on fatal
 * allocation/protocol failure. It is not a reusable nested-context executor.
 */
.intel_syntax noprefix
.section .text
.global executor_start,image_table,executor_end
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
    mov esi,4096
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
    /* 17 is the explicit unconnected business-service handoff in r1. */
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
    cmp qword ptr [rcx+24],0
    jne abi_error
    cmp qword ptr [r12+64],144
    jne abi_error
    mov rsi,[r15+IO_PTR]
    mov eax,5
    syscall
    jmp primitive_result
primitive_read:
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
    mov rdi,[r12+40]
    mov rsi,[r12+48]
    mov rdx,[r12+56]
    call range_view
    cmp qword ptr [rcx+24],1
    jne abi_error
    mov rsi,rax
    mov edi,1
    call write_all
    mov rdi,[r12+64]
    mov rsi,[r12+72]
    mov rdx,[r12+80]
    call range_view
    cmp qword ptr [rcx+24],1
    jne abi_error
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
    .p2align 3
image_table:
    .zero 512
executor_end:
.section .note.GNU-stack,"",@progbits
