/* Fixed eight-image native default-JSON forwarding carrier.
 * NEW UNEXECUTED fork. Mechanical operations are copied from exact ac4afce:
 * CALL=1 GROW=2 ZERO=3 COPY=4 RELEASE=5 PROTECT=6 VIEW=14.
 * HIA owns all UTF-8/JSON/number/schema decisions and every continuation.
 * This private component reads a framed byte payload; it is not yet the
 * ordinary eleven-tool Worker envelope or installed worker entry.
 * No execve, subprocess, JSON parser, file lookup or environmental selector.
 */
.intel_syntax noprefix
.section .text
.global executor_start
.equ LEASE,2056
.equ SEQ,2064
.equ CMDLEN,2072
.equ CMDMAP,2088
.equ FRAMEMAP,2096
.equ FIRST_RO,2160
.equ SECOND_RO,2168
.equ RESULT,2176
.equ IO_PTR,2184
.equ RAW_LEN,2224
.equ BUS_PINNED,2512
.equ EVENT,0x3130454443414948
.equ ACK,0x3130414443414948
.equ TWO_READ_MASK,0x4e

executor_start:
    and rsp,-16
    cld
    lea r14,[rip+image_table]
    xor edi,edi
    mov esi,16384
    call map_rw
    mov r15,rax
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
    mov edi,1
    mov esi,65536
    call resize_slot

/* Capture bytes only. The HIA private header and ordinary byte/decode budgets
 * are interpreted later. EOF may occur at every byte; EINTR does not recapture
 * or reenter any semantic image. Existing mappings preserve exact old bytes. */
read_input:
    mov rax,[r15+RAW_LEN]
    cmp rax,[r15+40]
    jb read_room
    jne abi_error
    mov rsi,[r15+40]
    shl rsi,1
    jc abi_error
    test rsi,rsi
    js io_error
    mov edi,1
    call resize_slot
read_room:
    xor edi,edi
    mov rsi,[r15+32]
    add rsi,[r15+RAW_LEN]
    jc abi_error
    mov rdx,[r15+40]
    sub rdx,[r15+RAW_LEN]
    mov eax,0
    syscall
    cmp rax,-4
    je read_input
    test rax,rax
    js io_error
    jz input_complete
    cmp rax,rdx
    ja abi_error
    add [r15+RAW_LEN],rax
    jc abi_error
    jmp read_input
input_complete:
    mov rax,[r15+RAW_LEN]
    mov [r15+40],rax
    mov edi,1
    mov esi,1
    call protect_slot
    mov rax,0x3130494457414948
    mov [r13],rax
    mov qword ptr [r13+8],1
    mov rax,[r15+RAW_LEN]
    mov [r13+16],rax
    mov qword ptr [r15+CMDLEN],64
    jmp controller_entry

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
    call qword ptr [r14+8*8]
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
    jmp abi_error

op_call:
    cmp qword ptr [r12+120],0
    jne abi_error
    mov rax,[r12+32]
    cmp rax,1
    jb abi_error
    cmp rax,7
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
    /* Writable second operands are owned mappings, never reserved inputs. */
    cmp qword ptr [r12+64],4
    jb abi_error
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


    .p2align 3
image_table:
    .zero 512
executor_end:
.section .note.GNU-stack,"",@progbits
