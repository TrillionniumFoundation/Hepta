/* Six already admitted immutable fds: [ABI,workload], baseline ELF, candidate
 * ELF, direct-call supervisor, baseline HIA reference batch, memory/deadline.
 * HIAEPL02 additionally opens fds 9..11 for the other reference and both Core files.
 * A nine-descriptor argv vector is retained before assignment to these slots.
 * HIAEPL04 obtains and charges one live budget grant per actual arm.
 * The ports below perform only bounded transport. HIA drives progress,
 * owns comparison, trap policy, warmups and report order, and emits the report. */
.intel_syntax noprefix
.text
.global _start,pair_call_hole
.equ G,67108864
.equ WORK,100663296
.equ OUT,1048576
.equ JSON,0
.equ REF,16
.equ CONFIG,32
.equ PRIVATE,48
.equ OUTPUT,56
.equ INFD,64
.equ OUTFD,72
.equ ERRFD,80
.equ CHILD,88
.equ STATUS,96
.equ STAT,120
.equ FRAME,280
.equ WHEN,320
.equ SECOND_REF,336
.equ BASE_CORE,352
.equ OTHER_CORE,368
.equ EVENT_FD,384
_start:
    mov r14,rsp
    sub rsp,4824
    mov rbp,rsp
    cmp QWORD PTR [r14],1
    je inputs_ready
    cmp QWORD PTR [r14],10
    jne refuse
    xor r13d,r13d
retain_descriptor:
    mov rsi,[r14+r13*8+16]
    call unsigned_decimal
    cmp rax,3
    jb refuse
    cmp rax,2147483647
    ja refuse
    mov edi,eax
    mov esi,1030
    mov edx,32
    mov eax,72
    syscall
    test rax,rax
    js refuse
    mov [rbp+r13*8+400],rax
    inc r13d
    cmp r13d,9
    jne retain_descriptor
    xor r13d,r13d
normalize_descriptor:
    mov edi,[rbp+r13*8+400]
    lea esi,[r13+3]
    xor edx,edx
    mov eax,292
    syscall
    cmp eax,esi
    jne refuse
    inc r13d
    cmp r13d,9
    jne normalize_descriptor
    mov edi,12
    mov esi,-1
    xor edx,edx
    mov eax,436
    syscall
    test rax,rax
    jne refuse
inputs_ready:
    mov QWORD PTR [rbp+SECOND_REF],0
    lea rdi,[rbp+FRAME]
    mov ecx,4
    xor eax,eax
    rep stosq
    mov edi,17
    lea rsi,[rbp+FRAME]
    xor edx,edx
    mov r10d,8
    mov eax,13
    syscall
    test rax,rax
    jne refuse
    mov edi,4
    xor esi,esi
    xor edx,edx
    xor r10d,r10d
    xor r8d,r8d
    mov eax,157
    syscall
    test rax,rax
    jne refuse
    mov edi,3
check_seals:
    mov esi,1034
    mov eax,72
    syscall
    test rax,rax
    js refuse
    and eax,15
    cmp eax,15
    jne refuse
    inc edi
    cmp edi,9
    jne check_seals
    mov esi,WORK
    call allocate
    mov [rbp+PRIVATE],rax
    lea r15,[rax+G]
    mov esi,OUT
    call allocate
    mov [rbp+OUTPUT],rax
    mov edi,3
    mov esi,16777219
    call map_input
    mov [rbp+JSON],rax
    mov [rbp+JSON+8],rsi
    mov edi,7
    mov esi,67108864
    call map_input
    mov [rbp+REF],rax
    mov [rbp+REF+8],rsi
    mov edi,8
    mov esi,4424
    call map_input
    mov [rbp+CONFIG],rax
    mov [rbp+CONFIG+8],rsi
    mov edi,4
    call extent
    mov [r15+32],rax
    mov edi,5
    call extent
    mov [r15+40],rax
    mov eax,39
    syscall
    mov [r15+8],rax
    call scratch
    mov [rbp+INFD],rax
    call scratch
    mov [rbp+OUTFD],rax
    call scratch
    mov [rbp+ERRFD],rax
    mov QWORD PTR [rbp+EVENT_FD],-1
    mov r14d,16
private_file:
    call scratch
    mov edi,eax
    mov r13d,eax
    mov esi,r14d
    mov edx,524288
    mov eax,292
    syscall
    cmp eax,r14d
    jne refuse
    mov edi,r13d
    mov eax,3
    syscall
    inc r14d
    cmp r14d,25
    jne private_file
    lea r14,[rbp+CONFIG]
    jmp dispatch
json:
    lea r14,[rbp+JSON]
    jmp dispatch
reference:
    lea r14,[rbp+REF]
    jmp dispatch
both_refs:
    call clock_now
    cmp QWORD PTR [rbp+SECOND_REF],0
    jne reference_pair_ready
    mov edi,9
    mov esi,67108864
    call sealed_input
    mov [rbp+SECOND_REF],rax
    mov [rbp+SECOND_REF+8],rsi
reference_pair_ready:
    lea r14,[rbp+REF]
    mov rdi,[r14]
    mov rsi,[r14+8]
    mov rdx,[rbp+SECOND_REF]
    mov rcx,[rbp+SECOND_REF+8]
    jmp enter_hia
base_core:
    mov edi,10
    mov esi,8388608
    call sealed_input
    lea r14,[rbp+BASE_CORE]
    jmp core_input
other_core:
    mov edi,11
    mov esi,8388608
    call sealed_input
    lea r14,[rbp+OTHER_CORE]
core_input:
    mov [r14],rax
    mov [r14+8],rsi
dispatch:
    call clock_now
    mov rdi,[r14]
    mov rsi,[r14+8]
    mov rdx,[rbp+OUTPUT]
    mov ecx,OUT
enter_hia:
    mov r8,[rbp+PRIVATE]
    mov r9d,WORK
    .byte 0xe8
pair_call_hole: .long 0
    cmp eax,1
    je json
    cmp eax,2
    je reference
    cmp eax,3
    je loan_write
    cmp eax,4
    je supervise
    cmp eax,5
    je loan_read
    cmp eax,7
    je both_refs
    cmp eax,8
    je base_core
    cmp eax,9
    je other_core
    cmp eax,10
    je event_only
    cmp eax,11
    je event_owner
    cmp eax,12
    je event_loan
    cmp eax,13
    je publish_archive
    cmp eax,14
    je gate_event
    cmp eax,6
    jne refuse
    mov edi,1
    mov rsi,[rbp+OUTPUT]
    mov rdx,[r15+112]
    cmp rdx,OUT
    ja refuse
    call write_all
    xor edi,edi
    jmp exit
gate_event:
    mov edi,1
    mov rsi,[rbp+OUTPUT]
    mov edx,64
    call write_all
    lea rsi,[rbp+FRAME]
    mov edx,8
    call read_gate
    mov r12,[rbp+FRAME]
    cmp r12,228
    jb refuse
    cmp r12,4400
    ja refuse
    lea rsi,[rbp+400]
    mov rdx,r12
    call read_gate
    call clock_now
    lea rdi,[rbp+400]
    mov rsi,r12
    mov rdx,[rbp+OUTPUT]
    mov ecx,OUT
    jmp enter_hia
/* Wait only within the original frozen context window. EOF, interruption
 * beyond the deadline and short receipts never authorize another arm. */

unsigned_decimal:
    xor eax,eax
    cmp BYTE PTR [rsi],49
    jb refuse
decimal_digit:
    movzx edx,BYTE PTR [rsi]
    cmp edx,48
    jb refuse
    cmp edx,57
    ja refuse
    imul rax,rax,10
    jo refuse
    sub edx,48
    add rax,rdx
    jo refuse
    inc rsi
    cmp BYTE PTR [rsi],0
    jne decimal_digit
    ret

read_gate:
    push r12
    push r13
    mov r12,rsi
    mov r13,rdx
gate_read_more:
    call clock_now
    mov rcx,[r15+408]
    cmp rax,rcx
    jae refuse
    sub rcx,rax
    mov rax,rcx
    xor edx,edx
    mov ecx,1000000
    div rcx
    test rdx,rdx
    jz gate_poll
    inc rax
gate_poll:
    cmp rax,86400000
    ja refuse
    mov edx,eax
    mov QWORD PTR [rbp+WHEN],0
    mov WORD PTR [rbp+WHEN+4],1
    lea rdi,[rbp+WHEN]
    mov esi,1
    mov eax,7
    syscall
    cmp rax,-4
    je gate_read_more
    cmp rax,1
    jne refuse
    xor edi,edi
    mov rsi,r12
    mov rdx,r13
    xor eax,eax
    syscall
    cmp rax,-4
    je gate_read_more
    test rax,rax
    jle refuse
    add r12,rax
    sub r13,rax
    jne gate_read_more
    pop r13
    pop r12
    ret
event_file:
    cmp QWORD PTR [rbp+EVENT_FD],-1
    jne event_ready
    call scratch
    mov [rbp+EVENT_FD],rax
event_ready:
    mov edi,[rbp+EVENT_FD]
    ret
event_header:
    call event_file
    mov rsi,[rbp+OUTPUT]
    mov edx,96
    jmp write_all
event_only:
    call event_header
    jmp json
event_owner:
    call event_header
    mov esi,[rbp+OUTFD]
    mov rdx,[r15+280]
    call file_append
    mov esi,[rbp+ERRFD]
    mov rdx,[r15+320]
    call file_append
    jmp reference
event_loan:
    call event_header
    mov rdx,[r15+112]
    cmp rdx,OUT
    ja refuse
    test rdx,rdx
    jz reference
    mov edi,[rbp+EVENT_FD]
    lea rsi,[r15+1048576]
    call write_all
    jmp reference
file_append:
    mov edi,[rbp+EVENT_FD]
copy_file:
    test rdx,rdx
    jz copied
    mov r12,rdx
    mov QWORD PTR [rbp+WHEN],0
copy_more:
    lea rdx,[rbp+WHEN]
    mov r10,r12
    mov eax,40
    syscall
    cmp rax,-4
    je copy_more
    test rax,rax
    jle refuse
    sub r12,rax
    jnz copy_more
copied:
    ret
publish_archive:
    call event_file
    call extent
    cmp rax,[r15+376]
    jne refuse
    cmp rax,268435456
    ja refuse
    mov rdx,[r15+112]
    cmp rdx,700000
    ja refuse
    mov edi,1
    mov rsi,[rbp+OUTPUT]
    add rsi,700000
    mov edx,32
    call write_all
    mov edi,1
    mov rsi,[rbp+OUTPUT]
    mov rdx,[r15+112]
    call write_all
    mov edi,1
    mov esi,[rbp+EVENT_FD]
    mov rdx,[r15+376]
    call copy_file
    xor edi,edi
    jmp exit
loan_fd:
    mov rdi,[r15+104]
    cmp rdi,16
    jb refuse
    cmp rdi,23
    ja refuse
    mov rdx,[r15+112]
    cmp rdx,OUT
    ja refuse
    ret
loan_write:
    call loan_fd
    call reset
    call loan_fd
    mov rsi,[rbp+OUTPUT]
    call write_all
    jmp json
loan_read:
    call loan_fd
    call extent
    call loan_fd
    mov rcx,1
    test rdx,rdx
    cmovne rcx,rdx
    cmp rax,rcx
    jne refuse
    mov rdx,rcx
    lea rsi,[r15+1048576]
    call pread_all
    jmp reference
supervise:
    mov edi,[rbp+INFD]
    call reset
    mov edi,[rbp+OUTFD]
    call reset
    mov edi,[rbp+ERRFD]
    call reset
    mov edi,24
    call reset
    mov edi,[rbp+INFD]
    mov rsi,[rbp+OUTPUT]
    mov rdx,[r15+112]
    cmp rdx,8192
    ja refuse
    call write_all
    mov edi,[rbp+INFD]
    call rewind
    call clock_now
    mov [r15+360],rax
    mov eax,57
    syscall
    test rax,rax
    js refuse
    jz child
    mov [rbp+CHILD],rax
wait_owner:
    mov rdi,[rbp+CHILD]
    lea rsi,[rbp+STATUS]
    xor edx,edx
    xor r10d,r10d
    mov eax,61
    syscall
    cmp rax,-4
    je wait_owner
    cmp rax,[rbp+CHILD]
    jne refuse
    cmp DWORD PTR [rbp+STATUS],0
    jne refuse
    call clock_now
    mov [r15+368],rax
    mov edi,24
    call extent
    cmp rax,24
    jne refuse
    mov edi,24
    lea rsi,[r15+256]
    mov edx,24
    call pread_all
    mov edi,[rbp+ERRFD]
    call extent
    mov [r15+320],rax
    mov edi,[rbp+OUTFD]
    call extent
    mov [r15+280],rax
    cmp rax,32
    jne reference
    mov edx,32
    lea rsi,[r15+288]
    call pread_all
    jmp reference
child:
    mov edi,1
    mov esi,9
    xor edx,edx
    xor r10d,r10d
    xor r8d,r8d
    mov eax,157
    syscall
    test rax,rax
    jne refuse
    mov eax,110
    syscall
    cmp rax,[r15+8]
    jne refuse
    mov edi,[rbp+INFD]
    xor esi,esi
    call bind_fd
    mov edi,[rbp+OUTFD]
    mov esi,1
    call bind_fd
    mov edi,[rbp+ERRFD]
    mov esi,2
    call bind_fd
    mov edi,3
    mov esi,-1
    mov edx,4               /* CLOSE_RANGE_CLOEXEC */
    mov eax,436
    syscall
    test rax,rax
    jne refuse
    mov edi,DWORD PTR [r15+72]
    add edi,4
    call inherit_fd
    mov edi,24
    call inherit_fd
    mov r12,16
pass_loans:
    mov rax,[r15+4096+40]
    add rax,16
    cmp r12,rax
    jae exec_owner
    mov edi,r12d
    call inherit_fd
    inc r12
    jmp pass_loans
exec_owner:
    lea rax,[rip+name]
    mov [rbp+FRAME],rax
    lea rax,[rip+option]
    mov [rbp+FRAME+8],rax
    mov QWORD PTR [rbp+FRAME+16],0
    mov edi,6
    lea rsi,[rip+empty]
    lea rdx,[rbp+FRAME]
    lea r10,[rbp+FRAME+16]
    mov r8d,4096
    mov eax,322
    syscall
    jmp refuse
clock_now:
    mov edi,1
    lea rsi,[rbp+WHEN]
    mov eax,228
    syscall
    test rax,rax
    jne refuse
    imul rax,[rbp+WHEN],1000000000
    add rax,[rbp+WHEN+8]
    mov [r15+48],rax
    ret
inherit_fd:
    mov esi,2
    xor edx,edx
    mov eax,72
    syscall
    test rax,rax
    jne refuse
    ret
bind_fd:
    mov eax,33
    syscall
    cmp eax,esi
    jne refuse
    ret
allocate:
    xor edi,edi
    mov edx,3
    mov r10d,34
    mov r8,-1
    xor r9d,r9d
    mov eax,9
    syscall
    test rax,rax
    js refuse
    ret
sealed_input:
    push rsi
    mov esi,1034
    mov eax,72
    syscall
    pop rsi
    test rax,rax
    js refuse
    and eax,15
    cmp eax,15
    jne refuse
map_input:
    mov r12,rsi
    call extent
    test rax,rax
    jle refuse
    cmp rax,r12
    ja refuse
    mov rsi,rax
    mov r8d,edi
    xor edi,edi
    mov edx,1
    mov r10d,2
    xor r9d,r9d
    mov eax,9
    syscall
    test rax,rax
    js refuse
    ret
extent:
    lea rsi,[rbp+STAT]
    mov eax,5
    syscall
    test rax,rax
    jne refuse
    mov rax,[rbp+STAT+48]
    ret
scratch:
    lea rdi,[rip+name]
    mov esi,1
    mov eax,319
    syscall
    test rax,rax
    js refuse
    mov rdi,rax
    mov esi,1030
    mov edx,32
    mov eax,72
    syscall
    test rax,rax
    js refuse
    push rax
    mov eax,3
    syscall
    pop rax
    ret
reset:
    xor esi,esi
    mov eax,77
    syscall
    test rax,rax
    jne refuse
rewind:
    xor esi,esi
    xor edx,edx
    mov eax,8
    syscall
    test rax,rax
    jne refuse
    ret
pread_all:
    xor r10d,r10d
pread_more:
    mov eax,17
    syscall
    cmp rax,-4
    je pread_more
    test rax,rax
    jle refuse
    add rsi,rax
    add r10,rax
    sub rdx,rax
    jne pread_more
    ret
write_all:
    mov eax,1
    syscall
    cmp rax,-4
    je write_all
    test rax,rax
    jle refuse
    add rsi,rax
    sub rdx,rax
    jne write_all
    ret
refuse:
    mov edi,2
exit:
    mov eax,60
    syscall
name: .asciz "hia-evaluate-pair"
option: .asciz "--supervise"
empty: .byte 0
