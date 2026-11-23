/* Six already admitted immutable fds: [ABI,workload], baseline ELF, candidate
 * ELF, direct-call supervisor, baseline HIA reference batch, memory/deadline.
 * HIAEPL02 additionally opens fds 9..11 for the other reference and both Core files.
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
_start:
    cmp QWORD PTR [rsp],1
    jne refuse
    sub rsp,384
    mov rbp,rsp
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
    mov esi,24
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
