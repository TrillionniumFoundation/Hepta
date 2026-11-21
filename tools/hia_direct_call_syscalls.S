/* Synchronous calls to one immutable direct HIA image. HIA chooses the
 * entry and closed GOT slots; this adapter owns Linux mappings and SysV
 * register/stack transfer. No loader hooks, libc or interpreter run. */
.intel_syntax noprefix
.text
.global _start, direct_plan_call_hole

.equ INPUT, 0
.equ INPUT_LIMIT, 69632
.equ PLAN, 69648
.equ INFO, 69736
.equ OUTPUT, 69888
.equ START, 70424
.equ LOAN_TAIL, 70440
.equ LIMIT, 69928
.equ CODE, 69944
.equ WORDS, 69952
.equ LOANS, 69960
.equ ENTRY, 69968
.equ MEMORY, 69976
.equ ABI_REGISTERS, 69984
.equ VERSION, 70032
.equ HEADER_BYTES, 70040
.equ LOAN_STRIDE, 70048
.equ STOP, 70056
.equ ITERATION, 70064
.equ STRICT, 70072
.equ RETURN_MASK, 70080
.equ FIRST_VALUE, 70088
.equ COMPARISON, 70096
.equ LOAN_STATE, 70104
.equ LOAN_RECORD, 40   /* mapped, initial, first, extent, readonly */
.equ OWNER, 70448
.equ OWNER_PID, 70456
.equ OWNER_CHILD, 70464
.equ OWNER_STOPPED, 70472
.equ OWNER_STATUS_FD, 70480
.equ OWNER_OLD_MASK, 70488
.equ OWNER_MASK, 70496
.equ OWNER_TIMER, 70504
.equ OWNER_POLL, 70536
.equ OWNER_OBSERVATION, 70560
.equ OWNER_TEXT, 70624
.equ OWNER_ARGV, 70712
.equ OWNER_ENV, 70760
.equ FRAME_BYTES, 70784
.equ MAGIC, 0x3130585244414948     /* HIADRX01 */
.equ RESULT, 0x3130525244414948    /* HIADRR01 */
.equ REPEAT_MAGIC, 0x3230585244414948
.equ REPEAT_RESULT, 0x3230525244414948

_start:
    xor r10d,r10d
    cmp QWORD PTR [rsp],1
    je mode_ready
    cmp QWORD PTR [rsp],3
    je sealed_reference_mode
    cmp QWORD PTR [rsp],2
    jne usage
    mov rsi,[rsp+16]
    lea rdi,[rip+owner_option]
    mov ecx,12
    cld
    repe cmpsb
    jne usage
    mov r10d,1
    jmp mode_ready
sealed_reference_mode:
    mov rsi,[rsp+16]
    lea rdi,[rip+exec_owner_option]
    mov ecx,15
    cld
    repe cmpsb
    jne usage
    mov rsi,[rsp+24]
    xor r14d,r14d
    xor ecx,ecx
reference_descriptor:
    movzx eax,BYTE PTR [rsi+rcx]
    test eax,eax
    jz reference_descriptor_ready
    sub eax,48
    cmp eax,9
    ja usage
    cmp ecx,10
    jae usage
    imul r14,r14,10
    add r14,rax
    inc ecx
    jmp reference_descriptor
reference_descriptor_ready:
    cmp r14,3
    jb usage
    cmp r14,0x7fffffff
    ja usage
    mov r10d,2
mode_ready:
    sub rsp,FRAME_BYTES
    mov rbp,rsp
    mov [rbp+OWNER],r10
    test r10d,r10d
    jz parent_death

    /* Block SIGTERM before subscribing to parent death. The disposable
     * owner observes cancellation and reaps its own child before exit. */
    mov QWORD PTR [rbp+OWNER_MASK],16384
    xor edi,edi
    lea rsi,[rbp+OWNER_MASK]
    lea rdx,[rbp+OWNER_OLD_MASK]
    mov r10d,8
    mov eax,14
    syscall
    test rax,rax
    js io

parent_death:
    /* Limit orphan custody while the request is read, then bind the PPID. */
    mov edi,1
    mov esi,9
    cmp QWORD PTR [rbp+OWNER],0
    je set_parent_death
    mov esi,15
set_parent_death:
    mov eax,157
    syscall
    test rax,rax
    jne io
    mov edi,4
    xor esi,esi
    mov eax,157
    syscall
    test rax,rax
    jne io

    cmp QWORD PTR [rbp+OWNER],2
    je supervise_reference
    xor ebx,ebx
read_input:
    xor eax,eax
    xor edi,edi
    lea rsi,[rbp+INPUT+rbx]
    mov edx,INPUT_LIMIT
    sub rdx,rbx
    syscall
    cmp rax,-4
    je read_input
    test rax,rax
    js io
    jz input_complete
    add rbx,rax
    cmp rbx,INPUT_LIMIT
    jae invalid
    jmp read_input

input_complete:
    cmp QWORD PTR [rbp+OWNER],0
    jne supervise_input
validate:
    cmp rbx,72
    jb invalid
    movabs rax,MAGIC
    cmp [rbp+INPUT],rax
    je single
    movabs rax,REPEAT_MAGIC
    cmp [rbp+INPUT],rax
    jne invalid
    cmp rbx,104
    jb invalid
    mov rax,[rbp+INPUT+72]
    cmp rax,100
    ja invalid
    mov rcx,[rbp+INPUT+80]
    test rcx,rcx
    jz invalid
    cmp rcx,10000
    ja invalid
    add rax,rcx
    mov [rbp+STOP],rax
    mov QWORD PTR [rbp+HEADER_BYTES],104
    mov QWORD PTR [rbp+LOAN_STRIDE],32
    mov QWORD PTR [rbp+VERSION],2
    mov rax,[rbp+INPUT+88]
    cmp rax,1
    ja invalid
    mov [rbp+STRICT],rax
    mov rax,[rbp+INPUT+96]
    mov [rbp+RETURN_MASK],rax
    jmp check_parent
single:
    mov QWORD PTR [rbp+HEADER_BYTES],72
    mov QWORD PTR [rbp+LOAN_STRIDE],24
    mov QWORD PTR [rbp+VERSION],1
    mov QWORD PTR [rbp+STOP],1
    mov QWORD PTR [rbp+STRICT],0
    mov QWORD PTR [rbp+RETURN_MASK],-1
check_parent:
    mov QWORD PTR [rbp+ITERATION],0
    mov QWORD PTR [rbp+COMPARISON],0
    mov QWORD PTR [rbp+OUTPUT+16],0
    mov eax,110
    syscall
    cmp rax,[rbp+INPUT+8]
    jne invalid
    mov rsi,[rbp+INPUT+16]
    cmp rsi,67108864
    jb invalid
    movabs rax,4294967296
    cmp rsi,rax
    ja invalid
    mov edi,9
    call set_limit
    mov rsi,[rbp+INPUT+24]
    test rsi,rsi
    jz invalid
    cmp rsi,86400
    ja invalid
    xor edi,edi
    call set_limit
    mov edi,4
    xor esi,esi
    call set_limit
    mov edi,1
    mov esi,8388608
    call set_limit

    mov r8,[rbp+INPUT+32]
    cmp r8,3
    jb invalid
    cmp r8,2147483647
    ja invalid
    mov edi,r8d
    mov esi,1034                 /* F_GET_SEALS */
    xor edx,edx
    mov eax,72
    syscall
    test rax,rax
    js invalid
    and eax,15
    cmp eax,15
    jne invalid
    mov rsi,[rbp+INPUT+40]
    test rsi,rsi
    jz invalid
    cmp rsi,67108864
    ja invalid
    mov edi,r8d
    call regular_file
    xor edi,edi
    mov edx,1
    mov r10d,2
    xor r9d,r9d
    call map_bytes
    mov r12,rax

    mov r13,[rbp+INPUT+48]
    cmp r13,8192
    ja invalid
    mov r14,[rbp+INPUT+56]
    cmp r14,8
    ja invalid
    mov r15,[rbp+INPUT+64]
    test r15,r15
    jz invalid
    cmp r15,512
    ja invalid
    mov rcx,[rbp+HEADER_BYTES]
    lea rax,[rcx+r13*8]
    mov rdx,r14
    imul rdx,[rbp+LOAN_STRIDE]
    add rdx,rax
    lea rsi,[rdx+r15]
    cmp rsi,rbx
    jne invalid
    lea r8,[rbp+INPUT+rdx]
    lea rcx,[rbp+INPUT+rax]
    mov [rbp+LOANS],rcx
    mov rax,[rbp+HEADER_BYTES]
    lea rax,[rbp+INPUT+rax]
    mov [rbp+WORDS],rax

    mov rdi,r12
    mov rsi,[rbp+INPUT+40]
    lea rdx,[rbp+PLAN]
    mov ecx,88
    mov r9,r15
    call direct_policy
    cmp eax,88
    jne invalid

    /* Keep the text-to-GOT layout intact, without mapping the ELF metadata.
     * The only writable page is private, then is sealed read-only. */
    mov rsi,[rbp+PLAN+16]
    sub rsi,[rbp+PLAN]
    add rsi,4096
    mov [rbp+MEMORY],rsi
    xor edi,edi
    mov edx,3
    mov r10d,0x22
    mov r8,-1
    xor r9d,r9d
    call map_bytes
    mov [rbp+CODE],rax
    mov rdi,rax
    mov rsi,[rbp+PLAN]
    add rsi,r12
    mov rcx,[rbp+PLAN+8]
    cld
    rep movsb

    lea rdx,[rip+runtime_offsets]
    xor ebx,ebx
bind_got:
    mov rax,[rbp+PLAN+32+rbx*8]
    test rax,rax
    jz next_import
    sub rax,[rbp+PLAN]
    movsxd rcx,DWORD PTR [rdx+rbx*4]
    add rcx,rdx
    mov rsi,[rbp+CODE]
    mov [rsi+rax],rcx
next_import:
    inc ebx
    cmp ebx,7
    jne bind_got
    mov rdi,[rbp+CODE]
    mov rsi,[rbp+MEMORY]
    sub rsi,4096
    mov edx,5
    mov eax,10
    syscall
    test rax,rax
    js io
    lea rdi,[rdi+rsi]
    mov esi,4096
    mov edx,1
    mov eax,10
    syscall
    test rax,rax
    js io
    mov rax,[rbp+PLAN+24]
    sub rax,[rbp+PLAN]
    add rax,[rbp+CODE]
    mov [rbp+ENTRY],rax
    mov rdi,r12
    mov rsi,[rbp+INPUT+40]
    mov eax,11
    syscall
    test rax,rax
    js io

    /* Each loan contributes exactly two ABI words. The caller owns a
     * distinct backing file and retains write observations after a trap. */
    xor ebx,ebx
    mov r15,[rbp+LOANS]
    mov r12,[rbp+WORDS]
    lea rdx,[rbp+LOAN_STATE]
    mov [rbp+LOAN_TAIL],rdx
loan_loop:
    test r14,r14
    jz dispatch
    mov rax,[r15]
    cmp rax,rbx
    jb invalid
    lea rbx,[rax+2]
    cmp rbx,r13
    ja invalid
    cmp QWORD PTR [r12+rax*8],0
    jne invalid
    mov rsi,[r15+16]
    cmp [r12+rax*8+8],rsi
    jne invalid
    cmp rsi,1048576
    ja invalid
    cmp rsi,1
    adc rsi,0                   /* Zero-length views still own one byte. */
    mov r8,[r15+8]
    cmp r8,3
    jb invalid
    cmp r8,2147483647
    ja invalid
    cmp r8,[rbp+INPUT+32]
    je invalid
    mov edi,r8d
    call regular_file
    xor edi,edi
    mov edx,3
    mov r10d,1
    xor r9d,r9d
    call map_bytes
    mov [r12+rbx*8-16],rax
    cmp QWORD PTR [rbp+VERSION],2
    jne next_loan
    mov rdx,[rbp+LOAN_TAIL]
    mov [rdx],rax
    mov rax,[r15+16]
    mov [rdx+24],rax
    mov rax,[r15+24]
    cmp rax,1
    ja invalid
    mov [rdx+32],rax
    /* Preserve caller-owned bytes for every reset, and a separate first
     * observation when the workload declared an exact expected result. */
    mov rsi,[r15+16]
    test rsi,rsi
    jz loan_empty
    cmp QWORD PTR [rbp+STRICT],1
    jne loan_backing
    cmp QWORD PTR [rdx+32],1
    je loan_backing
    shl rsi,1
loan_backing:
    xor edi,edi
    mov edx,3
    mov r10d,0x22
    mov r8,-1
    xor r9d,r9d
    call map_bytes
    mov rdx,[rbp+LOAN_TAIL]
    mov [rdx+8],rax
    mov rdi,rax
    mov rsi,[rdx]
    mov rcx,[rdx+24]
    lea rax,[rdi+rcx]
    mov [rdx+16],rax
    rep movsb
loan_empty:
    add QWORD PTR [rbp+LOAN_TAIL],LOAN_RECORD
next_loan:
    add r15,[rbp+LOAN_STRIDE]
    dec r14
    jmp loan_loop

dispatch:
    /* The saved frame has a fixed address even with stack arguments.
     * Unused argument registers remain zero. Stack slot 7 is nearest the
     * return address, regardless of an odd/even number of spill words. */
    mov ebx,6
    cmp  r13d,ebx
    cmovb ebx,r13d
    lea rdi,[rbp+ABI_REGISTERS]
    xor eax,eax
    mov ecx,6
    rep stosq
    lea rdi,[rbp+ABI_REGISTERS]
    mov rsi,r12
    mov ecx,ebx
    rep movsq
    mov rax,r13
    sub rax,rbx
    lea rcx,[rax*8+15]
    and rcx,-16
    sub rsp,rcx
    mov rdi,rsp
    mov rcx,rax
    rep movsq

invoke:
    cmp QWORD PTR [rbp+VERSION],2
    jne start_timer
    lea rdx,[rbp+LOAN_STATE]
    mov r14,[rbp+INPUT+56]
reset_loop:
    test r14,r14
    jz start_timer
    mov rcx,[rdx+24]
    test rcx,rcx
    jz reset_next
    mov rdi,[rdx]
    mov rsi,[rdx+8]
    rep movsb
reset_next:
    add rdx,LOAN_RECORD
    dec r14
    jmp reset_loop
start_timer:
    lea rsi,[rbp+START]
    call clock_read
    mov rdi,[rbp+ABI_REGISTERS]
    mov rsi,[rbp+ABI_REGISTERS+8]
    mov rdx,[rbp+ABI_REGISTERS+16]
    mov rcx,[rbp+ABI_REGISTERS+24]
    mov r8,[rbp+ABI_REGISTERS+32]
    mov r9,[rbp+ABI_REGISTERS+40]
    call QWORD PTR [rbp+ENTRY]
    mov [rbp+OUTPUT+8],rax
    lea rsi,[rbp+LIMIT]
    call clock_read
    mov rax,[rbp+LIMIT]
    sub rax,[rbp+START]
    imul rax,1000000000
    add rax,[rbp+LIMIT+8]
    sub rax,[rbp+START+8]
    cmp QWORD PTR [rbp+VERSION],2
    je observed
    mov [rbp+OUTPUT+16],rax
    movabs rax,RESULT
    mov r14d,24
    jmp send_result
observed:
    mov rcx,[rbp+ITERATION]
    cmp rcx,[rbp+INPUT+72]
    jb compare
    add [rbp+OUTPUT+16],rax
compare:
    cmp QWORD PTR [rbp+STRICT],1
    jne compare_buffers
    mov rax,[rbp+OUTPUT+8]
    and rax,[rbp+RETURN_MASK]
    test rcx,rcx
    jne compare_value
    mov [rbp+FIRST_VALUE],rax
    jmp compare_buffers
compare_value:
    cmp [rbp+FIRST_VALUE],rax
    je compare_buffers
    mov QWORD PTR [rbp+COMPARISON],1
compare_buffers:
    lea rdx,[rbp+LOAN_STATE]
    mov r14,[rbp+INPUT+56]
buffer_loop:
    test r14,r14
    jz advance
    mov rcx,[rdx+24]
    test rcx,rcx
    jz buffer_next
    mov rsi,[rdx]
    cmp QWORD PTR [rdx+32],1
    jne compare_mutable
    mov rdi,[rdx+8]
    jmp check_content
compare_mutable:
    cmp QWORD PTR [rbp+STRICT],1
    jne buffer_next
    mov rdi,[rdx+16]
    cmp QWORD PTR [rbp+ITERATION],0
    jne check_content
    rep movsb
    jmp buffer_next
check_content:
    repe cmpsb
    je buffer_next
    mov QWORD PTR [rbp+COMPARISON],1
buffer_next:
    add rdx,LOAN_RECORD
    dec r14
    jmp buffer_loop
advance:
    inc QWORD PTR [rbp+ITERATION]
    mov rax,[rbp+ITERATION]
    cmp rax,[rbp+STOP]
    jb invoke
    mov rax,[rbp+COMPARISON]
    mov [rbp+OUTPUT+24],rax
    movabs rax,REPEAT_RESULT
    mov r14d,32
send_result:
    mov [rbp+OUTPUT],rax
    lea rsi,[rbp+OUTPUT]
write_result:
    mov eax,1
    mov edi,1
    mov rdx,r14
    syscall
    cmp rax,-4
    je write_result
    test rax,rax
    jle io
    add rsi,rax
    sub r14,rax
    jne write_result
    xor edi,edi
    jmp finish

regular_file:
    mov r10,rsi
    lea rsi,[rbp+INFO]
    mov eax,5
    syscall
    test rax,rax
    js io
    mov eax,[rbp+INFO+24]
    and eax,0xf000
    cmp eax,0x8000
    jne invalid
    cmp [rbp+INFO+48],r10
    jne invalid
    mov rsi,r10
    ret

map_bytes:
    mov eax,9
    syscall
    cmp rax,-4095
    jae io
    ret

set_limit:
    mov [rbp+LIMIT],rsi
    mov [rbp+LIMIT+8],rsi
    lea rsi,[rbp+LIMIT]
    mov eax,160
    syscall
    test rax,rax
    js io
    ret

clock_read:
    mov edi,1
    mov eax,228
    syscall
    test rax,rax
    js io
    ret

direct_policy:
    sub rsp,8
    .byte 0xe8
direct_plan_call_hole: .long 0
    add rsp,8
    ret

/* Only the HIA policy admits the request and classifies readiness and
 * wait status. This transport owns one fork of the admitted executable,
 * three kernel event descriptors and one waitable child identity. */
supervise_input:
    cmp rbx,104
    jb invalid
    jmp owner_admit
supervise_reference:
    mov edi,r14d
    call owner_require_sealed
    lea rsi,[rbp+INPUT]
    mov edx,65
    xor r10d,r10d
    mov eax,17                /* pread64; never consume the child's stdin */
    syscall
    cmp rax,-4
    je supervise_reference
    cmp rax,64
    jne invalid
    mov edi,r14d
    call owner_close
owner_admit:
    mov QWORD PTR [rbp+OWNER_OBSERVATION],0
    mov eax,110
    syscall
    mov [rbp+OWNER_OBSERVATION+8],rax
    lea rsi,[rbp+INPUT]
    lea rdi,[rbp+OWNER_OBSERVATION+16]
    mov ecx,4
    cld
    rep movsq
    lea rsi,[rbp+OWNER_TIMER]
    call clock_read
    imul rax,[rbp+OWNER_TIMER],1000000000
    add rax,[rbp+OWNER_TIMER+8]
    mov [rbp+OWNER_OBSERVATION+48],rax
    mov esi,56
    call owner_policy
    cmp eax,2
    je owner_expired
    cmp eax,1
    jne invalid
    mov rax,[rbp+INPUT+24]
    mov [rbp+OWNER_STATUS_FD],rax
    xor edx,edx
    mov rax,[rbp+INPUT+16]
    mov ecx,1000000000
    div rcx
    mov QWORD PTR [rbp+OWNER_TIMER],0
    mov QWORD PTR [rbp+OWNER_TIMER+8],0
    mov [rbp+OWNER_TIMER+16],rax
    mov [rbp+OWNER_TIMER+24],rdx

    mov edi,1                 /* timerfd_create(CLOCK_MONOTONIC, 0) */
    xor esi,esi
    mov eax,283
    syscall
    test rax,rax
    js io
    mov DWORD PTR [rbp+OWNER_POLL+8],eax
    mov edi,eax
    mov esi,1                 /* TFD_TIMER_ABSTIME */
    lea rdx,[rbp+OWNER_TIMER]
    xor r10d,r10d
    mov eax,286
    syscall
    test rax,rax
    js io
    mov edi,-1
    lea rsi,[rbp+OWNER_MASK]
    mov edx,8
    xor r10d,r10d
    mov eax,289               /* signalfd4 */
    syscall
    test rax,rax
    js io
    mov DWORD PTR [rbp+OWNER_POLL+16],eax

    mov eax,39
    syscall
    mov [rbp+OWNER_PID],rax
    cmp QWORD PTR [rbp+OWNER],2
    jne owner_fork
    call reference_arguments
owner_fork:
    mov eax,57                /* fork exactly this immutable image */
    syscall
    test rax,rax
    js io
    jz supervised_child
    mov [rbp+OWNER_CHILD],rax
    mov edi,eax
    xor esi,esi
    mov eax,434               /* pidfd_open on the unreaped direct child */
    syscall
    test rax,rax
    js owner_cleanup_error
    mov DWORD PTR [rbp+OWNER_POLL],eax
    mov WORD PTR [rbp+OWNER_POLL+4],1
    mov WORD PTR [rbp+OWNER_POLL+12],1
    mov WORD PTR [rbp+OWNER_POLL+20],1
owner_poll:
    lea rdi,[rbp+OWNER_POLL]
    mov esi,3
    mov edx,-1
    mov eax,7
    syscall
    cmp rax,-4
    je owner_poll
    test rax,rax
    jle owner_cleanup_error
    movzx eax,WORD PTR [rbp+OWNER_POLL+6]
    movzx ecx,WORD PTR [rbp+OWNER_POLL+14]
    movzx edx,WORD PTR [rbp+OWNER_POLL+22]
    mov QWORD PTR [rbp+OWNER_OBSERVATION],1
    mov [rbp+OWNER_OBSERVATION+8],rax
    mov [rbp+OWNER_OBSERVATION+16],rcx
    mov [rbp+OWNER_OBSERVATION+24],rdx
    mov esi,32
    call owner_policy
    cmp eax,2
    je owner_stop
    cmp eax,3
    jne owner_cleanup_error
    mov QWORD PTR [rbp+OWNER_STOPPED],0
    jmp owner_reap
owner_stop:
    mov QWORD PTR [rbp+OWNER_STOPPED],1
    call owner_signal
owner_reap:
    call owner_wait
    cmp rax,[rbp+OWNER_CHILD]
    jne io
    mov eax,DWORD PTR [rbp+OWNER_TIMER]
    jmp owner_receipt
owner_expired:
    mov rax,[rbp+INPUT+24]
    mov [rbp+OWNER_STATUS_FD],rax
    mov QWORD PTR [rbp+OWNER_STOPPED],2
    xor eax,eax
owner_receipt:
    mov QWORD PTR [rbp+OWNER_OBSERVATION],2
    mov [rbp+OWNER_OBSERVATION+8],rax
    mov rax,[rbp+OWNER_STOPPED]
    mov [rbp+OWNER_OBSERVATION+16],rax
    mov esi,24
    call owner_policy
    cmp eax,24
    jne io
    mov edi,DWORD PTR [rbp+OWNER_STATUS_FD]
    lea rsi,[rbp+PLAN]
    mov edx,24
owner_write:
    mov eax,1
    syscall
    cmp rax,-4
    je owner_write
    cmp rax,24
    jne io
    xor edi,edi
    jmp finish

owner_policy:
    lea rdi,[rbp+OWNER_OBSERVATION]
    lea rdx,[rbp+PLAN]
    mov ecx,24
    lea r8,[rbp+OWNER_OBSERVATION]
    xor r9d,r9d
    jmp direct_policy
owner_cleanup_error:
    call owner_signal
    call owner_wait
    jmp io
owner_signal:
    /* This PID cannot be reused before this process reaps its child. */
    mov edi,DWORD PTR [rbp+OWNER_CHILD]
    mov esi,9
    mov eax,62
    syscall
    ret
owner_wait:
    mov edi,DWORD PTR [rbp+OWNER_CHILD]
    lea rsi,[rbp+OWNER_TIMER]
    xor edx,edx
    xor r10d,r10d
    mov eax,61
    syscall
    cmp rax,-4
    je owner_wait
    ret

supervised_child:
    mov edi,1
    mov esi,9
    mov eax,157
    syscall
    test rax,rax
    js io
    mov edi,2
    lea rsi,[rbp+OWNER_OLD_MASK]
    xor edx,edx
    mov r10d,8
    mov eax,14
    syscall
    test rax,rax
    js io
    mov edi,DWORD PTR [rbp+OWNER_STATUS_FD]
    call owner_close
    mov edi,DWORD PTR [rbp+OWNER_POLL+8]
    call owner_close
    mov edi,DWORD PTR [rbp+OWNER_POLL+16]
    call owner_close
    cmp QWORD PTR [rbp+OWNER],2
    je execute_reference
    sub rbx,32
    lea rsi,[rbp+INPUT+32]
    lea rdi,[rbp+INPUT]
    mov rcx,rbx
    cld
    rep movsb
    mov rax,[rbp+OWNER_PID]
    mov [rbp+INPUT+8],rax
    jmp validate
reference_arguments:
    mov QWORD PTR [rbp+OWNER_OBSERVATION],3
    mov rax,[rbp+OWNER_PID]
    mov [rbp+OWNER_OBSERVATION+8],rax
    lea rsi,[rbp+INPUT+32]
    lea rdi,[rbp+OWNER_OBSERVATION+16]
    mov ecx,4
    cld
    rep movsq
    mov rax,[rbp+OWNER_STATUS_FD]
    mov [rbp+OWNER_OBSERVATION+48],rax
    lea rdi,[rbp+OWNER_OBSERVATION]
    mov esi,56
    lea rdx,[rbp+OWNER_TEXT]
    mov ecx,84
    lea r8,[rbp+OWNER_OBSERVATION]
    xor r9d,r9d
    sub rsp,8
    call direct_policy
    add rsp,8
    cmp eax,84
    jne invalid
    mov edi,DWORD PTR [rbp+INPUT+32]
    call owner_require_sealed
    mov edi,DWORD PTR [rbp+INPUT+56]
    test edi,edi
    jz reference_seals_ready
    call owner_require_sealed
reference_seals_ready:
    lea rax,[rip+reference_name]
    mov [rbp+OWNER_ARGV],rax
    lea rax,[rbp+OWNER_TEXT]
    mov [rbp+OWNER_ARGV+8],rax
    lea rax,[rbp+OWNER_TEXT+21]
    mov [rbp+OWNER_ARGV+16],rax
    lea rax,[rbp+OWNER_TEXT+42]
    mov [rbp+OWNER_ARGV+24],rax
    xor eax,eax
    cmp QWORD PTR [rbp+INPUT+56],0
    je reference_argv_ready
    lea rax,[rbp+OWNER_TEXT+63]
reference_argv_ready:
    mov [rbp+OWNER_ARGV+32],rax
    mov QWORD PTR [rbp+OWNER_ARGV+40],0
    lea rax,[rip+reference_env]
    mov [rbp+OWNER_ENV],rax
    mov QWORD PTR [rbp+OWNER_ENV+8],0
    ret
execute_reference:
    mov edi,DWORD PTR [rbp+INPUT+32]
    lea rsi,[rip+empty_name]
    lea rdx,[rbp+OWNER_ARGV]
    lea r10,[rbp+OWNER_ENV]
    mov r8d,4096              /* AT_EMPTY_PATH */
    mov eax,322               /* execveat on the sealed reference descriptor */
    syscall
    jmp io
owner_require_sealed:
    mov esi,1034              /* F_GET_SEALS */
    mov eax,72
    syscall
    cmp rax,-4095
    jae invalid
    and eax,15                /* SEAL, SHRINK, GROW, WRITE */
    cmp eax,15
    jne invalid
    ret
owner_close:
    mov eax,3
    syscall
    test rax,rax
    js io
    ret
owner_option:
    .asciz "--supervise"
exec_owner_option:
    .asciz "--supervise-at"
reference_name:
    .asciz "hia-reference-wire"
reference_env:
    .asciz "PATH="
empty_name:
    .byte 0

runtime_offsets:
    .long core_abort-runtime_offsets, core_calloc-runtime_offsets
    .long core_free-runtime_offsets, core_malloc-runtime_offsets
    .long core_memcpy-runtime_offsets, core_memmove-runtime_offsets
    .long core_memset-runtime_offsets

core_abort:
    push 32
    mov edi,1
    mov rsi,rsp
    xor edx,edx
    mov r10d,8
    mov eax,14                  /* rt_sigprocmask(SIG_UNBLOCK, SIGABRT). */
    syscall
    test rax,rax
    js io
    mov eax,39
    syscall
    mov edi,eax
    mov eax,186
    syscall
    mov esi,eax
    mov edx,6
    mov eax,234                 /* Deliver the existing terminal SIGABRT. */
    syscall
    jmp io

core_calloc:
    mov rax,rdi
    mul rsi
    test rdx,rdx
    jne no_memory
    mov rdi,rax
core_malloc:
    lea rsi,[rdi+16]
    cmp rsi,rdi
    jb no_memory
    xor edi,edi
    mov edx,3
    mov r10d,0x22
    mov r8,-1
    xor r9d,r9d
    mov eax,9
    syscall
    cmp rax,-4095
    jae no_memory
    mov [rax],rsi
    add rax,16
    ret
no_memory:
    xor eax,eax
    ret
core_free:
    test rdi,rdi
    jz free_done
    sub rdi,16
    mov rsi,[rdi]
    mov eax,11
    syscall
    test rax,rax
    js io
free_done:
    ret

core_memmove:
    mov rax,rdi
    test rdx,rdx
    jz move_done
    cmp rdi,rsi
    jbe core_memcpy
    lea rdi,[rdi+rdx-1]
    lea rsi,[rsi+rdx-1]
    mov rcx,rdx
    std
    rep movsb
    cld
move_done:
    ret
core_memcpy:
    mov rax,rdi
    mov rcx,rdx
    rep movsb
    ret
core_memset:
    mov r8,rdi
    mov rcx,rdx
    mov eax,esi
    rep stosb
    mov rax,r8
    ret

usage:
    mov edi,64
    jmp finish
invalid:
    mov edi,2
    jmp finish
io:
    mov edi,4
finish:
    mov eax,60
    syscall
    ud2
