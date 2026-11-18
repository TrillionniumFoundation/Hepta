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
.equ FRAME_BYTES, 70448
.equ MAGIC, 0x3130585244414948     /* HIADRX01 */
.equ RESULT, 0x3130525244414948    /* HIADRR01 */
.equ REPEAT_MAGIC, 0x3230585244414948
.equ REPEAT_RESULT, 0x3230525244414948

_start:
    cmp QWORD PTR [rsp],1
    jne usage
    sub rsp,FRAME_BYTES
    mov rbp,rsp

    /* Limit orphan custody while the request is read, then bind the PPID. */
    mov edi,1
    mov esi,9
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
    jz validate
    add rbx,rax
    cmp rbx,INPUT_LIMIT
    jae invalid
    jmp read_input

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
    .byte 0xe8
direct_plan_call_hole: .long 0
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
