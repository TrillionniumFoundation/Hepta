/* One synchronous call to an immutable direct HIA image. HIA chooses the
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
.equ START, 69912
.equ LIMIT, 69928
.equ CODE, 69944
.equ WORDS, 69952
.equ LOANS, 69960
.equ ENTRY, 69968
.equ MEMORY, 69976
.equ ABI_REGISTERS, 69984
.equ FRAME_BYTES, 70032
.equ MAGIC, 0x3130585244414948     /* HIADRX01 */
.equ RESULT, 0x3130525244414948    /* HIADRR01 */

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
    jne invalid
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
    lea rax,[r13*8+72]
    lea rcx,[r14+r14*2]
    lea rdx,[rax+rcx*8]
    lea rsi,[rdx+r15]
    cmp rsi,rbx
    jne invalid
    lea r8,[rbp+INPUT+rdx]
    lea rcx,[rbp+INPUT+rax]
    mov [rbp+LOANS],rcx
    lea rax,[rbp+INPUT+72]
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
    add r15,24
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
    mov [rbp+OUTPUT+16],rax
    movabs rax,RESULT
    mov [rbp+OUTPUT],rax
    lea rsi,[rbp+OUTPUT]
    mov r14d,24
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
