/* Mechanical Linux x86-64 transport for the HIA NDU state machine.
 * The HIA owner validates argv, JSON, framing, session limits and all results.
 * The adapter copies startup bytes and performs bounded read/write/mmap/exit.
 * It contains no JSON parser, evaluator, hash, sequence or admission policy. */
.intel_syntax noprefix
.text
.global _start, ndu_call_hole
.equ INPUT_CAP, 0x102000
.equ OUTPUT_CAP, 0x102000
.equ WORK_CAP, 0x200000
.equ TOTAL_CAP, INPUT_CAP+OUTPUT_CAP+WORK_CAP

_start:
    mov rbp, rsp
    mov eax, 9
    xor edi, edi
    mov esi, TOTAL_CAP
    mov edx, 3
    mov r10d, 34
    mov r8, -1
    xor r9d, r9d
    syscall
    cmp rax, -4095
    jae failed
    mov r12, rax
    lea r14, [r12+INPUT_CAP]
    lea r15, [r14+OUTPUT_CAP]
    and rsp, -16
    mov rax, [rbp]
    mov [r12+8], rax
    mov r13d, 16
    cmp rax, 64
    ja startup_overflow
    xor r10d, r10d
startup_argument:
    cmp r10, [r12+8]
    jae call_owner
    mov rsi, [rbp+8+r10*8]
    xor ecx, ecx
startup_length:
    cmp rcx, 131072
    jae startup_overflow
    cmp BYTE PTR [rsi+rcx], 0
    je startup_copy
    inc rcx
    jmp startup_length
startup_copy:
    lea rax, [r13+rcx+8]
    cmp rax, INPUT_CAP
    ja startup_overflow
    mov [r12+r13], rcx
    lea rdi, [r12+r13+8]
    mov r13, rax
    rep movsb
    inc r10
    jmp startup_argument
startup_overflow:
    mov QWORD PTR [r12], 3
    mov r13d, 16

call_owner:
    mov rdi, r12
    mov rsi, r13
    mov rdx, r14
    mov ecx, OUTPUT_CAP
    mov r8, r15
    mov r9d, WORK_CAP
    .byte 0xe8
ndu_call_hole:
    .long 0
    cmp eax, 32
    jb failed
    cmp eax, OUTPUT_CAP
    ja failed
    mov rax, [r14]
    cmp rax, 1
    je read_command
    cmp rax, 4
    je read_command
    cmp rax, 2
    je write_command
    cmp rax, 3
    jne failed
    mov rdi, [r14+8]
    cmp rdi, 255
    ja failed
    mov eax, 60
    syscall
    ud2

read_command:
    mov rbx, [r14+16]
    cmp rbx, INPUT_CAP-16
    ja failed
    test rbx, rbx
    je failed
    mov QWORD PTR [r12], 0
    mov QWORD PTR [r12+8], 0
    mov r13d, 16
read_more:
    lea rdx, [rbx+16]
    sub rdx, r13
    je read_done
    lea rsi, [r12+r13]
    xor edi, edi
    xor eax, eax
    syscall
    cmp rax, -4
    je read_more
    test rax, rax
    js io_failed
    jz read_eof
    add r13, rax
    jmp read_more
read_eof:
    mov QWORD PTR [r12], 1
read_done:
    lea rax, [r13-16]
    mov [r12+8], rax
    jmp call_owner

write_command:
    mov rbx, [r14+8]
    cmp rbx, 1
    jb failed
    cmp rbx, 2
    ja failed
    mov r13, [r14+16]
    cmp r13, OUTPUT_CAP-32
    ja failed
    xor r10d, r10d
write_more:
    mov rdx, r13
    sub rdx, r10
    je write_done
    lea rsi, [r14+r10+32]
    mov rdi, rbx
    mov eax, 1
    syscall
    cmp rax, -4
    je write_more
    test rax, rax
    jle io_failed
    add r10, rax
    jmp write_more
write_done:
    mov QWORD PTR [r12], 0
    mov QWORD PTR [r12+8], 0
    mov r13d, 16
    jmp call_owner
io_failed:
    mov QWORD PTR [r12], 2
    mov QWORD PTR [r12+8], 0
    mov r13d, 16
    jmp call_owner
failed:
    mov edi, 2
    mov eax, 60
    syscall
    ud2
.section .note.GNU-stack,"",@progbits
