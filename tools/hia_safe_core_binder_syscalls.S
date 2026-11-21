/* Linux/x86-64 transport for three sealed borrowed-buffer images.
 * The HIA coordinator supplies each bounded call descriptor and decides
 * which returned bytes form a successful reply. No user-controlled jump. */
.intel_syntax noprefix
.text
.global _start
.set input_limit, 16777504
.set output_limit, 65704
.set output_offset, 16781312
.set work_offset, 16850944
.set work_limit, 5242880
.set work_payload, 4096

_start:
    cmp qword ptr [rsp], 1
    jne .usage
    xor edi, edi
    mov esi, work_offset + work_limit
    mov edx, 3                       /* PROT_READ | PROT_WRITE */
    mov r10d, 0x22                   /* MAP_PRIVATE | MAP_ANONYMOUS */
    mov r8, -1
    xor r9d, r9d
    mov eax, 9
    syscall
    cmp rax, -4095
    jae .io
    mov r12, rax                    /* mapping base */
    xor r13d, r13d                  /* complete stdin byte length */
    lea r14, [r12 + work_offset]
    xor r15d, r15d                  /* application dispatch count */

.read:
    xor eax, eax
    xor edi, edi
    lea rsi, [r12 + r13]
    mov edx, input_limit + 1
    sub rdx, r13
    syscall
    cmp rax, -4
    je .read
    test rax, rax
    js .io
    jz .plan
    add r13, rax
    cmp r13, input_limit
    ja .space
    jmp .read

.plan:
    mov rdi, r12
    mov rsi, r13
    lea rdx, [r12 + output_offset]
    mov ecx, output_limit
    mov r8, r14
    mov r9d, work_limit
    .byte 0xe8
.global binder_call_hole
binder_call_hole:
    .long 0
    cmp rax, 1
    jne .answer
    inc r15
    cmp r15, 14
    ja .invalid

    /* Admit input only in the immutable stdin range or in the owned arena.
     * Admit writable buffers only in the arena, never across its header. */
    mov rdi, [r14 + 16]
    mov rsi, [r14 + 24]
    mov rdx, [r14 + 32]
    mov rcx, [r14 + 40]
    mov r8, [r14 + 48]
    mov r9, [r14 + 56]
    mov rax, rdi
    add rax, rsi
    jc .invalid
    cmp rax, r13
    jbe .output_range
    cmp rdi, work_offset + work_payload
    jb .invalid
    cmp rax, work_offset + work_limit
    ja .invalid
.output_range:
    cmp rdx, work_payload
    jb .invalid
    mov r10, rdx
    add r10, rcx
    jc .invalid
    cmp r10, work_limit
    ja .invalid
    cmp r8, work_payload
    jb .invalid
    mov r11, r8
    add r11, r9
    jc .invalid
    cmp r11, work_limit
    ja .invalid
    cmp r10, r8
    jbe .source_overlap
    cmp r11, rdx
    ja .invalid
.source_overlap:
    cmp rax, r13
    jbe .invoke
    sub rdi, work_offset
    sub rax, work_offset
    cmp rax, rdx
    jbe .scratch_overlap
    cmp rdi, r10
    jb .invalid
.scratch_overlap:
    cmp rax, r8
    jbe .arena_input
    cmp rdi, r11
    jb .invalid
.arena_input:
    add rdi, work_offset
.invoke:
    add rdi, r12
    add rdx, r14
    add r8, r14
    cmp qword ptr [r14 + 8], 1
    je .elf
    cmp qword ptr [r14 + 8], 2
    jne .invalid
    .byte 0xe8
.global wire_call_hole
wire_call_hole:
    .long 0
    jmp .record
.elf:
    .byte 0xe8
.global elf_call_hole
elf_call_hole:
    .long 0
.record:
    cmp rax, [r14 + 40]
    ja .invalid
    mov [r14 + 64], rax
    jmp .plan

.answer:
    cmp rax, 24
    jb .invalid
    cmp rax, output_limit
    ja .invalid
    mov r13, rax
    lea r12, [r12 + output_offset]
.write:
    mov eax, 1
    mov edi, 1
    mov rsi, r12
    mov rdx, r13
    syscall
    cmp rax, -4
    je .write
    test rax, rax
    jle .io
    add r12, rax
    sub r13, rax
    jnz .write
    xor edi, edi
    jmp .exit
.invalid:
    mov edi, 2
    jmp .exit
.space:
    mov edi, 3
    jmp .exit
.io:
    mov edi, 4
    jmp .exit
.usage:
    mov edi, 64
.exit:
    mov eax, 60
    syscall
    ud2
.section .note.GNU-stack,"",@progbits
