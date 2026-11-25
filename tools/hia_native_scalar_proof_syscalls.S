/* Fixed span and descriptor transport for the native HIA scalar proof owner.
 * This adapter makes no admission, solver, replay or proof-claim decision. */
.intel_syntax noprefix
.text
.global _start, proof_policy_hole, embedded_roles
.set input_max, 16777408
.set input_cap, 17825792
.set output_cap, 262144
.set work_offset, 18087936
.set work_cap, 805306368
.set mapping_cap, 823394304
_start:
.image_anchor:
    cmp qword ptr [rsp], 1
    jne .usage
    xor edi, edi
    mov esi, mapping_cap
    mov edx, 3
    mov r10d, 0x22
    mov r8, -1
    xor r9d, r9d
    mov eax, 9
    syscall
    cmp rax, -4095
    jae .io
    mov r12, rax
    xor r13d, r13d
    lea r14, [r12 + work_offset]
    xor r15d, r15d
.read:
    xor eax, eax
    xor edi, edi
    lea rsi, [r12 + r13]
    mov edx, input_max + 1
    sub rdx, r13
    syscall
    cmp rax, -4
    je .read
    test rax, rax
    js .io
    jz .freeze
    add r13, rax
    cmp r13, input_max
    ja .space
    jmp .read
.freeze:
    mov rdi, r12
    mov esi, input_cap
    mov edx, 1
    mov eax, 10
    syscall
    test rax, rax
    jnz .io
    lea rbx, [rip + .image_anchor - 176]
    mov rax, [rbx + 96]
    cmp rax, 8388608
    ja .invalid
    cmp rax, 176
    jb .invalid
    mov [r14 + 96], rax
    mov qword ptr [r14 + 112], 9
.plan:
    mov eax, 228
    mov edi, 1
    lea rsi, [r14 + 80]
    syscall
    test rax, rax
    jnz .io
    mov rdi, r12
    mov rsi, r13
    lea rdx, [r12 + input_cap]
    mov ecx, output_cap
    mov r8, r14
    mov r9d, work_cap
    call .run_policy
    mov eax, eax
    cmp rax, 1
    jne .answer
    inc r15
    jz .invalid
    mov rax, [r14 + 8]
    cmp rax, 1
    jb .invalid
    cmp rax, 8
    ja .invalid
    shl rax, 4
    lea rbp, [rip + .role_table]
    add rax, rbp
    mov r11, [rax]
    mov rax, [rax + 8]
    test rax, rax
    jz .invalid
    cmp rax, 1048576
    ja .invalid
    add r11, rbp
    mov [r14 + 120], r11
    mov rax, [r14 + 40]
    cmp rax, 1024
    jb .invalid
    add rax, [r14 + 48]
    jc .invalid
    cmp rax, work_cap
    ja .invalid
    mov rax, [r14 + 56]
    cmp rax, 1024
    jb .invalid
    add rax, [r14 + 64]
    jc .invalid
    cmp rax, work_cap
    ja .invalid
    mov rax, [r14 + 16]
    xor edx, edx
    cmp rax, 0
    je .input_source
    cmp rax, 1
    je .work_source
    cmp rax, 2
    jne .invalid
    mov rdi, rbx
    mov rdx, [r14 + 96]
    jmp .source_range
.input_source:
    mov rdi, r12
    mov rdx, r13
    jmp .source_range
.work_source:
    mov rdi, r14
    mov edx, work_cap
.source_range:
    mov rax, [r14 + 24]
    cmp rax, rdx
    ja .invalid
    sub rdx, rax
    mov rsi, [r14 + 32]
    cmp rsi, rdx
    ja .invalid
    add rdi, rax
    mov rdx, [r14 + 40]
    add rdx, r14
    mov rcx, [r14 + 48]
    mov r8, [r14 + 56]
    add r8, r14
    mov r9, [r14 + 64]
    call qword ptr [r14 + 120]
    mov eax, eax
    mov [r14 + 72], rax
    mov qword ptr [r14 + 104], 0
    jmp .plan
.run_policy:
    sub rsp, 8
    .byte 0xe8
proof_policy_hole:
    .long 0
    add rsp, 8
    ret
.answer:
    cmp rax, 64
    jb .invalid
    cmp rax, output_cap
    ja .invalid
    lea rsi, [r12 + input_cap]
    mov rdx, rax
.write:
    test rdx, rdx
    jz .done
    mov eax, 1
    mov edi, 1
    syscall
    cmp rax, -4
    je .write
    test rax, rax
    jle .io
    add rsi, rax
    sub rdx, rax
    jmp .write
.done:
    xor edi, edi
    jmp .exit
.invalid:
    mov edi, 65
    jmp .exit
.space:
    mov edi, 3
    jmp .exit
.io:
    mov edi, 74
    jmp .exit
.usage:
    mov edi, 64
.exit:
    mov eax, 60
    syscall
    ud2
.balign 8
embedded_roles:
.role_table:
    .zero 144
.section .note.GNU-stack,"",@progbits
