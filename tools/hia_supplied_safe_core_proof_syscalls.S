/* Fixed Linux descriptor transport for embedded, read-only HIA executables.
 * Calls are restricted to the five packed images and the HIA SHA-256 entry;
 * only the HIA coordinator can construct a report. */
.intel_syntax noprefix
.text
.global _start, proof_policy_hole, proof_hash_hole, embedded_roles
.set input_limit, 25165872
.set input_cap, 25169920
.set output_limit, 2097152
.set work_offset, 27267072
.set work_limit, 1048576

_start:
    cmp qword ptr [rsp], 1
    jne .usage
    xor edi, edi
    mov esi, work_offset + work_limit
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
    mov edx, input_limit + 1
    sub rdx, r13
    syscall
    cmp rax, -4
    je .read
    test rax, rax
    js .io
    jz .freeze
    add r13, rax
    cmp r13, input_limit
    ja .space
    jmp .read
.freeze:
    mov rdi, r12
    mov esi, input_cap
    mov edx, 1
    mov eax, 10
    syscall
    test rax, rax
    js .io
    mov eax, 39
    syscall
    mov [r14 + 320], rax

.plan:
    mov eax, 228
    mov edi, 1
    lea rsi, [r14 + 112]
    syscall
    test rax, rax
    js .io
    mov rdi, r12
    mov rsi, r13
    lea rdx, [r12 + input_cap]
    mov ecx, output_limit
    mov r8, r14
    mov r9d, work_limit
    call .run_policy
    cmp rax, 1
    jne .answer
    inc r15
    cmp r15, 48
    ja .invalid

    mov rsi, [r14 + 16]
    mov rdx, [r14 + 24]
    call .source
    mov rax, [r14 + 32]
    cmp rax, 4096
    jb .invalid
    add rax, [r14 + 40]
    jc .invalid
    cmp rax, work_limit
    ja .invalid

    mov rax, [r14 + 8]
    cmp rax, 7
    je .canonical_hash
    cmp rax, 6
    je .hash
    cmp rax, 1
    jb .invalid
    cmp rax, 5
    ja .invalid
    shl rax, 4
    lea rbx, [rip + .roles]
    mov rdx, [rbx + rax - 8]
    mov rsi, [rbx + rax - 16]
    test rdx, rdx
    jz .invalid
    cmp rdx, 1048576
    ja .invalid
    cmp rsi, 80
    jb .invalid
    add rsi, rbx
    mov [r14 + 344], rsi
    mov [r14 + 352], rdx
    jmp .launch

.run_policy:
    sub rsp, 8
    .byte 0xe8
proof_policy_hole:
    .long 0
    add rsp, 8
    ret

# Only the register proof requests canonical Core identity. The HIA parser
# and SHA use the same frozen input as the other five binding/solver roles.
.canonical_hash:
    mov rbx, rsi
    mov rbp, rdx
    xor edi, edi
    mov esi, 50331648
    mov edx, 3
    mov r10d, 0x22
    mov r8, -1
    xor r9d, r9d
    mov eax, 9
    syscall
    cmp rax, -4095
    jae .io
    mov [r14 + 1056], rax
    mov rdi, rbx
    mov rsi, rbp
    mov rdx, rax
    mov ecx, 16777216
    lea r8, [rax + 16777216]
    mov r9d, 33554432
    call .run_policy
    test rax, rax
    jz .invalid
    cmp rax, rbp
    ja .invalid
    mov rbx, rax
    mov rdi, [r14 + 1056]
    mov esi, 16777216
    mov edx, 1
    mov eax, 10
    syscall
    test rax, rax
    jnz .io
    mov rdi, [r14 + 1056]
    add rdi, 16777216
    mov esi, 33554432
    mov eax, 11
    syscall
    test rax, rax
    jnz .io
    mov rsi, [r14 + 1056]
    mov rdx, rbx
.hash:
    mov rdi, rsi
    mov rsi, rdx
    mov rdx, [r14 + 32]
    add rdx, r14
    mov rcx, [r14 + 40]
    mov r8, [r14 + 48]
    mov r9, [r14 + 56]
    cmp r8, 4096
    jb .invalid
    mov rax, r8
    add rax, r9
    jc .invalid
    cmp rax, work_limit
    ja .invalid
    add r8, r14
    .byte 0xe8
proof_hash_hole:
    .long 0
    cmp rax, [r14 + 40]
    ja .invalid
    mov [r14 + 64], rax
    jmp .plan

.launch:
    mov rsi, [r14 + 48]
    mov rdx, [r14 + 56]
    call .source
    call .memfd
    mov [r14 + 280], eax           /* executable */
    mov edi, eax
    mov rsi, [r14 + 344]
    mov rdx, [r14 + 352]
    call .write_descriptor
    mov edi, [r14 + 280]
    call .seal

    call .memfd
    mov [r14 + 288], eax           /* input */
    mov rsi, [r14 + 16]
    mov rdx, [r14 + 24]
    call .source
    mov edi, [r14 + 288]
    call .write_descriptor
    mov rsi, [r14 + 48]
    mov rdx, [r14 + 56]
    call .source
    mov edi, [r14 + 288]
    call .write_descriptor
    mov edi, [r14 + 288]
    call .seal
    xor esi, esi
    xor edx, edx
    mov eax, 8
    syscall
    test rax, rax
    js .io

    call .memfd
    mov [r14 + 296], eax           /* output */
    mov eax, 57
    syscall
    test rax, rax
    js .io
    jz .child
    mov ebx, eax
.wait:
    mov edi, ebx
    lea rsi, [r14 + 304]
    xor edx, edx
    xor r10d, r10d
    mov eax, 61
    syscall
    cmp rax, -4
    je .wait
    cmp eax, ebx
    jne .io
    cmp dword ptr [r14 + 304], 0
    jne .invalid
    mov edi, [r14 + 296]
    call .seal
    mov eax, 8
    xor esi, esi
    mov edx, 2
    syscall
    test rax, rax
    js .io
    cmp rax, [r14 + 40]
    ja .invalid
    mov [r14 + 64], rax
    xor esi, esi
    xor edx, edx
    mov eax, 8
    syscall
    test rax, rax
    js .io
    mov rsi, [r14 + 32]
    add rsi, r14
    mov rdx, [r14 + 64]
.read_child:
    test rdx, rdx
    jz .close_child
    xor eax, eax
    syscall
    cmp rax, -4
    je .read_child
    test rax, rax
    jle .io
    add rsi, rax
    sub rdx, rax
    jmp .read_child
.close_child:
    mov edi, [r14 + 280]
    call .close
    mov edi, [r14 + 288]
    call .close
    mov edi, [r14 + 296]
    call .close
    jmp .plan

.child:
    mov eax, 157
    mov edi, 1                     /* PR_SET_PDEATHSIG */
    mov esi, 9
    xor edx, edx
    xor r10d, r10d
    xor r8d, r8d
    syscall
    test rax, rax
    js .io
    mov eax, 110
    syscall
    cmp rax, [r14 + 320]
    jne .io
    mov edi, [r14 + 288]
    xor esi, esi
    call .dup
    mov edi, [r14 + 296]
    mov esi, 1
    call .dup
    mov eax, 436                   /* inherited descriptors close on exec */
    mov edi, 3
    mov esi, -1
    mov edx, 4                     /* CLOSE_RANGE_CLOEXEC */
    syscall
    test rax, rax
    js .io
    sub rsp, 32
    lea rax, [rip + .fdname]
    mov [rsp], rax
    mov qword ptr [rsp + 8], 0
    mov qword ptr [rsp + 16], 0
    mov edi, [r14 + 280]
    lea rsi, [rip + .empty]
    mov rdx, rsp
    lea r10, [rsp + 16]
    mov r8d, 4096                  /* AT_EMPTY_PATH */
    mov eax, 322
    syscall
    jmp .io

.source:
    test rdx, rdx
    jz .source_ok
    mov rax, rsi
    add rax, rdx
    jc .invalid
    cmp rax, r13
    jbe .source_ok
    cmp rsi, work_offset + 4096
    jb .invalid
    cmp rax, work_offset + work_limit
    ja .invalid
.source_ok:
    add rsi, r12
    ret

.memfd:
    lea rdi, [rip + .fdname]
    mov esi, 3                     /* CLOEXEC | ALLOW_SEALING */
    mov eax, 319
    syscall
    test rax, rax
    js .io
    cmp rax, 3
    jae .memfd_done
    mov rdi, rax                   /* never reuse a missing stdio descriptor */
    mov esi, 1030                  /* F_DUPFD_CLOEXEC */
    mov edx, 3
    mov eax, 72
    syscall
    test rax, rax
    js .io
    push rax
    call .close
    pop rax
.memfd_done:
    ret
.seal:
    mov eax, 72
    mov esi, 1033                 /* F_ADD_SEALS */
    mov edx, 15                    /* immutable bytes and extent */
    syscall
    test rax, rax
    js .io
    mov eax, 72
    mov esi, 1034                  /* F_GET_SEALS */
    syscall
    cmp eax, 15
    jne .io
    ret
.dup:
    xor edx, edx
    mov eax, 292
    syscall
    test rax, rax
    js .io
    ret
.close:
    mov eax, 3
    syscall
    test rax, rax
    js .io
    ret
.write_descriptor:
    test rdx, rdx
    jz .written_descriptor
    mov eax, 1
    syscall
    cmp rax, -4
    je .write_descriptor
    test rax, rax
    jle .io
    sub rdx, rax
    add rsi, rax
    jmp .write_descriptor
.written_descriptor:
    ret

.answer:
    cmp rax, 464
    jb .invalid
    cmp rax, output_limit
    ja .invalid
    lea rsi, [r12 + input_cap]
    mov rdx, rax
    mov edi, 1
    call .write_descriptor
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
.fdname:
    .asciz "hia-proof-component"
.empty:
    .byte 0
.balign 8
embedded_roles:
.roles:
    .zero 80
.section .note.GNU-stack,"",@progbits
