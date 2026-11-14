/* Independent GNU assembler oracle for the HIA-produced fixed mechanism.
 * Not a production image build input. SysV AMD64, entry at offset zero.
 * Runtime dependencies remain the four pinned CPython API addresses. */
.intel_syntax noprefix
.section .text.entry,"ax",@progbits
.globl hia_cpython_note
.hidden hia_cpython_note
.type hia_cpython_note,@function
hia_cpython_note:
    test rdi, rdi
    jz invalid
    test rsi, rsi
    jz invalid
    cmp rdx, 1
    jb invalid
    cmp rdx, 4
    ja invalid
    cmp rdx, 2
    jne non_index
    test r9, r9
    js invalid
    jmp valid
non_index:
    test r9, r9
    jnz invalid
    cmp rdx, 4
    jne valid
    test rcx, rcx
    jnz invalid
    test r8, r8
    jnz invalid
valid:
    push rbp
    push rbx
    push r12
    push r13
    push r14
    push r15
    sub rsp, 8
    mov rbp, r9
    mov rbx, rdx
    mov r12, rdi
    mov r13, rsi
    mov r14, rcx
    mov r15, r8
    mov rdi, r13
    call QWORD PTR [r12]
    mov rdi, r13
    call QWORD PTR [r12 + 8]
    cmp ebx, 4
    je deliver
    mov rsi, r14
    cmp ebx, 1
    je dictionary
    cmp ebx, 2
    je sequence
    lea rdi, [rip + object_format]
    jmp format
dictionary:
    mov rdx, r15
    lea rdi, [rip + dictionary_format]
    jmp format
sequence:
    mov rdx, rbp
    lea rdi, [rip + sequence_format]
format:
    xor eax, eax
    call QWORD PTR [r12 + 24]
    call QWORD PTR [r12 + 16]
    jmp done
deliver:
    xor eax, eax
done:
    add rsp, 8
    pop r15
    pop r14
    pop r13
    pop r12
    pop rbx
    pop rbp
    ret
invalid:
    xor eax, eax
    ret
.size hia_cpython_note, .-hia_cpython_note
dictionary_format:
    .asciz "when serializing %T item %R"
sequence_format:
    .asciz "when serializing %T item %zd"
object_format:
    .asciz "when serializing %T object"
.section .note.GNU-stack,"",@progbits
