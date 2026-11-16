/* Candidate fixed descriptor ABI; no root, traversal, publication or retry policy.
 * SysV entry: request, request_bytes, output, output_bytes, state, state_bytes.
 * See docs/HIA_STORE_FILE_CAPTURE_DESCRIPTOR_ABI.md for exact layouts.
 * This source has NOT been assembled, mapped or executed in the static package.
 */
.text
.global hia_capture_descriptor_entry
.type hia_capture_descriptor_entry,@function
hia_capture_descriptor_entry:
    cmp $64, %rsi
    jb .invalid
    cmp $64, %rcx
    jne .invalid
    cmp $64, %r9
    jb .invalid
    movabs $0x3151504143464948, %rax
    cmp %rax, 0(%rdi)
    jne .invalid
    mov 8(%rdi), %rax
    cmp $1, %rax
    jb .invalid
    cmp $4, %rax
    ja .invalid
    mov 48(%rdi), %r10
    or 56(%rdi), %r10
    jz .invalid
    mov 0(%r8), %r10
    or 8(%r8), %r10
    or 16(%r8), %r10
    or 24(%r8), %r10
    or 32(%r8), %r10
    or 40(%r8), %r10
    or 48(%r8), %r10
    or 56(%r8), %r10
    jnz .invalid
    cmp $1, %rax
    je .check_open
    cmp $64, %rsi
    jne .invalid
    cmpq $0, 32(%rdi)
    jne .invalid
    cmpq $0, 40(%rdi)
    jne .invalid
    cmp $3, %rax
    je .check_read
    cmpq $0, 24(%rdi)
    jne .invalid
    cmp $2, %rax
    je .check_stat
    cmp $64, %r9
    jne .invalid
    jmp .admitted
.check_stat:
    cmp $208, %r9
    jne .invalid
    jmp .admitted
.check_read:
    mov %r9, %r10
    sub $64, %r10
    cmp 24(%rdi), %r10
    jne .invalid
    test %r10, %r10
    js .invalid
    jmp .admitted
.check_open:
    cmp $64, %r9
    jne .invalid
    cmp $65, %rsi
    jb .invalid
    mov %rsi, %r10
    sub $64, %r10
    cmp 40(%rdi), %r10
    jne .invalid
    cmpb $0, -1(%rdi,%rsi,1)
    jne .invalid
    mov $64, %r10
.open_path_loop:
    lea 1(%r10), %r11
    cmp %rsi, %r11
    je .admitted
    cmpb $0, (%rdi,%r10,1)
    je .invalid
    inc %r10
    jmp .open_path_loop
.admitted:
    push %rbx
    push %r12
    push %r13
    push %r14
    push %r15
    mov %rdi, %rbx
    mov %rdx, %r12
    mov %r8, %r13
    mov %r9, %r14
    mov 8(%rbx), %r15
    mov %r15, 8(%r13)
    mov 48(%rbx), %rax
    mov %rax, 24(%r13)
    mov 56(%rbx), %rax
    mov %rax, 32(%r13)
    /* All admission and stores above precede the actual syscall cutpoint. */
    movq $1, 0(%r13)
    cmp $1, %r15
    je .openat
    cmp $2, %r15
    je .fstat
    cmp $3, %r15
    je .read
    mov 16(%rbx), %rdi
    mov $3, %eax
    syscall
    jmp .returned
.openat:
    mov 16(%rbx), %rdi
    lea 64(%rbx), %rsi
    mov 24(%rbx), %rdx
    mov 32(%rbx), %r10
    mov $257, %eax
    syscall
    jmp .returned
.fstat:
    mov 16(%rbx), %rdi
    lea 64(%r13), %rsi
    mov $5, %eax
    syscall
    jmp .returned
.read:
    mov 16(%rbx), %rdi
    lea 64(%r13), %rsi
    mov 24(%rbx), %rdx
    xor %eax, %eax
    syscall
.returned:
    /* Persist the actual signed kernel outcome before resuming Python. */
    mov %rax, 16(%r13)
    movq $2, 0(%r13)
    movabs $0x3152504143464948, %r10
    mov %r10, 0(%r12)
    movq $0, 8(%r12)
    mov %r15, 16(%r12)
    movq $2, 24(%r12)
    mov %rax, 32(%r12)
    mov 24(%r13), %r10
    mov %r10, 40(%r12)
    mov 32(%r13), %r10
    mov %r10, 48(%r12)
    movq $0, 56(%r12)
    mov $64, %eax
    pop %r15
    pop %r14
    pop %r13
    pop %r12
    pop %rbx
    ret
.invalid:
    mov $0xfffffffd, %eax
    ret
.size hia_capture_descriptor_entry, .-hia_capture_descriptor_entry
.section .note.GNU-stack,"",@progbits
