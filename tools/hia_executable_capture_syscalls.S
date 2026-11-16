/* Linux x86-64 executable-capture I/O v1; one syscall per admitted entry.
 *
 * Six-argument SysV ABI: request/nrequest, receipt/nreceipt, workspace/nworkspace.
 * The complete input domain is checked before any write or syscall. Refusal
 * returns 0xfffffffd and changes no buffer. A successful transport returns 96.
 * This image has no retries, cleanup policy, filename input, libc, relocations,
 * or business decision. HIA owns all seven-operation sequencing.
 */
.text
.p2align 4
.globl hia_executable_capture_syscalls_entry
.type hia_executable_capture_syscalls_entry,@function
hia_executable_capture_syscalls_entry:
    push %rbx
    push %r12
    push %r13
    push %r14
    push %r15
    mov %rdi,%r12
    mov %rdx,%r13
    mov %r8,%r14
    cmp $96,%rsi
    jb .Lrefuse
    cmp $1048672,%rsi
    ja .Lrefuse
    cmp $96,%rcx
    jne .Lrefuse
    cmp $96,%r9
    jb .Lrefuse
    cmp $1048673,%r9
    ja .Lrefuse
    movabs $0x3152534143584548,%rax
    cmp %rax,0(%r12)
    jne .Lrefuse
    cmpq $1,8(%r12)
    jne .Lrefuse
    mov 16(%r12),%r15
    cmp $1,%r15
    jb .Lrefuse
    cmp $7,%r15
    ja .Lrefuse
    mov 48(%r12),%rax
    or 56(%r12),%rax
    jz .Lrefuse
    cmpq $0,64(%r12)
    je .Lrefuse
    cmpq $0,88(%r12)
    jne .Lrefuse
    xor %ebx,%ebx
.Lzero_header:
    cmpq $0,(%r14,%rbx)
    jne .Lrefuse
    add $8,%rbx
    cmp $96,%rbx
    jne .Lzero_header
    cmp $1,%r15
    je .Lcheck_memfd
    cmpq $0,24(%r12)
    jl .Lrefuse
    cmpq $2147483647,24(%r12)
    ja .Lrefuse
    cmp $2,%r15
    je .Lcheck_write
    cmpq $0,32(%r12)
    jne .Lrefuse
    cmpq $0,80(%r12)
    jne .Lrefuse
    cmp $96,%rsi
    jne .Lrefuse
    cmp $6,%r15
    je .Lcheck_pread
    cmp $96,%r9
    jne .Lrefuse
    cmpq $0,40(%r12)
    jne .Lrefuse
    cmp $3,%r15
    je .Lcheck_chmod
    cmp $4,%r15
    je .Lcheck_add
    cmpq $0,72(%r12)
    jne .Lrefuse
    jmp .Lprepared
.Lcheck_chmod:
    cmpq $320,72(%r12)
    jne .Lrefuse
    jmp .Lprepared
.Lcheck_add:
    cmpq $15,72(%r12)
    jne .Lrefuse
    jmp .Lprepared
.Lcheck_memfd:
    cmpq $-1,24(%r12)
    jne .Lrefuse
    cmpq $0,32(%r12)
    jne .Lrefuse
    cmpq $0,40(%r12)
    jne .Lrefuse
    cmpq $3,72(%r12)
    jne .Lrefuse
    cmpq $0,80(%r12)
    jne .Lrefuse
    cmp $96,%rsi
    jne .Lrefuse
    cmp $96,%r9
    jne .Lrefuse
    jmp .Lprepared
.Lcheck_write:
    cmpq $1048576,32(%r12)
    ja .Lrefuse
    cmpq $1048576,40(%r12)
    ja .Lrefuse
    cmpq $0,72(%r12)
    jne .Lrefuse
    mov 40(%r12),%rax
    cmp %rax,80(%r12)
    jne .Lrefuse
    add $96,%rax
    cmp %rax,%rsi
    jne .Lrefuse
    cmp $96,%r9
    jne .Lrefuse
    jmp .Lprepared
.Lcheck_pread:
    cmpq $1,40(%r12)
    jb .Lrefuse
    cmpq $1048577,40(%r12)
    ja .Lrefuse
    cmpq $0,72(%r12)
    jne .Lrefuse
    mov 40(%r12),%rax
    add $96,%rax
    cmp %rax,%r9
    jne .Lrefuse
.Lprepared:
    /* Persist the actual request before crossing the kernel boundary. */
    mov %r15,8(%r14)
    mov 48(%r12),%rax
    mov %rax,24(%r14)
    mov 56(%r12),%rax
    mov %rax,32(%r14)
    mov 64(%r12),%rax
    mov %rax,40(%r14)
    mov 24(%r12),%rax
    mov %rax,48(%r14)
    mov 32(%r12),%rax
    mov %rax,56(%r14)
    mov 40(%r12),%rax
    mov %rax,64(%r14)
    mov 72(%r12),%rax
    mov %rax,72(%r14)
    movq $1,0(%r14)
    cmp $1,%r15
    je .Lmemfd
    mov 24(%r12),%rdi
    cmp $2,%r15
    je .Lwrite
    cmp $3,%r15
    je .Lchmod
    cmp $4,%r15
    je .Ladd
    cmp $5,%r15
    je .Lget
    cmp $6,%r15
    je .Lpread
    mov $3,%eax
    syscall
    jmp .Lreturned
.Lmemfd:
    lea .Lname(%rip),%rdi
    mov $3,%esi
    mov $319,%eax
    syscall
    jmp .Lreturned
.Lwrite:
    lea 96(%r12),%rsi
    mov 40(%r12),%rdx
    mov $1,%eax
    syscall
    jmp .Lreturned
.Lchmod:
    mov $320,%esi
    mov $91,%eax
    syscall
    jmp .Lreturned
.Ladd:
    mov $1033,%esi
    mov $15,%edx
    mov $72,%eax
    syscall
    jmp .Lreturned
.Lget:
    mov $1034,%esi
    xor %edx,%edx
    mov $72,%eax
    syscall
    jmp .Lreturned
.Lpread:
    lea 96(%r14),%rsi
    mov 40(%r12),%rdx
    xor %r10d,%r10d
    mov $17,%eax
    syscall
.Lreturned:
    mov %rax,16(%r14)
    movabs $0x31524f5343584548,%rbx
    mov %rbx,0(%r13)
    movq $1,8(%r13)
    mov %r15,16(%r13)
    movq $2,24(%r13)
    mov %rax,32(%r13)
    mov 48(%r12),%rbx
    mov %rbx,40(%r13)
    mov 56(%r12),%rbx
    mov %rbx,48(%r13)
    mov 64(%r12),%rbx
    mov %rbx,56(%r13)
    movq $0,64(%r13)
    movq $0,72(%r13)
    movq $0,80(%r13)
    movq $0,88(%r13)
    /* COMPLETE follows the full persisted result and receipt, even on errno. */
    movq $2,0(%r14)
    mov $96,%eax
    jmp .Ldone
.Lrefuse:
    mov $0xfffffffd,%eax
.Ldone:
    pop %r15
    pop %r14
    pop %r13
    pop %r12
    pop %rbx
    ret
.Lname:
    .asciz "hia-selfhost-compiler"
.size hia_executable_capture_syscalls_entry,.-hia_executable_capture_syscalls_entry
.section .note.GNU-stack,"",@progbits
