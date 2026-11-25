.text
.globl hia_native_path_value
.type hia_native_path_value,@function
hia_native_path_value:
    push %rbx
    push %rbp
    push %r12
    push %r13
    push %r14
    push %r15
    sub $152,%rsp
    mov %rdi,%r12
    mov %rsi,%r15
    mov %rdx,%r13
    mov %rcx,%rbp
    mov %r8,%r14
    mov %r9,%rbx
    cmp $32768,%rbp
    jb .Lbad
    cmp $4096,%rbx
    jb .Lbad
    test %r13,%r13
    jz .Lbad
    test %r14,%r14
    jz .Lbad
    mov %r13,%rax
    add %rbp,%rax
    jc .Lbad
    mov %rax,104(%rsp)
    mov %r14,%rax
    add %rbx,%rax
    jc .Lbad
    mov %rax,112(%rsp)
    cmp 104(%rsp),%r14
    jae .Lsw
    cmp %r13,%rax
    ja .Lbad
.Lsw:
    mov %r12,%rax
    add %r15,%rax
    jc .Lbad
    mov %rax,96(%rsp)
    test %r15,%r15
    jz .Lviews_ok
    test %r12,%r12
    jz .Lbad
    cmp 104(%rsp),%r12
    jae .Lsw2
    cmp %r13,%rax
    ja .Lbad
.Lsw2:
    cmp 112(%rsp),%r12
    jae .Lviews_ok
    cmp %r14,%rax
    ja .Lbad
.Lviews_ok:
    movq $0,256(%r13)
    movq $0,0(%rsp)
    mov %r14,8(%rsp)
    mov %r12,16(%rsp)
    mov %r13,24(%rsp)
.Lloop:
    mov %r12,%rdi
    mov %r15,%rsi
    mov %r13,%rdx
    mov %rbp,%rcx
    mov %r14,%r8
    mov %rbx,%r9
    call native_path_policy
    test %eax,%eax
    jz .Lreturn
    cmp $10,%eax
    je .Lloop
    cmp $2,%eax
    je .Lcas
    cmp $3,%eax
    je .Lswap
    cmp $8,%eax
    je .Lcopy
    cmp $1,%eax
    je .Largs
    cmp $9,%eax
    je .Largs
    cmp $11,%eax
    jne .Lreturn
.Largs:
    mov %rax,88(%rsp)
    mov 136(%r13),%r10
    xor %ecx,%ecx
.Larg:
    mov 144(%r13,%rcx,8),%rax
    mov %r10,%r11
    and $3,%r11d
    add (%rsp,%r11,8),%rax
    jc .Lbad
    mov %rax,32(%rsp,%rcx,8)
    shr $2,%r10
    inc %ecx
    cmp $6,%ecx
    jb .Larg
    test %r10,%r10
    jnz .Lbad
    mov 32(%rsp),%rdi
    mov 40(%rsp),%rsi
    mov 48(%rsp),%rdx
    mov 56(%rsp),%rcx
    mov 64(%rsp),%r8
    mov 72(%rsp),%r9
    cmpq $1,88(%rsp)
    je .Lsyscall
    cmpq $11,88(%rsp)
    je .Lformatter
    call *128(%r13)
    jmp .Lfeedback
.Lsyscall:
    mov %rcx,%r10
    mov 128(%r13),%rax
    syscall
    jmp .Lfeedback
.Lformatter:
    call native_path_error
    jmp .Lfeedback
.Lcas:
    mov 128(%r13),%r10
    test $7,%r10b
    jnz .Lbad
    mov %rbx,%r11
    sub $8,%r11
    cmp %r11,%r10
    ja .Lbad
    add %r14,%r10
    mov 136(%r13),%rax
    mov 144(%r13),%rdx
    lock cmpxchg %rdx,(%r10)
    jmp .Lfeedback
.Lswap:
    mov 128(%r13),%r10
    test $7,%r10b
    jnz .Lbad
    mov %rbx,%r11
    sub $8,%r11
    cmp %r11,%r10
    ja .Lbad
    add %r14,%r10
    mov 144(%r13),%rax
    xchg %rax,(%r10)
    jmp .Lfeedback
.Lcopy:
    mov 128(%r13),%r10
    cmp $3,%r10
    ja .Lbad
    mov 136(%r13),%rsi
    add (%rsp,%r10,8),%rsi
    jc .Lbad
    mov 144(%r13),%r10
    cmp $3,%r10
    ja .Lbad
    mov 152(%r13),%rdi
    add (%rsp,%r10,8),%rdi
    jc .Lbad
    mov 160(%r13),%rcx
    mov %rsi,%rax
    add %rcx,%rax
    jc .Lbad
    mov %rdi,%rax
    add %rcx,%rax
    jc .Lbad
    cld
    rep movsb
    xor %eax,%eax
.Lfeedback:
    mov %rax,3840(%r13)
    jmp .Lloop
.Lbad:
    mov $0xfffffffd,%eax
.Lreturn:
    add $152,%rsp
    pop %r15
    pop %r14
    pop %r13
    pop %r12
    pop %rbp
    pop %rbx
    ret
.size hia_native_path_value,.-hia_native_path_value
.section .note.GNU-stack,"",@progbits
