.text
.globl hia_background_optimizer_report
.type hia_background_optimizer_report,@function
hia_background_optimizer_report:
    push %rbx
    push %rbp
    push %r12
    push %r13
    push %r14
    push %r15
    sub $120,%rsp
    mov %rdi,%r12
    mov %rsi,%r15
    mov %rdx,%r13
    mov %rcx,%rbp
    mov %r8,%r14
    mov %r9,%rbx
    cmp $8192,%rbp
    jb .Lguard_bad
    cmp $32768,%rbx
    jb .Lguard_bad
    test %r13,%r13
    jz .Lguard_bad
    test %r14,%r14
    jz .Lguard_bad
    mov %r13,%rax
    add %rbp,%rax
    jc .Lguard_bad
    mov %rax,96(%rsp)
    mov %r14,%rax
    add %rbx,%rax
    jc .Lguard_bad
    mov %rax,104(%rsp)
    cmp 96(%rsp),%r14
    jae .Lout_work_disjoint
    cmp %r13,%rax
    ja .Lguard_bad
.Lout_work_disjoint:
    mov %r12,%rax
    add %r15,%rax
    jc .Lguard_bad
    mov %rax,88(%rsp)
    test %r15,%r15
    jz .Lviews_ready
    test %r12,%r12
    jz .Lguard_bad
    cmp 96(%rsp),%r12
    jae .Lin_out_disjoint
    cmp %r13,%rax
    ja .Lguard_bad
.Lin_out_disjoint:
    cmp 104(%rsp),%r12
    jae .Lviews_ready
    cmp %r14,%rax
    ja .Lguard_bad
.Lviews_ready:
    mov 8(%r14),%rax
    mov %rax,80(%rsp)
    .byte 0x48,0x8d,0x05
report_value_address_rel32:
    .long 0
    mov %rax,8(%r14)
    movq $0,128(%r13)
    movq $0,0(%rsp)
    mov %r14,8(%rsp)
    mov %r12,16(%rsp)
    mov %r13,24(%rsp)
.Lpolicy:
    mov %r12,%rdi
    mov %r15,%rsi
    mov %r13,%rdx
    mov %rbp,%rcx
    mov %r14,%r8
    mov %rbx,%r9
    .byte 0xe8
report_policy_rel32:
    .long 0
    test %eax,%eax
    jz .Lrestore
    cmp $10,%eax
    je .Lpolicy
    cmp $4,%eax
    jne .Lpolicy_bad
    mov 8(%r13),%r10
    xor %ecx,%ecx
.Larguments:
    mov 16(%r13,%rcx,8),%rax
    mov %r10,%r11
    and $3,%r11d
    add (%rsp,%r11,8),%rax
    mov %rax,32(%rsp,%rcx,8)
    shr $2,%r10
    inc %ecx
    cmp $6,%ecx
    jb .Larguments
    mov 32(%rsp),%rdi
    mov 40(%rsp),%rsi
    mov 48(%rsp),%rdx
    mov 56(%rsp),%rcx
    mov 64(%rsp),%r8
    mov 72(%rsp),%r9
    .byte 0xe8
report_value_rel32:
    .long 0
    mov %rax,136(%r13)
    jmp .Lpolicy
.Lpolicy_bad:
    mov $0xfffffffd,%eax
.Lrestore:
    mov 80(%rsp),%rdx
    mov %rdx,8(%r14)
    jmp .Lout
.Lguard_bad:
    mov $0xfffffffd,%eax
.Lout:
    add $120,%rsp
    pop %r15
    pop %r14
    pop %r13
    pop %r12
    pop %rbp
    pop %rbx
    ret
.size hia_background_optimizer_report,.-hia_background_optimizer_report
.section .note.GNU-stack,"",@progbits
