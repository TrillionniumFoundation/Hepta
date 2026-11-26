.text
.p2align 4
.globl hia_generation_lease_owner
.type hia_generation_lease_owner,@function
hia_generation_lease_owner:
.Lowner_entry:
    push %rbx
    push %rbp
    push %r12
    push %r13
    push %r14
    push %r15
    sub $8,%rsp
    mov %rdi,%r12
    mov %rsi,%r15
    mov %rdx,%r13
    mov %rcx,%rbp
    mov %r8,%r14
    mov %r9,%rbx
    test %r12,%r12
    jz .Lbad
    test %r13,%r13
    jz .Lbad
    test %r14,%r14
    jz .Lbad
    cmp $64,%r15
    jb .Lbad
    cmp $67108928,%r15
    ja .Lbad
    cmp $100696064,%rbp
    jb .Lbad
    cmp $2048,%rbx
    jne .Lbad
    test $7,%r14b
    jnz .Lbad
    mov %r12,%rax
    add %r15,%rax
    jc .Lbad
    mov %r13,%rdx
    add %rbp,%rdx
    jc .Lbad
    mov %r14,%rcx
    add %rbx,%rcx
    jc .Lbad
    cmp %r13,%rax
    jbe .Lsource_output_ok
    cmp %r12,%rdx
    ja .Lbad
.Lsource_output_ok:
    cmp %r14,%rax
    jbe .Lsource_context_ok
    cmp %r12,%rcx
    ja .Lbad
.Lsource_context_ok:
    cmp %r14,%rdx
    jbe .Loutput_context_ok
    cmp %r13,%rcx
    ja .Lbad
.Loutput_context_ok:
    movq $0,256(%r13)
.Lpolicy:
    mov %r12,%rdi
    mov %r15,%rsi
    mov %r13,%rdx
    mov %rbp,%rcx
    mov %r14,%r8
    mov %rbx,%r9
    .byte 0xe8
.globl owner_policy_hole
owner_policy_hole:
    .long 0
    test %eax,%eax
    jz .Ldone
    cmp $10,%eax
    je .Lpolicy
    cmp $1,%eax
    je .Lpid
    cmp $2,%eax
    je .Llock
    cmp $3,%eax
    je .Lunlock
    cmp $4,%eax
    je .Lfacts
    cmp $12,%eax
    je .Lcarrier
    cmp $13,%eax
    je .Llifecycle
    cmp $14,%eax
    je .Lvalues
    cmp $15,%eax
    je .Lvalues_private
    cmp $16,%eax
    je .Ldup_tool
    cmp $17,%eax
    je .Lclose_tool
    cmp $18,%eax
    je .Lfinalizer_map
    cmp $19,%eax
    je .Lfinalizer_random
    cmp $20,%eax
    je .Lfinalizer_unmap
    cmp $21,%eax
    je .Lvalues_capture
    cmp $22,%eax
    je .Lresource_drop
    cmp $23,%eax
    je .Linfo_copy
    cmp $24,%eax
    je .Linfo_value
    cmp $25,%eax
    je .Linfo_free
    jmp .Lbad
.Lfinalizer_map:
    xor %edi,%edi
    mov $100663296,%esi
    mov $3,%edx
    mov $34,%r10d
    mov $-1,%r8
    xor %r9d,%r9d
    mov $9,%eax
    syscall
    jmp .Lfeedback
.Lfinalizer_random:
    mov 824(%r13),%rax
    lea 832(%r14,%rax),%rdi
    mov $8,%esi
    sub %rax,%rsi
    xor %edx,%edx
    mov $318,%eax
    syscall
    jmp .Lfeedback
.Lfinalizer_unmap:
    mov 800(%r14),%rdi
    mov 808(%r14),%rsi
    mov $11,%eax
    syscall
    jmp .Lfeedback
.Ldup_tool:
    mov 808(%r13),%rdi
    mov $1030,%esi
    mov $3,%edx
    mov $72,%eax
    syscall
    jmp .Lfeedback
.Lclose_tool:
    mov 808(%r13),%rdi
    mov %rdi,%rsi
    xor %edx,%edx
    mov $436,%eax
    syscall
    jmp .Lfeedback
.Lpid:
    mov $39,%eax
    syscall
    jmp .Lfeedback
.Llock:
    xor %eax,%eax
    mov $1,%ecx
    lock cmpxchg %ecx,64(%r14)
    pause
    jmp .Lfeedback
.Lunlock:
    xor %eax,%eax
    xchg %eax,64(%r14)
    xor %eax,%eax
    jmp .Lfeedback
.Lfacts:
    mov %r14,512(%r13)
    lea .Lowner_entry(%rip),%rax
    mov %rax,520(%r13)
    .byte 0x48,0x8d,0x05
.globl owner_carrier_address_hole
owner_carrier_address_hole:
    .long 0
    mov %rax,528(%r13)
    .byte 0x48,0x8d,0x05
.globl owner_values_address_hole
owner_values_address_hole:
    .long 0
    mov %rax,536(%r13)
    .byte 0x48,0x8d,0x05
.globl owner_finalizer_address_hole
owner_finalizer_address_hole:
    .long 0
    mov %rax,544(%r13)
    xor %eax,%eax
    jmp .Lfeedback
.Lcarrier:
    lea 64(%r12),%rdi
    mov 16(%r12),%rsi
    cmpq $0,560(%r13)
    je .Lcarrier_source_ready
    lea 4096(%r13),%rdi
    mov $128,%esi
    cmpq $2,560(%r13)
    jne .Lcarrier_source_ready
    lea 4352(%r13),%rdi
    mov 568(%r13),%rsi
.Lcarrier_source_ready:
    lea 16384(%r13),%rdx
    mov $100663296,%ecx
    lea 256(%r14),%r8
    mov $256,%r9d
    .byte 0xe8
.globl owner_carrier_call_hole
owner_carrier_call_hole:
    .long 0
    jmp .Lfeedback
.Llifecycle:
    lea 64(%r12),%rdi
    mov $64,%esi
    lea 16384(%r13),%rdx
    mov $100679680,%ecx
    lea 128(%r14),%r8
    mov $128,%r9d
    .byte 0xe8
.globl owner_lifecycle_call_hole
owner_lifecycle_call_hole:
    .long 0
    jmp .Lfeedback
.Lvalues:
    lea 64(%r12),%rdi
    mov 16(%r12),%rsi
    cmpq $0,560(%r13)
    je .Lvalues_source_ready
    lea 4096(%r13),%rdi
    mov $128,%esi
.Lvalues_source_ready:
    lea 16384(%r13),%rdx
    mov $100663296,%ecx
    lea 512(%r14),%r8
    mov $256,%r9d
    jmp .Lvalues_invoke
.Lvalues_capture:
    lea 4096(%r13),%rdi
    mov $152,%esi
    lea 16384(%r13),%rdx
    mov $100663296,%ecx
    lea 512(%r14),%r8
    mov $256,%r9d
    jmp .Lvalues_invoke
.Lresource_drop:
    lea 4096(%r13),%rdi
    mov $128,%esi
    lea 8192(%r13),%rdx
    mov $128,%ecx
    lea 768(%r14),%r8
    mov $256,%r9d
    .byte 0xe8
.globl owner_finalizer_call_hole
owner_finalizer_call_hole:
    .long 0
    jmp .Lfeedback
.Linfo_copy:
    mov 1104(%r13),%rsi
    lea 32896(%r13),%rdi
    mov 1112(%r13),%rcx
    cld
    rep movsb
    xor %eax,%eax
    jmp .Lfeedback
.Linfo_value:
    lea 32768(%r13),%rdi
    mov 1112(%r13),%rsi
    add $128,%rsi
    lea 16384(%r13),%rdx
    mov $16384,%ecx
    lea 512(%r14),%r8
    mov $256,%r9d
    jmp .Lvalues_invoke
.Linfo_free:
    mov 1104(%r13),%rdi
    call free
    xor %eax,%eax
    jmp .Lfeedback
.Lvalues_private:
    lea 4096(%r13),%rdi
    mov $128,%esi
    lea 8192(%r13),%rdx
    mov $8192,%ecx
    lea 512(%r14),%r8
    mov $256,%r9d
.Lvalues_invoke:
    .byte 0xe8
.globl owner_values_call_hole
owner_values_call_hole:
    .long 0
    jmp .Lfeedback
.Lfeedback:
    mov %rax,384(%r13)
    jmp .Lpolicy
.Lbad:
    mov $0xfffffffd,%eax
.Ldone:
    add $8,%rsp
    pop %r15
    pop %r14
    pop %r13
    pop %r12
    pop %rbp
    pop %rbx
    ret
    .p2align 4
.size hia_generation_lease_owner,.-hia_generation_lease_owner
.section .note.GNU-stack,"",@progbits
