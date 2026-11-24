/* Pure SysV/Linux/libc adapter for the HIA allocator witness policy.
 * Allocation decisions, identities, live entries and every counter/event are
 * owned by cold_allocator_witness.hepta. No process-wide interposition exists.
 * A HIA ELF binder maps the private context cell after the ordinary RELRO page.
 */
.text
.macro frame
    push %rbp
    mov %rsp,%rbp
    sub $128,%rsp
.endm
.macro packet operation
    movabs $0x3130574143414948,%rax
    mov %rax,-112(%rbp)
    movq $\operation,-104(%rbp)
    xor %eax,%eax
    mov %rax,-96(%rbp)
    mov %rax,-88(%rbp)
    mov %rax,-80(%rbp)
    mov %rax,-72(%rbp)
    mov %rax,-64(%rbp)
    mov %rax,-56(%rbp)
.endm
.p2align 4
.global hia_test_begin
.type hia_test_begin,@function
hia_test_begin:
    frame
    mov %rdi,-8(%rbp)
    mov %rsi,-16(%rbp)
    mov %rdx,-24(%rbp)
    mov %rcx,-40(%rbp)
    call .Lcontext
    mov %rax,-48(%rbp)
    mov (%rax),%rax
    test %rax,%rax
    jne .Lbegin_have
    xor %edi,%edi
    mov $393280,%esi
    mov $3,%edx
    mov $34,%r10d
    mov $-1,%r8
    xor %r9d,%r9d
    mov $9,%eax
    syscall
    cmp $-4095,%rax
    jae .Labort
    mov -48(%rbp),%rcx
    mov %rax,(%rcx)
.Lbegin_have:
    mov %rax,-32(%rbp)
    mov %rax,%r10
    mov -16(%rbp),%rax
    mov %rax,0(%r10)
    mov -40(%rbp),%rax
    shl $5,%rax
    add $128,%rax
    mov %rax,8(%r10)
    packet 0
    mov -8(%rbp),%rax
    mov %rax,-96(%rbp)
    mov -16(%rbp),%rax
    mov %rax,-88(%rbp)
    mov -24(%rbp),%rax
    mov %rax,-80(%rbp)
    mov -40(%rbp),%rax
    mov %rax,-72(%rbp)
    call .Lpolicy
    test %eax,%eax
    jne .Labort
    leave
    ret
.size hia_test_begin,.-hia_test_begin

.p2align 4
.global hia_witness_calloc
.type hia_witness_calloc,@function
hia_witness_calloc:
    frame
    mov %rdi,-8(%rbp)
    mov %rsi,-16(%rbp)
    call .Lcontext
    mov (%rax),%rax
    mov %rax,-32(%rbp)
    test %rax,%rax
    jne .Lcalloc_tracked
    mov -8(%rbp),%rdi
    mov -16(%rbp),%rsi
    call calloc
    leave
    ret
.Lcalloc_tracked:
    packet 1
    mov -8(%rbp),%rax
    mov %rax,-96(%rbp)
    mov -16(%rbp),%rax
    mov %rax,-88(%rbp)
    call .Lpolicy
    test %eax,%eax
    je .Lcalloc_null
    cmp $1,%eax
    jne .Labort
    mov -8(%rbp),%rdi
    mov -16(%rbp),%rsi
    call calloc
    mov %rax,-24(%rbp)
    packet 3
    movq $1,-96(%rbp)
    mov -32(%rbp),%rax
    mov 24(%rax),%rax
    mov %rax,-88(%rbp)
    mov -24(%rbp),%rax
    mov %rax,-80(%rbp)
    call .Lpolicy
    cmp $1,%eax
    ja .Labort
    mov -24(%rbp),%rax
    leave
    ret
.Lcalloc_null:
    xor %eax,%eax
    leave
    ret
.size hia_witness_calloc,.-hia_witness_calloc

.p2align 4
.global hia_witness_malloc
.type hia_witness_malloc,@function
hia_witness_malloc:
    frame
    mov %rdi,-8(%rbp)
    call .Lcontext
    mov (%rax),%rax
    mov %rax,-32(%rbp)
    test %rax,%rax
    jne .Lmalloc_tracked
    mov -8(%rbp),%rdi
    call malloc
    leave
    ret
.Lmalloc_tracked:
    packet 2
    mov -8(%rbp),%rax
    mov %rax,-96(%rbp)
    call .Lpolicy
    test %eax,%eax
    je .Lmalloc_null
    cmp $1,%eax
    jne .Labort
    mov -8(%rbp),%rdi
    call malloc
    mov %rax,-24(%rbp)
    packet 3
    movq $2,-96(%rbp)
    mov -32(%rbp),%rax
    mov 24(%rax),%rax
    mov %rax,-88(%rbp)
    mov -24(%rbp),%rax
    mov %rax,-80(%rbp)
    call .Lpolicy
    cmp $1,%eax
    ja .Labort
    mov -24(%rbp),%rax
    leave
    ret
.Lmalloc_null:
    xor %eax,%eax
    leave
    ret
.size hia_witness_malloc,.-hia_witness_malloc

.p2align 4
.global hia_witness_free
.type hia_witness_free,@function
hia_witness_free:
    frame
    mov %rdi,-8(%rbp)
    call .Lcontext
    mov (%rax),%rax
    mov %rax,-32(%rbp)
    test %rax,%rax
    jne .Lfree_tracked
    mov -8(%rbp),%rdi
    call free
    leave
    ret
.Lfree_tracked:
    packet 4
    mov -8(%rbp),%rax
    mov %rax,-96(%rbp)
    call .Lpolicy
    test %eax,%eax
    je .Lfree_done
    cmp $1,%eax
    jne .Labort
    mov -8(%rbp),%rdi
    call free
.Lfree_done:
    leave
    ret
.size hia_witness_free,.-hia_witness_free

.Labort:
    call abort
    ud2
.Lpolicy:
    lea -112(%rbp),%rdi
    mov $64,%esi
    mov -32(%rbp),%r8
    mov 0(%r8),%rdx
    mov 8(%r8),%rcx
    mov $393280,%r9d
    jmp .Lkernel
.Lcontext:
    .byte 0x48,0x8d,0x05
.global hia_allocator_context_hole
hia_allocator_context_hole:
    .long 0
    ret
.p2align 4
.global hia_allocator_policy_offset
hia_allocator_policy_offset:
.Lkernel:
.section .note.GNU-stack,"",@progbits
