# Closed allocation adapter for native rank ownership.
# SysV malloc(size)->pointer or NULL, free(owned_pointer)->void.
# No caller-selected callbacks, libc imports or fixed aggregate byte quota.
# Only pointers minted here and retained by the HIA registry may reach free.
.intel_syntax noprefix
.text
.global hia_ndu_context_malloc
.type hia_ndu_context_malloc,@function
hia_ndu_context_malloc:
    push rbx
    mov rbx,rdi
    mov rsi,rdi
    add rsi,32
    jc .Lalloc_fail
    xor edi,edi
    mov edx,3
    mov r10d,34
    mov r8,-1
    xor r9d,r9d
    mov eax,9
    syscall
    cmp rax,-4095
    jae .Lalloc_fail
    mov r10,0x314c414b4e414948
    mov [rax],r10
    lea rcx,[rbx+32]
    mov [rax+8],rcx
    mov [rax+16],rbx
    not rbx
    mov [rax+24],rbx
    add rax,32
    pop rbx
    ret
.Lalloc_fail:
    xor eax,eax
    pop rbx
    ret
.size hia_ndu_context_malloc,.-hia_ndu_context_malloc

.global hia_ndu_context_free
.type hia_ndu_context_free,@function
hia_ndu_context_free:
    test rdi,rdi
    je .Lfree_done
    test dil,15
    jne .Linvalid
    cmp rdi,32
    jb .Linvalid
    sub rdi,32
    mov rax,0x314c414b4e414948
    cmp [rdi],rax
    jne .Linvalid
    mov rsi,[rdi+8]
    mov rdx,[rdi+16]
    mov rcx,rdx
    not rcx
    cmp [rdi+24],rcx
    jne .Linvalid
    add rdx,32
    jc .Linvalid
    cmp rdx,rsi
    jne .Linvalid
    mov eax,11
    syscall
    test rax,rax
    jne .Linvalid
.Lfree_done:
    ret
.Linvalid:
    ud2
.size hia_ndu_context_free,.-hia_ndu_context_free
.section .note.GNU-stack,"",@progbits
