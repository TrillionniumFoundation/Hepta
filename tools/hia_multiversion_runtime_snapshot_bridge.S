.intel_syntax noprefix
.text
.global hia_multiversion_runtime_snapshot
.type hia_multiversion_runtime_snapshot,@function
hia_multiversion_runtime_snapshot:
    push r12
    push r13
    push r14
    mov r12,r8
    mov r13,rdi
    add r13,rsi
    jc .Lbad
    mov r14,rdx
    add r14,rcx
    jc .Lbad
    mov r11,r8
    add r11,r9
    jc .Lbad
    test rsi,rsi
    jz .Ls_empty
    test rdi,rdi
    jz .Lbad
.Ls_empty:
    test rcx,rcx
    jz .Lo_empty
    test rdx,rdx
    jz .Lbad
.Lo_empty:
    test r9,r9
    jz .Lw_empty
    test r8,r8
    jz .Lbad
.Lw_empty:
    test rsi,rsi
    jz .Lsw_done
    test rcx,rcx
    jz .Lso_done
    cmp rdi,r14
    jae .Lso_done
    cmp rdx,r13
    jb .Lbad
.Lso_done:
    test r9,r9
    jz .Lsw_done
    cmp rdi,r11
    jae .Lsw_done
    cmp r8,r13
    jb .Lbad
.Lsw_done:
    test rcx,rcx
    jz .Lcall
    test r9,r9
    jz .Lcall
    cmp rdx,r11
    jae .Lcall
    cmp r8,r14
    jb .Lbad
.Lcall:
    call .Lbody
    test eax,eax
    jz .Lok
    cmp eax,0xfffffffe
    je .Lshort
    cmp eax,0xfffffffc
    je .Lwork
.Lbad:
    mov rax,-1
    jmp .Lreturn
.Lshort:
    mov rax,-2
    jmp .Lreturn
.Lwork:
    mov rax,-3
    jmp .Lreturn
.Lok:
    mov rax,QWORD PTR [r12]
.Lreturn:
    pop r14
    pop r13
    pop r12
    ret
.Lbody:
.section .note.GNU-stack,"",@progbits
