# Six-word mechanical view guard for the closed owned-payload provider.
.intel_syntax noprefix
.text
.global hia_ndu_context_payload_guard
hia_ndu_context_payload_guard:
    test rdi,rdi
    je .Lbad
    test rdx,rdx
    je .Lbad
    test r8,r8
    je .Lbad
    cmp rsi,128
    jb .Lbad
    cmp rcx,512
    jb .Lbad
    cmp r9,256
    jb .Lbad
    mov rax,rdi
    add rax,rsi
    jc .Lbad
    mov r10,rdx
    add r10,rcx
    jc .Lbad
    mov r11,r8
    add r11,r9
    jc .Lbad
    cmp rdi,r10
    jae .Lso
    cmp rdx,rax
    jb .Lbad
.Lso:
    cmp rdi,r11
    jae .Lsw
    cmp r8,rax
    jb .Lbad
.Lsw:
    cmp rdx,r11
    jae .Low
    cmp r8,r10
    jb .Lbad
.Low:
    jmp .Lgood
.Lbad:
    mov eax,0xfffffffd
    ret
.Lgood:
.section .note.GNU-stack,"",@progbits
