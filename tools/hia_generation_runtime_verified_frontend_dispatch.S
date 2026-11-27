.intel_syntax noprefix
.text
.global hia_generation_runtime_verify_dispatch
hia_generation_runtime_verify_dispatch:
    test rdi,rdi
    jz .Lverify
    cmp rsi,8
    jb .Lverify
    movabs rax,0x3151585452414948
    cmp qword ptr [rdi],rax
    jne .Lverify
    .byte 0xe9
exception_hole:
    .long 0
.Lverify:
    .byte 0xe9
verify_hole:
    .long 0
.section .note.GNU-stack,"",@progbits
