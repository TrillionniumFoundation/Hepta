.text
.globl hia_future_truth_capsule
.type hia_future_truth_capsule,@function
hia_future_truth_capsule:
    cmpq $65536, %rcx
    jb .Lcleanup
    testq %rdx, %rdx
    jz .Lcleanup
    cmpq $1800, 128(%rdx)
    jae .Ltruth
.Lcleanup:
    .byte 0xe9
.globl hia_future_cleanup_fixed_hole
hia_future_cleanup_fixed_hole:
    .long 0
.Ltruth:
    .byte 0xe9
.globl hia_future_truth_fixed_hole
hia_future_truth_fixed_hole:
    .long 0
.size hia_future_truth_capsule,.-hia_future_truth_capsule
.section .note.GNU-stack,"",@progbits
