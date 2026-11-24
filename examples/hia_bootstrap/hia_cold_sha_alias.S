/* Mechanical six-word view admission only.  Hash semantics remain in HIA.
 * All empty ranges, overflowing endpoints and any pairwise overlap use the
 * original entry.  Argument registers and the caller stack are untouched. */
.intel_syntax noprefix
.text
.globl hia_cold_sha_alias_start
.globl hia_cold_sha_alias_old_hole
.globl hia_cold_sha_alias_fast_hole
hia_cold_sha_alias_start:
    test rsi, rsi
    jz .Lold
    test rcx, rcx
    jz .Lold
    test r9, r9
    jz .Lold
    mov r10, rdi
    add r10, rsi
    jc .Lold
    mov r11, rdx
    add r11, rcx
    jc .Lold
    cmp r10, rdx
    jbe .Lsource_output_disjoint
    cmp r11, rdi
    jbe .Lsource_output_disjoint
    jmp .Lold
.Lsource_output_disjoint:
    mov r11, r8
    add r11, r9
    jc .Lold
    cmp r10, r8
    jbe .Lsource_state_disjoint
    cmp r11, rdi
    jbe .Lsource_state_disjoint
    jmp .Lold
.Lsource_state_disjoint:
    mov r10, rdx
    add r10, rcx
    cmp r10, r8
    jbe .Lfast
    cmp r11, rdx
    jbe .Lfast
.Lold:
    .byte 0xe9
hia_cold_sha_alias_old_hole:
    .long 0
.Lfast:
    .byte 0xe9
hia_cold_sha_alias_fast_hole:
    .long 0
