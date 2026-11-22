/* Match only the fixed POSIX entry ABI. The selected HIA image owns all
 * admission, request identity, paging, Store transitions and publication.
 */
.intel_syntax noprefix
.text
.global _start, read_main_hole, read_store_hole, read_cost_hole, read_external_hole

_start:
 cmp QWORD PTR [rsp], 2
 jb .Lexternal
 mov rsi, [rsp+16]
 lea rdi, [rip+.Lmain_mode]
 call .Lmatches
 test eax, eax
 jnz .Lmain
 mov rsi, [rsp+16]
 lea rdi, [rip+.Lstore_mode]
 call .Lmatches
 test eax, eax
 jnz .Lstore
 mov rsi, [rsp+16]
 lea rdi, [rip+.Lcost_mode]
 call .Lmatches
 test eax, eax
 jnz .Lcost

.Lexternal:
 .byte 0xe9
read_external_hole: .long 0
.Lmain:
 .byte 0xe9
read_main_hole: .long 0
.Lstore:
 .byte 0xe9
read_store_hole: .long 0
.Lcost:
 .byte 0xe9
read_cost_hole: .long 0

.Lmatches:
 mov al, BYTE PTR [rsi]
 cmp al, BYTE PTR [rdi]
 jne .Ldifferent
 test al, al
 je .Lsame
 inc rsi
 inc rdi
 jmp .Lmatches
.Ldifferent:
 xor eax, eax
 ret
.Lsame:
 mov eax, 1
 ret

.Lmain_mode: .asciz "--worker-read"
.Lstore_mode: .asciz "--own-store"
.Lcost_mode: .asciz "--own-cost"
.section .note.GNU-stack,"",@progbits
