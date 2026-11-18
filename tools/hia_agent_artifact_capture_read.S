/* Linux read transport: consume this descriptor up to the admitted extent. */
.intel_syntax noprefix
.text
.global capture_read_to_limit
.type capture_read_to_limit,@function
capture_read_to_limit:
 xor r8d,r8d
read_next:
 test rdx,rdx
 jz read_complete
 xor eax,eax
 syscall
 cmp rax,-4
 je read_next
 test rax,rax
 js read_failed
 jz read_complete
 add r8,rax
 add rsi,rax
 sub rdx,rax
 jmp read_next
read_complete:
 mov rax,r8
read_failed:
 ret
.size capture_read_to_limit,.-capture_read_to_limit
.section .note.GNU-stack,"",@progbits
