/* Exact framed stdin intake: 1 complete, 0 clean EOF, -1 I/O, -2 short. */
.intel_syntax noprefix
.text
.global component_read_exact
.type component_read_exact,@function
component_read_exact:
 xor r8d,r8d
read_more:
 test rdx,rdx
 jz complete
 xor eax,eax
 xor edi,edi
 syscall
 cmp rax,-4
 je read_more
 test rax,rax
 js io_error
 jz read_eof
 add r8,rax
 add rsi,rax
 sub rdx,rax
 jmp read_more
read_eof:
 test r8,r8
 jz read_done
 mov eax,-2
 ret
io_error:
 mov eax,-1
 ret
complete:
 mov eax,1
read_done:
 ret
.size component_read_exact,.-component_read_exact
.section .note.GNU-stack,"",@progbits
