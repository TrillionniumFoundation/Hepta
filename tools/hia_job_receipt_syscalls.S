/* Linux x86-64 adapter for job_receipt.hepta.
 * fd 0: sealed input; fd 1: job registry directory; fd 2: result receipt.
 * HIA constructs the names and selects each effect from its prior result.
 */
.intel_syntax noprefix
.text
.global _start
_start:
 xor ebp,ebp
 and rsp,-16
 sub rsp,544
 mov rbp,rsp
 /* Put the descriptor observation and HIA state after the stat buffer. */
 lea rdi,[rbp+144]
 xor eax,eax
 mov ecx,50
 rep stosq
 mov edi,1
 mov esi,9
 xor edx,edx
 xor r10d,r10d
 xor r8d,r8d
 mov eax,157
 syscall
 test rax,rax
 js refusal
 mov eax,110
 syscall
 mov [rbp+160],rax
 xor edi,edi
 mov esi,1034
 mov eax,72
 syscall
 test rax,rax
 js refusal
 and eax,15
 cmp eax,15
 jne refusal
 xor edi,edi
 mov rsi,rbp
 mov eax,5
 syscall
 test rax,rax
 js refusal
 mov r13,[rbp+48]
 cmp r13,35
 jb refusal
 cmp r13,4194464
 ja refusal
 xor edi,edi
 mov rsi,r13
 mov edx,1
 mov r10d,2
 xor r8d,r8d
 xor r9d,r9d
 mov eax,9
 syscall
 test rax,rax
 js refusal
 mov r12,rax
next:
 mov rdi,r12
 mov rsi,r13
 lea rdx,[rbp+192]
 mov ecx,352
 lea r8,[rbp+144]
 mov r9d,48
 .byte 0xe8
policy_call_hole:
 .long 0
 cmp eax,1
 je stage
 cmp eax,2
 je write_record
 cmp eax,3
 je sync_file
 cmp eax,4
 je close_file
 cmp eax,5
 je publish
 cmp eax,6
 je sync_directory
 cmp eax,7
 je emit
 cmp eax,8
 je close_checked
 jmp refusal

stage:
 mov edi,1
 lea rsi,[rbp+384]
 mov edx,0xa00c1
 mov r10d,384
 mov eax,257
 syscall
 mov r14,rax
 jmp observed

write_record:
 mov rbx,[rbp+216]
write_next:
 mov rdx,r13
 sub rdx,rbx
 jz write_complete
 mov rdi,r14
 lea rsi,[r12+rbx]
 mov eax,1
 syscall
 cmp rax,-4
 je write_next
 test rax,rax
 js observed
 jz short_write
 add rbx,rax
 jmp write_next
write_complete:
 xor eax,eax
 jmp observed
short_write:
 mov rax,-5
 jmp observed

sync_file:
 mov rdi,r14
 mov eax,74
 syscall
 cmp rax,-4
 je sync_file
 jmp observed

close_file:
 mov rdi,r14
 mov eax,3
 syscall
 /* The original owner closes only after fsync, and does not retry close. */
 xor eax,eax
 jmp observed

close_checked:
 mov rdi,r14
 mov eax,3
 syscall
 jmp observed

publish:
 mov edi,1
 lea rsi,[rbp+384]
 mov edx,1
 lea r10,[rbp+224]
 mov eax,264
 syscall
 jmp observed

sync_directory:
 mov edi,1
 mov eax,74
 syscall
 cmp rax,-4
 je sync_directory

observed:
 mov [rbp+152],rax
 jmp next

emit:
 lea rbx,[rbp+192]
 lea r15,[rbx+24]
emit_next:
 mov edi,2
 mov rsi,rbx
 mov rdx,r15
 sub rdx,rbx
 jz success
 mov eax,1
 syscall
 cmp rax,-4
 je emit_next
 test rax,rax
 jle refusal
 add rbx,rax
 jmp emit_next

success:
 xor edi,edi
 jmp exit
refusal:
 mov edi,65
exit:
 mov eax,231
 syscall
 ud2
