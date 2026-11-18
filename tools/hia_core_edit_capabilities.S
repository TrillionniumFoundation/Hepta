.intel_syntax noprefix
.text
.global _start
_start:
.Lcaps_source:
 cmp QWORD PTR [rsp],1
 jne usage
 xor edi,edi
 mov esi,8192
 mov edx,3
 mov r10d,34
 mov r8,-1
 xor r9d,r9d
 mov eax,9
 syscall
 cmp rax,-4095
 jae io_failure
 mov r12,rax
 lea rdi,[rip+.Lcaps_source]
 xor esi,esi
 mov rdx,r12
 mov ecx,4096
 lea r8,[r12+4096]
 mov r9d,4096
 .byte 0xe8
capabilities_call_hole: .long 0
 test rax,rax
 jz io_failure
 cmp rax,4096
 ja io_failure
 mov r13,rax
 mov rdi,r12
 mov esi,4096
 mov edx,1
 mov eax,10
 syscall
 test rax,rax
 jnz io_failure
 lea rdi,[r12+4096]
 mov esi,4096
 mov eax,11
 syscall
 test rax,rax
 jnz io_failure
 xor r14d,r14d
write_output:
 lea rsi,[r12+r14]
 mov rdx,r13
 sub rdx,r14
 mov edi,1
 mov eax,1
 syscall
 cmp rax,-4
 je write_output
 test rax,rax
 jle io_failure
 add r14,rax
 cmp r14,r13
 ja io_failure
 jb write_output
 mov rdi,r12
 mov esi,4096
 mov eax,11
 syscall
 test rax,rax
 jnz io_failure
 xor edi,edi
 jmp exit_process
usage:
 mov edi,64
 jmp exit_process
io_failure:
 mov edi,4
exit_process:
 mov eax,60
 syscall
 ud2
