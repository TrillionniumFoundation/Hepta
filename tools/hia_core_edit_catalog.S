.intel_syntax noprefix
.text
.global _start
.equ CANON_AT,0
.equ CANON_N,16777216
.equ ARENA_AT,16777216
.equ ARENA_N,33554432
.equ RESULT_AT,50331648
.equ RESULT_N,8388608
.equ WORK_AT,58720256
.equ WORK_N,16384
.equ TOTAL_N,58736640
.equ DATA_N,13266
.equ O,4096
.equ S,8192
_start:
 mov rax,[rsp]
 cmp rax,1
 je arguments_ok
 cmp rax,3
 jne usage
arguments_ok:
 mov r13,rsp
 xor edi,edi
 mov esi,TOTAL_N
 mov edx,3
 mov r10d,34
 mov r8,-1
 xor r9d,r9d
 mov eax,9
 syscall
 cmp rax,-4095
 jae io_failure
 mov r12,rax
 lea rbp,[r12+WORK_AT]
 lea rbx,[r12+RESULT_AT]
 mov rax,[r13]
 mov [rbx],rax
 cmp rax,1
 je captured_arguments
 mov rsi,[r13+16]
 lea rdi,[rbx+32]
 mov ecx,63
 call capture_argument
 mov [rbx+8],rax
 mov rsi,[r13+24]
 lea rdi,[rbx+128]
 mov ecx,127
 call capture_argument
 mov [rbx+16],rax
captured_arguments:
 .byte 0x48,0x8d,0x35
data_lea_hole: .long 0
 mov r14,rsi
 mov QWORD PTR [r12+ARENA_AT+48],262144
 mov QWORD PTR [r12+ARENA_AT+56],64
 mov rdi,r14
 mov esi,DATA_N
 lea rdx,[r12+CANON_AT]
 mov ecx,CANON_N
 lea r8,[r12+ARENA_AT]
 mov r9d,ARENA_N
 .byte 0xe8
canonical_call_hole: .long 0
 mov [r12+ARENA_AT+48],rax
 lea rdi,[r12+CANON_AT]
 mov esi,CANON_N
 mov eax,11
 syscall
 test rax,rax
 jnz io_failure
 mov rdi,r14
 mov esi,DATA_N
 lea rdx,[r12+RESULT_AT]
 mov ecx,RESULT_N
 lea r8,[r12+ARENA_AT]
 mov r9d,ARENA_N
 .byte 0xe8
catalog_call_hole: .long 0
 mov [rbp+96],rax
 lea rdi,[r12+ARENA_AT]
 mov esi,ARENA_N
 mov eax,11
 syscall
 test rax,rax
 jnz io_failure
 lea rdi,[r12+RESULT_AT]
 mov esi,RESULT_N
 mov edx,1
 mov eax,10
 syscall
 test rax,rax
 jnz io_failure
pretty_loop:
 lea rdi,[r12+RESULT_AT]
 mov esi,RESULT_N
 lea rdx,[rbp+O]
 mov ecx,128
 mov r8,rbp
 mov r9d,4096
 .byte 0xe8
pretty_call_hole: .long 0
 test rax,rax
 jnz HIA_status
 mov rax,[rbp+80]
 cmp rax,128
 ja io_failure
 mov [rbp+S],rax
 mov QWORD PTR [rbp+S+8],0
 test rax,rax
 jnz write_output
 cmp QWORD PTR [rbp+8],5
 jne io_failure
 jmp completed
write_output:
 mov rax,[rbp+S+8]
 lea rsi,[rbp+O+rax]
 mov rdx,[rbp+S]
 sub rdx,rax
 mov edi,1
 mov eax,1
 syscall
 cmp rax,-4
 je write_output
 test rax,rax
 jle io_failure
 add [rbp+S+8],rax
 mov rax,[rbp+S+8]
 cmp rax,[rbp+S]
 ja io_failure
 jb write_output
 cmp QWORD PTR [rbp+8],5
 jne pretty_loop
completed:
 lea rdi,[r12+RESULT_AT]
 mov esi,RESULT_N
 mov eax,11
 syscall
 test rax,rax
 jnz io_failure
 mov rdi,rbp
 mov esi,WORK_N
 mov eax,11
 syscall
 test rax,rax
 jnz io_failure
 xor edi,edi
 jmp exit_process
capture_argument:
 xor eax,eax
capture_next:
 mov dl,[rsi+rax]
 test dl,dl
 jz capture_done
 cmp rax,rcx
 jae usage
 mov [rdi+rax],dl
 inc rax
 jmp capture_next
capture_done:
 ret
HIA_status:
 cmp rax,255
 ja io_failure
 mov rdi,rax
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
