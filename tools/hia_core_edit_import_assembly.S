.intel_syntax noprefix
.text
.global _start
.equ INPUT_N,1048576
.equ INPUT_EXTENT,1052672
.equ JSON_AT,1052672
.equ JSON_N,16777216
.equ CANON_AT,17829888
.equ CANON_N,16777216
.equ ARENA_AT,34607104
.equ ARENA_N,33554432
.equ SCRATCH_AT,68161536
.equ SCRATCH_N,16384
.equ CORE_AT,68177920
.equ CORE_N,67108864
.equ TOTAL_N,135286784
.equ O,4096
.equ S,8192
_start:
 cmp QWORD PTR [rsp],1
 jne usage
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
 lea rbp,[r12+SCRATCH_AT]
read_input:
 xor edi,edi
 mov rax,[rbp+S]
 lea rsi,[r12+rax]
 mov edx,INPUT_N+1
 sub rdx,rax
 mov eax,0
 syscall
 cmp rax,-4
 je read_input
 test rax,rax
 js io_failure
 jz input_complete
 add [rbp+S],rax
 cmp QWORD PTR [rbp+S],INPUT_N
 ja capacity
 jmp read_input
input_complete:
 mov rdi,r12
 mov esi,INPUT_EXTENT
 mov edx,1
 mov eax,10
 syscall
 test rax,rax
 jnz io_failure
 mov rdi,r12
 mov rsi,[rbp+S]
 lea rdx,[r12+JSON_AT]
 mov ecx,JSON_N
 lea r8,[r12+ARENA_AT]
 mov r9d,131072
 .byte 0xe8
syntax_call_hole: .long 0
 mov [rbp+120],rax
 mov [rbp+S+24],rax
 # This is only a CABI view-range check. HIA classifies every raw status.
 test rax,rax
 jz admission_skipped
 cmp rax,JSON_N
 ja admission_skipped
 lea rdi,[r12+JSON_AT]
 mov esi,JSON_N
 mov edx,1
 mov eax,10
 syscall
 test rax,rax
 jnz io_failure
 # Scratch reset between independent HIA owners; no parsed-object bridge.
 lea rdi,[r12+ARENA_AT]
 mov ecx,16384
 xor eax,eax
 rep stosq
 lea rdi,[r12+JSON_AT]
 mov rsi,[rbp+S+24]
 lea rdx,[r12+CORE_AT]
 mov ecx,CORE_N
 lea r8,[r12+ARENA_AT]
 mov r9d,ARENA_N
 .byte 0xe8
core_call_hole: .long 0
 # Preserve the full actual Core decision. HIA owns classification.
 mov [rbp+112],rax
 mov QWORD PTR [r12+ARENA_AT+48],262144
 mov QWORD PTR [r12+ARENA_AT+56],64
 lea rdi,[r12+JSON_AT]
 mov rsi,[rbp+S+24]
 lea rdx,[r12+CANON_AT]
 mov ecx,CANON_N
 lea r8,[r12+ARENA_AT]
 mov r9d,ARENA_N
 .byte 0xe8
canonical_call_hole: .long 0
 # The HIA presenter, not the adapter, classifies the raw CABI result.
 mov [rbp+96],rax
admission_skipped:
 lea rdi,[r12+CORE_AT]
 mov esi,CORE_N
 mov eax,11
 syscall
 test rax,rax
 jnz io_failure
 mov rdi,r12
 mov esi,INPUT_EXTENT
 mov eax,11
 syscall
 test rax,rax
 jnz io_failure
 lea rdi,[r12+JSON_AT]
 mov esi,JSON_N
 mov eax,11
 syscall
 test rax,rax
 jnz io_failure
 lea rdi,[r12+ARENA_AT]
 mov esi,ARENA_N
 mov eax,11
 syscall
 test rax,rax
 jnz io_failure
 lea rdi,[r12+CANON_AT]
 mov esi,CANON_N
 mov edx,1
 mov eax,10
 syscall
 test rax,rax
 jnz io_failure
pretty_loop:
 lea rdi,[r12+CANON_AT]
 mov esi,CANON_N
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
 mov [rbp+S+8],rax
 mov QWORD PTR [rbp+S+16],0
 test rax,rax
 jnz write_output
 cmp QWORD PTR [rbp+8],5
 jne io_failure
 jmp completed
write_output:
 mov rax,[rbp+S+16]
 lea rsi,[rbp+O+rax]
 mov rdx,[rbp+S+8]
 sub rdx,rax
 mov edi,1
 mov eax,1
 syscall
 cmp rax,-4
 je write_output
 test rax,rax
 jle io_failure
 add [rbp+S+16],rax
 mov rax,[rbp+S+16]
 cmp rax,[rbp+S+8]
 ja io_failure
 jb write_output
 cmp QWORD PTR [rbp+8],5
 jne pretty_loop
completed:
 lea rdi,[r12+CANON_AT]
 mov esi,CANON_N
 mov eax,11
 syscall
 test rax,rax
 jnz io_failure
 mov rdi,rbp
 mov esi,SCRATCH_N
 mov eax,11
 syscall
 test rax,rax
 jnz io_failure
 xor edi,edi
 jmp exit_process
HIA_status:
 cmp rax,255
 ja io_failure
 mov rdi,rax
 jmp exit_process
capacity:
 mov edi,3
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
