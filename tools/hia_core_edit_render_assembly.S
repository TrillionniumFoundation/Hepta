.intel_syntax noprefix
.text
.global _start
.equ INPUT_N,8388608
.equ INPUT_EXTENT,8392704
.equ C1_AT,8392704
.equ C2_AT,25169920
.equ CANON_N,16777216
.equ ASM_AT,41947136
.equ ASM_N,8388608
.equ JSON_AT,50335744
.equ JSON_N,16777216
.equ ARENA_AT,67112960
.equ ARENA_N,33554432
.equ SCRATCH_AT,100667392
.equ SCRATCH_N,16384
.equ CORE_AT,100683776
.equ CORE_N,67108864
.equ TOTAL_N,167792640
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
 xor eax,eax
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
 lea rdx,[r12+CORE_AT]
 mov ecx,CORE_N
 lea r8,[r12+ARENA_AT]
 mov r9d,ARENA_N
 .byte 0xe8
original_core_hole: .long 0
 mov [rbp+176],rax
 test rax,rax
 jnz finish
 lea rdi,[r12+ARENA_AT]
 mov ecx,ARENA_N/8
 xor eax,eax
 rep stosq
 mov QWORD PTR [r12+ARENA_AT+48],262144
 mov QWORD PTR [r12+ARENA_AT+56],64
 mov rdi,r12
 mov rsi,[rbp+S]
 lea rdx,[r12+C1_AT]
 mov ecx,CANON_N
 lea r8,[r12+ARENA_AT]
 mov r9d,ARENA_N
 .byte 0xe8
original_canonical_hole: .long 0
 mov [rbp+160],rax
 test rax,rax
 jz finish
 cmp rax,CANON_N
 ja finish
 lea rdi,[r12+C1_AT]
 mov esi,CANON_N
 mov edx,1
 mov eax,10
 syscall
 test rax,rax
 jnz io_failure
 lea rdi,[r12+ARENA_AT]
 mov ecx,ARENA_N/8
 xor eax,eax
 rep stosq
 mov QWORD PTR [r12+ARENA_AT+48],262144
 mov QWORD PTR [r12+ARENA_AT+56],64
 mov rax,[rbp+176]
 mov [r12+ARENA_AT+112],rax
 lea rdi,[r12+C1_AT]
 mov rsi,[rbp+160]
 lea rdx,[r12+ASM_AT]
 mov ecx,ASM_N
 lea r8,[r12+ARENA_AT]
 mov r9d,ARENA_N
 .byte 0xe8
render_hole: .long 0
 mov [rbp+192],rax
 test rax,rax
 jz finish
 cmp rax,1048576
 ja finish
 lea rdi,[r12+ASM_AT]
 mov esi,ASM_N
 mov edx,1
 mov eax,10
 syscall
 test rax,rax
 jnz io_failure
 lea rdi,[r12+ARENA_AT]
 mov ecx,ARENA_N/8
 xor eax,eax
 rep stosq
 lea rdi,[r12+ASM_AT]
 mov rsi,[rbp+192]
 lea rdx,[r12+JSON_AT]
 mov ecx,JSON_N
 lea r8,[r12+ARENA_AT]
 mov r9d,131072
 .byte 0xe8
syntax_hole: .long 0
 mov [rbp+200],rax
 test rax,rax
 jz finish
 cmp rax,JSON_N
 ja finish
 lea rdi,[r12+JSON_AT]
 mov esi,JSON_N
 mov edx,1
 mov eax,10
 syscall
 test rax,rax
 jnz io_failure
 lea rdi,[r12+ARENA_AT]
 mov ecx,ARENA_N/8
 xor eax,eax
 rep stosq
 lea rdi,[r12+CORE_AT]
 mov ecx,CORE_N/8
 xor eax,eax
 rep stosq
 lea rdi,[r12+JSON_AT]
 mov rsi,[rbp+200]
 lea rdx,[r12+CORE_AT]
 mov ecx,CORE_N
 lea r8,[r12+ARENA_AT]
 mov r9d,ARENA_N
 .byte 0xe8
roundtrip_core_hole: .long 0
 mov [rbp+184],rax
 test rax,rax
 jnz finish
 lea rdi,[r12+ARENA_AT]
 mov ecx,ARENA_N/8
 xor eax,eax
 rep stosq
 mov QWORD PTR [r12+ARENA_AT+48],262144
 mov QWORD PTR [r12+ARENA_AT+56],64
 lea rdi,[r12+JSON_AT]
 mov rsi,[rbp+200]
 lea rdx,[r12+C2_AT]
 mov ecx,CANON_N
 lea r8,[r12+ARENA_AT]
 mov r9d,ARENA_N
 .byte 0xe8
roundtrip_canonical_hole: .long 0
 mov [rbp+168],rax
 test rax,rax
 jz finish
 cmp rax,CANON_N
 ja finish
 lea rdi,[r12+C2_AT]
 mov esi,CANON_N
 mov edx,1
 mov eax,10
 syscall
 test rax,rax
 jnz io_failure
finish:
 movabs rax,5208772604367785568
 mov [rbp],rax
 lea rdi,[r12+C1_AT]
 mov esi,CANON_N*2
 lea rdx,[r12+CORE_AT]
 mov ecx,CORE_N
 mov r8,rbp
 mov r9d,4096
 .byte 0xe8
finish_hole: .long 0
 mov r13,rax
 cmp r13,255
 ja io_failure
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
 lea rdi,[r12+CORE_AT]
 mov esi,CORE_N
 mov eax,11
 syscall
 test rax,rax
 jnz io_failure
 lea rdi,[r12+C1_AT]
 mov esi,CANON_N*2
 mov eax,11
 syscall
 test rax,rax
 jnz io_failure
 test r13,r13
 jnz HIA_status
 mov QWORD PTR [rbp+S+16],0
write_output:
 mov rax,[rbp+S+16]
 lea rsi,[r12+ASM_AT+rax]
 mov rdx,[rbp+192]
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
 cmp rax,[rbp+192]
 ja io_failure
 jb write_output
 lea rdi,[r12+ASM_AT]
 mov esi,ASM_N
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
 mov rdi,r13
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
