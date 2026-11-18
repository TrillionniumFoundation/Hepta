.intel_syntax noprefix
.text
.global _start
.equ INPUT_N,8388608
.equ INPUT_EXTENT,8392704
.equ CANON_AT,8392704
.equ CANON_N,16777216
.equ ARENA_AT,25169920
.equ ARENA_N,33554432
.equ SCRATCH_AT,58724352
.equ SCRATCH_N,16384
.equ CORE_AT,58740736
.equ CORE_N,67108864
.equ REPORT_AT,125849600
.equ REPORT_N,33554432
.equ TOTAL_N,159404032
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
 lea rdx,[r12+CORE_AT]
 mov ecx,CORE_N
 lea r8,[r12+ARENA_AT]
 mov r9d,ARENA_N
 .byte 0xe8
core_call_hole: .long 0
 # Preserve the full actual Core decision. HIA owns classification.
 mov [rbp+112],rax
 lea rdi,[r12+CORE_AT]
 mov esi,CORE_N
 mov eax,11
 syscall
 test rax,rax
 jnz io_failure
 mov QWORD PTR [r12+ARENA_AT+48],262144
 mov QWORD PTR [r12+ARENA_AT+56],64
 mov rdi,r12
 mov rsi,[rbp+S]
 lea rdx,[r12+CANON_AT]
 mov ecx,CANON_N
 lea r8,[r12+ARENA_AT]
 mov r9d,ARENA_N
 .byte 0xe8
canonical_call_hole: .long 0
 # HIA report policy owns both actual Core and canonicalizer statuses.
 mov rcx,[rbp+112]
 mov [r12+ARENA_AT+48],rcx
 mov [r12+ARENA_AT+56],rax
 # Both captured source and canonical bytes are immutable during inspection.
 lea rdi,[r12+CANON_AT]
 mov esi,CANON_N
 mov edx,1
 mov eax,10
 syscall
 test rax,rax
 jnz io_failure
 mov QWORD PTR [r12+REPORT_AT],CANON_AT
 mov rdi,r12
 mov esi,ARENA_AT
 lea rdx,[r12+REPORT_AT]
 mov ecx,REPORT_N
 lea r8,[r12+ARENA_AT]
 mov r9d,ARENA_N
 .byte 0xe8
report_call_hole: .long 0
 # Preserve the full actual HIA report result for the HIA presenter.
 mov [rbp+96],rax
 lea rdi,[r12+CANON_AT]
 mov esi,CANON_N
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
 lea rdi,[r12+ARENA_AT]
 mov esi,ARENA_N
 mov eax,11
 syscall
 test rax,rax
 jnz io_failure
 lea rdi,[r12+REPORT_AT]
 mov esi,REPORT_N
 mov edx,1
 mov eax,10
 syscall
 test rax,rax
 jnz io_failure
pretty_loop:
 lea rdi,[r12+REPORT_AT]
 mov esi,REPORT_N
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
 lea rdi,[r12+REPORT_AT]
 mov esi,REPORT_N
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
