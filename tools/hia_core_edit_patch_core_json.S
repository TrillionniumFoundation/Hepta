.intel_syntax noprefix
.text
.global _start
.equ WIRE_N,16777219
.equ INPUT_N,16781312
.equ FRAME_AT,16781312
.equ FRAME_N,67108864
.equ SCRATCH_AT,83890176
.equ PATCH_WORK_N,67108864
.equ CORE_STATE_N,67108864
.equ CORE_ARENA_N,33554432
.equ SCRATCH_N,100663296
.equ TOTAL_N,184553472
.equ OUTPUT_AT,SCRATCH_AT
.equ OUTPUT_N,33554432
.equ WORK_AT,117444608
.equ WORK_N,16384
.equ UNUSED_AT,117460992
.equ UNUSED_N,67092480
.equ O,4096
.equ S,8192
_start:
 cmp QWORD PTR [rsp],2
 jne usage
 mov rax,[rsp+16]
 cmp BYTE PTR [rax],118
 jne usage
 movzx r15d,BYTE PTR [rax+1]
 cmp r15d,49
 jb usage
 cmp r15d,50
 ja usage
 cmp BYTE PTR [rax+2],0
 jne usage
 sub r15d,48
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
 xor r13d,r13d
read_input:
 xor edi,edi
 lea rsi,[r12+r13]
 mov edx,WIRE_N+1
 sub rdx,r13
 xor eax,eax
 syscall
 cmp rax,-4
 je read_input
 test rax,rax
 js io_failure
 jz captured
 add r13,rax
 cmp r13,WIRE_N
 ja capacity
 jmp read_input
captured:
 mov rdi,r12
 mov esi,INPUT_N
 mov edx,1
 mov eax,10
 syscall
 test rax,rax
 jnz io_failure
 # Original mode0, full base admission, mode2, full candidate admission.
 lea rdi,[r12+FRAME_AT]
 xor eax,eax
 mov ecx,FRAME_N+PATCH_WORK_N
 cld
 rep stosb
 mov rdi,r12
 mov rsi,r13
 lea rdx,[r12+FRAME_AT]
 mov ecx,FRAME_N
 lea r8,[r12+SCRATCH_AT]
 mov r9d,PATCH_WORK_N
 .byte 0xe8
extract_call_hole: .long 0
 call patch_status
 cmp rax,32
 jbe invalid
 cmp rax,8388640
 ja invalid
 mov r14,rax
 sub r14,32
 mov r10,0x3130544150414948
 cmp [r12+FRAME_AT],r10
 jne invalid
 cmp QWORD PTR [r12+FRAME_AT+8],0
 jne invalid
 cmp QWORD PTR [r12+FRAME_AT+16],0
 jne invalid
 cmp QWORD PTR [r12+FRAME_AT+24],0
 jne invalid
 lea rdi,[r12+SCRATCH_AT]
 xor eax,eax
 mov ecx,SCRATCH_N
 rep stosb
 lea rdi,[r12+FRAME_AT+32]
 mov rsi,r14
 lea rdx,[r12+SCRATCH_AT]
 mov ecx,CORE_STATE_N
 lea r8,[r12+SCRATCH_AT+CORE_STATE_N]
 mov r9d,CORE_ARENA_N
 .byte 0xe8
base_admission_call_hole: .long 0
 call core_status
 lea rdi,[r12+FRAME_AT]
 xor eax,eax
 mov ecx,FRAME_N+PATCH_WORK_N
 rep stosb
 mov QWORD PTR [r12+SCRATCH_AT],2
 mov [r12+SCRATCH_AT+8],r15
 mov rdi,r12
 mov rsi,r13
 lea rdx,[r12+FRAME_AT]
 mov ecx,FRAME_N
 lea r8,[r12+SCRATCH_AT]
 mov r9d,PATCH_WORK_N
 .byte 0xe8
result_call_hole: .long 0
 call patch_status
 # A policy refusal cannot reach candidate or publication handling.
 cmp eax,0xffffffe0
 jae patch_diagnostic
 cmp rax,32
 jbe invalid
 cmp rax,16777248
 ja invalid
 mov r13,rax
 mov r10,0x3130524150414948
 cmp [r12+FRAME_AT],r10
 jne invalid
 cmp QWORD PTR [r12+FRAME_AT+24],0
 jne invalid
 mov r14,[r12+FRAME_AT+8]
 cmp r14,2
 jb invalid
 cmp r14,8388608
 ja invalid
 mov r10,[r12+FRAME_AT+16]
 cmp r10,2
 jb invalid
 cmp r10,8388608
 ja invalid
 add r10,r14
 add r10,32
 cmp r10,r13
 jne invalid
 # Result frame is immutable and disjoint from both Core output views.
 lea rdi,[r12+FRAME_AT]
 mov esi,FRAME_N
 mov edx,1
 mov eax,10
 syscall
 test rax,rax
 jnz io_failure
 lea rdi,[r12+SCRATCH_AT]
 xor eax,eax
 mov ecx,SCRATCH_N
 rep stosb
 lea rdi,[r12+FRAME_AT+32]
 mov rsi,r14
 lea rdx,[r12+SCRATCH_AT]
 mov ecx,CORE_STATE_N
 lea r8,[r12+SCRATCH_AT+CORE_STATE_N]
 mov r9d,CORE_ARENA_N
 .byte 0xe8
candidate_admission_call_hole: .long 0
 mov r14,rax
 call core_status
 # Reuse released Core state for private composed output and presenter scratch.
 lea rdi,[r12+SCRATCH_AT]
 xor eax,eax
 mov ecx,OUTPUT_N+WORK_N
 rep stosb
 lea rbp,[r12+WORK_AT]
 mov [rbp+96],r13
 mov [rbp+104],r14
 lea rdi,[r12+UNUSED_AT]
 mov esi,UNUSED_N
 mov eax,11
 syscall
 test rax,rax
 jnz io_failure
 mov rdi,r12
 mov esi,INPUT_N
 mov eax,11
 syscall
 test rax,rax
 jnz io_failure
 lea rdi,[r12+FRAME_AT]
 mov esi,FRAME_N
 lea rdx,[r12+OUTPUT_AT]
 mov ecx,OUTPUT_N
 mov r8,rbp
 mov r9d,4096
 .byte 0xe8
compose_call_hole: .long 0
 mov [rbp+96],rax
 lea rdi,[r12+FRAME_AT]
 mov esi,FRAME_N
 mov eax,11
 syscall
 test rax,rax
 jnz io_failure
 lea rdi,[r12+OUTPUT_AT]
 mov esi,OUTPUT_N
 mov edx,1
 mov eax,10
 syscall
 test rax,rax
 jnz io_failure
pretty_loop:
 lea rdi,[r12+OUTPUT_AT]
 mov esi,OUTPUT_N
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
 lea rdi,[r12+OUTPUT_AT]
 mov esi,OUTPUT_N
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
core_status:
 call patch_status
 test rax,rax
 jnz invalid
 ret
patch_status:
 mov r10,rax
 shr r10,32
 test r10,r10
 jnz io_failure
 mov r10d,0xfffffffe
 cmp rax,r10
 je capacity
 mov r10d,0xfffffffd
 cmp rax,r10
 je io_failure
 ret
HIA_status:
 cmp rax,255
 ja io_failure
 mov rdi,rax
 jmp exit_process
patch_diagnostic:
 lea rdi,[r12+FRAME_AT]
 mov [rdi],rax
 mov esi,8
 lea rdx,[rdi+16]
 mov ecx,512
 xor r8d,r8d
 xor r9d,r9d
 .byte 0xe8
patch_diagnostic_hole: .long 0
 test eax,eax
 jz invalid
 cmp eax,512
 ja io_failure
 mov edx,eax
 lea rsi,[r12+FRAME_AT+16]
patch_diagnostic_write:
 mov edi,1
 mov eax,1
 syscall
 cmp rax,-4
 je patch_diagnostic_write
 test rax,rax
 jle io_failure
 add rsi,rax
 sub rdx,rax
 jnz patch_diagnostic_write
 jmp invalid
invalid:
 mov edi,2
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
