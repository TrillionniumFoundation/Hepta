.intel_syntax noprefix
.text
.global _start
.equ WIRE_N,16777219
.equ INPUT_N,16781312
.equ FRAME_AT,16781312
.equ FRAME_N,67108864
.equ BASE_OFFSET,33554432
.equ SCRATCH_AT,83890176
.equ PATCH_WORK_N,67108864
.equ CORE_STATE_N,67108864
.equ CORE_ARENA_N,33554432
.equ SCRATCH_N,100663296
.equ TOTAL_N,184553472
.equ ENVELOPE_AT,SCRATCH_AT
.equ ENVELOPE_N,33554432
.equ GRAPH_AT,117444608
.equ GRAPH_N,67108864
.equ OUTPUT_N,33554432
.equ WORK_N,16384
.equ O,4096
.equ S,8192
_start:
 cmp QWORD PTR [rsp],2
 jne usage
 mov rax,[rsp+16]
 cmp BYTE PTR [rax],118
 jne usage
 movzx r15d,BYTE PTR [rax+1]
 cmp r15d,48
 jb usage
 cmp r15d,50
 ja usage
 cmp BYTE PTR [rax+2],0
 jne usage
 sub r15d,48
 sub rsp,128
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
extract_hole: .long 0
 call patch_status
 cmp rax,32
 jbe invalid
 cmp rax,8388640
 ja invalid
 sub rax,32
 mov [rsp],rax
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
 mov rsi,[rsp]
 lea rdx,[r12+SCRATCH_AT]
 mov ecx,CORE_STATE_N
 lea r8,[r12+SCRATCH_AT+CORE_STATE_N]
 mov r9d,CORE_ARENA_N
 .byte 0xe8
base_admission_hole: .long 0
 mov [rsp+8],rax
 call core_status
 # Preserve the exact admitted BASE outside the complete mode2 result extent.
 lea rsi,[r12+FRAME_AT+32]
 lea rdi,[r12+FRAME_AT+BASE_OFFSET]
 mov rcx,[rsp]
 rep movsb
 # The checked mode2 ABI is at most16MiB+32;32MiB output keeps full ABI domain.
 lea rdi,[r12+FRAME_AT]
 xor eax,eax
 mov ecx,BASE_OFFSET
 rep stosb
 lea rdi,[r12+SCRATCH_AT]
 mov ecx,PATCH_WORK_N
 rep stosb
 # Application mode returns a sealed result for v0, v1 and v2.
 mov QWORD PTR [r12+SCRATCH_AT],2
 mov [r12+SCRATCH_AT+8],r15
 mov rdi,r12
 mov rsi,r13
 lea rdx,[r12+FRAME_AT]
 mov ecx,BASE_OFFSET
 lea r8,[r12+SCRATCH_AT]
 mov r9d,PATCH_WORK_N
 .byte 0xe8
result_hole: .long 0
 call patch_status
 # A policy refusal cannot reach candidate or publication handling.
 cmp eax,0xffffffe0
 jae patch_diagnostic
 cmp rax,32
 jbe invalid
 cmp rax,16777248
 ja invalid
 mov [rsp+16],rax
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
 cmp r10,rax
 jne invalid
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
candidate_admission_hole: .long 0
 mov [rsp+24],rax
 call core_status
 # HIA alone constructs the private checked triplet; no public bytes yet.
 lea rdi,[r12+SCRATCH_AT]
 xor eax,eax
 mov ecx,SCRATCH_N
 rep stosb
 lea rbp,[r12+GRAPH_AT]
 mov rax,5208772604367785560
 mov [rbp],rax
 mov rax,[rsp+16]
 mov [rbp+96],rax
 mov rax,[rsp+24]
 mov [rbp+104],rax
 mov rax,[rsp]
 mov [rbp+112],rax
 mov rax,[rsp+8]
 mov [rbp+120],rax
 lea rdi,[r12+FRAME_AT]
 mov esi,FRAME_N
 lea rdx,[r12+ENVELOPE_AT]
 mov ecx,ENVELOPE_N
 mov r8,rbp
 mov r9d,4096
 .byte 0xe8
compose_hole: .long 0
 call patch_status
 cmp rax,4
 jbe invalid
 cmp rax,ENVELOPE_N
 ja invalid
 mov [rsp+32],rax
 mov rax,[rbp+88]
 mov [rsp+40],rax
 mov rdi,r12
 mov esi,INPUT_N
 mov eax,11
 syscall
 test rax,rax
 jnz io_failure
 lea rdi,[r12+FRAME_AT]
 mov esi,FRAME_N
 mov eax,11
 syscall
 test rax,rax
 jnz io_failure
 lea rdi,[r12+ENVELOPE_AT]
 mov esi,ENVELOPE_N
 mov edx,1
 mov eax,10
 syscall
 test rax,rax
 jnz io_failure
 # Fresh output map, reused after canonicalization; private source remains RO.
 xor edi,edi
 mov esi,OUTPUT_N
 mov edx,3
 mov r10d,34
 mov r8,-1
 xor r9d,r9d
 mov eax,9
 syscall
 cmp rax,-4095
 jae io_failure
 mov rbx,rax
 lea rdi,[r12+GRAPH_AT]
 xor eax,eax
 mov ecx,GRAPH_N
 rep stosb
 mov QWORD PTR [r12+GRAPH_AT+48],1048576
 mov QWORD PTR [r12+GRAPH_AT+56],128
 mov QWORD PTR [r12+GRAPH_AT+120],1
 lea rdi,[r12+ENVELOPE_AT]
 mov rsi,[rsp+32]
 mov rdx,rbx
 mov ecx,OUTPUT_N
 lea r8,[r12+GRAPH_AT]
 mov r9d,GRAPH_N
 .byte 0xe8
canonical_hole: .long 0
 mov [rsp+48],rax
 mov rdi,rbx
 xor eax,eax
 mov ecx,OUTPUT_N
 rep stosb
 mov rax,[rsp+48]
 mov [rbx],rax
 mov rax,[rsp+40]
 mov [rbx+8],rax
 mov rax,[rsp+8]
 mov [r12+GRAPH_AT+48],rax
 mov rax,[rsp+24]
 mov [r12+GRAPH_AT+56],rax
 mov QWORD PTR [rsp+64],0
impact_loop:
 inc QWORD PTR [rsp+64]
 cmp QWORD PTR [rsp+64],3
 ja io_failure
 lea rdi,[r12+ENVELOPE_AT]
 mov rsi,[rsp+32]
 mov rdx,rbx
 mov ecx,OUTPUT_N
 lea r8,[r12+GRAPH_AT]
 mov r9d,GRAPH_N
 .byte 0xe8
impact_hole: .long 0
 cmp rax,1
 jne impact_finished
 mov r10,5208772604367785554
 cmp [r12+GRAPH_AT],r10
 jne io_failure
 jmp impact_loop
impact_finished:
 call patch_status
 cmp rax,1
 jbe invalid
 cmp rax,OUTPUT_N
 ja invalid
 mov [rsp+56],rax
 mov r10,5208772604367785555
 cmp [r12+GRAPH_AT],r10
 jne io_failure
 lea rdi,[r12+GRAPH_AT]
 mov esi,GRAPH_N
 mov eax,11
 syscall
 test rax,rax
 jnz io_failure
 lea rdi,[r12+ENVELOPE_AT]
 mov esi,ENVELOPE_N
 mov eax,11
 syscall
 test rax,rax
 jnz io_failure
 mov rdi,rbx
 mov esi,OUTPUT_N
 mov edx,1
 mov eax,10
 syscall
 test rax,rax
 jnz io_failure
 xor edi,edi
 mov esi,WORK_N
 mov edx,3
 mov r10d,34
 mov r8,-1
 xor r9d,r9d
 mov eax,9
 syscall
 cmp rax,-4095
 jae io_failure
 mov rbp,rax
 mov rax,[rsp+56]
 mov [rbp+96],rax
 mov QWORD PTR [rbp+120],2
pretty_loop:
 mov rdi,rbx
 mov esi,OUTPUT_N
 lea rdx,[rbp+O]
 mov ecx,128
 mov r8,rbp
 mov r9d,4096
 .byte 0xe8
pretty_hole: .long 0
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
 mov rdi,rbx
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
io_failure:
 mov edi,4
 jmp exit_process
usage:
 mov edi,64
exit_process:
 mov eax,60
 syscall
 ud2
