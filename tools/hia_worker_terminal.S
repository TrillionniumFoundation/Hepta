/* Stdio transport only. HIA owns framing, request admission, response
 * canonicalization and terminal rendering for this process-owner interface. */
.intel_syntax noprefix
.text
.global _start
.type _start,@function
.equ WIRE_LIMIT,8<<20
.equ WORKSPACE,64+262144*56+WIRE_LIMIT+16384
.equ PRIVATE,WORKSPACE-16384
.equ FRAME_BYTES,296
.equ ADMISSION_BYTES,88
.equ ADMISSION_OUTPUT,0x32304f5257414948

_start:
 cld
 cmp QWORD PTR [rsp+8],1
 jne bad_frame
 mov edi,13
 lea rsi,[rip+sigpipe]
 xor edx,edx
 mov r10d,8
 mov eax,13
 syscall
 test rax,rax
 jne io_failure
 lea rsi,[rip+header]
 mov edx,8
 call read_exact
 mov esi,8
 call check_header
 cmp eax,ADMISSION_BYTES
 je admission
 cmp eax,FRAME_BYTES
 jne bad_frame
 lea rsi,[rip+header+8]
 mov edx,FRAME_BYTES-8
 call read_exact
 mov esi,FRAME_BYTES
 call check_header
 cmp eax,0xfffffffe
 je budget
 cmp eax,FRAME_BYTES
 jne bad_frame
 mov esi,WIRE_LIMIT
 call map_private
 mov r12,rax
 mov esi,WIRE_LIMIT
 call map_private
 mov r13,rax
 mov esi,WORKSPACE
 call map_private
 mov r14,rax
 mov QWORD PTR [r14],1
 mov rax,[rip+header+24]
 mov [r14+8],rax
 lea rdi,[r14+PRIVATE+64]
 lea rsi,[rip+header+40]
 mov ecx,8
 rep movsq

 mov rsi,r12
 mov rdx,[rip+header+8]
 call read_exact
 mov rdi,r12
 mov rsi,[rip+header+8]
 mov rdx,r13
 mov r8,r14
 call run_hia

 mov rsi,r12
 mov rdx,[rip+header+16]
 call read_exact
 call read_eof
 mov esi,WORKSPACE
 call map_private
 mov r15,rax
 mov QWORD PTR [r15],3
 mov rax,[rip+header+24]
 mov QWORD PTR [r15+8],rax
 mov rdi,r12
 mov rsi,[rip+header+16]
 mov rdx,r13
 mov r8,r15
 call run_hia
 mov rbx,rax

 mov QWORD PTR [r14],2
 mov rax,[rip+header+32]
 mov [r14+PRIVATE+520],rax
 lea rdi,[r14+PRIVATE+528]
 lea rsi,[rip+header+104]
 mov ecx,24
 rep movsq
 mov rdi,r13
 mov rsi,rbx
 mov rdx,r12
 mov r8,r14
 call run_hia
 mov rdx,rax
 mov rsi,r12
 call write_exact
 lea rsi,[rip+newline]
 mov edx,1
 call write_exact
 xor edi,edi
 jmp exit

/* This route hands the existing HIA decoder arena to the process owner.
 * No parsing, normalization, identity computation or refusal judgment is
 * performed by the transport. Only parsed refusals carry an arena. */
admission:
 lea rsi,[rip+header+8]
 mov edx,ADMISSION_BYTES-8
 call read_exact
 mov esi,ADMISSION_BYTES
 call check_header
 cmp eax,0xfffffffe
 je budget
 cmp eax,ADMISSION_BYTES
 jne bad_frame
 mov esi,WIRE_LIMIT
 call map_private
 mov r12,rax
 mov esi,WIRE_LIMIT
 call map_private
 mov r13,rax
 mov esi,WORKSPACE
 call map_private
 mov r14,rax
 mov QWORD PTR [r14],1
 mov rax,[rip+header+16]
 mov [r14+8],rax
 lea rdi,[r14+PRIVATE+64]
 lea rsi,[rip+header+24]
 mov ecx,8
 rep movsq
 mov rsi,r12
 mov rdx,[rip+header+8]
 test rdx,rdx
 jz admit_eof
 call read_exact
admit_eof:
 call read_eof
 mov rdi,r12
 mov rsi,[rip+header+8]
 mov rdx,r13
 mov ecx,WIRE_LIMIT
 mov r8,r14
 mov r9d,WORKSPACE
 call worker_request_start
 mov eax,eax
 mov [rip+header+8],rax
 xor r15d,r15d
 cmp eax,WIRE_LIMIT
 jbe admit_arena
 cmp eax,0xffffffe9
 jb admit_reply
 cmp eax,0xffffffef
 ja admit_reply
admit_arena:
 mov r15,[r14+32]
 cmp r15,64
 jb io_failure
 cmp r15,PRIVATE
 ja io_failure
admit_reply:
 movabs rax,ADMISSION_OUTPUT
 mov [rip+header],rax
 mov [rip+header+16],r15
 lea rsi,[rip+header]
 mov edx,24
 call write_exact
 test r15,r15
 jz admission_complete
 mov rsi,r14
 mov rdx,r15
 call write_exact
admission_complete:
 xor edi,edi
 jmp exit

check_header:
 lea rdi,[rip+header]
 xor edx,edx
 xor ecx,ecx
 lea r8,[rip+transport_mode]
 mov r9d,8
 jmp worker_request_start
run_hia:
 mov ecx,WIRE_LIMIT
 mov r9d,WORKSPACE
 call worker_request_start
 cmp eax,0xfffffffe
 je budget
 cmp eax,0xffffffea
 je budget
 cmp eax,0xfffffffd
 je bad_frame
 cmp eax,0xffffff00
 jae rejected
 test eax,eax
 jz io_failure
 cmp eax,WIRE_LIMIT
 ja io_failure
 mov eax,eax
 ret
map_private:
 xor edi,edi
 mov edx,3
 mov r10d,34
 mov r8,-1
 xor r9d,r9d
 mov eax,9
 syscall
 cmp rax,-4095
 jae io_failure
 ret
read_exact:
 xor edi,edi
 xor eax,eax
 syscall
 cmp rax,-4
 je read_exact
 test rax,rax
 js io_failure
 jz bad_frame
 add rsi,rax
 sub rdx,rax
 jne read_exact
 ret
read_eof:
 xor edi,edi
 lea rsi,[rip+extra]
 mov edx,1
 xor eax,eax
 syscall
 cmp rax,-4
 je read_eof
 test rax,rax
 js io_failure
 jne bad_frame
 ret
write_exact:
 mov edi,1
 mov eax,1
 syscall
 cmp rax,-4
 je write_exact
 test rax,rax
 jle io_failure
 add rsi,rax
 sub rdx,rax
 jne write_exact
 ret
rejected:
 mov edi,2
 jmp exit
budget:
 mov edi,3
 jmp exit
io_failure:
 mov edi,4
 jmp exit
bad_frame:
 mov edi,64
exit:
 mov eax,60
 syscall
 ud2
.size _start,.-_start

.section .rodata
.balign 8
sigpipe: .quad 1,0,0,0
newline: .byte 10

.data
.balign 8
transport_mode: .quad 4

.bss
.balign 8
header: .skip FRAME_BYTES
extra: .skip 1
.section .note.GNU-stack,"",@progbits
