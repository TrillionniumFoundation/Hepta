.intel_syntax noprefix
.text
.global _start
.equ INPUT_BYTES,4096
.equ OUTPUT_BYTES,65536
.equ WORK_BYTES,131072
.equ MAPPING_BYTES,INPUT_BYTES+OUTPUT_BYTES+WORK_BYTES

_start:
 mov rbp,rsp
 mov rbx,[rbp]
 cmp rbx,1
 je arguments_ok
 cmp rbx,3
 jne usage
 mov rsi,[rbp+16]
 lea rdi,[rip+schema_option]
 mov ecx,9
 cld
 repe cmpsb
 jne usage
arguments_ok:
 xor edi,edi
 mov esi,MAPPING_BYTES
 mov edx,3
 mov r10d,34
 mov r8,-1
 xor r9d,r9d
 mov eax,9
 syscall
 cmp rax,-4095
 jae io_failure
 mov r12,rax
 lea r13,[r12+INPUT_BYTES]
 movabs rax,0x314e4f534a4c4348
 mov [r12],rax
 mov QWORD PTR [r12+8],2
 cmp rbx,1
 je request_ready
 mov QWORD PTR [r12+16],1
 mov rsi,[rbp+24]
 xor ecx,ecx
capture_schema:
 mov dl,[rsi+rcx]
 test dl,dl
 jz schema_ready
 cmp rcx,127
 jae usage
 mov [r12+32+rcx],dl
 inc rcx
 jmp capture_schema
schema_ready:
 mov [r12+24],rcx
request_ready:
 mov rdi,r12
 mov esi,INPUT_BYTES
 mov eax,10
 mov edx,1
 syscall
 test rax,rax
 jnz io_failure
 mov rdi,r12
 mov rsi,[r12+24]
 add rsi,32
 mov rdx,r13
 mov ecx,OUTPUT_BYTES
 lea r8,[r13+OUTPUT_BYTES]
 mov r9d,WORK_BYTES
 .byte 0xe8
catalog_call_hole: .long 0
 cmp eax,0xfffffffd
 je usage
 test eax,eax
 jz io_failure
 cmp eax,OUTPUT_BYTES
 ja io_failure
 mov ebx,eax
 mov rdi,r13
 mov esi,OUTPUT_BYTES
 mov eax,10
 mov edx,1
 syscall
 test rax,rax
 jnz io_failure
write_output:
 mov edi,1
 mov rsi,r13
 mov edx,ebx
 mov eax,1
 syscall
 cmp rax,-4
 je write_output
 test rax,rax
 jle io_failure
 cmp rax,rbx
 ja io_failure
 add r13,rax
 sub rbx,rax
 jnz write_output
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
schema_option:
 .asciz "--schema"
