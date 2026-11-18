/* Fixed stdio transport for the checked-in HIA nominal JSON codec.
 * stdin: HIANJQ01 codec request (64), little-endian input length (8), JSON.
 * stdout: exact 64-byte codec header and packet, or a fixed refusal frame.
 */
.intel_syntax noprefix
.text
.global _start
.type _start,@function
.equ RAW_LIMIT,8<<20
.equ CAPACITY,32<<20
.equ BAD_BYTES,0xfffffffb
.equ REPLY_MAGIC,0x3130504a4e414948
.equ ERROR_MAGIC,0x3130454a4e414948

_start:
 cmp QWORD PTR [rsp+8],1
 jne malformed
 sub rsp,8
 lea rsi,[rip+sigpipe]
 mov edi,13
 xor edx,edx
 mov r10d,8
 mov eax,13
 syscall
 test rax,rax
 jnz io_error
 lea rsi,[rip+input_header]
 mov edx,72
 call read_exact
 mov r15,[rip+input_header+64]
 cmp r15,RAW_LIMIT
 ja bytes_refusal
 mov esi,1
 test r15,r15
 cmovnz rsi,r15
 call allocate
 mov r12,rax
 test r15,r15
 jz eof
 mov rsi,r12
 mov rdx,r15
 call read_exact
 mov rdi,r12
 mov rsi,r15
 mov edx,1
 mov eax,10
 syscall
 test rax,rax
 jnz io_error
eof:
 xor edi,edi
 lea rsi,[rip+spare]
 mov edx,1
 xor eax,eax
 syscall
 cmp rax,-4
 je eof
 test rax,rax
 js io_error
 jnz malformed
 mov esi,CAPACITY
 call allocate
 mov r13,rax
 mov esi,CAPACITY
 call allocate
 mov r14,rax
 lea rsi,[rip+input_header]
 mov rdi,r14
 mov ecx,8
 rep movsq

 mov rdi,r12
 mov rsi,r15
 mov rdx,r13
 mov ecx,CAPACITY
 mov r8,r14
 mov r9d,CAPACITY
 call nominal_json
 mov eax,eax
 cmp eax,0xfffffff9
 jae codec_refusal
 cmp eax,16
 jb io_error
 cmp eax,CAPACITY
 ja io_error
 mov r12,rax
 mov rax,REPLY_MAGIC
 cmp [r14],rax
 jne io_error
 cmp [r14+8],r12
 jne io_error
 cmp [r14+40],r15
 jne io_error
 cmp QWORD PTR [r14+56],1
 jne io_error
 mov rax,[rip+input_header+8]
 cmp [r14+16],rax
 jne io_error
 mov rax,[rip+input_header+16]
 cmp [r14+24],rax
 jne io_error
 mov rax,[rip+input_header+24]
 cmp [r14+32],rax
 jne io_error
 mov edi,1
 mov rsi,r14
 mov edx,64
 call write_exact
 mov edi,1
 mov rsi,r13
 mov rdx,r12
 call write_exact
 xor edi,edi
 jmp exit

bytes_refusal:
 mov eax,BAD_BYTES
codec_refusal:
 mov [rip+refusal+8],rax
 mov rax,ERROR_MAGIC
 mov [rip+refusal],rax
 mov edi,1
 lea rsi,[rip+refusal]
 mov edx,16
 call write_exact
 mov edi,65
 jmp exit

allocate:
 xor edi,edi
 mov edx,3
 mov r10d,34
 mov r8,-1
 xor r9d,r9d
 mov eax,9
 syscall
 cmp rax,-4095
 jae io_error
 ret
read_exact:
 xor edi,edi
 xor eax,eax
 syscall
 cmp rax,-4
 je read_exact
 test rax,rax
 js io_error
 jz malformed
 add rsi,rax
 sub rdx,rax
 jnz read_exact
 ret
write_exact:
 mov eax,1
 syscall
 cmp rax,-4
 je write_exact
 test rax,rax
 jle io_error
 add rsi,rax
 sub rdx,rax
 jnz write_exact
 ret
malformed:
 mov edi,64
 jmp exit
io_error:
 mov edi,74
exit:
 mov eax,60
 syscall
 ud2
.size _start,.-_start
.balign 8
sigpipe: .quad 1,0,0,0
.balign 16
nominal_json: .incbin "nominal-json.image.bin"
.bss
.balign 8
input_header: .skip 72
refusal: .skip 16
spare: .skip 1
.section .note.GNU-stack,"",@progbits
