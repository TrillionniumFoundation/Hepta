/* Execute a sealed private ELF decoded by the HIA argument inflater.
   The archive and inflater are embedded in the already admitted launcher. */
.intel_syntax noprefix
.text
.global _start
.equ CHUNK_N,524288
.equ IMAGE_LIMIT,13<<19

_start:
 mov r15,rsp
 sub rsp,48
 .byte 0x48,0x8d,0x1d
archive_hole: .long 0
 mov r13,QWORD PTR ds:0x400060
 add r13,0x400000
 lea rax,[rbx+16]
 cmp rax,r13
 ja failure
 cmp DWORD PTR [rbx],0x45414948
 jne failure
 cmp DWORD PTR [rbx+4],0x31305043
 jne failure
 mov r12,[rbx+8]
 test r12,r12
 jz failure
 cmp r12,IMAGE_LIMIT
 ja failure
 add rbx,16
 mov esi,CHUNK_N+4096
 call allocate
 mov r14,rax
 lea rdi,[rip+image_name]
 mov esi,3
 mov eax,319
 syscall
 test rax,rax
 js failure
 mov [rsp],rax

next_block:
 lea rdi,[r14+CHUNK_N]
 xor eax,eax
 mov ecx,512
 cld
 rep stosq
 mov rax,r13
 sub rax,rbx
 cmp rax,16
 jb failure
 sub rax,16
 mov rsi,[rbx]
 test rsi,rsi
 jz failure
 cmp rsi,rax
 ja failure
 cmp rsi,1048576
 ja failure
 mov rcx,[rbx+8]
 mov eax,CHUNK_N
 cmp r12,rax
 cmovb rax,r12
 cmp rcx,rax
 jne failure
 mov [rsp+8],rcx
 lea rdi,[rbx+16]
 lea rbx,[rdi+rsi]
 mov rdx,r14
 lea r8,[r14+CHUNK_N]
 mov r9d,4096
 .byte 0xe8
decompress_hole: .long 0
 cmp rax,[rsp+8]
 jne failure
 mov rsi,r14
 mov rdx,rax
 mov rdi,[rsp]
write_block:
 mov eax,1
 syscall
 cmp rax,-4
 je write_block
 test rax,rax
 jle failure
 cmp rax,rdx
 ja failure
 add rsi,rax
 sub rdx,rax
 jnz write_block
 sub r12,[rsp+8]
 jnz next_block
 cmp rbx,r13
 jne failure

 mov rdi,[rsp]
 mov esi,0500
 mov eax,91
 syscall
 test rax,rax
 jnz failure
 mov rdi,[rsp]
 mov esi,1033
 mov edx,15
 mov eax,72
 syscall
 test rax,rax
 jnz failure
 mov rdi,[rsp]
 lea rsi,[rip+empty_path]
 lea rdx,[r15+8]
 mov rax,[r15]
 lea r10,[r15+rax*8+16]
 mov r8d,4096
 mov eax,322
 syscall
 jmp failure

allocate:
 xor edi,edi
 mov edx,3
 mov r10d,34
 mov r8,-1
 xor r9d,r9d
 mov eax,9
 syscall
 cmp rax,-4095
 jae failure
 ret

failure:
 mov edi,4
 mov eax,60
 syscall
 ud2

image_name: .asciz "hia-packed-object-builder"
empty_path: .byte 0
