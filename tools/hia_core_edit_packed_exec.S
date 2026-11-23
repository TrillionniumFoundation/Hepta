/* Execute a sealed private ELF decoded by the HIA argument inflater.
   The archive and inflater are embedded in the already admitted launcher. */
.intel_syntax noprefix
.text
.global _start
.equ CHUNK_N,524288
.equ IMAGE_LIMIT,8<<20

_start:
 mov r15,rsp
 sub rsp,96
 .byte 0x48,0x8d,0x1d
archive_hole: .long 0
 mov r13,QWORD PTR ds:0x400060
 add r13,0x400000
 mov esi,CHUNK_N+4096
 call allocate
 mov r14,rax
 call decode_image
 mov [rsp],rax
 cmp rbx,r13
 je begin_exec
 # The packer aligns each independently bounded archive to eight bytes.
archive_padding:
 test bl,7
 jz attached_image
 cmp rbx,r13
 jae failure
 cmp BYTE PTR [rbx],0
 jne failure
 inc rbx
 jmp archive_padding
attached_image:
 # An attached verifier is expanded only for the HIA-dispatched proof role.
 mov rsi,[r15+8]
 lea rdi,[rip+verified_role]
 mov ecx,18
 cld
 repe cmpsb
 jne begin_exec
 # The verified role has an optional fixed-ISA digit and no other suffix.
 movzx eax,BYTE PTR [rsi]
 test al,al
 jz verified_role_ready
 sub eax,'1'
 cmp eax,2
 ja failure
 cmp BYTE PTR [rsi+1],0
 jne failure
verified_role_ready:
 mov rax,[r15]
 sub rax,2
 cmp rax,1
 ja failure
 call decode_image
 cmp rbx,r13
 jne failure
 mov rdi,rax
 xor edx,edx
 mov esi,2                       # F_SETFD: allow the proof fd across this exec
 mov eax,72
 syscall
 test rax,rax
 jnz failure
 mov eax,edi
 lea rdi,[rsp+39]
 mov ecx,8
 lea rsi,[rip+hex_digits]
encode_fd:
 mov edx,eax
 and edx,15
 mov dl,[rsi+rdx]
 mov [rdi],dl
 dec rdi
 shr eax,4
 loop encode_fd
 mov BYTE PTR [rsp+40],0
 mov rcx,[r15]
 lea rsi,[r15+8]
 lea rdi,[rsp+48]
 rep movsq
 lea rax,[rsp+32]
 stosq
 xor eax,eax
 stosq
 lea rdx,[rsp+48]
 jmp execute_image

begin_exec:
 lea rdx,[r15+8]
execute_image:
 mov rdi,[rsp]
 lea rsi,[rip+empty_path]
 mov rax,[r15]
 lea r10,[r15+rax*8+16]
 mov r8d,4096
 mov eax,322
 syscall
 jmp failure

decode_image:
 # Both images have independently bounded envelopes and are sealed before use.
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
 lea rdi,[rip+image_name]
 mov esi,3
 mov eax,319
 syscall
 test rax,rax
 js failure
 cmp eax,2
 ja image_fd
 mov rdi,rax
 mov esi,1030
 mov edx,3
 mov eax,72
 syscall
 test rax,rax
 js failure
 mov [rsp+24],rax
 mov eax,3
 syscall
 test rax,rax
 js failure
 mov rax,[rsp+24]
image_fd:
 mov [rsp+16],rax

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
 mov [rsp+24],rcx
 lea rdi,[rbx+16]
 lea rbx,[rdi+rsi]
 mov rdx,r14
 lea r8,[r14+CHUNK_N]
 mov r9d,4096
 .byte 0xe8
decompress_hole: .long 0
 cmp rax,[rsp+24]
 jne failure
 mov rsi,r14
 mov rdx,rax
 mov rdi,[rsp+16]
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
 sub r12,[rsp+24]
 jnz next_block
 mov rdi,[rsp+16]
 mov esi,0500
 mov eax,91
 syscall
 test rax,rax
 jnz failure
 mov rdi,[rsp+16]
 mov esi,1033
 mov edx,15
 mov eax,72
 syscall
 test rax,rax
 jnz failure
 mov eax,72
 mov esi,1034
 syscall
 cmp eax,15
 jne failure
 mov rax,[rsp+16]
 ret

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
verified_role: .asciz "hia-build-verified"
hex_digits: .ascii "0123456789abcdef"
empty_path: .byte 0
