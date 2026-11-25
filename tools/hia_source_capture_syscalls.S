/* Linux x86-64 transport for the HIA source-capture policy.
 * The policy owns paths, source pins, source packet layout, read limits,
 * transitions and exit classes. This adapter binds requested descriptors and
 * ranges to its retained mappings, performs syscalls, and calls embedded HIA.
 */
.intel_syntax noprefix
.text
.global _start, policy_hole, sha_hole
.equ INPUT_CAP, 1048576
.equ FILE_CAP, 67108864
.equ OUTPUT_AT, 2097152
.equ OUTPUT_CAP, 67108864
.equ WORK_AT, 69206016
.equ WORK_CAP, 68157440
.equ MAP_BYTES, 137363456
.equ PATH_AT, 512
.equ STAT_AT, 4608
.equ AFTER_AT, 4752
.equ DIGEST_AT, 4896
.equ SHA_AT, 8192
.equ FILE_AT, 65536
_start:
 cld
 mov r15,rsp
 mov eax,9
 xor edi,edi
 mov esi,MAP_BYTES
 mov edx,3
 mov r10d,0x22
 mov r8,-1
 xor r9d,r9d
 syscall
 cmp rax,-4095
 jae early_io
 mov r12,rax
 lea r13,[r12+OUTPUT_AT]
 lea r14,[r12+WORK_AT]
 mov rax,[r15]
 mov [r14+136],rax
 sub rsp,64
 mov QWORD PTR [rsp],-1
 mov QWORD PTR [rsp+16],1
 mov QWORD PTR [rsp+24],0
 mov QWORD PTR [rsp+32],0
 mov QWORD PTR [rsp+40],0
 mov edi,13
 lea rsi,[rsp+16]
 xor edx,edx
 mov r10d,8
 mov eax,13
 syscall
 test rax,rax
 jne io
 xor ebp,ebp
read_request:
 xor edi,edi
 lea rsi,[r12+rbp]
 mov edx,INPUT_CAP+1
 sub rdx,rbp
 xor eax,eax
 syscall
 cmp rax,-4
 je read_request
 test rax,rax
 js io
 jz request_complete
 add rbp,rax
 cmp rbp,INPUT_CAP
 ja invalid
 jmp read_request
request_complete:
 /* A source request is fully captured before any source descriptor is opened. */
 mov rdi,r12
 mov esi,OUTPUT_AT
 mov edx,1
 mov eax,10
 syscall
 test rax,rax
 jne io
policy_next:
 mov rdi,r12
 mov rsi,rbp
 mov rdx,r13
 mov ecx,OUTPUT_CAP
 mov r8,r14
 mov r9d,WORK_CAP
 .byte 0xe8
policy_hole: .long 0
 cmp rax,[r14+16]
 jne invalid
 cmp rax,10
 ja invalid
 test rax,rax
 jz invalid
 mov [rsp+8],rax
 cmp eax,1
 je root_stat
 cmp eax,2
 je open_source
 cmp eax,3
 je file_stat
 cmp eax,4
 je read_source
 cmp eax,5
 je after_stat
 cmp eax,6
 je close_source
 cmp eax,9
 jbe hash_source
 jmp finish
root_stat:
 mov rdi,[r14+56]
 cmp rdi,[r12+8]
 jne invalid
 lea rsi,[r14+STAT_AT]
 mov eax,5
 syscall
 jmp returned
open_source:
 cmp QWORD PTR [rsp],-1
 jne invalid
 mov rdi,[r14+56]
 cmp rdi,[r12+8]
 jne invalid
 lea rsi,[r14+PATH_AT]
 /* open_how is fixed mechanical custody: readonly, CLOEXEC, no symlinks,
  * confined below the retained root directory descriptor. */
 mov QWORD PTR [rsp+16],0xa0800
 mov QWORD PTR [rsp+24],0
 mov QWORD PTR [rsp+32],12
 lea rdx,[rsp+16]
 mov r10d,24
 mov eax,437
 syscall
 test rax,rax
 js returned
 mov [rsp],rax
 jmp returned
file_stat:
 mov rdi,[r14+64]
 cmp rdi,[rsp]
 jne invalid
 lea rsi,[r14+STAT_AT]
 mov eax,5
 syscall
 jmp returned
after_stat:
 mov rdi,[r14+64]
 cmp rdi,[rsp]
 jne invalid
 lea rsi,[r14+AFTER_AT]
 mov eax,5
 syscall
 jmp returned
read_source:
 mov rdi,[r14+64]
 cmp rdi,[rsp]
 jne invalid
 mov rcx,[r14+80]
 cmp rcx,FILE_CAP
 ja invalid
 mov rdx,[r14+144]
 test rdx,rdx
 jz invalid
 mov eax,FILE_CAP+1
 sub rax,rcx
 cmp rdx,rax
 ja invalid
 lea rsi,[r14+rcx+FILE_AT+1]
 xor eax,eax
 syscall
 jmp returned
close_source:
 mov rdi,[r14+64]
 cmp rdi,[rsp]
 jne invalid
 mov eax,3
 syscall
 mov QWORD PTR [rsp],-1
 jmp returned
hash_source:
 cmp QWORD PTR [rsp+8],7
 jne hash_not_initial
 mov BYTE PTR [r14+FILE_AT],0
 mov esi,1
 lea rdi,[r14+FILE_AT]
 jmp hash_call
hash_not_initial:
 cmp QWORD PTR [rsp+8],8
 jne hash_final
 /* The HIA policy selects a bounded view and owns its command prefix.
  * Only the retained file mapping may be read by the embedded hash role. */
 mov rdx,[r14+72]
 cmp rdx,FILE_CAP
 ja invalid
 mov rcx,[r14+152]
 cmp rcx,rdx
 ja invalid
 sub rdx,rcx
 mov rsi,[r14+160]
 cmp rsi,rdx
 ja invalid
 lea rdi,[r14+rcx+FILE_AT]
 cmp BYTE PTR [rdi],1
 jne invalid
 inc rsi
 jmp hash_call
hash_final:
 mov BYTE PTR [r14+FILE_AT],2
 mov esi,1
 lea rdi,[r14+FILE_AT]
hash_call:
 lea rdx,[r14+DIGEST_AT]
 mov ecx,32
 lea r8,[r14+SHA_AT]
 mov r9d,1184
 .byte 0xe8
sha_hole: .long 0
returned:
 mov [r14+8],rax
 jmp policy_next
finish:
 mov eax,[r14+128]
 mov [rsp+48],eax
 cmp QWORD PTR [rsp],-1
 je closed
 mov rdi,[rsp]
 mov eax,3
 syscall
closed:
 cmp DWORD PTR [rsp+48],0
 jne exit_saved
 mov rbx,[r14+48]
 test rbx,rbx
 jz invalid
 cmp rbx,OUTPUT_CAP
 ja invalid
 mov rsi,r13
write_output:
 mov edi,1
 mov rdx,rbx
 mov eax,1
 syscall
 cmp rax,-4
 je write_output
 test rax,rax
 jle io
 add rsi,rax
 sub rbx,rax
 jnz write_output
exit_saved:
 mov edi,[rsp+48]
 mov eax,60
 syscall
invalid:
 mov edi,16
 jmp fail_cleanup
io:
 mov edi,15
fail_cleanup:
 mov [rsp+48],edi
 cmp QWORD PTR [rsp],-1
 je exit_saved
 mov rdi,[rsp]
 mov eax,3
 syscall
 jmp exit_saved
early_io:
 mov edi,15
 mov eax,60
 syscall
