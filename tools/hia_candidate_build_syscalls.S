/* Fixed Linux x86-64 transport for the HIA candidate-build dispatcher.
 * HIA owns all candidate/bundle/manifest policy and every stage request.
 * Only resident HIA images are called. Input data is never executed.
 * There is no pathname lookup, Python, libc, assembler, or child process.
 */
.intel_syntax noprefix
.text
.global _start, policy_hole, source_policy_hole, compiler_hole, sha_hole
.global compiler_data_hole, compiler_size_hole

_start:
 mov r15,rsp
 xor edi,edi
 mov esi,MAPSIZE
 mov edx,3
 mov r10d,0x22
 mov r8,-1
 xor r9d,r9d
 mov eax,9
 syscall
 cmp rax,-4095
 jae io_exit
 mov rbp,rax
 mov QWORD PTR [rbp+256],1
 mov edi,13
 lea rsi,[rbp+256]
 xor edx,edx
 mov r10d,8
 mov eax,13
 syscall
 test rax,rax
 js io_exit
 mov rax,[rip+.Lcompiler_size]
 mov [rbp+WORK+88],rax
 mov rax,[r15]
 dec rax
 mov [rbp+ARGS],rax
 xor ecx,ecx
 cmp QWORD PTR [r15],2
 jb args_ready
 mov rsi,[r15+16]
args_next:
 cmp rcx,128
 jae args_ready
 mov al,[rsi+rcx]
 test al,al
 jz args_ready
 mov [rbp+ARGS+16+rcx],al
 inc rcx
 jmp args_next
args_ready:
 mov [rbp+ARGS+8],rcx
 lea rdi,[rbp+ARGS]
 lea rsi,[rcx+16]
 call policy_common
 test eax,eax
 jnz policy_exit
 lea r12,[rbp+WIRE]
 xor r13d,r13d
stdin_next:
 xor edi,edi
 lea rsi,[r12+r13]
 mov edx,LIMIT+1
 sub rdx,r13
 xor eax,eax
 syscall
 cmp rax,-4
 je stdin_next
 test rax,rax
 js io_exit
 jz stdin_done
 add r13,rax
 cmp r13,LIMIT
 ja space_exit
 jmp stdin_next
stdin_done:
 mov rdi,r12
 mov esi,WIRE_CAP
 mov edx,1
 mov eax,10
 syscall
 test rax,rax
 js io_exit
 mov QWORD PTR [rbp+WORK],1
 call policy_wire
 test eax,eax
 jnz policy_exit
next_action:
 mov rax,[rbp+WORK+16]
 cmp rax,1
 je source_arguments
 cmp rax,2
 je source_wire
 cmp rax,3
 je compile_source
 cmp rax,4
 je hash_source
 cmp rax,5
 je hash_image
 cmp rax,6
 je hash_compiler
 cmp rax,7
 je publish
 jmp io_exit
source_arguments:
 lea rdi,[rbp+WORK+256]
 mov esi,21
 call source_policy_common
 jmp acknowledge
source_wire:
 mov rdi,r12
 mov rsi,r13
 call source_policy_common
 jmp acknowledge
compile_source:
 lea rdi,[rbp+COMPWORK]
 mov ecx,IMAGE_LIMIT/8
 xor eax,eax
 rep stosq
 mov rdi,[rbp+WORK+CONTROL_BYTES+56]
 add rdi,r12
 mov rsi,[rbp+WORK+CONTROL_BYTES+64]
 lea rdx,[rbp+WORK+CONTROL_BYTES+IMAGE_AT]
 mov ecx,IMAGE_LIMIT
 lea r8,[rbp+COMPWORK]
 mov r9d,IMAGE_LIMIT
 .byte 0xe8
compiler_hole: .long 0
 jmp acknowledge
hash_source:
 mov rdi,[rbp+WORK+48]
 add rdi,r12
 mov rsi,[rbp+WORK+56]
 lea rdx,[rbp+WORK+512]
 jmp hash_common
hash_image:
 lea rdi,[rbp+WORK+CONTROL_BYTES+IMAGE_AT]
 mov rsi,[rbp+WORK+40]
 lea rdx,[rbp+WORK+544]
 jmp hash_common
hash_compiler:
 .byte 0x48,0x8d,0x3d
compiler_data_hole: .long 0
 mov rsi,[rip+.Lcompiler_size]
 lea rdx,[rbp+WORK+576]
hash_common:
 mov ecx,32
 lea r8,[rbp+SHAWORK]
 mov r9d,1088
 .byte 0xe8
sha_hole: .long 0
acknowledge:
 mov [rbp+WORK+24],rax
 mov QWORD PTR [rbp+WORK],2
 call policy_wire
 test eax,eax
 jnz policy_exit
 jmp next_action
publish:
 mov r14,[rbp+WORK+64]
 lea rdi,[rbp+OUT]
 mov esi,LIMIT
 mov edx,1
 mov eax,10
 syscall
 test rax,rax
 js io_exit
 xor r15d,r15d
write_next:
 cmp r15,r14
 jae success
 mov edi,1
 lea rsi,[rbp+OUT]
 add rsi,r15
 mov rdx,r14
 sub rdx,r15
 mov eax,1
 syscall
 cmp rax,-4
 je write_next
 test rax,rax
 jle io_exit
 add r15,rax
 jmp write_next
policy_wire:
 mov rdi,r12
 mov rsi,r13
policy_common:
 lea rdx,[rbp+OUT]
 mov ecx,LIMIT
 lea r8,[rbp+WORK]
 mov r9d,WORK_BYTES
 sub rsp,8
 .byte 0xe8
policy_hole: .long 0
 add rsp,8
 ret
source_policy_common:
 lea rdx,[rbp+OUT]
 mov ecx,LIMIT
 lea r8,[rbp+WORK+CONTROL_BYTES]
 mov r9d,BUILD_WORK_BYTES
 sub rsp,8
 .byte 0xe8
source_policy_hole: .long 0
 add rsp,8
 ret
success:
 xor edi,edi
 jmp exit
policy_exit:
 mov edi,eax
 jmp exit
io_exit:
 mov edi,15
 jmp exit
space_exit:
 mov edi,17
exit:
 mov eax,60
 syscall
 ud2
.balign 8
compiler_size_hole:
.Lcompiler_size: .quad 0
