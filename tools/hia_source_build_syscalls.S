/* Fixed Linux x86-64 transport. HIA owns argument/bundle/name admission,
 * compile sequencing, pair identity, output serialization and ELF bytes.
 * No file opening, child execution, payload parsing or JIT of input images.
 * Constants are injected by the generator from the explicit memory layout.
 */
.intel_syntax noprefix
.text
.global _start, policy_initial_hole, policy_hole, compiler_hole, packer_hole

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
 /* Ignore SIGPIPE in this process, so write errors produce an exit code. */
 mov QWORD PTR [rbp+256],1
 mov edi,13
 lea rsi,[rbp+256]
 xor edx,edx
 mov r10d,8
 mov eax,13
 syscall
 test rax,rax
 js io_exit
 mov rax,[r15]
 dec rax
 mov [rbp+ARGS],rax
 xor ecx,ecx
 cmp QWORD PTR [r15],2
 jb args_ready
 mov rsi,[r15+16]
args_next:
 cmp rcx,17
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
 lea rdx,[rbp+OUT]
 mov ecx,LIMIT
 lea r8,[rbp+WORK]
 mov r9d,WORK_BYTES
 .byte 0xe8
policy_initial_hole: .long 0
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
 /* All subsequent HIA readbuf views refer to this immutable allocation. */
 mov rdi,r12
 mov esi,WIRE_CAP
 mov edx,1
 mov eax,10
 syscall
 test rax,rax
 js io_exit
 mov QWORD PTR [rbp+WORK],1
 call policy_call
 test eax,eax
 jnz policy_exit
next_action:
 mov QWORD PTR [rbp+WORK],2
 call policy_call
 cmp eax,1
 je compile_source
 cmp eax,2
 je pack_images
 cmp eax,3
 je publish
 jmp policy_exit
compile_source:
 /* Match a fresh zero-filled compiler workspace for every source. */
 lea rdi,[rbp+COMPWORK]
 mov ecx,COMPILER_WORK_BYTES/8
 xor eax,eax
 rep stosq
 mov rdi,[rbp+WORK+56]
 add rdi,r12
 mov rsi,[rbp+WORK+64]
 lea rdx,[rbp+WORK+IMAGE_AT]
 mov ecx,IMAGE_LIMIT
 lea r8,[rbp+COMPWORK]
 mov r9d,COMPILER_WORK_BYTES
 .byte 0xe8
compiler_hole: .long 0
 mov [rbp+WORK+72],rax
 mov QWORD PTR [rbp+WORK],3
 call policy_call
 test eax,eax
 jnz policy_exit
 jmp next_action
pack_images:
 mov QWORD PTR [rbp+WORK],4
 mov rdi,r12
 mov rsi,r13
 lea rdx,[rbp+FRAME]
 mov ecx,FRAME_CAP
 call policy_common
 test eax,eax
 jnz policy_exit
 lea rdi,[rbp+FRAME]
 mov rsi,[rbp+WORK+80]
 lea rdx,[rbp+OUT]
 mov ecx,LIMIT
 lea r8,[rbp+COMPWORK]
 mov r9d,COMPILER_WORK_BYTES
 .byte 0xe8
packer_hole: .long 0
 mov [rbp+WORK+72],rax
 mov QWORD PTR [rbp+WORK],5
 call policy_call
 test eax,eax
 jnz policy_exit
publish:
 /* The first write occurs only after all native stages have succeeded. */
 mov r14,[rbp+WORK+88]
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
policy_call:
 mov rdi,r12
 mov rsi,r13
 lea rdx,[rbp+OUT]
 mov ecx,LIMIT
policy_common:
 lea r8,[rbp+WORK]
 mov r9d,WORK_BYTES
 sub rsp,8
 .byte 0xe8
policy_hole: .long 0
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
