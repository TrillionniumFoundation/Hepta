/* Linux x86-64 transport for the HIA release installer.
 * HIA owns argument/package admission, hashes, paths, names, modes, inode and
 * byte comparisons, directory entry admission and receipts. No payload parser
 * or external program runs here. Failed private stages are deliberately kept.
 */
.intel_syntax noprefix
.text
.global _start, policy_initial_hole, policy_hole, sha_hole
.equ OUT,8192
.equ WORK,16384
.equ BUF,81920
.equ SHAIN,147456
.equ SHAOUT,217088
.equ SHAWORK,221184
.equ MAPSIZE,229376
.equ WIRE,67108864

.macro retry name
 mov [rbp+WORK+2048],rax
\name:
 mov rax,[rbp+WORK+2048]
 syscall
 cmp rax,-4
 je \name
.endm

.macro gate phase
 mov QWORD PTR [rbp+WORK],\phase
 call policy_call
 test eax,eax
 jnz policy_exit
.endm

.macro stat_current fd
 mov edi,\fd
 lea rsi,[rbp+WORK+416]
 mov eax,5
 retry stat_retry_\@
 test rax,rax
 js io_exit
.endm

_start:
 mov r15,rsp
 cmp QWORD PTR [r15],4
 jne usage
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
 /* Ignore SIGPIPE only in this child, preserving an authoritative I/O exit. */
 mov QWORD PTR [rbp+WORK+2000],1
 mov edi,13
 lea rsi,[rbp+WORK+2000]
 xor edx,edx
 mov r10d,8
 mov eax,13
 syscall
 test rax,rax
 js io_exit
 mov r12d,24
 mov ebx,1
argv_next:
 mov rsi,[r15+rbx*8+8]
 call strlen_bounded
 cmp rax,4095
 ja input_exit
 mov [rbp+rbx*8-8],rax
 mov rcx,rax
 lea rdi,[rbp+r12]
 add r12,rax
 cmp r12,8192
 ja input_exit
 rep movsb
 inc ebx
 cmp ebx,4
 jne argv_next
 mov rdi,rbp
 mov rsi,r12
 lea rdx,[rbp+OUT]
 mov ecx,8192
 lea r8,[rbp+WORK]
 mov r9d,65536
 .byte 0xe8
policy_initial_hole: .long 0
 cmp eax,1
 jb input_exit
 cmp eax,2
 ja input_exit
 /* Immutable captured package, including a one-byte oversize guard. */
 xor edi,edi
 mov esi,WIRE+4096
 mov edx,3
 mov r10d,0x22
 mov r8,-1
 xor r9d,r9d
 mov eax,9
 syscall
 cmp rax,-4095
 jae io_exit
 mov r12,rax
 xor r13d,r13d
stdin_next:
 xor edi,edi
 lea rsi,[r12+r13]
 mov edx,WIRE+1
 sub rdx,r13
 xor eax,eax
 retry stdin_retry
 test rax,rax
 js io_exit
 jz stdin_done
 add r13,rax
 cmp r13,WIRE
 ja space_exit
 jmp stdin_next
stdin_done:
 /* Hash all captured bytes in bounded HIA streaming chunks. */
 mov BYTE PTR [rbp+SHAIN],0
 mov esi,1
 call sha_call
 test eax,eax
 jnz input_exit
 xor ebx,ebx
hash_next:
 cmp rbx,r13
 je hash_finish
 mov rcx,r13
 sub rcx,rbx
 cmp rcx,65536
 jbe hash_count
 mov ecx,65536
hash_count:
 mov [rbp+WORK+80],rcx
 lea rsi,[r12+rbx]
 lea rdi,[rbp+SHAIN+1]
 rep movsb
 mov BYTE PTR [rbp+SHAIN],1
 mov rsi,[rbp+WORK+80]
 add rbx,rsi
 inc rsi
 call sha_call
 test eax,eax
 jnz input_exit
 jmp hash_next
hash_finish:
 mov BYTE PTR [rbp+SHAIN],2
 mov esi,1
 call sha_call
 cmp eax,32
 jne input_exit
 mov QWORD PTR [rbp+WORK],1
 lea rdi,[rbp+SHAOUT]
 mov esi,32
 call policy_inputs
 test eax,eax
 jnz policy_exit
 gate 2
 /* Even the package cannot be modified through this adapter after admission. */
 mov rdi,r12
 mov esi,WIRE+4096
 mov edx,1
 mov eax,10
 syscall
 test rax,rax
 js io_exit
 mov eax,107
 syscall
 mov [rbp+WORK+64],rax
 /* Traverse the operator path one component at a time, refusing all symlinks. */
 mov edi,-100
 lea rsi,[rip+slash]
 mov edx,0x2b0000
 xor r10d,r10d
 mov eax,257
 retry root_open_retry
 test rax,rax
 js identity_exit
 mov r14,rax
 mov ebx,1
root_next:
 cmp rbx,[rbp+WORK+88]
 jae root_done
 mov rdi,r14
 lea rsi,[rbp+OUT+rbx]
 mov edx,0x2b0000
 xor r10d,r10d
 mov eax,257
 retry component_open_retry
 test rax,rax
 js identity_exit
 mov [rbp+WORK+120],rax
 mov rdi,r14
 mov eax,3
 syscall
 test rax,rax
 js io_exit
 mov r14,[rbp+WORK+120]
root_advance:
 cmp BYTE PTR [rbp+OUT+rbx],0
 je root_advanced
 inc rbx
 jmp root_advance
root_advanced:
 inc rbx
 jmp root_next
root_done:
 /* Ancestors need search authority only; open the held final root for fsync. */
 mov rdi,r14
 lea rsi,[rip+dot]
 mov edx,0xb0000
 xor r10d,r10d
 mov eax,257
 retry final_root_retry
 test rax,rax
 js identity_exit
 mov [rbp+WORK+120],rax
 mov rdi,r14
 mov eax,3
 syscall
 test rax,rax
 js io_exit
 mov r14,[rbp+WORK+120]
 stat_current r14d
 gate 5
 cmp QWORD PTR [rbp+WORK+8],2
 je open_release
 /* Private mode contract, independent of the invoking process's umask. */
 mov edi,63
 mov eax,95
 syscall
 /* Private staging name comes from the kernel and is encoded by HIA. */
 lea rdi,[rbp+WORK+912]
 mov esi,16
 xor edx,edx
 mov eax,318
 retry random_retry
 cmp rax,16
 jne io_exit
 gate 13
 mov rdi,r14
 lea rsi,[rbp+WORK+848]
 mov edx,448
 mov eax,258
 retry mkdir_retry
 test rax,rax
 js no_replace_exit
 mov rdi,r14
 lea rsi,[rbp+WORK+848]
 mov edx,0xb0000
 xor r10d,r10d
 mov eax,257
 retry stage_open_retry
 test rax,rax
 js identity_exit
 mov rbx,rax
 stat_current ebx
 gate 6
 /* Clear only an admitted owned stage's inherited SGID, never operator root. */
 mov rdi,rbx
 mov esi,448
 mov eax,91
 retry private_stage_retry
 test rax,rax
 js io_exit
 mov QWORD PTR [rbp+WORK+32],0
materialize_next:
 mov rax,[rbp+WORK+32]
 cmp rax,[rbp+WORK+24]
 jae materialized
 gate 4
 mov rdi,rbx
 lea rsi,[rbp+WORK+960]
 mov edx,0xa00c2
 mov r10d,384
 mov eax,257
 retry file_create_retry
 test rax,rax
 js io_exit
 mov [rbp+WORK+120],rax
 mov QWORD PTR [rbp+WORK+72],0
file_write_next:
 mov rdx,[rbp+WORK+48]
 sub rdx,[rbp+WORK+72]
 jz file_written
 mov rdi,[rbp+WORK+120]
 mov rsi,[rbp+WORK+40]
 add rsi,r12
 add rsi,[rbp+WORK+72]
 mov eax,1
 retry file_write_retry
 test rax,rax
 jle io_exit
 add [rbp+WORK+72],rax
 jmp file_write_next
file_written:
 mov rdi,[rbp+WORK+120]
 mov rsi,[rbp+WORK+56]
 mov eax,91
 retry chmod_file_retry
 test rax,rax
 js io_exit
 mov rdi,[rbp+WORK+120]
 mov eax,74
 retry fsync_file_retry
 test rax,rax
 js io_exit
 mov rdi,[rbp+WORK+120]
 lea rsi,[rbp+WORK+416]
 mov eax,5
 retry created_stat_retry
 test rax,rax
 js io_exit
 gate 8
 mov rdi,[rbp+WORK+120]
 mov eax,3
 syscall
 test rax,rax
 js io_exit
 inc QWORD PTR [rbp+WORK+32]
 jmp materialize_next
materialized:
 mov rdi,rbx
 mov esi,320
 mov eax,91
 retry chmod_stage_retry
 test rax,rax
 js io_exit
 mov rdi,rbx
 mov eax,74
 retry fsync_stage_retry
 test rax,rax
 js io_exit
 call verify_tree
 /* Check the staged pathname still names the held sealed directory. */
 mov rdi,r14
 lea rsi,[rbp+WORK+848]
 lea rdx,[rbp+WORK+560]
 mov r10d,256
 mov eax,262
 retry stage_named_stat_retry
 test rax,rax
 js identity_exit
 gate 7
 stat_current r14d
 gate 5
 /* No fallback can overwrite an existing directory or dangling symlink. */
 mov rdi,r14
 lea rsi,[rbp+WORK+848]
 mov rdx,r14
 lea r10,[rbp+WORK+768]
 mov r8d,1
 mov eax,316
 retry rename_retry
 test rax,rax
 js no_replace_exit
 mov rdi,r14
 mov eax,74
 retry fsync_root_retry
 test rax,rax
 js io_exit
 jmp published_verify
open_release:
 mov rdi,r14
 lea rsi,[rbp+WORK+768]
 mov edx,0xb0000
 xor r10d,r10d
 mov eax,257
 retry release_open_retry
 test rax,rax
 js identity_exit
 mov rbx,rax
 stat_current ebx
 gate 6
published_verify:
 call verify_tree
 mov rdi,r14
 lea rsi,[rbp+WORK+768]
 lea rdx,[rbp+WORK+560]
 mov r10d,256
 mov eax,262
 retry release_named_stat_retry
 test rax,rax
 js identity_exit
 gate 7
 stat_current r14d
 gate 5
 mov QWORD PTR [rbp+WORK],14
 call policy_call
 test eax,eax
 jz input_exit
 cmp eax,512
 ja input_exit
 mov r13d,eax
 lea r12,[rbp+OUT]
stdout_next:
 test r13,r13
 jz success
 mov edi,1
 mov rsi,r12
 mov rdx,r13
 mov eax,1
 retry stdout_retry
 test rax,rax
 jle io_exit
 add r12,rax
 sub r13,rax
 jmp stdout_next

/* Capture every named file through the held directory, then exact inventory. */
verify_tree:
 sub rsp,8
 stat_current ebx
 gate 17
 mov QWORD PTR [rbp+WORK+32],0
verify_file_next:
 mov rax,[rbp+WORK+32]
 cmp rax,[rbp+WORK+24]
 jae verify_entries
 gate 4
 mov rdi,rbx
 lea rsi,[rbp+WORK+960]
 mov edx,0xa0800
 xor r10d,r10d
 mov eax,257
 retry verify_open_retry
 test rax,rax
 js identity_exit
 mov [rbp+WORK+120],rax
 mov rdi,rax
 lea rsi,[rbp+WORK+416]
 mov eax,5
 retry verify_stat_retry
 test rax,rax
 js io_exit
 gate 8
 mov QWORD PTR [rbp+WORK+72],0
pread_next:
 mov rdx,[rbp+WORK+48]
 sub rdx,[rbp+WORK+72]
 jz pread_eof
 cmp rdx,65536
 jbe pread_count
 mov edx,65536
pread_count:
 mov rdi,[rbp+WORK+120]
 lea rsi,[rbp+BUF]
 mov r10,[rbp+WORK+72]
 mov eax,17
 retry pread_retry
 test rax,rax
 js io_exit
 jz bytes_exit
 mov [rbp+WORK+80],rax
 mov QWORD PTR [rbp+WORK],10
 call policy_buffer
 test eax,eax
 jnz policy_exit
 mov rax,[rbp+WORK+80]
 add [rbp+WORK+72],rax
 jmp pread_next
pread_eof:
 mov rdi,[rbp+WORK+120]
 lea rsi,[rbp+BUF]
 mov edx,1
 mov r10,[rbp+WORK+72]
 mov eax,17
 retry eof_retry
 test rax,rax
 js io_exit
 jnz bytes_exit
 mov rdi,[rbp+WORK+120]
 lea rsi,[rbp+WORK+416]
 mov eax,5
 retry stable_stat_retry
 test rax,rax
 js io_exit
 gate 9
 mov rdi,[rbp+WORK+120]
 mov eax,3
 syscall
 test rax,rax
 js io_exit
 inc QWORD PTR [rbp+WORK+32]
 jmp verify_file_next
verify_entries:
 gate 15
 mov rdi,rbx
 xor esi,esi
 xor edx,edx
 mov eax,8
 retry seek_retry
 test rax,rax
 js io_exit
entries_next:
 mov rdi,rbx
 lea rsi,[rbp+BUF]
 mov edx,65536
 mov eax,217
 retry entries_retry
 test rax,rax
 js io_exit
 jz entries_end
 mov [rbp+WORK+80],rax
 mov QWORD PTR [rbp+WORK],11
 call policy_buffer
 test eax,eax
 jnz policy_exit
 jmp entries_next
entries_end:
 gate 12
 stat_current ebx
 gate 17
 add rsp,8
 ret

strlen_bounded:
 xor eax,eax
strlen_next:
 cmp rax,4096
 jae strlen_end
 cmp BYTE PTR [rsi+rax],0
 je strlen_end
 inc rax
 jmp strlen_next
strlen_end:
 ret

policy_call:
 mov rdi,r12
 mov rsi,r13
policy_inputs:
 lea rdx,[rbp+OUT]
 mov ecx,8192
 jmp policy_common
policy_buffer:
 mov rdi,r12
 mov rsi,r13
 lea rdx,[rbp+BUF]
 mov ecx,65536
policy_common:
 lea r8,[rbp+WORK]
 mov r9d,65536
 sub rsp,8
 .byte 0xe8
policy_hole: .long 0
 add rsp,8
 ret
sha_call:
 lea rdi,[rbp+SHAIN]
 lea rdx,[rbp+SHAOUT]
 mov ecx,32
 lea r8,[rbp+SHAWORK]
 mov r9d,4096
 sub rsp,8
 .byte 0xe8
sha_hole: .long 0
 add rsp,8
 ret

success:
 xor edi,edi
 jmp exit
policy_exit:
 mov edi,eax
 jmp exit
identity_exit:
 mov edi,10
 jmp exit
bytes_exit:
 mov edi,11
 jmp exit
no_replace_exit:
 mov edi,14
 jmp exit
io_exit:
 mov edi,15
 jmp exit
input_exit:
 mov edi,16
 jmp exit
space_exit:
 mov edi,17
 jmp exit
usage:
 mov edi,64
exit:
 mov eax,60
 syscall
 ud2
slash: .asciz "/"
dot: .asciz "."
