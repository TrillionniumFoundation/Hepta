/* Fixed Linux x86-64 transport only. HIA decides commands, path normalization,
 * exact bytes, inode identities, cleanup ownership, SHA and receipt bytes.
 * Anonymous expected input grows with mremap; no arbitrary artifact-size cap.
 */
.intel_syntax noprefix
.text
.global _start, policy_hole, sha_hole
.equ PATHS,524320
.equ WORK,1576960
.equ FILEBUF,1581056
.equ SHAWORK,1646592
.equ SHAIN,1650688
.equ MAPSIZE,1720320
.macro gate phase
 mov QWORD PTR [rbp+WORK],\phase
 xor edi,edi
 xor esi,esi
 call policy_call
.endm
.macro retry name
 mov [rbp+WORK+96],rax
\name:
 mov rax,[rbp+WORK+96]
 syscall
 cmp rax,-4
 je \name
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
 /* Report EPIPE as an I/O exit, without changing parent/process-global policy. */
 mov QWORD PTR [rbp+WORK+2000],1
 mov edi,13
 lea rsi,[rbp+WORK+2000]
 xor edx,edx
 mov r10d,8
 mov eax,13
 syscall
 test rax,rax
 js io_exit
 /* Pack three argv strings with a fourth getcwd string for HIA admission. */
 mov r12d,32
 mov ebx,1
argv_next:
 mov rsi,[r15+rbx*8+8]
 call strlen_bounded
 cmp rax,-1
 je input_exit
 mov [rbp+rbx*8-8],rax
 mov rcx,rax
 lea rdi,[rbp+r12]
 add r12,rax
 rep movsb
 inc ebx
 cmp ebx,4
 jne argv_next
 lea rdi,[rbp+r12]
 mov esi,131072
 mov eax,79
 syscall
 test rax,rax
 js io_exit
 dec rax
 mov [rbp+24],rax
 add r12,rax
 mov QWORD PTR [rbp+WORK],0
 mov rdi,rbp
 mov rsi,r12
 lea rdx,[rbp+PATHS]
 mov ecx,1048576
 lea r8,[rbp+WORK]
 mov r9d,4096
 sub rsp,0
 .byte 0xe8
policy_initial_hole: .long 0
 cmp eax,6
 ja input_exit
 test eax,eax
 jz input_exit
 cmp eax,3
 je withdraw
 cmp eax,5
 je store_get
 /* Grow exact expected stdin with OS resource availability, not a profile cap. */
 xor edi,edi
 mov esi,65536
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
 mov ebx,65536
stdin_next:
 cmp r13,rbx
 jne stdin_room
 mov rdi,r12
 mov rsi,rbx
 mov rdx,rbx
 shl rdx,1
 jc input_exit
 mov r10d,1
 mov eax,25
 syscall
 cmp rax,-4095
 jae io_exit
 mov r12,rax
 shl rbx,1
stdin_room:
 xor eax,eax
 xor edi,edi
 lea rsi,[r12+r13]
 mov rdx,rbx
 sub rdx,r13
 retry stdin_read
 test rax,rax
 js io_exit
 jz stdin_done
 add r13,rax
 cmp QWORD PTR [rbp+WORK+8],4
 jb stdin_next
 mov [rbp+WORK+16],r13
 gate 16
 test eax,eax
 jnz policy_exit
 jmp stdin_next
stdin_done:
 mov [rbp+WORK+16],r13
 cmp QWORD PTR [rbp+WORK+8],4
 jae hash_begin
 test r13,r13
 jz input_exit
 mov [rbp+WORK+16],r13
 mov QWORD PTR [rbp+WORK+32],0
 lea rdi,[rbp+PATHS]
 call read_exact
 test eax,eax
 jnz fail
 cmp QWORD PTR [rbp+WORK+8],2
 je verify_destination
 /* link is intrinsically no-replace, including dangling symlinks. */
 lea rdi,[rbp+PATHS]
 lea rsi,[rbp+PATHS+262160]
 mov eax,86
 retry link_retry
 test rax,rax
 js link_error
 mov QWORD PTR [rbp+WORK+48],1
 mov QWORD PTR [rbp+WORK+32],1
 lea rdi,[rbp+PATHS]
 call read_exact
 test eax,eax
 jnz fail
verify_destination:
 mov QWORD PTR [rbp+WORK+32],2
 lea rdi,[rbp+PATHS+262160]
 call read_exact
 test eax,eax
 jnz fail
hash_begin:
 /* Streaming hash is HIA, independent from byte-authoritative admission. */
 mov BYTE PTR [rbp+SHAIN],0
 mov esi,1
 call sha_call
 test eax,eax
 jnz sha_error
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
 mov [rbp+WORK+88],rcx
 lea rsi,[r12+rbx]
 lea rdi,[rbp+SHAIN+1]
 rep movsb
 mov BYTE PTR [rbp+SHAIN],1
 mov rsi,[rbp+WORK+88]
 add rbx,rsi
 inc rsi
 call sha_call
 test eax,eax
 jnz sha_error
 jmp hash_next
hash_finish:
 mov BYTE PTR [rbp+SHAIN],2
 mov esi,1
 call sha_call
 cmp eax,32
 jne sha_error
 cmp QWORD PTR [rbp+WORK+8],4
 jae store_hashed
 gate 7
 cmp eax,87
 jb sha_error
 mov edx,eax
 lea rsi,[rbp+FILEBUF]
 jmp stdout_write
sha_error:
 mov eax,16
 jmp fail
link_error:
 mov eax,14
 jmp fail
/* read_exact(path): each phase is admitted by the HIA identity/byte policy. */
/* Agent artifact store: descriptor-rooted names, 64-MiB quota, native hash,
 * exact dedup, file+directory fsync. Namespace/SQLite journal is NOT here. */
store_get:
 xor edi,edi
 mov esi,67108865
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
 call store_root
 test eax,eax
 jnz policy_exit
 mov QWORD PTR [rbp+WORK+112],1
 mov QWORD PTR [rbp+WORK+32],0
 lea rdi,[rbp+WORK+2256]
 call store_read_exact
 test eax,eax
 jnz policy_exit
 mov r13,[rbp+WORK+16]
 jmp hash_begin
store_hashed:
 gate 13
 test eax,eax
 jnz policy_exit
 cmp QWORD PTR [rbp+WORK+8],5
 je store_get_hashed
 cmp QWORD PTR [rbp+WORK+8],6
 je store_result
 call store_root
 test eax,eax
 jnz policy_exit
 mov r14,-1
 xor ebx,ebx
store_random:
 lea rdi,[rbp+WORK+2200+rbx]
 mov esi,16
 sub rsi,rbx
 xor edx,edx
 mov eax,318
 retry random_read
 test rax,rax
 jle store_io
 add rbx,rax
 cmp rbx,16
 jb store_random
 gate 12
 test eax,eax
 jnz store_fail
 mov rdi,r15
 lea rsi,[rbp+WORK+2336]
 mov edx,0xa00c1
 mov r10d,256
 mov eax,257
 retry store_create
 test rax,rax
 js store_io
 mov r14,rax
 mov QWORD PTR [rbp+WORK+1008],1
 /* Capture our own inode before any later cleanup is permitted. */
 mov rdi,r14
 lea rsi,[rbp+WORK+128]
 mov eax,5
 retry store_created_stat
 test rax,rax
 js store_io
 xor ebx,ebx
store_write:
 cmp rbx,r13
 je store_file_sync
 mov rdi,r14
 lea rsi,[r12+rbx]
 mov rdx,r13
 sub rdx,rbx
 mov eax,1
 retry store_write_retry
 test rax,rax
 jle store_io
 add rbx,rax
 jmp store_write
store_file_sync:
 mov rdi,r14
 mov eax,74
 retry store_fsync_file
 test rax,rax
 js store_io
 mov rdi,r14
 lea rsi,[rbp+WORK+128]
 mov eax,5
 retry store_written_stat
 test rax,rax
 js store_io
 mov rdi,r14
 mov eax,3
 syscall
 mov r14,-1
 test rax,rax
 js store_io
 gate 17
 mov QWORD PTR [rbp+WORK+32],2
 lea rdi,[rbp+WORK+2336]
 call store_read_exact
 test eax,eax
 jnz store_fail
 gate 18
 mov rdi,r15
 lea rsi,[rbp+WORK+2336]
 mov rdx,r15
 lea r10,[rbp+WORK+2256]
 xor r8d,r8d
 mov eax,265
 retry store_link
 cmp rax,-17
 je store_existing
 test rax,rax
 js store_io
 mov QWORD PTR [rbp+WORK+1016],1
 mov QWORD PTR [rbp+WORK+32],1
 lea rdi,[rbp+WORK+2336]
 call store_read_exact
 test eax,eax
 jnz store_fail
 mov QWORD PTR [rbp+WORK+32],2
 lea rdi,[rbp+WORK+2256]
 call store_read_exact
 test eax,eax
 jnz store_fail
 jmp store_directory_sync
store_existing:
 mov QWORD PTR [rbp+WORK+32],0
 lea rdi,[rbp+WORK+2256]
 call store_read_exact
 mov [rbp+WORK+1056],rax
 gate 19
 mov rax,[rbp+WORK+1056]
 test eax,eax
 jnz store_fail
store_directory_sync:
 mov rdi,r15
 mov eax,74
 retry store_fsync_directory
 test rax,rax
 jns store_durable
 /* Like AgentStore.put, directory-fsync failure leaves a possible immutable
  * content file but never emits an issuance/success receipt. No replay. */
 mov QWORD PTR [rbp+WORK+1016],0
 jmp store_io
store_durable:
 call store_cleanup_temp
 test eax,eax
 jnz policy_exit
store_result:
 gate 15
 test eax,eax
 jnz policy_exit
 gate 7
 cmp eax,87
 jb policy_exit
 mov edx,eax
 lea rsi,[rbp+FILEBUF]
 jmp stdout_write
store_get_hashed:
 gate 14
 test eax,eax
 jnz policy_exit
 mov rsi,r12
 mov rdx,r13
 jmp stdout_write
store_root:
 push rbx
 lea rdi,[rbp+PATHS]
 mov esi,0xb0000
 xor edx,edx
 mov eax,2
 retry root_open
 test rax,rax
 js store_root_io
 mov r15,rax
 mov rdi,r15
 lea rsi,[rbp+WORK+2048]
 mov eax,5
 retry root_stat
 test rax,rax
 js store_root_io
 mov eax,107
 syscall
 mov [rbp+WORK+120],rax
 gate 10
 pop rbx
 ret
store_root_io:
 mov eax,15
 pop rbx
 ret
store_io:
 mov eax,15
store_fail:
 mov [rbp+WORK+1024],rax
 cmp r14,-1
 je store_fail_link
 mov rdi,r14
 mov eax,3
 syscall
 mov r14,-1
store_fail_link:
 cmp QWORD PTR [rbp+WORK+1016],1
 jne store_fail_temp
 mov rdi,r15
 lea rsi,[rbp+WORK+2256]
 lea rdx,[rbp+WORK+272]
 mov r10d,256
 mov eax,262
 syscall
 test rax,rax
 js store_fail_temp
 gate 6
 test eax,eax
 jnz store_fail_temp
 mov rdi,r15
 lea rsi,[rbp+WORK+2256]
 xor edx,edx
 mov eax,263
 syscall
store_fail_temp:
 call store_cleanup_temp
 mov rax,[rbp+WORK+1024]
 jmp policy_exit
store_cleanup_temp:
 push rbx
 cmp QWORD PTR [rbp+WORK+1008],1
 jne store_clean_ok
 mov rdi,r15
 lea rsi,[rbp+WORK+2336]
 lea rdx,[rbp+WORK+272]
 mov r10d,256
 mov eax,262
 retry cleanup_temp_stat
 cmp rax,-2
 je store_clean_ok
 test rax,rax
 js store_clean_io
 gate 6
 test eax,eax
 jnz store_clean_ok
 mov rdi,r15
 lea rsi,[rbp+WORK+2336]
 xor edx,edx
 mov eax,263
 retry cleanup_temp_unlink
 test rax,rax
 js store_clean_io
 mov QWORD PTR [rbp+WORK+1008],0
store_clean_ok:
 xor eax,eax
 pop rbx
 ret
store_clean_io:
 mov eax,15
 pop rbx
 ret
policy_exit:
 mov rdi,rax
 jmp exit
store_read_exact:
 push rbx
 mov rbx,rdi
 mov r14,-1
 mov QWORD PTR [rbp+WORK+40],0
 mov rsi,rbx
 mov rdi,r15
 lea rdx,[rbp+WORK+272]
 mov r10d,256
 mov eax,262
 retry store_before_stat
 test rax,rax
 js store_read_io
 gate 1
 test eax,eax
 jnz store_read_bad
 gate 11
 test eax,eax
 jnz store_read_bad
 mov rdi,r15
 mov rsi,rbx
 mov edx,0xa0800
 xor r10d,r10d
 mov eax,257
 retry store_file_open
 test rax,rax
 js store_read_io
 mov r14,rax
 mov rdi,r14
 lea rsi,[rbp+WORK+416]
 mov eax,5
 retry store_descriptor_before
 test rax,rax
 js store_read_io
 gate 2
 test eax,eax
 jnz store_read_bad
store_file_next:
 xor eax,eax
 mov rdi,r14
 lea rsi,[rbp+FILEBUF]
 mov edx,65536
 retry store_file_read
 test rax,rax
 js store_read_io
 jz store_file_eof
 mov [rbp+WORK+24],rax
 cmp QWORD PTR [rbp+WORK+112],1
 je store_copy_capture
 mov rax,[rbp+WORK+40]
 lea rdi,[r12+rax]
 mov rsi,r13
 sub rsi,rax
 mov QWORD PTR [rbp+WORK],3
 call policy_call
 test eax,eax
 jnz store_read_bad
store_count_chunk:
 mov rax,[rbp+WORK+24]
 add [rbp+WORK+40],rax
 jmp store_file_next
store_copy_capture:
 gate 20
 test eax,eax
 jnz store_read_bad
 mov rax,[rbp+WORK+40]
 lea rdi,[r12+rax]
 lea rsi,[rbp+FILEBUF]
 mov rcx,[rbp+WORK+24]
 rep movsb
 jmp store_count_chunk
store_file_eof:
 mov rdi,r14
 lea rsi,[rbp+WORK+560]
 mov eax,5
 retry store_descriptor_after
 test rax,rax
 js store_read_io
 gate 4
 test eax,eax
 jnz store_read_bad
 mov rdi,r14
 mov eax,3
 syscall
 mov r14,-1
 test rax,rax
 js store_read_io
 mov rdi,r15
 mov rsi,rbx
 lea rdx,[rbp+WORK+704]
 mov r10d,256
 mov eax,262
 retry store_pathname_after
 test rax,rax
 js store_read_io
 gate 5
 jmp store_read_bad
store_read_io:
 mov eax,15
store_read_bad:
 mov [rbp+WORK+64],rax
 cmp r14,-1
 je store_read_return
 mov rdi,r14
 mov eax,3
 syscall
store_read_return:
 mov r14,-1
 mov rax,[rbp+WORK+64]
 pop rbx
 ret
read_exact:
 push rbx
 mov rbx,rdi
 mov r14,-1
 mov QWORD PTR [rbp+WORK+40],0
 lea rsi,[rbp+WORK+272]
 mov eax,6
 retry before_stat
 test rax,rax
 js read_io
 gate 1
 test eax,eax
 jnz read_bad
 mov rdi,rbx
 mov esi,0xa0800
 xor edx,edx
 mov eax,2
 retry file_open
 test rax,rax
 js read_io
 mov r14,rax
 mov rdi,r14
 lea rsi,[rbp+WORK+416]
 mov eax,5
 retry descriptor_before
 test rax,rax
 js read_io
 gate 2
 test eax,eax
 jnz read_bad
file_next:
 xor eax,eax
 mov rdi,r14
 lea rsi,[rbp+FILEBUF]
 mov edx,65536
 retry file_read
 test rax,rax
 js read_io
 jz file_eof
 mov [rbp+WORK+24],rax
 mov rax,[rbp+WORK+40]
 lea rdi,[r12+rax]
 mov rsi,r13
 sub rsi,rax
 mov QWORD PTR [rbp+WORK],3
 call policy_call
 test eax,eax
 jnz read_bad
 mov rax,[rbp+WORK+24]
 add [rbp+WORK+40],rax
 jmp file_next
file_eof:
 mov rdi,r14
 lea rsi,[rbp+WORK+560]
 mov eax,5
 retry descriptor_after
 test rax,rax
 js read_io
 gate 4
 test eax,eax
 jnz read_bad
 mov rdi,r14
 mov eax,3
 syscall
 mov r14,-1
 test rax,rax
 js read_io
 mov rdi,rbx
 lea rsi,[rbp+WORK+704]
 mov eax,6
 retry pathname_after
 test rax,rax
 js read_io
 gate 5
 jmp read_bad
read_io:
 mov eax,15
read_bad:
 mov [rbp+WORK+64],rax
 cmp r14,-1
 je read_return
 mov rdi,r14
 mov eax,3
 syscall
read_return:
 mov rax,[rbp+WORK+64]
 pop rbx
 ret
/* Called with aligned stack in main/read_exact; preserve syscall-clobbered
 * rcx/r11 by never retaining policy state in those registers. */
policy_call:
 lea rdx,[rbp+FILEBUF]
 mov ecx,65536
 lea r8,[rbp+WORK]
 mov r9d,4096
 sub rsp,8
 .byte 0xe8
policy_hole: .long 0
 add rsp,8
 ret
sha_call:
 lea rdi,[rbp+SHAIN]
 lea rdx,[rbp+FILEBUF]
 mov ecx,65536
 lea r8,[rbp+SHAWORK]
 mov r9d,4096
 sub rsp,8
 .byte 0xe8
sha_hole: .long 0
 add rsp,8
 ret
fail:
 mov [rbp+WORK+80],rax
 cmp QWORD PTR [rbp+WORK+48],1
 jne fail_exit
 lea rdi,[rbp+PATHS+262160]
 lea rsi,[rbp+WORK+272]
 mov eax,6
 syscall
 test rax,rax
 js fail_exit
 gate 6
 test eax,eax
 jnz fail_exit
 lea rdi,[rbp+PATHS+262160]
 mov eax,87
 syscall
fail_exit:
 mov rdi,[rbp+WORK+80]
 jmp exit
withdraw:
 mov QWORD PTR [rbp+WORK+48],0
 lea rdi,[rbp+PATHS]
 lea rsi,[rbp+WORK+128]
 mov eax,6
 syscall
 test rax,rax
 js withdrawn
 lea rdi,[rbp+PATHS+262160]
 lea rsi,[rbp+WORK+272]
 mov eax,6
 syscall
 test rax,rax
 js withdrawn
 gate 6
 test eax,eax
 jnz withdrawn
 lea rdi,[rbp+PATHS+262160]
 mov eax,87
 syscall
 test rax,rax
 js withdrawn
 mov QWORD PTR [rbp+WORK+48],1
withdrawn:
 gate 8
 mov edx,eax
 lea rsi,[rbp+FILEBUF]
stdout_write:
 test rdx,rdx
 jz success
 mov eax,1
 mov edi,1
 retry stdout_retry
 test rax,rax
 jle io_exit
 add rsi,rax
 sub rdx,rax
 jmp stdout_write
strlen_bounded:
 xor eax,eax
strlen_next:
 cmp BYTE PTR [rsi+rax],0
 je strlen_return
 inc rax
 cmp rax,131072
 jb strlen_next
 mov rax,-1
strlen_return:
 ret
success: xor edi,edi
 jmp exit
input_exit: mov edi,16
 jmp exit
io_exit: mov edi,15
 jmp exit
usage: mov edi,64
exit: mov eax,60
 syscall
 ud2
