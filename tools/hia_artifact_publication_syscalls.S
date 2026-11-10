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
 cmp eax,3
 ja input_exit
 test eax,eax
 jz input_exit
 cmp eax,3
 je withdraw
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
 jmp stdin_next
stdin_done:
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
