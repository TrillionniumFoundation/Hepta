/* Fixed Linux x86-64 transport only. HIA owns names, contents, flags,
 * phases, receipts, validation and ordering. Caller supplies parent FD11.
 * Created capabilities: WAL3 anchor4 directory5 lock6 namespace7. */
.intel_syntax noprefix
.text
.global _start, policy_call_hole
.equ OUTPUT,8192
.equ WORK,16384
.equ SCRATCH,49152
.equ IO_MAGIC,0x314f494446414948
_start:
 mov r12,rsp
 cmp QWORD PTR [rsp],3
 jne bad_exit
 xor edi,edi
 mov esi,65536
 mov edx,3
 mov r10d,0x22
 mov r8,-1
 xor r9d,r9d
 mov eax,9
 syscall
 cmp rax,-4095
 jae early_io
 mov rbp,rax
 mov rax,[r12+16]
 mov [rbp+SCRATCH+88],rax
 mov rax,[r12+24]
 mov [rbp+SCRATCH+104],rax
 mov QWORD PTR [rbp+SCRATCH],1
 mov edi,13
 lea rsi,[rbp+SCRATCH]
 xor edx,edx
 mov r10d,8
 mov eax,13
 syscall
 test rax,rax
 js io_exit
 # Fresh standalone ABI; no foreign descriptor may be overwritten.
 mov r13d,3
probe_fresh:
 mov edi,r13d
 mov esi,1
 mov eax,72
 syscall
 cmp rax,-9
 jne protocol_exit
 inc r13d
 cmp r13d,12
 jb probe_fresh
 # Transport an exact name <=256 bytes, or a 256-byte refusal witness.
 # HIA200 validates length1..255/dot/slash/content BEFORE parent filesystem IO.
 mov rsi,[rbp+SCRATCH+104]
 xor r12d,r12d
copy_argv_name:
 cmp r12,256
 je name_copied
 mov al,[rsi+r12]
 test al,al
 jz name_copied
 mov [rbp+r12+40],al
 inc r12
 jmp copy_argv_name
name_copied:
 mov rax,0x3130494e57414948
 mov [rbp],rax
 mov QWORD PTR [rbp+8],1
 mov QWORD PTR [rbp+16],0
 mov QWORD PTR [rbp+24],0
 mov [rbp+32],r12
 mov eax,107
 syscall
 mov [rbp+r12+40],rax
 mov eax,39
 syscall
 mov [rbp+r12+48],rax
 add r12,56
policy_loop:
 mov rdi,rbp
 mov rsi,r12
 lea rdx,[rbp+OUTPUT]
 mov ecx,8192
 lea r8,[rbp+WORK]
 mov r9d,32768
 .byte 0xe8
policy_call_hole: .long 0
 cmp rax,64
 jb protocol_exit
 cmp rax,8192
 ja protocol_exit
 mov rbx,IO_MAGIC
 cmp [rbp+OUTPUT],rbx
 jne protocol_exit
 mov r13,[rbp+OUTPUT+8]
 mov r14,[rbp+OUTPUT+16]
 mov [rbp+SCRATCH+48],rax
 cmp r14,1
 je fd_stat
 cmp r14,2
 je fd_lock
 cmp r14,3
 je random_bytes
 cmp r14,4
 je mkdir_at
 cmp r14,5
 je open_at
 cmp r14,6
 je fd_write
 cmp r14,7
 je fd_sync
 cmp r14,8
 je fd_read
 cmp r14,9
 je fd_chmod
 cmp r14,10
 je rename_new
 cmp r14,11
 je write_receipt
 cmp r14,12
 je policy_exit
 cmp r14,13
 je path_stat
 cmp r14,14
 je dir_reset
 cmp r14,15
 je dir_entries
 jmp protocol_exit
fd_stat:
 cmp QWORD PTR [rbp+OUTPUT+24],11
 jne fd_stat_ready
 cmp QWORD PTR [rbp+SCRATCH+80],0
 jne fd_stat_ready
 # Lazy first-parent-stat path binding preserves HIA name-admission precedence.
open_parent_path:
 mov QWORD PTR [rbp+SCRATCH+128],0xb0000
 mov QWORD PTR [rbp+SCRATCH+136],0
 mov QWORD PTR [rbp+SCRATCH+144],6
 mov edi,-100
 mov rsi,[rbp+SCRATCH+88]
 lea rdx,[rbp+SCRATCH+128]
 mov r10d,24
 mov eax,437
 syscall
 cmp rax,-4
 je open_parent_path
 test rax,rax
 js io_exit
 mov [rbp+SCRATCH+96],rax
 mov rdi,rax
 mov esi,11
 mov edx,0x80000
 mov eax,292
 syscall
 test rax,rax
 js io_exit
 cmp rax,11
 jne io_exit
 mov QWORD PTR [rbp+SCRATCH+80],1
 mov edi,11
 mov esi,1
 mov eax,72
 syscall
 cmp rax,1
 jne io_exit
 mov rdi,[rbp+SCRATCH+96]
 lea rsi,[rbp+SCRATCH+160]
 mov eax,5
 syscall
 test rax,rax
 jnz io_exit
 mov edi,11
 lea rsi,[rbp+SCRATCH+304]
 mov eax,5
 syscall
 test rax,rax
 jnz io_exit
 mov rax,[rbp+SCRATCH+160]
 cmp rax,[rbp+SCRATCH+304]
 jne protocol_exit
 mov rax,[rbp+SCRATCH+168]
 cmp rax,[rbp+SCRATCH+312]
 jne protocol_exit
 mov rdi,[rbp+SCRATCH+96]
 mov eax,3
 syscall
 test rax,rax
 jnz io_exit
 mov rdi,[rbp+SCRATCH+96]
 mov esi,1
 mov eax,72
 syscall
 cmp rax,-9
 jne io_exit
fd_stat_ready:
 mov rdi,[rbp+OUTPUT+24]
 lea rsi,[rbp+32]
 mov eax,5
 syscall
 cmp rax,-4
 je fd_stat
 mov r15,rax
 test rax,rax
 js meta_reply
get_flags:
 mov rdi,[rbp+OUTPUT+24]
 mov esi,3
 mov eax,72
 syscall
 cmp rax,-4
 je get_flags
 mov r15,rax
 test rax,rax
 js meta_reply
 mov [rbp+176],rax
 xor r15d,r15d
 call make_meta
 mov r12d,184
 jmp policy_loop
path_stat:
 mov rdi,[rbp+OUTPUT+24]
 lea rsi,[rbp+OUTPUT+64]
 lea rdx,[rbp+32]
 mov r10d,256
 mov eax,262
 syscall
 cmp rax,-4
 je path_stat
 mov r15,rax
 test rax,rax
 js meta_reply
 call make_meta
 mov r12d,176
 jmp policy_loop
dir_reset:
 mov rdi,[rbp+OUTPUT+24]
 xor esi,esi
 xor edx,edx
 mov eax,8
 syscall
 cmp rax,-4
 je dir_reset
 mov r15,rax
 jmp meta_reply
dir_entries:
 mov rdx,[rbp+OUTPUT+32]
 cmp rdx,4096
 ja protocol_exit
 mov rdi,[rbp+OUTPUT+24]
 lea rsi,[rbp+32]
 mov eax,217
 syscall
 cmp rax,-4
 je dir_entries
 mov r15,rax
 test rax,rax
 js meta_reply
 call make_meta
 lea r12,[r15+32]
 jmp policy_loop
fd_lock:
 mov rdi,[rbp+OUTPUT+24]
 mov esi,6
 mov eax,73
 syscall
 cmp rax,-4
 je fd_lock
 mov r15,rax
 jmp meta_reply
random_bytes:
 mov rdx,[rbp+OUTPUT+32]
 cmp rdx,16
 ja protocol_exit
 test rdx,rdx
 jz protocol_exit
 lea rdi,[rbp+32]
 mov rsi,rdx
 xor edx,edx
 mov eax,318
 syscall
 cmp rax,-4
 je random_bytes
 mov r15,rax
 test rax,rax
 js meta_reply
 call make_meta
 lea r12,[r15+32]
 jmp policy_loop
mkdir_at:
 mov QWORD PTR [rbp+SCRATCH+32],1
 mov rdi,[rbp+OUTPUT+24]
 lea rsi,[rbp+OUTPUT+64]
 mov rdx,[rbp+OUTPUT+40]
 mov eax,258
 syscall
 mov r15,rax
 jmp meta_reply
open_at:
 mov rax,[rbp+OUTPUT+32]
 mov [rbp+SCRATCH+64],rax
 mov rax,[rbp+OUTPUT+40]
 mov [rbp+SCRATCH+72],rax
 mov QWORD PTR [rbp+SCRATCH+80],14
 mov rdi,[rbp+OUTPUT+24]
 lea rsi,[rbp+OUTPUT+64]
 lea rdx,[rbp+SCRATCH+64]
 mov r10d,24
 mov eax,437
 syscall
 mov r15,rax
 test rax,rax
 js meta_reply
 cmp rax,[rbp+OUTPUT+48]
 je open_done
 mov [rbp+SCRATCH+88],rax
 mov rdi,rax
 mov rsi,[rbp+OUTPUT+48]
 mov edx,0x80000
 mov eax,292
 syscall
 mov r15,rax
 mov rdi,[rbp+SCRATCH+88]
 mov eax,3
 syscall
 test r15,r15
 js meta_reply
open_done:
 xor r15d,r15d
 jmp meta_reply
fd_write:
 mov rax,[rbp+OUTPUT+32]
 cmp rax,4096
 ja protocol_exit
 lea rdx,[rax+64]
 cmp rdx,[rbp+SCRATCH+48]
 ja protocol_exit
 xor ebx,ebx
write_next:
 mov rdi,[rbp+OUTPUT+24]
 lea rsi,[rbp+OUTPUT+rbx+64]
 mov rdx,[rbp+OUTPUT+32]
 sub rdx,rbx
 mov r10,[rbp+OUTPUT+40]
 add r10,rbx
 mov eax,18
 syscall
 cmp rax,-4
 je write_next
 test rax,rax
 js transfer_error
 jz zero_write
 add rbx,rax
 cmp rbx,[rbp+OUTPUT+32]
 jb write_next
 mov r15,rbx
 jmp meta_reply
zero_write:
 mov r15,-5
 jmp meta_reply
fd_sync:
 mov rdi,[rbp+OUTPUT+24]
 mov eax,74
 syscall
 cmp rax,-4
 je fd_sync
 mov r15,rax
 jmp meta_reply
fd_read:
 cmp QWORD PTR [rbp+OUTPUT+32],4096
 ja protocol_exit
 xor ebx,ebx
read_next:
 mov rdi,[rbp+OUTPUT+24]
 lea rsi,[rbp+rbx+32]
 mov rdx,[rbp+OUTPUT+32]
 sub rdx,rbx
 mov r10,[rbp+OUTPUT+40]
 add r10,rbx
 mov eax,17
 syscall
 cmp rax,-4
 je read_next
 test rax,rax
 js transfer_error
 jz read_done
 add rbx,rax
 cmp rbx,[rbp+OUTPUT+32]
 jb read_next
read_done:
 mov r15,rbx
 call make_meta
 lea r12,[rbx+32]
 jmp policy_loop
transfer_error:
 mov r15,rax
 jmp meta_reply
fd_chmod:
 mov rdi,[rbp+OUTPUT+24]
 mov rsi,[rbp+OUTPUT+40]
 mov eax,91
 syscall
 cmp rax,-4
 je fd_chmod
 mov r15,rax
 jmp meta_reply
rename_new:
 mov rdi,[rbp+OUTPUT+24]
 lea rsi,[rbp+OUTPUT+64]
 mov rdx,rdi
 lea r10,[rbp+OUTPUT+105]
 mov r8d,1
 mov eax,316
 syscall
 mov r15,rax
 jmp meta_reply
write_receipt:
 mov rax,[rbp+OUTPUT+32]
 cmp rax,4096
 ja protocol_exit
 lea rdx,[rax+64]
 cmp rdx,[rbp+SCRATCH+48]
 ja protocol_exit
 xor ebx,ebx
stdout_next:
 mov edi,1
 lea rsi,[rbp+OUTPUT+rbx+64]
 mov rdx,[rbp+OUTPUT+32]
 sub rdx,rbx
 mov eax,1
 syscall
 cmp rax,-4
 je stdout_next
 test rax,rax
 js transfer_error
 jz zero_write
 add rbx,rax
 cmp rbx,[rbp+OUTPUT+32]
 jb stdout_next
 mov r15,rbx
 jmp meta_reply
meta_reply:
 call make_meta
 mov r12d,32
 jmp policy_loop
make_meta:
 mov rax,IO_MAGIC
 mov [rbp],rax
 mov [rbp+8],r13
 mov [rbp+16],r14
 mov [rbp+24],r15
 ret
policy_exit:
 mov rdi,[rbp+OUTPUT+24]
 jmp exit_now
protocol_exit:
 mov edi,73
 jmp choose_unknown
io_exit:
 mov edi,74
choose_unknown:
 cmp QWORD PTR [rbp+SCRATCH+32],0
 je exit_now
 mov edi,76
 jmp exit_now
early_io:
 mov edi,74
 jmp exit_now
bad_exit:
 mov edi,64
exit_now:
 mov eax,60
 syscall
