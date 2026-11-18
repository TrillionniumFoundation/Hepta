/* Fixed Linux x86-64 descriptor transport. HIA admits every effect, FD,
 * byte extent, namespace, phase, receipt and outcome. No libc or loader.
 * Without argv, the caller supplies the Store capabilities and proposal.
 * Direct staging acquires the same capabilities in an initialized Store.
 */
.intel_syntax noprefix
.text
.global _start, writer_call_hole, stager_call_hole, producer_call_hole
.equ OUTPUT,131072
.equ WORK,262144
.equ SCRATCH,294912
.equ PRODUCERWORK,327680
.equ STAGERWORK,344064
.equ MAPSIZE,352256
.equ IO_MAGIC,0x314f494446414948
.equ PROPOSAL_LIMIT,1000000032
.equ OPEN_STORE_READ,0xa0800   /* CLOEXEC | NOFOLLOW | NONBLOCK */
.equ OPEN_STORE_WRITE,0xa0802

_start:
 xor r15d,r15d
 cmp QWORD PTR [rsp],1
 je allocate
 cmp QWORD PTR [rsp],2
 jne early_bad
 mov r15,[rsp+16]
allocate:
 xor edi,edi
 mov esi,MAPSIZE
 mov edx,3
 mov r10d,0x22
 mov r8,-1
 xor r9d,r9d
 mov eax,9
 syscall
 cmp rax,-4095
 jae early_io
 mov rbp,rax
 /* SIGPIPE is reported as an I/O result, never an implicit replay. */
 mov QWORD PTR [rbp+SCRATCH],1
 mov edi,13
 lea rsi,[rbp+SCRATCH]
 xor edx,edx
 mov r10d,8
 mov eax,13
 syscall
 test rax,rax
 js io_exit
 test r15,r15
 jnz direct_stage
 mov rsi,rbp
 mov edx,128
 call read_stdin_exact
 call require_stdin_eof
prepare_anchor_policy:
 mov eax,107
 syscall
 mov [rbp+128],rax
 mov eax,39
 syscall
 mov [rbp+136],rax
 /* Cache original anchor and kernel UID/PID, never a client callback. */
 lea rsi,[rbp]
 lea rdi,[rbp+SCRATCH+512]
 mov ecx,18
 rep movsq
 mov QWORD PTR [rbp+SCRATCH+128],1
 mov rax,0x3254535854414948
 mov [rbp],rax
 mov QWORD PTR [rbp+8],1
 mov rax,[rbp+SCRATCH+640]
 mov [rbp+16],rax
 mov rax,[rbp+SCRATCH+648]
 mov [rbp+24],rax
probe_unused_transaction_role:
 mov edi,9
 mov esi,1
 mov eax,72
 syscall
 cmp rax,-4
 je probe_unused_transaction_role
 mov [rbp+32],rax
 mov r12d,40

policy_loop:
 mov rdi,rbp
 mov rsi,r12
 lea rdx,[rbp+OUTPUT]
 mov ecx,131072
 cmp QWORD PTR [rbp+SCRATCH+128],1
 je call_stager_policy
 lea r8,[rbp+WORK]
 mov r9d,32768
 .byte 0xe8
writer_call_hole: .long 0
 jmp policy_returned
call_stager_policy:
 lea r8,[rbp+STAGERWORK]
 mov r9d,8192
 .byte 0xe8
stager_call_hole: .long 0
policy_returned:
 cmp rax,64
 jb protocol_exit
 cmp rax,131072
 ja protocol_exit
 mov rbx,IO_MAGIC
 cmp QWORD PTR [rbp+OUTPUT],rbx
 jne protocol_exit
 mov r13,[rbp+OUTPUT+8]
 mov r14,[rbp+OUTPUT+16]
 cmp r14,0
 je copy_packet
 cmp r14,1
 je fd_stat
 cmp r14,2
 je fd_lock
 cmp r14,3
 je read_meta
 cmp r14,4
 je read_scan
 cmp r14,5
 je fd_sync
 cmp r14,6
 je fd_link
 cmp r14,7
 je root_stat
 cmp r14,8
 je write_receipt
 cmp r14,9
 je policy_exit
 cmp r14,10
 je dir_reset
 cmp r14,11
 je dir_entries
 cmp r14,12
 je fd_pwrite
 cmp r14,13
 je fd_truncate
 cmp r14,14
 je fd_chmod
 cmp QWORD PTR [rbp+SCRATCH+128],1
 jne protocol_exit
 cmp r14,22
 je fd_stat
 cmp r14,30
 je source_readonly_map
 cmp r14,31
 je call_native_producer
 cmp r14,34
 je source_owned_unmap
 cmp r14,43
 je fresh_transaction_memfd
 cmp r14,45
 je private_transaction_pwrite
 cmp r14,46
 je private_transaction_seal
 cmp r14,50
 je staged_transaction_ready
 jmp protocol_exit

copy_packet:
 mov r12,[rbp+OUTPUT+32]
 cmp r12,131008
 ja protocol_exit
 lea rdx,[r12+64]
 cmp rax,rdx
 jb protocol_exit
 mov rcx,r12
 lea rsi,[rbp+OUTPUT+64]
 mov rdi,rbp
 rep movsb
 jmp policy_loop

fd_stat:
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
 cmp QWORD PTR [rbp+OUTPUT+24],9
 je sealed_request_get_seals
 cmp QWORD PTR [rbp+OUTPUT+24],12
 jne ordinary_fd_stat_done
sealed_request_get_seals:
 mov rdi,[rbp+OUTPUT+24]
 mov esi,1034
 mov eax,72
 syscall
 cmp rax,-4
 je sealed_request_get_seals
 mov r15,rax
 test rax,rax
 js meta_reply
 mov [rbp+184],rax
 xor r15d,r15d
 call make_meta
 mov r12d,192
 jmp policy_loop
ordinary_fd_stat_done:
 xor r15d,r15d
 call make_meta
 mov r12d,184
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

read_meta:
 mov rax,[rbp+OUTPUT+32]
 cmp rax,65536
 ja protocol_exit
 test rax,rax
 jz protocol_exit
 xor ebx,ebx
read_meta_next:
 mov rdi,[rbp+OUTPUT+24]
 lea rsi,[rbp+rbx+32]
 mov rdx,[rbp+OUTPUT+32]
 sub rdx,rbx
 mov r10,[rbp+OUTPUT+40]
 add r10,rbx
 mov eax,17
 syscall
 cmp rax,-4
 je read_meta_next
 test rax,rax
 js read_meta_error
 jz read_meta_done
 add rbx,rax
 cmp rbx,[rbp+OUTPUT+32]
 jb read_meta_next
read_meta_done:
 mov r15,rbx
 call make_meta
 lea r12,[rbx+32]
 jmp policy_loop
read_meta_error:
 mov r15,rax
 jmp meta_reply

read_scan:
 cmp QWORD PTR [rbp+OUTPUT+32],65536
 ja protocol_exit
 mov ecx,4
 lea rsi,[rbp+OUTPUT+64]
 mov rdi,rbp
 rep movsq
read_scan_retry:
 mov rdi,[rbp+OUTPUT+24]
 lea rsi,[rbp+32]
 mov rdx,[rbp+OUTPUT+32]
 mov r10,[rbp+OUTPUT+40]
 mov eax,17
 syscall
 cmp rax,-4
 je read_scan_retry
 test rax,rax
 js read_meta_error
 lea r12,[rax+32]
 jmp policy_loop

fd_sync:
 mov rdi,[rbp+OUTPUT+24]
 mov eax,74
 syscall
 cmp rax,-4
 je fd_sync
 mov r15,rax
 jmp meta_reply

fd_link:
 /* Even an interrupted mutation may be ambiguous to a caller. */
 mov QWORD PTR [rbp+SCRATCH+32],1
 mov rdi,-100
 lea rsi,[rip+stage_fd_path]
 mov edx,5
 lea r10,[rbp+OUTPUT+64]
 mov r8d,1024
 mov eax,265
 syscall
 mov r15,rax
 jmp meta_reply

root_stat:
 mov edi,5
 lea rsi,[rbp+OUTPUT+64]
 lea rdx,[rbp+32]
 mov r10d,256
 mov eax,262
 syscall
 cmp rax,-4
 je root_stat
 mov r15,rax
 test rax,rax
 js meta_reply
 mov QWORD PTR [rbp+176],0
 call make_meta
 mov r12d,184
 jmp policy_loop

write_receipt:
 cmp QWORD PTR [rbp+SCRATCH+32],1
 jne protocol_exit
 mov rdx,[rbp+OUTPUT+32]
 cmp rdx,131008
 ja protocol_exit
 lea rcx,[rdx+64]
 cmp rax,rcx
 jb protocol_exit
 xor ebx,ebx
write_receipt_next:
 mov edi,1
 lea rsi,[rbp+OUTPUT+rbx+64]
 mov rdx,[rbp+OUTPUT+32]
 sub rdx,rbx
 mov eax,1
 syscall
 cmp rax,-4
 je write_receipt_next
 test rax,rax
 js write_receipt_error
 jz write_receipt_zero
 add rbx,rax
 cmp rbx,[rbp+OUTPUT+32]
 jb write_receipt_next
 mov r15,rbx
 jmp meta_reply
write_receipt_zero:
 mov rax,-5
write_receipt_error:
 mov r15,rax
 jmp meta_reply

dir_reset:
 mov edi,5
 xor esi,esi
 xor edx,edx
 mov eax,8
 syscall
 cmp rax,-4
 je dir_reset
 mov r15,rax
 jmp meta_reply

dir_entries:
 mov edi,5
 lea rsi,[rbp+32]
 mov rdx,[rbp+OUTPUT+32]
 cmp rdx,65536
 ja protocol_exit
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

fd_pwrite:
 mov QWORD PTR [rbp+SCRATCH+32],1
 mov rdx,[rbp+OUTPUT+32]
 cmp rdx,65536
 ja protocol_exit
 lea rcx,[rdx+64]
 cmp rax,rcx
 jb protocol_exit
 mov rdi,[rbp+OUTPUT+24]
 lea rsi,[rbp+OUTPUT+64]
 mov r10,[rbp+OUTPUT+40]
 mov eax,18
 syscall
 mov r15,rax
 jmp meta_reply

fd_truncate:
 mov QWORD PTR [rbp+SCRATCH+32],1
 mov rdi,[rbp+OUTPUT+24]
 mov rsi,[rbp+OUTPUT+40]
 mov eax,77
 syscall
 mov r15,rax
 jmp meta_reply

fd_chmod:
 mov QWORD PTR [rbp+SCRATCH+32],1
 mov rdi,[rbp+OUTPUT+24]
 mov rsi,[rbp+OUTPUT+40]
 mov eax,91
 syscall
 mov r15,rax
 jmp meta_reply

meta_reply:
 call make_meta
 jmp policy_loop
make_meta:
 mov rax,IO_MAGIC
 mov [rbp],rax
 mov [rbp+8],r13
 mov [rbp+16],r14
 mov [rbp+24],r15
 mov r12d,32
 ret

policy_exit:
 mov rdi,[rbp+OUTPUT+24]
 test rdi,rdi
 jz process_exit
 cmp QWORD PTR [rbp+SCRATCH+32],0
 je process_exit
 mov edi,76
 jmp process_exit
protocol_exit:
 mov edi,73
 jmp maybe_unknown
io_exit:
 mov edi,74
 jmp maybe_unknown
bad_exit:
 mov edi,64
maybe_unknown:
 cmp QWORD PTR [rbp+SCRATCH+32],0
 je process_exit
 mov edi,76
 jmp process_exit
early_bad:
 mov edi,64
 jmp process_exit
early_io:
 mov edi,74
process_exit:
 mov eax,60
 syscall
 ud2
stage_fd_path: .asciz "/proc/self/fd/10"

source_readonly_map:
 cmp QWORD PTR [rbp+OUTPUT+24],12
 jne protocol_exit
 cmp QWORD PTR [rbp+SCRATCH+256],0
 jne protocol_exit
 xor edi,edi
 mov rsi,[rbp+OUTPUT+32]
 mov edx,1
 mov r10d,2
 mov r8d,12
 xor r9d,r9d
 mov eax,9
 syscall
 mov r15,rax
 cmp rax,-4095
 jae meta_reply
 mov [rbp+SCRATCH+256],rax
 mov rax,[rbp+OUTPUT+32]
 mov [rbp+SCRATCH+264],rax
 jmp meta_reply

call_native_producer:
 cmp QWORD PTR [rbp+SCRATCH+256],0
 je protocol_exit
 mov rdi,[rbp+SCRATCH+256]
 mov rsi,[rbp+SCRATCH+264]
 lea rdx,[rbp+OUTPUT]
 mov ecx,131072
 lea r8,[rbp+PRODUCERWORK]
 mov r9d,16384
 .byte 0xe8
producer_call_hole: .long 0
 cmp rax,320
 ja protocol_exit
 mov r15,rax
 cmp rax,64
 jb meta_reply
 mov [rbp+SCRATCH+304],rax
 mov rcx,rax
 lea rsi,[rbp+OUTPUT]
 lea rdi,[rbp+32]
 rep movsb
 call make_meta
 mov r12,[rbp+SCRATCH+304]
 add r12,32
 jmp policy_loop

fresh_transaction_memfd:
 cmp QWORD PTR [rbp+OUTPUT+24],9
 jne protocol_exit
 cmp QWORD PTR [rbp+SCRATCH+272],0
 jne protocol_exit
 lea rdi,[rip+private_transaction_memfd_name]
 mov esi,3
 mov eax,319
 syscall
 cmp rax,-4
 je fresh_transaction_memfd
 mov r15,rax
 test rax,rax
 js meta_reply
 mov [rbp+SCRATCH+272],rax
fresh_transaction_chmod:
 mov rdi,[rbp+SCRATCH+272]
 mov esi,256
 mov eax,91
 syscall
 cmp rax,-4
 je fresh_transaction_chmod
 mov r15,rax
 test rax,rax
 js meta_reply
 mov r15,[rbp+SCRATCH+272]
 jmp meta_reply

private_transaction_pwrite:
 cmp QWORD PTR [rbp+OUTPUT+24],9
 jne protocol_exit
 cmp QWORD PTR [rbp+OUTPUT+32],256
 ja protocol_exit
 mov edi,9
 lea rsi,[rbp+OUTPUT+64]
 mov rdx,[rbp+OUTPUT+32]
 mov r10,[rbp+OUTPUT+40]
 mov eax,18
 syscall
 mov r15,rax
 jmp meta_reply

private_transaction_seal:
 cmp QWORD PTR [rbp+OUTPUT+24],9
 jne protocol_exit
 mov edi,9
 mov esi,1033
 mov edx,15
 mov eax,72
 syscall
 cmp rax,-4
 je private_transaction_seal
 mov r15,rax
 jmp meta_reply

source_owned_unmap:
 cmp QWORD PTR [rbp+OUTPUT+24],12
 jne protocol_exit
 mov rdi,[rbp+SCRATCH+256]
 mov rsi,[rbp+SCRATCH+264]
 cmp rsi,[rbp+OUTPUT+32]
 jne protocol_exit
 test rdi,rdi
 jz protocol_exit
 mov eax,11
 syscall
 mov r15,rax
 test rax,rax
 jnz meta_reply
 mov QWORD PTR [rbp+SCRATCH+256],0
 mov QWORD PTR [rbp+SCRATCH+264],0
 jmp meta_reply

staged_transaction_ready:
 cmp QWORD PTR [rbp+SCRATCH+272],9
 jne protocol_exit
 cmp QWORD PTR [rbp+SCRATCH+256],0
 jne protocol_exit
 lea rsi,[rbp+SCRATCH+512]
 mov rdi,rbp
 mov ecx,18
 rep movsq
 mov QWORD PTR [rbp+SCRATCH+128],0
 mov r12d,144
 jmp policy_loop

private_transaction_memfd_name: .asciz "hia-native-owned-transaction"

/* Direct input is a single length-prefixed proposal and EOF. Fd 8 reserves
 * the gap so the stager can allocate fd 9 exactly as in descriptor mode. */
direct_stage:
 mov r12d,3
direct_check_role:
 mov edi,r12d
 mov esi,1
 mov eax,72
 syscall
 cmp rax,-4
 je direct_check_role
 cmp rax,-9
 jne bad_exit
 inc r12d
 cmp r12d,12
 jbe direct_check_role

 mov rsi,r15
 cmp BYTE PTR [rsi],0
 je bad_exit
 mov rax,rsi
direct_path_end:
 inc rax
 cmp BYTE PTR [rax],0
 jne direct_path_end
 cmp BYTE PTR [rax-1],47
 je bad_exit
 mov edi,-100
 mov edx,OPEN_STORE_READ | 0x10000    /* DIRECTORY */
 xor r10d,r10d
 mov r12d,5
 call open_direct_role

 lea rsi,[rip+wal_data_name]
 mov edx,OPEN_STORE_WRITE
 mov r12d,3
 call open_direct_store_file
 lea rsi,[rip+initial_anchor_name]
 mov edx,OPEN_STORE_READ
 mov r12d,4
 call open_direct_store_file
 lea rsi,[rip+wal_lock_name]
 mov edx,OPEN_STORE_WRITE
 mov r12d,6
 call open_direct_store_file
 lea rsi,[rip+namespace_name]
 mov edx,OPEN_STORE_READ
 mov r12d,7
 call open_direct_store_file
 mov edi,5
 mov esi,8
 mov edx,0x80000
 mov eax,292
 syscall
 test rax,rax
 js io_exit

 mov rsi,rbp
 mov edx,8
 call read_stdin_exact
 mov r14,[rbp]
 cmp r14,32
 jb bad_exit
 cmp r14,PROPOSAL_LIMIT
 ja bad_exit
direct_create_proposal:
 lea rdi,[rip+direct_proposal_name]
 mov esi,3    /* CLOEXEC | ALLOW_SEALING */
 mov eax,319
 syscall
 cmp rax,-4
 je direct_create_proposal
 test rax,rax
 js io_exit
 mov r12d,12
 call position_direct_fd
direct_read_chunk:
 mov r13d,65536
 cmp r14,r13
 cmovb r13,r14
 mov rsi,rbp
 mov rdx,r13
 call read_stdin_exact
 xor ebx,ebx
direct_write_chunk:
 mov edi,12
 lea rsi,[rbp+rbx]
 mov rdx,r13
 sub rdx,rbx
 mov eax,1
 syscall
 cmp rax,-4
 je direct_write_chunk
 test rax,rax
 jle io_exit
 add rbx,rax
 cmp rbx,r13
 jb direct_write_chunk
 sub r14,r13
 jnz direct_read_chunk
 call require_stdin_eof
direct_chmod_proposal:
 mov edi,12
 mov esi,256
 mov eax,91
 syscall
 cmp rax,-4
 je direct_chmod_proposal
 test rax,rax
 js io_exit
direct_seal_proposal:
 mov edi,12
 mov esi,1033
 mov edx,15
 mov eax,72
 syscall
 cmp rax,-4
 je direct_seal_proposal
 test rax,rax
 js io_exit

 mov edi,5
 lea rsi,[rip+current_directory_name]
 mov edx,0x490002    /* TMPFILE | CLOEXEC | RDWR */
 mov r10d,384
 mov r12d,10
 call open_direct_role
 /* Read 129 to reject a long anchor, not merely accept a 128-byte prefix. */
 xor ebx,ebx
direct_read_anchor:
 mov edi,4
 lea rsi,[rbp+rbx]
 mov edx,129
 sub rdx,rbx
 mov r10,rbx
 mov eax,17
 syscall
 cmp rax,-4
 je direct_read_anchor
 test rax,rax
 js io_exit
 jz direct_anchor_eof
 add rbx,rax
 cmp rbx,129
 jb direct_read_anchor
 jmp bad_exit
direct_anchor_eof:
 cmp rbx,128
 jne bad_exit
 jmp prepare_anchor_policy

open_direct_store_file:
 mov edi,5
 xor r10d,r10d
open_direct_role:
 mov eax,257
 syscall
 cmp rax,-4
 je open_direct_role
 test rax,rax
 js io_exit
position_direct_fd:
 cmp eax,r12d
 je direct_fd_ready
 mov r8d,eax
direct_dup_role:
 mov edi,r8d
 mov esi,r12d
 mov edx,0x80000
 mov eax,292
 syscall
 cmp rax,-4
 je direct_dup_role
 test rax,rax
 js io_exit
 mov edi,r8d
 mov eax,3
 syscall
 test rax,rax
 js io_exit
direct_fd_ready:
 ret

read_stdin_exact:
 xor edi,edi
 xor eax,eax
 syscall
 cmp rax,-4
 je read_stdin_exact
 test rax,rax
 js io_exit
 jz bad_exit
 add rsi,rax
 sub rdx,rax
 jnz read_stdin_exact
 ret

require_stdin_eof:
 xor edi,edi
 lea rsi,[rbp+OUTPUT]
 mov edx,1
 xor eax,eax
 syscall
 cmp rax,-4
 je require_stdin_eof
 test rax,rax
 js io_exit
 jnz bad_exit
 ret

wal_data_name: .asciz "wal.data"
initial_anchor_name: .asciz "anchor.0000000000000000"
wal_lock_name: .asciz "wal.lock"
namespace_name: .asciz "namespace.bin"
direct_proposal_name: .asciz "hia-native-batch-proposal"
current_directory_name: .asciz "."
