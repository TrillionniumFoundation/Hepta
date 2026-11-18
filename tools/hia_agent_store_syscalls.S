.intel_syntax noprefix
.text
.global json_call_hole, _start, loader_call_hole, owner_call_hole, manifest_address_hole
.equ OUTPUT,131072
.equ SCRATCH,524288
.equ OWNERWORK,589824
.equ LOADERWORK,655360
.equ OWNEROUTPUT,1114112
.equ QUERYEXPORT,1245184
.equ PACKETEXPORT,1376256
.equ COPYBUFFER,1441792
.equ READER_WORK,1572864
.equ READER_TRANSIENT,196608
.equ READER_WITH_MEMO,6922760
.equ MAPSIZE,READER_WORK+READER_WITH_MEMO
.equ IO_MAGIC,0x314f494446414948
.equ ARGV_NAMESPACE,224
_start:
 cmp QWORD PTR [rsp],1
 je startup_roles
 mov rax,[rsp]
 sub rax,4
 cmp rax,1
 ja early_bad
startup_roles:
 /* Refuse occupied private roles before any possible dup3 replacement. */
 mov ebx,3
startup_probe:
 cmp QWORD PTR [rsp],1
 jne startup_probe_fd
 cmp ebx,8
 je startup_next
 cmp ebx,11
 je startup_next
 cmp ebx,20
 je startup_next
startup_probe_fd:
 mov edi,ebx
 mov esi,1
 mov eax,72
 syscall
 cmp rax,-9
 jne early_bad
startup_next:
 inc ebx
 cmp ebx,35
 jb startup_probe
 cmp QWORD PTR [rsp],1
 je startup_map
 cmp ebx,37
 jb startup_probe
startup_map:
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
 cmp QWORD PTR [rsp],1
 je startup_signal
 /* File mode opens only the operator's directory capabilities. The same
  * HIA loader and Store owner admit their metadata and children. */
 mov rax,[rsp+24]
 mov [rbp+SCRATCH+ARGV_NAMESPACE],rax
 mov rsi,[rsp+16]
 mov ebx,11
 call open_argument_directory
 /* In descriptor mode the executable already occupies slot 8. Reserve it
  * here too so native file creation cannot allocate that private slot. */
 mov edi,11
 mov esi,8
 mov edx,0x80000
 mov eax,292
 syscall
 test rax,rax
 js io_exit
 mov rsi,[rsp+32]
 mov ebx,20
 call open_argument_directory
 cmp QWORD PTR [rsp],5
 jne startup_signal
 mov rsi,[rsp+40]
 mov ebx,36
 call open_argument_directory
startup_signal:
 mov QWORD PTR [rbp+SCRATCH],1
 mov edi,13
 lea rsi,[rbp+SCRATCH]
 xor edx,edx
 mov r10d,8
 mov eax,13
 syscall
 test rax,rax
 js io_exit
 mov eax,107
 syscall
 mov [rbp+SCRATCH+480],rax
 mov eax,39
 syscall
 mov [rbp+SCRATCH+488],rax
 mov QWORD PTR [rbp+SCRATCH+56],20
 .byte 0x48,0x8d,0x35
manifest_address_hole: .long 0
 mov rdi,rbp
 mov ecx,544
 rep movsb
 mov rax,[rbp+SCRATCH+480]
 mov [rbp+544],rax
 mov rax,[rbp+SCRATCH+488]
 mov [rbp+552],rax
 mov r12d,560
 jmp policy_loop

open_argument_directory:
 mov edi,-100
 mov edx,0xb0000                  /* O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC */
 xor r10d,r10d
 mov eax,257                      /* openat */
 syscall
 cmp rax,-4
 je open_argument_directory
 test rax,rax
 js io_exit
 cmp rax,3
 jb protocol_exit
 cmp eax,ebx
 je argument_directory_ready
 mov r15,rax
 mov edi,eax
 mov esi,ebx
 mov edx,0x80000
 mov eax,292                      /* dup3 */
 syscall
 test rax,rax
 js io_exit
 mov rdi,r15
 mov eax,3                        /* close */
 syscall
 test rax,rax
 js io_exit
argument_directory_ready:
 ret

policy_loop:
 mov rdi,rbp
 mov rsi,r12
 lea rdx,[rbp+OUTPUT]
 mov ecx,131072
 mov rax,[rbp+SCRATCH+56]
 cmp rax,20
 je call_loader
 cmp rax,18
 je call_owner
 cmp rax,24
 ja protocol_exit
 lea rbx,[rip+unit_table]
 imul rax,rax,32
 add rbx,rax
 mov rax,[rbx]
 mov r11,[rbp+SCRATCH+256+rax*8]
 add r11,[rbx+8]
 mov r8,[rbx+16]
 add r8,rbp
 mov r9,[rbx+24]
 cmp QWORD PTR [rbp+SCRATCH+56],6
 jne fixed_output_ready
 mov ecx,128
fixed_output_ready:
 cmp QWORD PTR [rbp+SCRATCH+56],19
 je small_fixed_output
 cmp QWORD PTR [rbp+SCRATCH+56],21
 je small_fixed_output
 cmp QWORD PTR [rbp+SCRATCH+56],22
 je small_fixed_output
 cmp QWORD PTR [rbp+SCRATCH+56],24
 jne dynamic_output_checks
small_fixed_output:
 mov ecx,8192
dynamic_output_checks:
 cmp QWORD PTR [rbp+SCRATCH+56],2
 je dynamic_raw_unit
 cmp QWORD PTR [rbp+SCRATCH+56],10
 je dynamic_owned_unit
 cmp QWORD PTR [rbp+SCRATCH+56],11
 jne call_fixed_unit
dynamic_owned_unit:
 mov rdi,[rbp+SCRATCH+736]
 mov rsi,[rbp+SCRATCH+744]
 jmp dynamic_unit_output
dynamic_raw_unit:
 mov rdi,[rbp+SCRATCH+4096+15*16]
 mov rsi,[rbp+SCRATCH+4096+15*16+8]
dynamic_unit_output:
 mov rdx,[rbp+SCRATCH+512]
 mov rcx,[rbp+SCRATCH+520]
call_fixed_unit:
 call r11
 jmp policy_result
call_loader:
 lea r8,[rbp+LOADERWORK]
 mov r9d,65536
 .byte 0xe8
loader_call_hole: .long 0
 jmp policy_result
call_owner:
 lea rdx,[rbp+OWNEROUTPUT]
 lea r8,[rbp+OWNERWORK]
 mov r9d,65536
 .byte 0xe8
owner_call_hole: .long 0
 cmp rax,64
 jb protocol_exit
 cmp rax,131072
 ja protocol_exit
 mov [rbp+SCRATCH+608],rax
 mov rcx,rax
 lea rsi,[rbp+OWNEROUTPUT]
 lea rdi,[rbp+OUTPUT]
 rep movsb
 mov rax,[rbp+SCRATCH+608]
 jmp policy_result

policy_result:
 mov rbx,[rbp+SCRATCH+56]
 cmp rbx,2
 je pure_result
 cmp rbx,3
 je pure_result
 cmp rbx,4
 je pure_result
 cmp rbx,5
 je pure_result
 cmp rbx,6
 je pure_result
 cmp rbx,10
 je pure_result
 cmp rbx,11
 je pure_result
 cmp rbx,12
 je pure_result
 cmp rbx,13
 je pure_result
 cmp rax,64
 jb protocol_exit
 cmp rax,131072
 ja protocol_exit
 mov rdx,IO_MAGIC
 cmp [rbp+OUTPUT],rdx
 jne protocol_exit
 mov r13,[rbp+OUTPUT+8]
 mov r14,[rbp+OUTPUT+16]
 cmp rbx,20
 je loader_effect
 cmp rbx,18
 je owner_effect
 cmp rbx,22
 je frontend_effect
 cmp rbx,19
 je controller_effect
 cmp rbx,23
 je query_coprocessor_effect
 cmp rbx,24
 je artifact_capture_effect
 cmp rbx,14
 jae new_helper_effect
ordinary_helper_effect:
 cmp r14,23
 je query_coprocessor_call
 cmp r14,0
 je copy_packet
 cmp r14,9
 je inner_terminal
 cmp r14,19
 je opener_handoff
 cmp r14,50
 je stager_handoff
 cmp r14,8
 je inner_write
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
 cmp r14,15
 je open_owned
 cmp r14,16
 je dup_owned
 cmp r14,17
 je close_owned
 cmp r14,18
 je stat_owned_path
 cmp r14,21
 je create_private
 cmp r14,22
 je sealed_stat
 cmp r14,30
 je proposal_map
 cmp r14,31
 je producer_next
 cmp r14,34
 je proposal_unmap
 cmp r14,43
 je writer_stage_create
 cmp r14,45
 je fd_pwrite
 cmp r14,46
 je add_seals
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

pure_result:
 mov r15,rax
 xor ebx,ebx
 cmp rax,64
 jb return_owner
 cmp QWORD PTR [rbp+SCRATCH+56],2
 je pure_dynamic
 cmp QWORD PTR [rbp+SCRATCH+56],10
 je pure_dynamic
 cmp QWORD PTR [rbp+SCRATCH+56],11
 jne pure_fixed
pure_dynamic:
 mov [rbp+SCRATCH+704],rax
 cmp rax,[rbp+SCRATCH+520]
 ja protocol_exit
 mov ebx,64
 mov rsi,[rbp+SCRATCH+512]
 jmp pure_copy
pure_fixed:
 cmp rax,320
 ja protocol_exit
 mov rbx,rax
 lea rsi,[rbp+OUTPUT]
 cmp QWORD PTR [rbp+SCRATCH+56],3
 je export_packet_result
 cmp QWORD PTR [rbp+SCRATCH+56],12
 jne pure_copy
export_packet_result:
 mov rcx,rax
 lea rdi,[rbp+PACKETEXPORT]
 rep movsb
 mov [rbp+SCRATCH+696],rbx
 lea rsi,[rbp+PACKETEXPORT]
pure_copy:
 lea rdi,[rbp+32]
 mov rcx,rbx
 rep movsb
 jmp return_owner

inner_terminal:
 mov r15,[rbp+OUTPUT+24]
 xor ebx,ebx
 cmp QWORD PTR [rbp+SCRATCH+56],9
 jne return_owner
 /* Writer itself owns known-vs-unknown mutation fencing. */
 jmp return_owner
opener_handoff:
 cmp QWORD PTR [rbp+SCRATCH+56],0
 jne protocol_exit
 cmp QWORD PTR [rbp+OUTPUT+32],176
 jne protocol_exit
 mov r15d,176
 mov ebx,176
 lea rsi,[rbp+OUTPUT+64]
 lea rdi,[rbp+32]
 mov ecx,176
 rep movsb
 jmp return_owner
inner_write:
 cmp QWORD PTR [rbp+SCRATCH+56],1
 jne write_receipt
 mov rbx,[rbp+OUTPUT+32]
 cmp rbx,131008
 ja protocol_exit
 mov [rbp+SCRATCH+600],r13
 mov [rbp+SCRATCH+688],rbx
 mov rcx,rbx
 lea rsi,[rbp+OUTPUT+64]
 lea rdi,[rbp+QUERYEXPORT]
 rep movsb
 lea rsi,[rbp+QUERYEXPORT]
 lea rdi,[rbp+32]
 mov rcx,rbx
 rep movsb
 mov r15,rbx
 jmp return_owner

return_owner:
 mov rcx,[rbp+SCRATCH+768]
 test rcx,rcx
 jz protocol_exit
 dec rcx
 mov [rbp+SCRATCH+768],rcx
 shl rcx,5
 lea rdx,[rbp+SCRATCH+784+rcx]
 mov rax,[rdx]
 mov [rbp+SCRATCH+56],rax
 mov rax,IO_MAGIC
 mov [rbp],rax
 mov rax,[rdx+8]
 mov [rbp+8],rax
 mov rax,[rdx+16]
 mov [rbp+16],rax
 mov [rbp+24],r15
 lea r12,[rbx+32]
 jmp policy_loop

owner_effect:
 cmp r14,19
 je generic_handoff
 cmp r14,0
 je owner_empty_reply
 cmp r14,9
 je owner_process_exit
 cmp r14,10
 je dir_reset
 cmp r14,11
 je dir_entries
 cmp r14,22
 je sealed_stat
 cmp r14,101
 je owner_probe
 cmp r14,102
 je owner_create
 cmp r14,103
 je add_seals
 cmp r14,104
 je owner_copy
 cmp r14,105
 je owner_compare
 cmp r14,106
 je owner_map
 cmp r14,107
 je owner_close
 cmp r14,108
 je raw_private_view
 cmp r14,109
 je owner_unit
 cmp r14,110
 je read_meta
 cmp r14,111
 je owner_random
 cmp r14,112
 je owner_sql_write
 cmp r14,114
 je query_resume
 jmp protocol_exit
owner_empty_reply:
 xor r15d,r15d
 jmp meta_reply
owner_probe:
 mov rdi,[rbp+OUTPUT+24]
 mov esi,1
 mov eax,72
 syscall
 mov r15,rax
 test rax,rax
 js meta_reply
 xor r15d,r15d
 jmp meta_reply
owner_process_exit:
 cmp QWORD PTR [rbp+SCRATCH+56],20
 je outer_process_exit
 cmp QWORD PTR [rbp+SCRATCH+56],22
 je outer_process_exit
 cmp QWORD PTR [rbp+SCRATCH+768],0
 jne inner_terminal
 jmp protocol_exit
outer_process_exit:
 mov rdi,[rbp+OUTPUT+24]
 jmp process_exit

owner_unit:
 mov rbx,[rbp+OUTPUT+24]
 mov rax,[rbp+SCRATCH+56]
 cmp rax,22
 jne check_controller_call
 cmp rbx,19
 je owner_unit_allowed
 cmp rbx,24
 jne protocol_exit
 jmp owner_unit_allowed
check_controller_call:
 cmp rax,19
 jne check_owner_call
 cmp rbx,0
 je owner_unit_allowed
 cmp rbx,1
 je owner_unit_allowed
 cmp rbx,8
 je controller_writer_call
 cmp rbx,14
 jb protocol_exit
 cmp rbx,18
 jbe owner_unit_allowed
 cmp rbx,21
 jne protocol_exit
 jmp owner_unit_allowed
controller_writer_call:
 mov ebx,9
 jmp owner_unit_allowed
check_owner_call:
 cmp rax,18
 jne protocol_exit
 cmp rbx,7
 jbe owner_unit_allowed
 cmp rbx,10
 jb protocol_exit
 cmp rbx,13
 ja protocol_exit
owner_unit_allowed:
 call push_native_parent
 mov [rbp+SCRATCH+56],rbx
 mov [rbp+SCRATCH+616],rbx
 cmp rbx,7
 je start_commit
 cmp QWORD PTR [rbp+OUTPUT+56],0
 je owner_unit_input
 cmp rbx,17
 jne reset_non_stager
 lea rdi,[rbp+1011712]
 mov ecx,16384
 xor eax,eax
 rep stosb
reset_non_stager:
 cmp rbx,18
 jne reset_bundled_unit
 lea rdi,[rbp+OWNERWORK]
 mov ecx,65536
 jmp reset_native_work
reset_bundled_unit:
 lea rax,[rip+unit_table]
 imul rcx,rbx,32
 add rax,rcx
 mov rdi,[rax+16]
 add rdi,rbp
 mov rcx,[rax+24]
reset_native_work:
 /* The reader resets transaction state but retains its private memo suffix.
  * HIA compares the complete inputs before reusing either digest. */
 cmp rbx,1
 jne reset_native_work_full
 mov ecx,READER_TRANSIENT
reset_native_work_full:
 xor eax,eax
 rep stosb
owner_unit_input:
 cmp rbx,2
 je binder_output
 cmp rbx,10
 je dynamic_owned_input
 cmp rbx,11
 je dynamic_owned_input
 cmp rbx,12
 je mapped_unit_input
 cmp rbx,13
 je mapped_unit_input
 cmp rbx,3
 je mapped_unit_input
 cmp rbx,4
 je mapped_unit_input
 cmp rbx,5
 je mapped_unit_input
 mov r12,[rbp+OUTPUT+40]
 cmp r12,131008
 ja protocol_exit
 mov rcx,r12
 lea rsi,[rbp+OUTPUT+64]
 mov rdi,rbp
 rep movsb
 jmp policy_loop
dynamic_owned_input:
 mov rax,[rbp+OUTPUT+32]
 shl rax,4
 mov rsi,[rbp+SCRATCH+4096+rax]
 mov [rbp+SCRATCH+736],rsi
 mov rax,[rbp+OUTPUT+40]
 mov [rbp+SCRATCH+744],rax
 jmp binder_output
mapped_unit_input:
 mov rax,[rbp+OUTPUT+32]
 shl rax,4
 mov rsi,[rbp+SCRATCH+4096+rax]
 /* Input pointers stay private; pure units use a separate entry lane. */
 mov [rbp+SCRATCH+624],rsi
 mov rax,[rbp+SCRATCH+616]
 lea rbx,[rip+unit_table]
 imul rax,rax,32
 add rbx,rax
 mov rax,[rbx]
 mov r11,[rbp+SCRATCH+256+rax*8]
 add r11,[rbx+8]
 mov rdi,[rbp+SCRATCH+624]
 mov rsi,[rbp+OUTPUT+40]
 lea rdx,[rbp+OUTPUT]
 mov ecx,320
 cmp QWORD PTR [rbp+SCRATCH+616],3
 je mapped_capacity_ok
 cmp QWORD PTR [rbp+SCRATCH+616],12
 je mapped_capacity_ok
 mov ecx,64
mapped_capacity_ok:
 mov r8,[rbx+16]
 add r8,rbp
 mov r9,[rbx+24]
 call r11
 jmp policy_result
query_resume:
 call push_native_parent
 mov rax,IO_MAGIC
 mov [rbp],rax
 mov rax,[rbp+SCRATCH+600]
 mov [rbp+8],rax
 mov QWORD PTR [rbp+16],8
 mov rax,[rbp+OUTPUT+32]
 mov [rbp+24],rax
 mov r12d,32
 mov QWORD PTR [rbp+SCRATCH+56],1
 jmp policy_loop

/* Allocate native binder output from original raw size +512, not 128KiB. */
binder_output:
 mov rdi,[rbp+SCRATCH+512]
 test rdi,rdi
 jz binder_allocate
 mov rsi,[rbp+SCRATCH+520]
 mov eax,11
 syscall
 test rax,rax
 js io_exit
binder_allocate:
 mov rsi,[rbp+OUTPUT+40]
 add rsi,512
 jc protocol_exit
 mov [rbp+SCRATCH+520],rsi
 xor edi,edi
 mov edx,3
 mov r10d,0x22
 mov r8,-1
 xor r9d,r9d
 mov eax,9
 syscall
 cmp rax,-4095
 jae owner_kernel_error
 mov [rbp+SCRATCH+512],rax
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
 je fd_stat_seals
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
 mov QWORD PTR [rbp+SCRATCH+32],1
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
 mov rdx,[rbp+OUTPUT+32]
 cmp rdx,131008
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


open_owned:
 mov rcx,[rbp+OUTPUT+56]
 test rcx,rcx
 jz protocol_exit
 cmp rcx,256
 ja protocol_exit
 lea rdx,[rcx+64]
 cmp rax,rdx
 jb protocol_exit
 cmp BYTE PTR [rbp+OUTPUT+63+rcx],0
 jne protocol_exit
 mov rax,[rbp+OUTPUT+32]
 mov [rbp+SCRATCH+64],rax
 mov QWORD PTR [rbp+SCRATCH+72],0
 mov rax,[rbp+OUTPUT+40]
 mov [rbp+SCRATCH+80],rax
open_owned_retry:
 mov rdi,[rbp+OUTPUT+24]
 lea rsi,[rbp+OUTPUT+64]
 lea rdx,[rbp+SCRATCH+64]
 mov r10d,24
 mov eax,437
 syscall
 cmp rax,-4
 je open_owned_retry
 mov r15,rax
 cmp rax,3
 jb meta_reply
 cmp rax,7
 ja meta_reply
 bts QWORD PTR [rbp+SCRATCH+96],rax
 jmp meta_reply
dup_owned:
 cmp QWORD PTR [rbp+SCRATCH+56],19
 jne legacy_dup_owned
 mov rdi,[rbp+OUTPUT+32]
 cmp rdi,3
 je controller_dup_target
 cmp rdi,4
 je controller_dup_target
 cmp rdi,12
 je controller_dup_target
 cmp rdi,27
 je controller_dup_target
 cmp rdi,28
 je controller_dup_target
 cmp rdi,29
 je controller_dup_target
 cmp rdi,33
 je controller_dup_target
 cmp rdi,34
 jne protocol_exit
controller_dup_target:
 mov esi,1
 mov eax,72
 syscall
 cmp rax,-9
 jne protocol_exit
legacy_dup_owned:
 mov rdi,[rbp+OUTPUT+24]
 mov rsi,[rbp+OUTPUT+32]
 mov edx,0x80000
 mov eax,292
 syscall
 mov r15,rax
 test rax,rax
 js meta_reply
 mov rcx,[rbp+OUTPUT+32]
 cmp QWORD PTR [rbp+SCRATCH+56],19
 jne legacy_dup_admission
 bts QWORD PTR [rbp+SCRATCH+664],rcx
 jmp meta_reply
legacy_dup_admission:
 cmp rcx,3
 jb protocol_exit
 cmp rcx,10
 je dup_fixed_stage
 cmp rcx,7
 ja protocol_exit
dup_fixed_stage:
 bts QWORD PTR [rbp+SCRATCH+96],rcx
 jmp meta_reply
close_owned:
 mov rdi,[rbp+OUTPUT+24]
 mov eax,3
 syscall
 mov r15,rax
 mov rcx,[rbp+OUTPUT+24]
 btr QWORD PTR [rbp+SCRATCH+664],rcx
 cmp rcx,3
 jb meta_reply
 cmp rcx,7
 ja meta_reply
 btr QWORD PTR [rbp+SCRATCH+96],rcx
 jmp meta_reply
stat_owned_path:
 mov rcx,[rbp+OUTPUT+56]
 test rcx,rcx
 jz protocol_exit
 cmp rcx,256
 ja protocol_exit
 lea rdx,[rcx+64]
 cmp rax,rdx
 jb protocol_exit
 cmp BYTE PTR [rbp+OUTPUT+63+rcx],0
 jne protocol_exit
stat_owned_path_retry:
 mov rdi,[rbp+OUTPUT+24]
 lea rsi,[rbp+OUTPUT+64]
 lea rdx,[rbp+32]
 mov r10d,256
 mov eax,262
 syscall
 cmp rax,-4
 je stat_owned_path_retry
 mov r15,rax
 test rax,rax
 js meta_reply
 mov QWORD PTR [rbp+176],0
 call make_meta
 mov r12d,184
 jmp policy_loop


owner_boot_input:
 mov rsi,[rbp+SCRATCH+ARGV_NAMESPACE]
 test rsi,rsi
 jnz boot_argument_name
 xor ebx,ebx
boot_length_next:
 xor edi,edi
 lea rsi,[rbp+rbx+32]
 mov edx,8
 sub rdx,rbx
 xor eax,eax
 syscall
 cmp rax,-4
 je boot_length_next
 test rax,rax
 js io_exit
 jz protocol_exit
 add rbx,rax
 cmp rbx,8
 jb boot_length_next
 mov rax,[rbp+32]
 test rax,rax
 jz protocol_exit
 cmp rax,256
 ja protocol_exit
 mov [rbp+SCRATCH+752],rax
 xor ebx,ebx
boot_path_next:
 xor edi,edi
 lea rsi,[rbp+rbx+40]
 mov rdx,[rbp+SCRATCH+752]
 sub rdx,rbx
 xor eax,eax
 syscall
 cmp rax,-4
 je boot_path_next
 test rax,rax
 js io_exit
 jz protocol_exit
 add rbx,rax
 cmp rbx,[rbp+SCRATCH+752]
 jb boot_path_next
 jmp boot_path_ready
boot_argument_name:
 xor ebx,ebx
boot_argument_next:
 mov al,[rsi+rbx]
 test al,al
 jz boot_argument_end
 cmp ebx,256
 jae protocol_exit
 mov [rbp+rbx+40],al
 inc ebx
 jmp boot_argument_next
boot_argument_end:
 test ebx,ebx
 jz protocol_exit
boot_path_ready:
 mov rax,0x3130435854414948
 mov [rbp],rax
 mov QWORD PTR [rbp+8],2
 mov rax,[rbp+SCRATCH+480]
 mov [rbp+16],rax
 mov rax,[rbp+SCRATCH+488]
 mov [rbp+24],rax
 mov [rbp+32],rbx
 lea r12,[rbx+40]
 mov QWORD PTR [rbp+SCRATCH+56],22
 jmp policy_loop

fd_stat_seals:
 mov edi,9
 jmp seals_after_flags
sealed_stat:
 mov rdi,[rbp+OUTPUT+24]
 lea rsi,[rbp+32]
 mov eax,5
 syscall
 cmp rax,-4
 je sealed_stat
 test rax,rax
 js generic_negative
sealed_flags:
 mov rdi,[rbp+OUTPUT+24]
 mov esi,3
 mov eax,72
 syscall
 cmp rax,-4
 je sealed_flags
 test rax,rax
 js generic_negative
 mov [rbp+176],rax
 mov rdi,[rbp+OUTPUT+24]
seals_after_flags:
 mov esi,1034
 mov eax,72
 syscall
 cmp rax,-4
 je seals_after_flags
 test rax,rax
 js generic_negative
 mov [rbp+184],rax
 xor r15d,r15d
 call make_meta
 mov r12d,192
 jmp policy_loop

create_private:
 cmp QWORD PTR [rbp+SCRATCH+56],0
 je opener_private_stage
 cmp QWORD PTR [rbp+SCRATCH+56],1
 jne protocol_exit
 mov rbx,[rbp+OUTPUT+32]
 cmp rbx,13
 je create_spool
 cmp rbx,14
 jne protocol_exit
create_spool:
 mov edi,5
 lea rsi,[rip+private_dot]
 mov edx,0x4b0002
 mov r10d,0x180
 mov eax,257
 syscall
 cmp rax,-4
 je create_spool
 test rax,rax
 js generic_negative
 mov r12,rax
 cmp r12,rbx
 je spool_ready
 mov rdi,r12
 mov rsi,rbx
 mov edx,0x80000
 mov eax,292
 syscall
 mov r15,rax
 mov rdi,r12
 mov eax,3
 syscall
 test r15,r15
 js meta_reply
spool_ready:
 bts QWORD PTR [rbp+SCRATCH+664],rbx
 mov r15,rbx
 jmp meta_reply
opener_private_stage:
 /* Native opener's original action21 is path open O_TMPFILE, followed
  * by its original dup/stat admission into owned stage10. */
 mov rdi,[rbp+OUTPUT+24]
 lea rsi,[rbp+OUTPUT+64]
 mov rdx,[rbp+OUTPUT+32]
 mov r10d,0x180
 mov eax,257
 syscall
 cmp rax,-4
 je opener_private_stage
 mov r15,rax
 jmp meta_reply

owner_create:
 mov rbx,[rbp+OUTPUT+24]
 call create_private_memfd
 mov r15,rax
 jmp meta_reply
writer_stage_create:
 mov ebx,9
 call create_private_memfd
 test rax,rax
 js generic_negative
 mov r15d,9
 jmp meta_reply
create_private_memfd:
 mov rdi,rbx
 mov esi,1
 mov eax,72
 syscall
 cmp rax,-9
 jne create_occupied
 lea rdi,[rip+owner_memfd_name]
 mov esi,3
 mov eax,319
 syscall
 cmp rax,-4
 je create_private_memfd
 test rax,rax
 js create_return
 mov r12,rax
 mov rdi,r12
 mov esi,0x100
 mov eax,91
 syscall
 test rax,rax
 js create_cleanup
 cmp r12,rbx
 je create_owned
 mov rdi,r12
 mov rsi,rbx
 mov edx,0x80000
 mov eax,292
 syscall
 test rax,rax
 js create_cleanup
 mov rdi,r12
 mov eax,3
 syscall
 test rax,rax
 js create_return
create_owned:
 bts QWORD PTR [rbp+SCRATCH+664],rbx
 xor eax,eax
 ret
create_cleanup:
 mov r15,rax
 mov rdi,r12
 mov eax,3
 syscall
 mov rax,r15
 ret
create_occupied:
 mov rax,-9
create_return:
 ret

add_seals:
 mov rdi,[rbp+OUTPUT+24]
 mov esi,1033
 mov edx,15
 mov eax,72
 syscall
 cmp rax,-4
 je add_seals
 jmp generic_negative

owner_map:
 mov rbx,[rbp+OUTPUT+24]
 mov rsi,[rbp+OUTPUT+32]
 xor edi,edi
 mov edx,1
 mov r10d,2
 mov r8,rbx
 xor r9d,r9d
 mov eax,9
 syscall
 cmp rax,-4095
 jae generic_negative
 imul rbx,rbx,16
 mov [rbp+SCRATCH+4096+rbx],rax
 mov rax,[rbp+OUTPUT+32]
 mov [rbp+SCRATCH+4096+rbx+8],rax
 xor r15d,r15d
 jmp meta_reply
owner_close:
 mov rbx,[rbp+OUTPUT+24]
 bt QWORD PTR [rbp+SCRATCH+664],rbx
 jnc protocol_exit
 imul rax,rbx,16
 mov [rbp+SCRATCH+672],rax
 mov rdi,[rbp+SCRATCH+4096+rax]
 test rdi,rdi
 jz owner_close_fd
 mov rsi,[rbp+SCRATCH+4096+rax+8]
 mov eax,11
 syscall
 test rax,rax
 js generic_negative
owner_close_fd:
 mov rdi,rbx
 mov eax,3
 syscall
 mov r15,rax
 btr QWORD PTR [rbp+SCRATCH+664],rbx
 mov rax,[rbp+SCRATCH+672]
 mov QWORD PTR [rbp+SCRATCH+4096+rax],0
 mov QWORD PTR [rbp+SCRATCH+4096+rax+8],0
 jmp meta_reply

raw_private_view:
 mov rdi,[rbp+SCRATCH+4096+15*16]
 test rdi,rdi
 jz raw_map
 mov rsi,[rbp+SCRATCH+4096+15*16+8]
 mov eax,11
 syscall
 test rax,rax
 js generic_negative
raw_map:
 xor edi,edi
 mov rsi,[rbp+OUTPUT+32]
 mov edx,3
 mov r10d,2
 mov r8d,15
 xor r9d,r9d
 mov eax,9
 syscall
 cmp rax,-4095
 jae generic_negative
 mov [rbp+SCRATCH+4096+15*16],rax
 mov rdx,[rbp+OUTPUT+40]
 mov [rax+24],rdx
 mov rdi,rax
 mov rsi,[rbp+OUTPUT+32]
 mov [rbp+SCRATCH+4096+15*16+8],rsi
 mov edx,1
 mov eax,10
 syscall
 jmp generic_negative

/* Reference selection copies opaque ranges only. Equality is native HIA. */
reference_bytes:
 mov rdx,[rbp+OUTPUT+32]
 cmp rdx,65536
 ja protocol_exit
 mov rax,[rbp+OUTPUT+48]
 mov r10,[rbp+OUTPUT+56]
 test rax,rax
 jz reference_header
 cmp rax,1
 je reference_binder
 cmp rax,2
 je reference_query
 cmp rax,3
 je reference_packet
 cmp rax,15
 je reference_file
 cmp rax,21
 je reference_file
 cmp rax,23
 je reference_file
 cmp rax,25
 jne protocol_exit
reference_file:
 mov rdi,rax
 lea rsi,[rbp+COPYBUFFER]
 call pread_full
 lea rsi,[rbp+COPYBUFFER]
 ret
reference_header:
 lea rsi,[rbp+OUTPUT+64]
 mov rax,rdx
 ret
reference_binder:
 mov rsi,[rbp+SCRATCH+512]
 mov rcx,[rbp+SCRATCH+704]
 jmp reference_memory
reference_query:
 lea rsi,[rbp+QUERYEXPORT]
 mov rcx,[rbp+SCRATCH+688]
 jmp reference_memory
reference_packet:
 lea rsi,[rbp+PACKETEXPORT]
 mov rcx,[rbp+SCRATCH+696]
reference_memory:
 cmp r10,rcx
 ja protocol_exit
 sub rcx,r10
 cmp rdx,rcx
 ja protocol_exit
 add rsi,r10
 mov rax,rdx
 ret
owner_copy:
 call reference_bytes
 test rax,rax
 js generic_negative
 mov rdx,rax
 mov rdi,[rbp+OUTPUT+24]
 mov r10,[rbp+OUTPUT+40]
 mov eax,18
 syscall
 jmp generic_negative
owner_compare:
 call reference_bytes
 test rax,rax
 js generic_negative
 mov [rbp+SCRATCH+712],rax
 mov [rbp+SCRATCH+720],rsi
 mov rdi,[rbp+OUTPUT+24]
 lea rsi,[rbp+32]
 mov rdx,[rbp+OUTPUT+32]
 mov r10,[rbp+OUTPUT+40]
 call pread_full
 test rax,rax
 js generic_negative
 lea rdi,[rbp+rax+32]
 mov rsi,[rbp+SCRATCH+720]
 mov rcx,[rbp+SCRATCH+712]
 mov r15,rax
 add r15,rcx
 rep movsb
 call make_meta
 lea r12,[r15+32]
 jmp policy_loop

/* Mechanical short-read/EINTR completion, returns actual count or errno. */
pread_full:
 push rbx
 push r12
 push r13
 push r14
 mov r12,rsi
 mov r13,rdx
 mov r14,r10
 xor ebx,ebx
pread_full_next:
 lea rsi,[r12+rbx]
 mov rdx,r13
 sub rdx,rbx
 lea r10,[r14+rbx]
 mov eax,17
 syscall
 cmp rax,-4
 je pread_full_next
 test rax,rax
 js pread_full_return
 jz pread_full_done
 add rbx,rax
 cmp rbx,r13
 jb pread_full_next
pread_full_done:
 mov rax,rbx
pread_full_return:
 pop r14
 pop r13
 pop r12
 pop rbx
 ret

owner_random:
 lea rdi,[rbp+32]
 mov rsi,[rbp+OUTPUT+32]
 xor edx,edx
 mov eax,318
 syscall
 cmp rax,-4
 je owner_random
 mov r15,rax
 test rax,rax
 js meta_reply
 call make_meta
 lea r12,[r15+32]
 jmp policy_loop
owner_sql_write:
 xor ebx,ebx
owner_sql_next:
 mov edi,1
 lea rsi,[rbp+OUTPUT+rbx+64]
 mov rdx,[rbp+OUTPUT+32]
 sub rdx,rbx
 mov eax,1
 syscall
 cmp rax,-4
 je owner_sql_next
 test rax,rax
 js generic_negative
 jz owner_sql_zero
 add rbx,rax
 cmp rbx,[rbp+OUTPUT+32]
 jb owner_sql_next
 xor r15d,r15d
 jmp meta_reply
owner_sql_zero:
 mov rax,-5
 jmp generic_negative

start_commit:
 /* Save native writer request while stager and producer use shared IO. */
 lea rsi,[rbp+OUTPUT+64]
 lea rdi,[rbp+SCRATCH+1024]
 mov ecx,144
 rep movsb
 lea rdi,[rbp+1003520]
 xor eax,eax
 mov ecx,57344
 rep stosb
 mov rax,0x3154535854414948
 mov [rbp],rax
 mov QWORD PTR [rbp+8],1
 mov rax,[rbp+SCRATCH+480]
 mov [rbp+16],rax
 mov rax,[rbp+SCRATCH+488]
 mov [rbp+24],rax
 mov edi,9
 mov esi,1
 mov eax,72
 syscall
 mov [rbp+32],rax
 mov r12d,40
 mov QWORD PTR [rbp+SCRATCH+56],7
 jmp policy_loop
proposal_map:
 xor edi,edi
 mov rsi,[rbp+OUTPUT+32]
 mov edx,1
 mov r10d,2
 mov r8d,12
 xor r9d,r9d
 mov eax,9
 syscall
 cmp rax,-4095
 jae generic_negative
 mov [rbp+SCRATCH+648],rax
 mov rdx,[rbp+OUTPUT+32]
 mov [rbp+SCRATCH+656],rdx
 mov r15,rax
 jmp meta_reply
proposal_unmap:
 mov rdi,[rbp+SCRATCH+648]
 mov rsi,[rbp+SCRATCH+656]
 mov eax,11
 syscall
 mov QWORD PTR [rbp+SCRATCH+648],0
 jmp generic_negative
producer_next:
 mov [rbp+SCRATCH+632],r13
 mov rdi,[rbp+SCRATCH+648]
 mov rsi,[rbp+SCRATCH+656]
 lea rdx,[rbp+OUTPUT]
 mov ecx,131072
 lea r8,[rbp+1011712]
 mov r9d,16384
 mov r11,[rbp+SCRATCH+256+3*8]
 add r11,354960
 call r11
 mov r15,rax
 xor ebx,ebx
 cmp rax,64
 jb producer_callback
 cmp rax,131072
 ja protocol_exit
 mov rbx,rax
 lea rsi,[rbp+OUTPUT]
 lea rdi,[rbp+32]
 mov rcx,rax
 rep movsb
producer_callback:
 mov r13,[rbp+SCRATCH+632]
 mov r14d,31
 call make_meta
 lea r12,[rbx+32]
 jmp policy_loop
stager_handoff:
 cmp QWORD PTR [rbp+SCRATCH+56],17
 jne legacy_stager_handoff
 xor r15d,r15d
 xor ebx,ebx
 jmp return_owner
legacy_stager_handoff:
 cmp QWORD PTR [rbp+SCRATCH+56],7
 jne protocol_exit
 lea rsi,[rbp+SCRATCH+1024]
 mov rdi,rbp
 mov ecx,144
 rep movsb
 mov r12d,144
 mov QWORD PTR [rbp+SCRATCH+56],9
 jmp policy_loop

owner_kernel_error:
 mov r15,rax
 xor ebx,ebx
 jmp return_owner
generic_negative:
 mov r15,rax
 jmp meta_reply
protocol_exit:
 mov edi,73
 jmp maybe_unknown
io_exit:
 mov edi,74
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
private_dot: .asciz "."
owner_memfd_name: .asciz "hia-native-INSERT-owned"

loader_effect:
 cmp r14,0
 je copy_packet
 cmp r14,9
 je owner_process_exit
 cmp r14,40
 je module_open
 cmp r14,41
 je module_stat
 cmp r14,42
 je module_read
 cmp r14,43
 je module_create
 cmp r14,44
 je module_private_stat
 cmp r14,45
 je module_write
 cmp r14,46
 je module_seal
 cmp r14,47
 je module_map
 cmp r14,48
 je module_path_stat
 cmp r14,49
 je module_close
 cmp r14,50
 je modules_ready
 jmp protocol_exit

module_open:
 cmp rax,128
 jne protocol_exit
 cmp QWORD PTR [rbp+OUTPUT+24],20
 jne protocol_exit
 cmp QWORD PTR [rbp+OUTPUT+32],64
 jne protocol_exit
 cmp QWORD PTR [rbp+SCRATCH+448],0
 jne protocol_exit
 mov QWORD PTR [rbp+SCRATCH+112],655360
 mov QWORD PTR [rbp+SCRATCH+120],0
 mov QWORD PTR [rbp+SCRATCH+128],14
module_open_retry:
 mov edi,20
 lea rsi,[rbp+OUTPUT+64]
 lea rdx,[rbp+SCRATCH+112]
 mov r10d,24
 mov eax,437
 syscall
 cmp rax,-4
 je module_open_retry
 test rax,rax
 js module_negative_reply
 mov rbx,rax
 cmp rbx,16
 je module_source_owned
 mov rdi,rbx
 mov esi,16
 mov edx,0x80000
 mov eax,292
 syscall
 mov r15,rax
 mov rdi,rbx
 mov eax,3
 syscall
 test r15,r15
 js meta_reply
module_source_owned:
 mov QWORD PTR [rbp+SCRATCH+448],1
 mov r15d,16
 jmp meta_reply

module_stat:
 cmp rax,64
 jne protocol_exit
 mov rdi,[rbp+OUTPUT+24]
 cmp rdi,20
 je module_stat_retry
 cmp rdi,16
 jne protocol_exit
 test QWORD PTR [rbp+SCRATCH+448],1
 jz protocol_exit
module_stat_retry:
 lea rsi,[rbp+32]
 mov eax,5
 syscall
 cmp rax,-4
 je module_stat_retry
 test rax,rax
 js module_negative_reply
module_flags_retry:
 mov rdi,[rbp+OUTPUT+24]
 mov esi,3
 mov eax,72
 syscall
 cmp rax,-4
 je module_flags_retry
 test rax,rax
 js module_negative_reply
 mov [rbp+176],rax
 xor r15d,r15d
 call make_meta
 mov r12d,184
 jmp policy_loop

module_read:
 cmp rax,64
 jne protocol_exit
 cmp QWORD PTR [rbp+OUTPUT+24],16
 jne protocol_exit
 test QWORD PTR [rbp+SCRATCH+448],1
 jz protocol_exit
 mov rdx,[rbp+OUTPUT+32]
 test rdx,rdx
 jz protocol_exit
 cmp rdx,32768
 ja protocol_exit
 mov r10,[rbp+OUTPUT+40]
 cmp r10,1048576
 ja protocol_exit
 mov edi,16
 lea rsi,[rbp+32]
 mov eax,17
 syscall
 mov r15,rax
 call make_meta
 test r15,r15
 js policy_loop
 add r12,r15
 jmp policy_loop

module_create:
 cmp rax,64
 jne protocol_exit
 cmp QWORD PTR [rbp+SCRATCH+448],1
 jne protocol_exit
module_memfd_retry:
 lea rdi,[rip+module_memfd_name]
 mov esi,3
 mov eax,319
 syscall
 cmp rax,-4
 je module_memfd_retry
 test rax,rax
 js module_negative_reply
 mov rbx,rax
 cmp rbx,17
 je module_memfd_owned
 mov rdi,rbx
 mov esi,17
 mov edx,0x80000
 mov eax,292
 syscall
 mov r15,rax
 mov rdi,rbx
 mov eax,3
 syscall
 test r15,r15
 js meta_reply
module_memfd_owned:
 mov QWORD PTR [rbp+SCRATCH+448],3
module_mode_retry:
 mov edi,17
 mov esi,256
 mov eax,91
 syscall
 cmp rax,-4
 je module_mode_retry
 test rax,rax
 js module_negative_reply
 mov r15d,17
 jmp meta_reply

module_private_stat:
 cmp rax,64
 jne protocol_exit
 test QWORD PTR [rbp+SCRATCH+448],2
 jz protocol_exit
module_private_fstat_retry:
 mov edi,17
 lea rsi,[rbp+32]
 mov eax,5
 syscall
 cmp rax,-4
 je module_private_fstat_retry
 test rax,rax
 js module_negative_reply
module_private_flags_retry:
 mov edi,17
 mov esi,3
 mov eax,72
 syscall
 cmp rax,-4
 je module_private_flags_retry
 test rax,rax
 js module_negative_reply
 mov [rbp+176],rax
module_get_seals_retry:
 mov edi,17
 mov esi,1034
 mov eax,72
 syscall
 cmp rax,-4
 je module_get_seals_retry
 test rax,rax
 js module_negative_reply
 mov [rbp+184],rax
 xor r15d,r15d
 call make_meta
 mov r12d,192
 jmp policy_loop

module_write:
 cmp QWORD PTR [rbp+OUTPUT+24],17
 jne protocol_exit
 test QWORD PTR [rbp+SCRATCH+448],2
 jz protocol_exit
 mov rdx,[rbp+OUTPUT+32]
 test rdx,rdx
 jz protocol_exit
 cmp rdx,32768
 ja protocol_exit
 lea rcx,[rdx+64]
 cmp rax,rcx
 jne protocol_exit
 mov r10,[rbp+OUTPUT+40]
 cmp r10,1048576
 ja protocol_exit
 mov edi,17
 lea rsi,[rbp+OUTPUT+64]
 mov eax,18
 syscall
 mov r15,rax
 jmp meta_reply

module_seal:
 cmp rax,64
 jne protocol_exit
 test QWORD PTR [rbp+SCRATCH+448],2
 jz protocol_exit
module_add_seals_retry:
 mov edi,17
 mov esi,1033
 mov edx,15
 mov eax,72
 syscall
 cmp rax,-4
 je module_add_seals_retry
 jmp module_negative_reply

module_map:
 cmp rax,64
 jne protocol_exit
 cmp QWORD PTR [rbp+SCRATCH+448],3
 jne protocol_exit
 mov rbx,[rbp+OUTPUT+40]
 cmp rbx,4
 jae protocol_exit
 cmp QWORD PTR [rbp+SCRATCH+256+rbx*8],0
 jne protocol_exit
 mov rsi,[rbp+OUTPUT+32]
 test rsi,rsi
 jz protocol_exit
 cmp rsi,1048576
 ja protocol_exit
 xor edi,edi
 mov edx,5
 mov r10d,2
 mov r8d,17
 xor r9d,r9d
 mov eax,9
 syscall
 cmp rax,-4095
 jae module_negative_reply
 test rax,rax
 jz protocol_exit
 mov [rbp+SCRATCH+256+rbx*8],rax
 bts QWORD PTR [rbp+SCRATCH+456],rbx
 xor r15d,r15d
 jmp meta_reply

module_path_stat:
 cmp rax,128
 jne protocol_exit
 cmp QWORD PTR [rbp+OUTPUT+24],20
 jne protocol_exit
module_path_retry:
 mov edi,20
 lea rsi,[rbp+OUTPUT+64]
 lea rdx,[rbp+32]
 mov r10d,256
 mov eax,262
 syscall
 cmp rax,-4
 je module_path_retry
 test rax,rax
 js module_negative_reply
 mov QWORD PTR [rbp+176],0
 xor r15d,r15d
 call make_meta
 mov r12d,184
 jmp policy_loop

module_close:
 cmp rax,64
 jne protocol_exit
 cmp QWORD PTR [rbp+SCRATCH+448],3
 jne protocol_exit
 xor r15d,r15d
 mov edi,16
 mov eax,3
 syscall
 test rax,rax
 jns module_close_second
 mov r15,rax
module_close_second:
 mov edi,17
 mov eax,3
 syscall
 test rax,rax
 jns module_close_done
 test r15,r15
 jnz module_close_done
 mov r15,rax
module_close_done:
 mov QWORD PTR [rbp+SCRATCH+448],0
 jmp meta_reply

modules_ready:
 cmp rax,64
 jne protocol_exit
 cmp QWORD PTR [rbp+OUTPUT+32],4
 jne protocol_exit
 cmp QWORD PTR [rbp+SCRATCH+448],0
 jne protocol_exit
 cmp QWORD PTR [rbp+SCRATCH+456],15
 jne protocol_exit
 jmp owner_boot_input
module_negative_reply:
 mov r15,rax
 jmp meta_reply
module_memfd_name: .asciz "hia-native-owned-module"


push_native_parent:
 mov rcx,[rbp+SCRATCH+768]
 cmp rcx,3
 jae protocol_exit
 mov rax,rcx
 shl rax,5
 lea rdx,[rbp+SCRATCH+784+rax]
 mov rax,[rbp+SCRATCH+56]
 mov [rdx],rax
 mov [rdx+8],r13
 mov [rdx+16],r14
 inc rcx
 mov [rbp+SCRATCH+768],rcx
 ret

generic_handoff:
 mov rbx,[rbp+OUTPUT+32]
 cmp rbx,8192
 ja protocol_exit
 lea rdx,[rbx+64]
 cmp rax,rdx
 jb protocol_exit
 mov r15,rbx
 lea rsi,[rbp+OUTPUT+64]
 lea rdi,[rbp+32]
 mov rcx,rbx
 rep movsb
 jmp return_owner

frontend_effect:
 cmp r14,123
 je frontend_metadata_JSON
 cmp r14,102
 je frontend_metadata_create
 cmp r14,103
 je frontend_metadata_seal
 cmp r14,22
 je frontend_metadata_stat
 cmp r14,45
 je frontend_metadata_write
 cmp r14,3
 je frontend_get_read
 cmp r14,120
 je frontend_query_ack
 cmp r14,17
 je frontend_public_close
 cmp r14,101
 je frontend_anchor_probe
 cmp r14,9
 je owner_process_exit
 cmp r14,109
 je owner_unit
 cmp r14,112
 je owner_sql_write
 cmp r14,118
 je frontend_read
 jmp protocol_exit
controller_effect:
 cmp r14,119
 je controller_query_frame
 cmp r14,112
 je owner_sql_write
 cmp r14,114
 je query_resume
 cmp r14,9
 je owner_process_exit
 cmp r14,19
 je generic_handoff
 cmp r14,109
 je owner_unit
 cmp r14,101
 je owner_probe
 cmp r14,107
 je owner_close
 cmp r14,16
 je dup_owned
 cmp r14,17
 je close_owned
 cmp r14,3
 je read_meta
 jmp protocol_exit
new_helper_effect:
 cmp r14,125
 je stream_binding_read
 cmp r14,101
 je owner_probe
 cmp r14,102
 je owner_create
 cmp r14,103
 je add_seals
 cmp r14,50
 je new_helper_complete
 jmp ordinary_helper_effect
new_helper_complete:
 xor r15d,r15d
 xor ebx,ebx
 jmp return_owner
frontend_read:
 cmp QWORD PTR [rbp+OUTPUT+24],0
 jne protocol_exit
 cmp QWORD PTR [rbp+OUTPUT+32],48
 jne protocol_exit
 xor ebx,ebx
frontend_read_next:
 xor edi,edi
 lea rsi,[rbp+rbx+32]
 mov edx,48
 sub rdx,rbx
 xor eax,eax
 syscall
 cmp rax,-4
 je frontend_read_next
 test rax,rax
 js generic_negative
 jz frontend_read_done
 add rbx,rax
 cmp rbx,48
 jb frontend_read_next
frontend_read_done:
 mov r15,rbx
 call make_meta
 lea r12,[rbx+32]
 jmp policy_loop

query_coprocessor_call:
 cmp QWORD PTR [rbp+SCRATCH+56],1
 jne protocol_exit
 cmp rax,128
 jne protocol_exit
 cmp QWORD PTR [rbp+OUTPUT+24],0
 jne protocol_exit
 cmp QWORD PTR [rbp+OUTPUT+32],64
 jne protocol_exit
 mov QWORD PTR [rbp+SCRATCH+56],23
 jmp copy_packet
query_coprocessor_effect:
 cmp r14,0
 je copy_packet
 cmp r14,9
 je inner_terminal
 cmp r14,22
 je sealed_stat
 cmp r14,3
 je read_meta
 cmp r14,24
 jne protocol_exit
 cmp rax,64
 jne protocol_exit
 cmp QWORD PTR [rbp+OUTPUT+24],0
 jne protocol_exit
 cmp QWORD PTR [rbp+OUTPUT+32],0
 jne protocol_exit
 cmp QWORD PTR [rbp+OUTPUT+40],0
 jne protocol_exit
 mov QWORD PTR [rbp+SCRATCH+56],1
 xor r15d,r15d
 jmp meta_reply

frontend_anchor_probe:
 cmp QWORD PTR [rbp+OUTPUT+24],10
 jne protocol_exit
 jmp owner_probe
frontend_public_close:
 mov rax,[rbp+OUTPUT+24]
 cmp rax,38
 je get_owned_close
 cmp rax,39
 je get_owned_close
 cmp rax,10
 je close_owned
 cmp rax,3
 jb protocol_exit
 cmp rax,7
 ja protocol_exit
 jmp close_owned


controller_query_frame:
 cmp QWORD PTR [rbp+SCRATCH+768],1
 jne protocol_exit
 cmp QWORD PTR [rbp+SCRATCH+784],22
 jne protocol_exit
 cmp QWORD PTR [rbp+SCRATCH+800],109
 jne protocol_exit
 cmp QWORD PTR [rbp+SCRATCH+2056],0
 jne protocol_exit
 cmp QWORD PTR [rbp+OUTPUT+24],1
 jne protocol_exit
 mov rbx,[rbp+OUTPUT+32]
 cmp rbx,64
 jb protocol_exit
 cmp rbx,8128
 ja protocol_exit
 lea rdx,[rbx+64]
 cmp rax,rdx
 jne protocol_exit
 cmp QWORD PTR [rbp+OUTPUT+40],0
 jne protocol_exit
 cmp QWORD PTR [rbp+OUTPUT+48],0
 jne protocol_exit
 cmp QWORD PTR [rbp+OUTPUT+56],0
 jne protocol_exit
 mov [rbp+SCRATCH+2048],r13
 mov QWORD PTR [rbp+SCRATCH+2056],1
 mov rax,IO_MAGIC
 mov [rbp],rax
 mov rax,[rbp+SCRATCH+792]
 mov [rbp+8],rax
 mov QWORD PTR [rbp+16],109
 mov [rbp+24],rbx
 lea rsi,[rbp+OUTPUT+64]
 lea rdi,[rbp+32]
 mov rcx,rbx
 rep movsb
 lea r12,[rbx+32]
 mov QWORD PTR [rbp+SCRATCH+56],22
 jmp policy_loop
frontend_query_ack:
 cmp QWORD PTR [rbp+SCRATCH+2056],1
 jne protocol_exit
 cmp QWORD PTR [rbp+SCRATCH+768],1
 jne protocol_exit
 cmp QWORD PTR [rbp+SCRATCH+784],22
 jne protocol_exit
 cmp QWORD PTR [rbp+SCRATCH+800],109
 jne protocol_exit
 cmp rax,64
 jne protocol_exit
 cmp QWORD PTR [rbp+OUTPUT+24],0
 jne protocol_exit
 cmp QWORD PTR [rbp+OUTPUT+32],0
 jne protocol_exit
 cmp QWORD PTR [rbp+OUTPUT+40],0
 jne protocol_exit
 cmp QWORD PTR [rbp+OUTPUT+48],0
 jne protocol_exit
 cmp QWORD PTR [rbp+OUTPUT+56],0
 jne protocol_exit
 mov QWORD PTR [rbp+SCRATCH+2056],0
 mov rax,IO_MAGIC
 mov [rbp],rax
 mov rax,[rbp+SCRATCH+2048]
 mov [rbp+8],rax
 mov QWORD PTR [rbp+16],119
 mov QWORD PTR [rbp+24],0
 mov r12,32
 mov QWORD PTR [rbp+SCRATCH+56],19
 jmp policy_loop


/* Fixed artifact capability effects. HIA owns filename bytes, root/file
 * admission, stability/race guards, all hashes, limits, progress and receipts. */
artifact_capture_effect:
 cmp r14,121
 je capture_open
 cmp r14,122
 je capture_path_stat
 cmp r14,1
 je capture_stat
 cmp r14,3
 je capture_read
 cmp r14,17
 je capture_close
 cmp r14,102
 je capture_create
 cmp r14,103
 je capture_seal
 cmp r14,22
 je capture_sealed_stat
 cmp r14,45
 je capture_write
 cmp r14,19
 je generic_handoff
 cmp r14,9
 je inner_terminal
 jmp protocol_exit
capture_stat:
 mov rax,[rbp+OUTPUT+24]
 cmp rax,36
 je capture_exact_fstat
 cmp rax,37
 jne protocol_exit
 bt QWORD PTR [rbp+SCRATCH+664],rax
 jnc protocol_exit
 jmp capture_exact_fstat
capture_exact_fstat:
 mov rdi,[rbp+OUTPUT+24]
 lea rsi,[rbp+32]
 mov eax,5
 syscall
 cmp rax,-4
 je capture_exact_fstat
 test rax,rax
 js generic_negative
 xor r15d,r15d
 call make_meta
 mov r12d,176
 jmp policy_loop
capture_read:
 mov rax,[rbp+OUTPUT+24]
 cmp rax,37
 je capture_read_owned
 cmp rax,38
 jne protocol_exit
capture_read_owned:
 bt QWORD PTR [rbp+SCRATCH+664],rax
 jnc protocol_exit
 cmp QWORD PTR [rbp+OUTPUT+32],1024
 ja protocol_exit
 jmp read_meta
capture_close:
 mov rax,[rbp+OUTPUT+24]
 cmp rax,37
 je get_owned_close
 cmp rax,38
 jne protocol_exit
get_owned_close:
 bt QWORD PTR [rbp+SCRATCH+664],rax
 jnc protocol_exit
 jmp close_owned
capture_create:
 cmp QWORD PTR [rbp+OUTPUT+24],38
 jne protocol_exit
 jmp owner_create
capture_seal:
 cmp QWORD PTR [rbp+OUTPUT+24],38
 jne protocol_exit
 jmp get_owned_seal
capture_sealed_stat:
 cmp QWORD PTR [rbp+OUTPUT+24],38
 jne protocol_exit
 jmp get_owned_stat
capture_write:
 cmp QWORD PTR [rbp+OUTPUT+24],38
 jne protocol_exit
 jmp get_owned_write
frontend_metadata_create:
 cmp QWORD PTR [rbp+OUTPUT+24],39
 jne protocol_exit
 jmp owner_create
frontend_metadata_seal:
 cmp QWORD PTR [rbp+OUTPUT+24],39
 jne protocol_exit
get_owned_seal:
 mov rax,[rbp+OUTPUT+24]
 bt QWORD PTR [rbp+SCRATCH+664],rax
 jnc protocol_exit
 cmp QWORD PTR [rbp+OUTPUT+32],15
 jne protocol_exit
 jmp add_seals
frontend_metadata_stat:
 cmp QWORD PTR [rbp+OUTPUT+24],39
 jne protocol_exit
get_owned_stat:
 mov rax,[rbp+OUTPUT+24]
 bt QWORD PTR [rbp+SCRATCH+664],rax
 jnc protocol_exit
 jmp sealed_stat
frontend_metadata_write:
 cmp QWORD PTR [rbp+OUTPUT+24],39
 jne protocol_exit
get_owned_write:
 mov rdx,[rbp+OUTPUT+24]
 bt QWORD PTR [rbp+SCRATCH+664],rdx
 jnc protocol_exit
 cmp QWORD PTR [rbp+OUTPUT+32],1024
 ja protocol_exit
 jmp fd_pwrite
frontend_get_read:
 mov rax,[rbp+OUTPUT+24]
 cmp rax,35
 je frontend_kind_parameter_read
 cmp rax,38
 je capture_read_owned
 cmp rax,39
 jne protocol_exit
 jmp capture_read_owned
/* Borrowed sealed parameter capability already admitted by binding_capture.
 * This lane only permits finite reads; it cannot write, close, replace or
 * publish FD35. HIA retains range/kind/state/error/authority decisions. */
frontend_kind_parameter_read:
 cmp QWORD PTR [rbp+OUTPUT+32],1024
 ja protocol_exit
 cmp QWORD PTR [rbp+OUTPUT+48],0
 jne protocol_exit
 cmp QWORD PTR [rbp+OUTPUT+56],0
 jne protocol_exit
 jmp read_meta
capture_path_arguments:
 cmp QWORD PTR [rbp+OUTPUT+24],36
 jne protocol_exit
 cmp QWORD PTR [rbp+OUTPUT+32],65
 jne protocol_exit
 cmp QWORD PTR [rbp+OUTPUT+40],0
 jne protocol_exit
 cmp QWORD PTR [rbp+OUTPUT+48],0
 jne protocol_exit
 cmp QWORD PTR [rbp+OUTPUT+56],0
 jne protocol_exit
 cmp BYTE PTR [rbp+OUTPUT+128],0
 jne protocol_exit
 ret
capture_path_stat:
 cmp rax,129
 jne protocol_exit
 call capture_path_arguments
capture_path_stat_retry:
 mov edi,36
 lea rsi,[rbp+OUTPUT+64]
 lea rdx,[rbp+32]
 mov r10d,256
 mov eax,262
 syscall
 cmp rax,-4
 je capture_path_stat_retry
 test rax,rax
 js generic_negative
 xor r15d,r15d
 call make_meta
 mov r12d,176
 jmp policy_loop
capture_open:
 cmp rax,129
 jne protocol_exit
 call capture_path_arguments
 mov edi,37
 mov esi,1
 mov eax,72
 syscall
 cmp rax,-9
 jne capture_role_occupied
capture_open_retry:
 mov edi,36
 lea rsi,[rbp+OUTPUT+64]
 mov edx,0xa0800
 xor r10d,r10d
 mov eax,257
 syscall
 cmp rax,-4
 je capture_open_retry
 test rax,rax
 js generic_negative
 mov r12,rax
 cmp r12,37
 je capture_open_ready
 mov rdi,r12
 mov esi,37
 mov edx,0x80000
 mov eax,292
 syscall
 test rax,rax
 js capture_dup_failed
 mov rdi,r12
 mov eax,3
 syscall
 test rax,rax
 js capture_source_close_failed
capture_open_ready:
 bts QWORD PTR [rbp+SCRATCH+664],37
 mov r15d,37
 jmp meta_reply
capture_source_close_failed:
 mov r15,rax
 mov edi,37
 mov eax,3
 syscall
 jmp meta_reply
capture_dup_failed:
 mov r15,rax
 mov rdi,r12
 mov eax,3
 syscall
 jmp meta_reply
capture_role_occupied:
 mov r15,-9
 jmp meta_reply

/* Mechanical sealed-buffer call of the fixed HIA JSON admission component.
 * No JSON/token/key/numeric decisions occur in this adapter. Profiles are the
 * original Agent 8MiB input / 4MiB key index / 4256-byte parser workspace. */
frontend_metadata_JSON:
 cmp rax,64
 jne protocol_exit
 mov rdx,[rbp+OUTPUT+24]
 cmp rdx,38
 je json_fixed_role
 cmp rdx,39
 jne protocol_exit
json_fixed_role:
 bt QWORD PTR [rbp+SCRATCH+664],rdx
 jnc protocol_exit
 mov [rbp+SCRATCH+2112],rdx
 mov rax,[rbp+OUTPUT+32]
 cmp rax,8388608
 ja protocol_exit
 mov [rbp+SCRATCH+2088],rax
 mov rdx,[rbp+OUTPUT+40]
 mov [rbp+SCRATCH+2120],rdx
 cmp QWORD PTR [rbp+OUTPUT+48],0
 jne protocol_exit
 cmp QWORD PTR [rbp+OUTPUT+56],0
 jne protocol_exit
 mov QWORD PTR [rbp+SCRATCH+2080],0
 mov QWORD PTR [rbp+SCRATCH+2096],0
 mov QWORD PTR [rbp+SCRATCH+2104],0
 mov rdi,[rbp+SCRATCH+2112]
 mov esi,1034
 mov eax,72
 syscall
 cmp rax,15
 jne json_mapping_refused
json_stat_retry:
 mov rdi,[rbp+SCRATCH+2112]
 lea rsi,[rbp+32]
 mov eax,5
 syscall
 cmp rax,-4
 je json_stat_retry
 test rax,rax
 js json_mapping_failed
 mov rax,[rbp+80]
 mov rdx,[rbp+SCRATCH+2120]
 cmp rdx,rax
 ja json_mapping_refused
 sub rax,rdx
 cmp rax,[rbp+SCRATCH+2088]
 jb json_mapping_refused
 mov r9,rdx
 and r9,-4096
 and rdx,4095
 mov [rbp+SCRATCH+2136],rdx
 add rdx,[rbp+SCRATCH+2088]
 mov [rbp+SCRATCH+2128],rdx
 test rdx,rdx
 jz json_workspace_map
 xor edi,edi
 mov rsi,rdx
 mov edx,1
 mov r10d,2
 mov r8,[rbp+SCRATCH+2112]
 mov eax,9
 syscall
 cmp rax,-4095
 jae json_mapping_failed
 mov [rbp+SCRATCH+2080],rax
json_workspace_map:
 xor edi,edi
 mov esi,4198560
 mov edx,3
 mov r10d,0x22
 mov r8,-1
 xor r9d,r9d
 mov eax,9
 syscall
 cmp rax,-4095
 jae json_mapping_failed
 mov [rbp+SCRATCH+2096],rax
 mov rdi,[rbp+SCRATCH+2080]
 add rdi,[rbp+SCRATCH+2136]
 mov rsi,[rbp+SCRATCH+2088]
 mov rdx,rax
 mov ecx,4194304
 lea r8,[rax+4194304]
 mov r9d,4256
 .byte 0xe8
json_call_hole: .long 0
 mov [rbp+SCRATCH+2104],rax
 jmp json_mapping_cleanup
json_mapping_refused:
 mov rax,-1
json_mapping_failed:
 mov [rbp+SCRATCH+2104],rax
json_mapping_cleanup:
 mov rdi,[rbp+SCRATCH+2096]
 test rdi,rdi
 jz json_input_unmap
 mov esi,4198560
 mov eax,11
 syscall
 test rax,rax
 jns json_input_unmap
 mov [rbp+SCRATCH+2104],rax
json_input_unmap:
 mov rdi,[rbp+SCRATCH+2080]
 test rdi,rdi
 jz json_native_return
 mov rsi,[rbp+SCRATCH+2128]
 mov eax,11
 syscall
 test rax,rax
 jns json_native_return
 mov [rbp+SCRATCH+2104],rax
json_native_return:
 mov r15,[rbp+SCRATCH+2104]
 jmp meta_reply


/* Private capture2 only: exact finite read of the next stdin extent. HIA
 * chooses size/progress, validates every copied byte and seals the new FD15.
 * No extra access to borrowed35 or arbitrary descriptor adoption. */
stream_binding_read:
 cmp QWORD PTR [rbp+SCRATCH+56],21
 jne protocol_exit
 cmp rax,64
 jne protocol_exit
 cmp QWORD PTR [rbp+OUTPUT+24],0
 jne protocol_exit
 cmp QWORD PTR [rbp+OUTPUT+32],1
 jb protocol_exit
 cmp QWORD PTR [rbp+OUTPUT+32],1024
 ja protocol_exit
 cmp QWORD PTR [rbp+OUTPUT+40],0
 jne protocol_exit
 cmp QWORD PTR [rbp+OUTPUT+48],0
 jne protocol_exit
 cmp QWORD PTR [rbp+OUTPUT+56],0
 jne protocol_exit
 xor ebx,ebx
stream_binding_read_next:
 xor edi,edi
 lea rsi,[rbp+rbx+32]
 mov rdx,[rbp+OUTPUT+32]
 sub rdx,rbx
 xor eax,eax
 syscall
 cmp rax,-4
 je stream_binding_read_next
 test rax,rax
 js read_meta_error
 jz stream_binding_read_done
 add rbx,rax
 cmp rbx,[rbp+OUTPUT+32]
 jb stream_binding_read_next
stream_binding_read_done:
 mov r15,rbx
 call make_meta
 lea r12,[rbx+32]
 jmp policy_loop

unit_table:
 .quad 0,136,720896,65536
 .quad 1,136,READER_WORK,READER_WITH_MEMO
 .quad 2,136,983040,4096
 .quad 0,635912,999424,4096
 .quad 3,761488,995328,80
 .quad 0,939352,987136,80
 .quad 1,763936,991232,2048
 .quad 1,590136,1003520,8192
 .quad 3,354960,1011712,16384
 .quad 3,136,1028096,32768
 .quad 2,192544,1507328,4096
 .quad 2,674592,1511424,4096
 .quad 3,625568,1515520,4096
 .quad 1,938576,1519616,80
 .quad 0,169664,1060864,16384
 .quad 0,373840,1077248,16384
 .quad 1,814128,1093632,8192
 .quad 1,590136,1003520,8192
 .quad 0,0,0,0
 .quad 0,757920,1519704,16384
 .quad 0,0,0,0
 .quad 3,832560,1101824,8192
 .quad 2,725336,1536096,8192
 .quad 2,511120,READER_WORK,READER_TRANSIENT
 .quad 3,917912,1544288,16384
