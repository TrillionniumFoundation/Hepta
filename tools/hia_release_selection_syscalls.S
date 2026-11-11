/* HIA release selection transport. The generator inserts byte-identical
 * verification paths from the immutable release installer at these markers.
 * New policy/state/receipt decisions are in release_selection_policy.hepta.
 */
/* @INSTALLER_HEADER@ */
.equ SELWORK,229376
.equ SELINPUT,237568
.equ SELOUT,245760

.macro sgate phase
 mov QWORD PTR [rbp+SELWORK],\phase
 xor edi,edi
 xor esi,esi
 call selection_call
 test eax,eax
 jnz policy_exit
.endm

_start:
 mov r15,rsp
 cmp QWORD PTR [r15],3
 je selection_argc_ok
 cmp QWORD PTR [r15],6
 jne usage
selection_argc_ok:
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
 mov QWORD PTR [rbp+WORK+2000],1
 mov edi,13
 lea rsi,[rbp+WORK+2000]
 xor edx,edx
 mov r10d,8
 mov eax,13
 syscall
 test rax,rax
 js io_exit
 mov r12d,40
 mov ebx,1
selection_argv_next:
 mov rsi,[r15+rbx*8+8]
 call strlen_bounded
 cmp rax,4095
 ja input_exit
 mov [rbp+SELINPUT+rbx*8-8],rax
 mov rcx,rax
 lea rdi,[rbp+SELINPUT+r12]
 add r12,rax
 cmp r12,8192
 ja input_exit
 rep movsb
 inc ebx
 cmp rbx,[r15]
 jne selection_argv_next
 lea rdi,[rbp+SELINPUT]
 mov rsi,r12
 call selection_call
 cmp eax,95
 jb input_exit
 cmp eax,8192
 ja input_exit
 cmp QWORD PTR [rbp+SELWORK+8],3
 jne selection_arity_ok
 cmp QWORD PTR [r15],3
 jne usage
selection_arity_ok:
 /* HIA emits the actual installer's verify argument packet. */
 mov r12d,eax
 mov ecx,eax
 lea rsi,[rbp+SELOUT]
 mov rdi,rbp
 rep movsb
 mov rdi,rbp
 mov rsi,r12
 lea rdx,[rbp+OUT]
 mov ecx,8192
 lea r8,[rbp+WORK]
 mov r9d,65536
 .byte 0xe8
policy_initial_hole: .long 0
 cmp eax,2
 jne input_exit
 cmp QWORD PTR [rbp+SELWORK+8],3
 jne selection_capture
 xor r12d,r12d
 xor r13d,r13d
 jmp selection_root
selection_capture:
/* @INSTALLER_CAPTURE@ */
selection_root:
/* @INSTALLER_ROOT@ */
 mov rax,[rbp+WORK+64]
 mov [rbp+SELWORK+64],rax
 /* Lock descriptors never become request parameters or inherited authority. */
 mov QWORD PTR [rbp+SELWORK+48],-1
 mov rdi,r14
 lea rsi,[rip+selection_lock_name]
 mov edx,0xa0800
 xor r10d,r10d
 cmp QWORD PTR [rbp+SELWORK+8],3
 je selection_lock_open
 /* The private child fixes its own umask, never the operator's. */
 mov edi,63
 mov eax,95
 syscall
 mov rdi,r14
 lea rsi,[rip+selection_lock_name]
 mov edx,0xa0842
 mov r10d,384
selection_lock_open:
 mov eax,257
 retry selection_lock_open_retry
 cmp rax,-2
 jne selection_lock_result
 cmp QWORD PTR [rbp+SELWORK+8],3
 jne identity_exit
 jmp selection_read_initial
selection_lock_result:
 test rax,rax
 js identity_exit
 mov [rbp+SELWORK+48],rax
 mov rdi,rax
 lea rsi,[rbp+SELWORK+912]
 mov eax,5
 retry selection_lock_stat_retry
 test rax,rax
 js io_exit
 sgate 7
 mov rdi,[rbp+SELWORK+48]
 mov esi,6
 cmp QWORD PTR [rbp+SELWORK+8],3
 jne selection_lock_flock
 mov esi,5
selection_lock_flock:
 mov eax,73
 retry selection_flock_retry
 cmp rax,-11
 je selection_busy_exit
 test rax,rax
 js io_exit
 call selection_check_lock_name
selection_read_initial:
 call selection_read_state
 cmp QWORD PTR [rbp+SELWORK+8],3
 je selection_receipt
 sgate 4
 /* The exact actual installed-tree verifier runs under the exclusive lock. */
 jmp open_release
/* @INSTALLER_VERIFY@ */
 jmp selection_commit

selection_commit:
 /* HIA created the 160-byte state body; HIA SHA supplies its checksum. */
 lea rdi,[rbp+SELWORK+448]
 call selection_hash_record
 mov QWORD PTR [rbp+SELWORK],6
 lea rdi,[rbp+SHAOUT]
 mov esi,32
 call selection_call
 test eax,eax
 jnz policy_exit
 lea rdi,[rbp+SELWORK+704]
 mov esi,16
 xor edx,edx
 mov eax,318
 retry selection_random_retry
 cmp rax,16
 jne io_exit
 sgate 10
 mov rdi,r14
 lea rsi,[rbp+SELWORK+640]
 mov edx,0xa00c2
 mov r10d,384
 mov eax,257
 retry selection_stage_open_retry
 test rax,rax
 js no_replace_exit
 mov [rbp+SELWORK+56],rax
 mov QWORD PTR [rbp+SELWORK+1368],0
selection_write_next:
 mov rdx,192
 sub rdx,[rbp+SELWORK+1368]
 jz selection_written
 mov rdi,[rbp+SELWORK+56]
 lea rsi,[rbp+SELWORK+448]
 add rsi,[rbp+SELWORK+1368]
 mov eax,1
 retry selection_write_retry
 test rax,rax
 jle io_exit
 add [rbp+SELWORK+1368],rax
 jmp selection_write_next
selection_written:
 mov rdi,[rbp+SELWORK+56]
 mov esi,256
 mov eax,91
 retry selection_chmod_retry
 test rax,rax
 js io_exit
 mov rdi,[rbp+SELWORK+56]
 mov eax,74
 retry selection_stage_fsync_retry
 test rax,rax
 js io_exit
 mov rdi,[rbp+SELWORK+56]
 lea rsi,[rbp+SELWORK+912]
 mov eax,5
 retry selection_stage_stat_retry
 test rax,rax
 js io_exit
 sgate 9
 call selection_check_lock_name
 /* Both source and destination names are checked just before atomic rename. */
 mov rdi,r14
 lea rsi,[rbp+SELWORK+640]
 lea rdx,[rbp+SELWORK+912]
 mov r10d,256
 mov eax,262
 retry selection_stage_name_retry
 test rax,rax
 js identity_exit
 sgate 11
 mov rdi,r14
 lea rsi,[rip+selection_current_name]
 lea rdx,[rbp+SELWORK+912]
 mov r10d,256
 mov eax,262
 retry selection_old_name_retry
 cmp QWORD PTR [rbp+SELWORK+32],0
 je selection_expect_absent
 test rax,rax
 js identity_exit
 sgate 8
 jmp selection_rename
selection_expect_absent:
 cmp rax,-2
 jne selection_conflict_exit
selection_rename:
 mov rdi,r14
 lea rsi,[rbp+SELWORK+640]
 mov rdx,r14
 lea r10,[rip+selection_current_name]
 xor r8d,r8d
 cmp QWORD PTR [rbp+SELWORK+32],0
 jne selection_rename_ready
 mov r8d,1
selection_rename_ready:
 mov eax,316
 retry selection_rename_retry
 test rax,rax
 js no_replace_exit
 mov rdi,r14
 mov eax,74
 retry selection_root_fsync_retry
 test rax,rax
 js io_exit
 /* The old record descriptor is no longer the selected object after rename. */
 cmp QWORD PTR [rbp+SELWORK+32],0
 je selection_read_published
 mov rdi,[rbp+SELWORK+40]
 mov eax,3
 syscall
 test rax,rax
 js io_exit
selection_read_published:
 call selection_read_state
 sgate 12
 sgate 17
 call selection_check_lock_name
 stat_current r14d
 gate 5
selection_receipt:
 mov QWORD PTR [rbp+SELWORK],14
 xor edi,edi
 xor esi,esi
 call selection_call
 test eax,eax
 jz input_exit
 cmp eax,512
 ja input_exit
 mov r13d,eax
 lea r12,[rbp+SELOUT]
selection_stdout_next:
 test r13,r13
 jz success
 mov edi,1
 mov rsi,r12
 mov rdx,r13
 mov eax,1
 retry selection_stdout_retry
 test rax,rax
 jle io_exit
 add r12,rax
 sub r13,rax
 jmp selection_stdout_next

/* All metadata is read through a held inode and exact length/identity checks. */
selection_read_state:
 sub rsp,8
 mov QWORD PTR [rbp+SELWORK+32],0
 mov QWORD PTR [rbp+SELWORK+40],-1
 mov QWORD PTR [rbp+SELWORK+72],0
 mov rdi,r14
 lea rsi,[rip+selection_current_name]
 mov edx,0xa0800
 xor r10d,r10d
 mov eax,257
 retry selection_state_open_retry
 cmp rax,-2
 je selection_state_absent
 test rax,rax
 js identity_exit
 cmp QWORD PTR [rbp+SELWORK+48],-1
 je identity_exit
 mov [rbp+SELWORK+40],rax
 mov QWORD PTR [rbp+SELWORK+32],1
 mov rdi,rax
 lea rsi,[rbp+SELWORK+912]
 mov eax,5
 retry selection_state_stat_retry
 test rax,rax
 js io_exit
 sgate 16
selection_state_read_next:
 mov rdx,193
 sub rdx,[rbp+SELWORK+72]
 jz selection_state_read_done
 mov rdi,[rbp+SELWORK+40]
 lea rsi,[rbp+SELWORK+256]
 add rsi,[rbp+SELWORK+72]
 mov eax,0
 retry selection_state_read_retry
 test rax,rax
 js io_exit
 jz selection_state_read_done
 add [rbp+SELWORK+72],rax
 jmp selection_state_read_next
selection_state_read_done:
 sgate 2
 mov rdi,[rbp+SELWORK+40]
 lea rsi,[rbp+SELWORK+912]
 mov eax,5
 retry selection_state_stable_retry
 test rax,rax
 js io_exit
 sgate 8
 mov rdi,r14
 lea rsi,[rip+selection_current_name]
 lea rdx,[rbp+SELWORK+912]
 mov r10d,256
 mov eax,262
 retry selection_state_name_retry
 test rax,rax
 js identity_exit
 sgate 8
 lea rdi,[rbp+SELWORK+256]
 call selection_hash_record
 mov QWORD PTR [rbp+SELWORK],3
 lea rdi,[rbp+SHAOUT]
 mov esi,32
 call selection_call
 test eax,eax
 jnz policy_exit
 add rsp,8
 ret
selection_state_absent:
 sgate 2
 add rsp,8
 ret

selection_hash_record:
 sub rsp,8
 mov [rbp+SELWORK+1360],rdi
 mov BYTE PTR [rbp+SHAIN],0
 mov esi,1
 call sha_call
 test eax,eax
 jnz input_exit
 mov rsi,[rbp+SELWORK+1360]
 lea rdi,[rbp+SHAIN+1]
 mov ecx,160
 rep movsb
 mov BYTE PTR [rbp+SHAIN],1
 mov esi,161
 call sha_call
 test eax,eax
 jnz input_exit
 mov BYTE PTR [rbp+SHAIN],2
 mov esi,1
 call sha_call
 cmp eax,32
 jne input_exit
 add rsp,8
 ret

selection_check_lock_name:
 sub rsp,8
 mov rdi,r14
 lea rsi,[rip+selection_lock_name]
 lea rdx,[rbp+SELWORK+912]
 mov r10d,256
 mov eax,262
 retry selection_lock_name_retry
 test rax,rax
 js identity_exit
 sgate 15
 add rsp,8
 ret

selection_call:
 lea rdx,[rbp+SELOUT]
 mov ecx,8192
 lea r8,[rbp+SELWORK]
 mov r9d,8192
 sub rsp,8
 .byte 0xe8
selection_hole: .long 0
 add rsp,8
 ret

selection_busy_exit:
 mov edi,18
 jmp exit
selection_conflict_exit:
 mov edi,19
 jmp exit
selection_lock_name: .asciz ".hia-selection.lock"
selection_current_name: .asciz ".hia-selection.current"
/* @INSTALLER_HELPERS@ */
/* @INSTALLER_EXIT@ */
