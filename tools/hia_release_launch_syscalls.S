/* Independent launch entry. The generator retains the complete original
 * selection verifier and inserts only these exact fixed transport fragments.
 * HIA owns argument/entry/header/seal/metadata/digest/terminal admission.
 */
_start:
 mov r15,rsp
 cmp QWORD PTR [r15],7
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
 /* No private SIGPIPE override can survive this new exec boundary. */
 mov r12d,48
 mov ebx,1
launch_argv_next:
 mov rsi,[r15+rbx*8+8]
 call strlen_bounded
 cmp rax,4095
 ja input_exit
 mov [rbp+RUNINPUT+rbx*8-8],rax
 mov rcx,rax
 lea rdi,[rbp+RUNINPUT+r12]
 add r12,rax
 cmp r12,8192
 ja input_exit
 rep movsb
 inc ebx
 cmp ebx,7
 jne launch_argv_next
 lea rdi,[rbp+RUNINPUT]
 mov rsi,r12
 call launch_inputs
 cmp eax,111
 jb input_exit
 cmp eax,8192
 ja input_exit
 lea rdi,[rbp+RUNOUT]
 mov esi,eax
 call selection_call
 cmp eax,95
 jb input_exit
 cmp eax,8192
 ja input_exit
 cmp QWORD PTR [rbp+SELWORK+8],4
 jne input_exit
/* @LAUNCH_HELPERS@ */
launch_prepare_image:
 sub rsp,8
 mov QWORD PTR [rbp+RUNWORK],1
 mov rdi,r12
 mov rsi,r13
 lea rdx,[rbp+WORK]
 mov ecx,65536
 call launch_common
 test eax,eax
 jnz policy_exit
 /* Select the actual matching row with the unchanged installer policy. */
 mov rax,[rbp+RUNWORK+48]
 mov [rbp+WORK+32],rax
 gate 4
 lea rdi,[rip+launch_memfd_name]
 mov esi,19
 mov eax,319
 retry launch_memfd_retry
 test rax,rax
 js io_exit
 mov [rbp+RUNWORK+56],rax
 mov QWORD PTR [rbp+RUNWORK+72],0
launch_write_next:
 mov rdx,[rbp+RUNWORK+40]
 sub rdx,[rbp+RUNWORK+72]
 jz launch_written
 mov rdi,[rbp+RUNWORK+56]
 mov rsi,r12
 add rsi,[rbp+RUNWORK+32]
 add rsi,[rbp+RUNWORK+72]
 mov eax,1
 retry launch_write_retry
 test rax,rax
 jle io_exit
 add [rbp+RUNWORK+72],rax
 jmp launch_write_next
launch_written:
 mov rdi,[rbp+RUNWORK+56]
 mov esi,320
 mov eax,91
 retry launch_chmod_retry
 test rax,rax
 js io_exit
 mov rdi,[rbp+RUNWORK+56]
 mov esi,1033
 mov edx,63
 mov eax,72
 retry launch_seal_retry
 test rax,rax
 js io_exit
 mov rdi,[rbp+RUNWORK+56]
 mov esi,1034
 xor edx,edx
 mov eax,72
 retry launch_seals_read_retry
 test rax,rax
 js io_exit
 mov [rbp+RUNWORK+64],rax
 mov rdi,[rbp+RUNWORK+56]
 lea rsi,[rbp+RUNWORK+832]
 mov eax,5
 retry launch_stat_retry
 test rax,rax
 js io_exit
 mov rax,[rbp+WORK+64]
 mov [rbp+RUNWORK+88],rax
 mov rdi,[rbp+RUNWORK+56]
 xor esi,esi
 xor edx,edx
 mov eax,8
 retry launch_seek_retry
 test rax,rax
 jnz io_exit
 mov BYTE PTR [rbp+SHAIN],0
 mov esi,1
 call sha_call
 test eax,eax
 jnz input_exit
 mov QWORD PTR [rbp+RUNWORK+80],0
launch_read_next:
 mov rdi,[rbp+RUNWORK+56]
 lea rsi,[rbp+BUF]
 mov edx,65536
 xor eax,eax
 retry launch_read_retry
 test rax,rax
 js io_exit
 jz launch_read_done
 mov [rbp+WORK+80],rax
 mov rax,[rbp+RUNWORK+80]
 mov [rbp+WORK+72],rax
 /* Exact bytes against the same protected captured package, not a path. */
 mov QWORD PTR [rbp+WORK],10
 call policy_buffer
 test eax,eax
 jnz policy_exit
 mov rcx,[rbp+WORK+80]
 lea rsi,[rbp+BUF]
 lea rdi,[rbp+SHAIN+1]
 rep movsb
 mov BYTE PTR [rbp+SHAIN],1
 mov rsi,[rbp+WORK+80]
 add [rbp+RUNWORK+80],rsi
 inc rsi
 call sha_call
 test eax,eax
 jnz input_exit
 jmp launch_read_next
launch_read_done:
 mov BYTE PTR [rbp+SHAIN],2
 mov esi,1
 call sha_call
 cmp eax,32
 jne input_exit
 mov QWORD PTR [rbp+RUNWORK],2
 lea rdi,[rbp+SHAOUT]
 mov esi,32
 call launch_inputs
 test eax,eax
 jnz policy_exit
 add rsp,8
 ret

launch_enter:
 /* The unchanged final selection/lock/root rechecks have just succeeded. */
 mov QWORD PTR [rbp+RUNWORK],3
 xor edi,edi
 xor esi,esi
 call launch_inputs
 test eax,eax
 jnz policy_exit
 mov edi,3
 mov esi,-1
 mov edx,4
 mov eax,436
 retry launch_cloexec_retry
 test rax,rax
 js io_exit
 lea rax,[rbp+RUNWORK+256]
 mov [rbp+RUNWORK+768],rax
 lea rax,[rbp+RUNWORK+512]
 mov [rbp+RUNWORK+776],rax
 mov QWORD PTR [rbp+RUNWORK+784],0
 mov QWORD PTR [rbp+RUNWORK+800],0
 mov rdi,[rbp+RUNWORK+56]
 lea rsi,[rip+launch_empty_path]
 lea rdx,[rbp+RUNWORK+768]
 lea r10,[rbp+RUNWORK+800]
 mov r8d,4096
 mov eax,322
 syscall
 /* Successful exec never returns; there is no release/path fallback. */
 mov edi,22
 jmp exit

launch_inputs:
 lea rdx,[rbp+RUNOUT]
 mov ecx,8192
launch_common:
 lea r8,[rbp+RUNWORK]
 mov r9d,8192
 sub rsp,8
 .byte 0xe8
launch_hole: .long 0
 add rsp,8
 ret

launch_memfd_name: .asciz "hia-selected-native"
launch_empty_path: .asciz ""
