/* Fixed Linux/SysV adapter for a sealed HIA Worker action stream.
 * The embedded HIA image owns every authorization, role selection, argument,
 * byte fragment, state/receipt transition and final publication decision.
 */
.intel_syntax noprefix
.text
.global _start, worker_policy_hole
.equ WORK, 0
.equ COMMAND, 4096
.equ OBS, 8192
.equ SCRATCH, 65536
.equ ROLES, 32768
.equ ARGV, 33024
.equ CARRIED, 33200
.equ NUMBERS, 33408
.equ PROCESS, 34000
.equ OBS_SIZE, 34064
.equ SEQUENCE, 34072
.equ CURRENT, 34080
.equ OUTPUT_END, 34088
.equ LOCAL_ARGS, 34096
.equ STAGED, 34104
.equ TEMP, 34112
.equ SAMPLE, 34240
.equ FD_INFO, 34272
.equ CLOCK, 34312
.ifdef WORKER_ARTIFACT
.equ MAP_BYTES, 327680
.equ ARG_SPAN, 81920
.equ ARG_SPAN_SIZE, 20480
.equ ROLE_OFFSET, 376
.else
.equ MAP_BYTES, 81920
.endif
.ifdef WORKER_COST
.ifndef WORKER_ARTIFACT
.equ ROLE_OFFSET, 64
.endif
.equ PEER, 34400
.ifdef WORKER_STORED_READ
.ifdef WORKER_ARTIFACT
.equ ROLE_COUNT, 23
.equ EXTRA_ARGS, 6
.equ FIRST_ROLE, 0
.else
.ifdef WORKER_INPUT
.equ ROLE_COUNT, 6
.equ EXTRA_ARGS, 3
.equ FIRST_ROLE, 0
.else
.ifdef WORKER_EXTERNAL_READ
.equ ROLE_COUNT, 6
.equ EXTRA_ARGS, 6
.equ FIRST_ROLE, 2
.else
.equ ROLE_COUNT, 8
.equ EXTRA_ARGS, 4
.equ FIRST_ROLE, 0
.endif
.endif
.endif
.equ PEER_COUNT, 2
.equ JOINED, 36864
.else
.equ EXTRA_ARGS, 4
.equ FIRST_ROLE, 0
.equ ROLE_COUNT, 3
.equ PEER_COUNT, 1
.endif
.else
.equ ROLE_OFFSET, 376
.equ FIRST_ROLE, 0
.ifdef WORKER_READ
.equ ROLE_COUNT, 19
.equ EXTRA_ARGS, 5
.else
.equ ROLE_COUNT, 22
.equ EXTRA_ARGS, 6
.endif
.endif
.equ ROLE_RECORD_END, ROLE_OFFSET + 40 * ROLE_COUNT
.ifdef WORKER_INPUT
.equ ENTRY_SIZE, ROLE_RECORD_END + 64
.else
.equ ENTRY_SIZE, ROLE_RECORD_END
.endif
.equ HEADER, 512

_start:
 cld
 xor ebp, ebp
 mov r15, rsp
 .ifdef WORKER_DISCOVERY
 cmp QWORD PTR [r15], ROLE_COUNT + EXTRA_ARGS + 2
 .else
 .ifdef WORKER_INPUT
 cmp QWORD PTR [r15], ROLE_COUNT + EXTRA_ARGS + 1
 .else
 cmp QWORD PTR [r15], ROLE_COUNT + EXTRA_ARGS
 .endif
 .endif
 jne .Lrefused
 .ifdef WORKER_INPUT
 mov rax, [r15+16]
 cmp BYTE PTR [rax], 47
 jne .Lrefused
 mov rax, [r15+24]
 cmp BYTE PTR [rax], 47
 jne .Lrefused
 .else
 .ifdef WORKER_EXTERNAL_READ
 mov rax, [r15+16]
 cmp BYTE PTR [rax], 47
 jne .Lrefused
 .else
 mov rsi, [r15+16]
 lea rdi, [rip+.Lmode]
.Lmode_next:
 mov al, BYTE PTR [rdi]
 cmp al, BYTE PTR [rsi]
 jne .Lrefused
 test al, al
 jz .Lmode_ready
 inc rsi
 inc rdi
 jmp .Lmode_next
.Lmode_ready:
 mov rax, [r15+24]
 cmp BYTE PTR [rax], 47
 jne .Lrefused
 mov rax, [r15+32]
 cmp BYTE PTR [rax], 47
 jne .Lrefused
 .endif
 .endif
 xor edi, edi
 mov esi, MAP_BYTES
 mov edx, 3
 mov r10d, 34
 mov r8, -1
 xor r9d, r9d
 mov eax, 9
 syscall
 cmp rax, -4095
 jae .Lrefused
 mov rbp, rax
 /* Exec can inherit SIG_IGN for SIGCHLD. Own waitable children explicitly. */
 mov edi, 17
 lea rsi, [rbp+FD_INFO]
 xor edx, edx
 mov r10d, 8
 mov eax, 13
 syscall
 test rax, rax
 js .Lrefused
 .ifdef WORKER_COST
 mov QWORD PTR [rbp+FD_INFO], 1
 mov edi, 13
 lea rsi, [rbp+FD_INFO]
 xor edx, edx
 mov r10d, 8
 mov eax, 13
 syscall
 test rax, rax
 js .Lrefused
 .endif
 .ifdef WORKER_STORED_READ
 mov QWORD PTR [rbp+FD_INFO], 67112960
 mov QWORD PTR [rbp+FD_INFO+8], 67112960
 mov edi, 1
 lea rsi, [rbp+FD_INFO]
 mov eax, 160
 syscall
 test rax, rax
 js .Lrefused
 .ifdef WORKER_EXTERNAL_READ
 mov rsi, [r15+24]
 call .Lparse_unsigned_word
 mov [rbp+OBS+32], rax
 mov rsi, [r15+32]
 call .Lparse_unsigned_word
 mov [rbp+OBS+40], rax
 mov rsi, [r15+40]
 call .Lparse_fd
 mov [rbp+OBS+48], rax
 mov edi, eax
 mov esi, 1
 mov eax, 72
 syscall
 test rax, rax
 js .Lrefused
 mov rsi, [r15+48]
 call .Lparse_fd
 mov [rbp+OBS+56], rax
 mov edi, eax
 mov esi, 1
 mov eax, 72
 syscall
 test rax, rax
 js .Lrefused
 .else
 .ifdef WORKER_INPUT
 mov rsi, [r15+16]
 .else
 mov rsi, [r15+24]
 .endif
 xor eax, eax
.Lstate_length:
 cmp BYTE PTR [rsi+rax], 0
 je .Lstate_length_ready
 inc rax
 cmp rax, 4083
 jb .Lstate_length
 jmp .Lrefused
.Lstate_length_ready:
 mov [rbp+OBS+16], rax
 movzx eax, BYTE PTR [rsi+rax-1]
 mov [rbp+OBS+24], rax
 .endif
 .endif
 .ifdef WORKER_DISCOVERY
 mov rsi, [r15+80]
 call .Lparse_unsigned_word
 mov [rbp+OBS+32], rax
 mov rsi, [r15+88]
 call .Lparse_unsigned_word
 mov [rbp+OBS+40], rax
 .else
 .ifdef WORKER_INPUT
 mov rsi, [r15+80]
 lea rdi, [rbp+OBS+ROLE_RECORD_END]
 xor eax, eax
.Lexpected_copy:
 mov dl, BYTE PTR [rsi+rax]
 test dl, dl
 jz .Lexpected_done
 cmp rax, 64
 jae .Lrefused
 mov BYTE PTR [rdi+rax], dl
 inc rax
 jmp .Lexpected_copy
.Lexpected_done:
 mov [rbp+OBS+32], rax
 .endif
 .endif
 lea rdi, [rip+.Lentry_magic]
 mov rax, [rdi]
 mov [rbp+OBS], rax
 xor edi, edi
 lea rsi, [rbp+FD_INFO]
 call hia_worker_fd_observe
 test rax, rax
 js .Lrefused
 mov rax, [rbp+FD_INFO+24]
 mov [rbp+OBS+8], rax
 cmp QWORD PTR [rbp+FD_INFO+8], 15
 jne .Lrefused
 mov edi, 1
 lea rsi, [rbp+FD_INFO]
 call hia_worker_fd_observe
 test rax, rax
 js .Lrefused
 cmp QWORD PTR [rbp+FD_INFO+8], 0
 jne .Lrefused
 cmp QWORD PTR [rbp+FD_INFO+24], 0
 jne .Lrefused
 .ifdef WORKER_ARTIFACT
 .equ HAS_ENTRY_DOSSIER, 1
 .else
 .ifndef WORKER_COST
 .equ HAS_ENTRY_DOSSIER, 1
 .endif
 .endif
 .ifdef HAS_ENTRY_DOSSIER
 mov rsi, [r15+40]
 call .Lparse_fd
 mov [rbp+OBS+32], rax
 mov edi, eax
 lea rsi, [rbp+FD_INFO]
 call hia_worker_fd_observe
 test rax, rax
 js .Lrefused
 mov rax, [rbp+FD_INFO+8]
 mov [rbp+OBS+48], rax
 mov rax, [rbp+FD_INFO+24]
 mov [rbp+OBS+16], rax
 mov edi, DWORD PTR [rbp+OBS+32]
 lea rsi, [rbp+OBS+64]
 mov edx, 312
 xor r10d, r10d
 call .Lread_exact
 .ifndef WORKER_READ
 mov rsi, [r15+48]
 call .Lparse_fd
 mov [rbp+OBS+40], rax
 mov edi, eax
 lea rsi, [rbp+FD_INFO]
 call hia_worker_fd_observe
 test rax, rax
 js .Lrefused
 mov rax, [rbp+FD_INFO+8]
 mov [rbp+OBS+56], rax
 mov rax, [rbp+FD_INFO+24]
 mov [rbp+OBS+24], rax
 .endif
 .endif
 xor r12d, r12d
 lea r13, [rbp+OBS+ROLE_OFFSET]
.Lentry_roles:
 cmp r12, ROLE_COUNT
 jae .Lentry_ready
 mov rsi, [r15+r12*8+8*(EXTRA_ARGS+1)]
 call .Lparse_fd
 mov [rbp+ROLES+r12*8+8*FIRST_ROLE], rax
 mov edi, eax
 mov rsi, r13
 call hia_worker_fd_observe
 test rax, rax
 js .Lrefused
 add r13, 40
 inc r12
 jmp .Lentry_roles
.Lentry_ready:
 mov QWORD PTR [rbp+OBS_SIZE], ENTRY_SIZE

.Lnext:
 lea rdi, [rbp+OBS]
 mov rsi, [rbp+OBS_SIZE]
 lea rdx, [rbp+COMMAND]
 mov ecx, 2048
 lea r8, [rbp+WORK]
 mov r9d, 4096
 .byte 0xe8
worker_policy_hole: .long 0
 cmp eax, HEADER
 jb .Lrefused
 cmp eax, 2048
 ja .Lrefused
 mov [rbp+OUTPUT_END], rax
 mov rax, [rip+.Lcommand_magic]
 cmp QWORD PTR [rbp+COMMAND], rax
 jne .Lrefused
 mov rax, [rbp+SEQUENCE]
 inc rax
 cmp QWORD PTR [rbp+COMMAND+8], rax
 jne .Lrefused
 mov [rbp+SEQUENCE], rax
 cmp QWORD PTR [rbp+COMMAND+40], 3
 ja .Lrefused
 cmp QWORD PTR [rbp+COMMAND+56], HEADER
 jne .Lrefused
 mov rax, [rbp+OUTPUT_END]
 sub rax, HEADER
 cmp QWORD PTR [rbp+COMMAND+48], rax
 jne .Lrefused
 mov rax, [rbp+COMMAND+16]
 mov [rbp+CURRENT], rax
 mov rax, [rip+.Lobservation_magic]
 mov [rbp+OBS], rax
 mov rax, [rbp+SEQUENCE]
 mov [rbp+OBS+8], rax
 mov rax, [rbp+CURRENT]
 mov [rbp+OBS+16], rax
 mov QWORD PTR [rbp+OBS+24], 0
 mov QWORD PTR [rbp+OBS+32], 0
 mov QWORD PTR [rbp+OBS+40], 0
 mov QWORD PTR [rbp+OBS+48], 0
 mov QWORD PTR [rbp+OBS+56], 0
 mov QWORD PTR [rbp+OBS_SIZE], 64
 cmp rax, 1
 je .Lrun
 cmp rax, 2
 je .Lread
 cmp rax, 3
 je .Lpublish
 cmp rax, 4
 je .Lclock
 .ifdef WORKER_COST
 cmp rax, 6
 je .Lrun
 cmp rax, 7
 je .Lreceive_peer
 cmp rax, 8
 je .Lfinish_peer
 .ifdef WORKER_STORED_READ
 cmp rax, 9
 je .Lstage
 .ifdef WORKER_INPUT
 cmp rax, 10
 je .Lrandom
 .endif
 .endif
 .endif
 cmp rax, 5
 jne .Lrefused
 .ifdef WORKER_COST
 cmp QWORD PTR [rbp+PEER], 0
 jne .Lrefused
 .ifdef WORKER_STORED_READ
 cmp QWORD PTR [rbp+PEER+32], 0
 jne .Lrefused
 .endif
 .endif
 xor edi, edi
 .ifdef WORKER_INPUT
 mov rdi, [rbp+COMMAND+144]
 cmp rdi, 255
 ja .Lrefused
 .endif
 jmp .Lexit

.Lrun:
 mov rax, [rbp+COMMAND+24]
 cmp rax, ROLE_COUNT + FIRST_ROLE
 jae .Lrefused
 mov rax, [rbp+ROLES+rax*8]
 mov [rbp+PROCESS], rax
.Lstage:
 call hia_worker_memfd
 test rax, rax
 js .Lrefused
 mov [rbp+STAGED], rax
 mov [rbp+PROCESS+8], rax
 mov edi, eax
 lea rsi, [rbp+COMMAND+HEADER]
 mov rdx, [rbp+COMMAND+48]
 call .Lwrite_exact
 xor r12d, r12d
 lea r13, [rbp+COMMAND+64]
.Lfragments:
 cmp r12, [rbp+COMMAND+40]
 jae .Lseal_input
 .ifdef WORKER_ARTIFACT
 cmp QWORD PTR [r13], -1
 jne .Lfile_fragment
 mov rsi, [r13+8]
 cmp rsi, 384
 jb .Lrefused
 cmp rsi, HEADER
 ja .Lrefused
 mov eax, HEADER
 sub rax, rsi
 mov rdx, [r13+16]
 cmp rdx, rax
 ja .Lrefused
 lea rsi, [rbp+COMMAND+rsi]
 mov edi, DWORD PTR [rbp+STAGED]
 call .Lwrite_exact
 jmp .Lfragment_done
.Lfile_fragment:
 .endif
 mov edi, DWORD PTR [r13]
 mov rsi, [r13+8]
 mov rdx, [r13+16]
 mov ecx, DWORD PTR [rbp+STAGED]
 lea r8, [rbp+SCRATCH]
 mov r9d, 16384
 call hia_worker_fragment_copy
 test rax, rax
 jnz .Lrefused
 .ifdef WORKER_ARTIFACT
.Lfragment_done:
 .endif
 inc r12
 add r13, 24
 jmp .Lfragments
.Lseal_input:
 mov edi, DWORD PTR [rbp+STAGED]
 call hia_worker_seal
 test rax, rax
 jnz .Lrefused
 .ifdef WORKER_STORED_READ
 cmp QWORD PTR [rbp+CURRENT], 9
 je .Lsend_peer
 .endif
 call hia_worker_memfd
 test rax, rax
 js .Lrefused
 mov [rbp+PROCESS+16], rax
 call hia_worker_memfd
 test rax, rax
 js .Lrefused
 mov [rbp+PROCESS+24], rax
 lea rax, [rip+.Lchild_name]
 mov [rbp+ARGV], rax
 mov rax, [rbp+COMMAND+32]
 cmp rax, 12
 ja .Lrefused
 mov [rbp+LOCAL_ARGS], rax
 lea rax, [rbp+ARGV]
 mov [rbp+PROCESS+32], rax
 lea rax, [rbp+CARRIED]
 mov [rbp+PROCESS+40], rax
 mov QWORD PTR [rbp+PROCESS+48], 0
 xor r12d, r12d
 lea r13, [rbp+COMMAND+192]
.Larguments:
 cmp r12, [rbp+LOCAL_ARGS]
 jae .Lexec
 mov rax, [r13]
 mov rdx, [r13+8]
 cmp rax, 1
 je .Larg_original
 cmp rax, 2
 je .Larg_literal
 cmp rax, 3
 je .Larg_number
 .ifdef WORKER_STORED_READ
 cmp rax, 5
 je .Larg_join
 .endif
 .ifdef WORKER_ARTIFACT
 cmp rax, 6
 je .Larg_span
 .endif
 cmp rax, 4
 jne .Lrefused
 cmp rdx, 3
 jb .Lrefused
 cmp rdx, 2147483647
 ja .Lrefused
 mov rcx, [rbp+PROCESS+48]
 mov DWORD PTR [rbp+CARRIED+rcx*4], edx
 inc QWORD PTR [rbp+PROCESS+48]
 jmp .Larg_number
.Larg_original:
 .ifdef WORKER_EXTERNAL_READ
 cmp rdx, 1
 jne .Lrefused
 .else
 .ifdef WORKER_INPUT
 cmp rdx, 1
 jb .Lrefused
 cmp rdx, 2
 ja .Lrefused
 .else
 cmp rdx, 2
 jb .Lrefused
 cmp rdx, 3
 ja .Lrefused
 .endif
 .endif
 mov rax, [r15+rdx*8+8]
 jmp .Larg_store
.Larg_literal:
 cmp rdx, 136
 jb .Lrefused
 lea rdi, [rbp+COMMAND+176]
 cmp rdx, 176
 jb .Lliteral_bounds
 cmp rdx, 384
 jb .Lrefused
 cmp rdx, 512
 jae .Lrefused
 lea rdi, [rbp+COMMAND+512]
.Lliteral_bounds:
 lea rax, [rbp+COMMAND+rdx]
 mov rsi, rax
.Lliteral_end:
 cmp rsi, rdi
 jae .Lrefused
 cmp BYTE PTR [rsi], 0
 je .Larg_store
 inc rsi
 jmp .Lliteral_end
.ifdef WORKER_STORED_READ
.Larg_join:
 cmp rdx, 384
 jb .Lrefused
 cmp rdx, 512
 jae .Lrefused
 lea rdi, [rbp+JOINED]
 .ifdef WORKER_INPUT
 mov rsi, [r15+16]
 .else
 mov rsi, [r15+24]
 .endif
.Ljoin_path:
 .ifdef WORKER_ARTIFACT
 lea rax, [rbp+JOINED+4083]
 cmp rdi, rax
 jae .Lrefused
 .endif
 lodsb
 test al, al
 jz .Ljoin_suffix
 stosb
 jmp .Ljoin_path
.Ljoin_suffix:
 .ifdef WORKER_ARTIFACT
 lea rax, [rbp+JOINED+2]
 cmp rdi, rax
 jb .Lrefused
 cmp BYTE PTR [rdi-1], 47
 je .Lrefused
 .endif
 lea rsi, [rbp+COMMAND+rdx]
 lea rcx, [rbp+JOINED+4096]
 lea r8, [rbp+COMMAND+512]
.Ljoin_copy:
 cmp rdi, rcx
 jae .Lrefused
 cmp rsi, r8
 jae .Lrefused
 lodsb
 stosb
 test al, al
 jnz .Ljoin_copy
 lea rax, [rbp+JOINED]
 jmp .Larg_store
.endif
.ifdef WORKER_ARTIFACT
.Larg_span:
 /* The HIA commands provide a bounded fd/offset/extent tuple. */
 cmp rdx, 384
 jb .Lrefused
 cmp rdx, HEADER-24
 ja .Lrefused
 lea r14, [rbp+COMMAND+rdx]
 mov rdi, [r14]
 cmp rdi, 2147483647
 ja .Lrefused
 lea rsi, [rbp+FD_INFO]
 call hia_worker_fd_observe
 test rax, rax
 js .Lrefused
 cmp QWORD PTR [rbp+FD_INFO+8], 15
 jne .Lrefused
 mov rax, [rbp+FD_INFO+24]
 mov r10, [r14+8]
 cmp r10, rax
 ja .Lrefused
 sub rax, r10
 mov rdx, [r14+16]
 cmp rdx, 16384
 ja .Lrefused
 cmp rdx, rax
 ja .Lrefused
 imul rbx, r12, ARG_SPAN_SIZE
 lea rbx, [rbp+ARG_SPAN+rbx]
 mov rsi, rbx
 mov edi, DWORD PTR [r14]
 call .Lread_exact
 mov rcx, [r14+16]
 mov BYTE PTR [rbx+rcx], 0
 jrcxz .Larg_span_ready
 mov rdi, rbx
 xor eax, eax
 repne scasb
 je .Lrefused
.Larg_span_ready:
 mov rax, rbx
 jmp .Larg_store
.endif
.Larg_number:
 mov rax, rdx
 mov rcx, r12
 imul rcx, 24
 lea rsi, [rbp+NUMBERS+rcx+23]
 mov BYTE PTR [rsi], 0
 mov edi, 10
.Ldecimal:
 xor edx, edx
 div rdi
 add dl, 48
 dec rsi
 mov BYTE PTR [rsi], dl
 test rax, rax
 jnz .Ldecimal
 mov rax, rsi
.Larg_store:
 mov [rbp+ARGV+r12*8+8], rax
 inc r12
 add r13, 16
 jmp .Larguments
.Lexec:
 mov QWORD PTR [rbp+ARGV+r12*8+8], 0
 call .Ldeadline
 mov [rbp+PROCESS+56], rax
 .ifdef WORKER_COST
 cmp QWORD PTR [rbp+CURRENT], 6
 je .Lstart_peer
 .endif
 lea rdi, [rbp+PROCESS]
 call hia_worker_run
 mov [rbp+OBS+24], rax
 mov edi, DWORD PTR [rbp+STAGED]
 mov eax, 3
 syscall
 mov edi, DWORD PTR [rbp+PROCESS+24]
 lea rsi, [rbp+FD_INFO]
 call hia_worker_fd_observe
 test rax, rax
 js .Lrefused
 cmp QWORD PTR [rbp+FD_INFO+24], 0
 jne .Lrefused
 mov edi, DWORD PTR [rbp+PROCESS+24]
 mov eax, 3
 syscall
 .ifdef WORKER_ARTIFACT
 mov edi, DWORD PTR [rbp+PROCESS+16]
 lea rsi, [rbp+FD_INFO]
 call hia_worker_fd_observe
 test rax, rax
 js .Lrefused
 mov rax, [rbp+FD_INFO+8]
 mov [rbp+OBS+48], rax
 .endif
 mov edi, DWORD PTR [rbp+PROCESS+16]
 call hia_worker_seal
 test rax, rax
 jnz .Lrefused
 mov edi, DWORD PTR [rbp+PROCESS+16]
 lea rsi, [rbp+FD_INFO]
 call hia_worker_fd_observe
 test rax, rax
 js .Lrefused
 mov rax, [rbp+PROCESS+16]
 mov [rbp+OBS+32], rax
 mov rax, [rbp+FD_INFO+24]
 mov [rbp+OBS+40], rax
 mov edx, 64
 cmp rax, rdx
 cmovb rdx, rax
 mov [rbp+OBS+56], rdx
 mov edi, DWORD PTR [rbp+OBS+32]
 lea rsi, [rbp+OBS+64]
 xor r10d, r10d
 call .Lread_exact
 mov rax, [rbp+OBS+56]
 add rax, 64
 mov [rbp+OBS_SIZE], rax
 jmp .Lnext

.Ldeadline:
 call hia_worker_now
 test rax, rax
 js .Lrefused
 mov rcx, [rbp+COMMAND+152]
 test rcx, rcx
 jz .Lrefused
 add rax, rcx
 jc .Lrefused
 js .Lrefused
 ret

.ifdef WORKER_COST
.Lpeer_index:
 lea rax, [rbp+PEER]
 .ifdef WORKER_STORED_READ
 mov rcx, [rbp+COMMAND+176]
 cmp rcx, PEER_COUNT
 jae .Lrefused
 shl rcx, 5
 add rax, rcx
 .endif
 ret

.Lstart_peer:
 mov rax, [rbp+PROCESS+16]
 mov [rbp+TEMP], rax
 call .Lpeer_index
 mov r14, rax
 lea rdi, [rbp+PROCESS]
 mov rsi, r14
 call hia_worker_peer_start
 test rax, rax
 js .Lrefused
 mov rax, [rbp+PROCESS+24]
 mov [r14+24], rax
 mov edi, DWORD PTR [rbp+STAGED]
 mov eax, 3
 syscall
 mov edi, DWORD PTR [rbp+TEMP]
 mov eax, 3
 syscall
 mov rax, [r14+8]
 mov [rbp+OBS+64], rax
 mov rax, [r14+16]
 mov [rbp+OBS+72], rax
 mov QWORD PTR [rbp+OBS+40], 16
 mov QWORD PTR [rbp+OBS+56], 16
 mov QWORD PTR [rbp+OBS_SIZE], 80
 jmp .Lnext

.Lreceive_peer:
 cmp QWORD PTR [rbp+COMMAND+40], 0
 jne .Lrefused
 mov r12, [rbp+COMMAND+144]
 cmp r12, 8192
 ja .Lrefused
 call .Ldeadline
 mov r14, rax
 call .Lpeer_index
 mov rdi, rax
 lea rsi, [rbp+OBS+64]
 mov rdx, r12
 mov rcx, r14
 call hia_worker_peer_read
 test rax, rax
 jnz .Lrefused
 .ifdef WORKER_STORED_READ
 cmp QWORD PTR [rbp+COMMAND+184], 0
 je .Lpeer_read_size
 call hia_worker_memfd
 test rax, rax
 js .Lrefused
 mov [rbp+OBS+32], rax
 mov edi, eax
 lea rsi, [rbp+OBS+64]
 mov rdx, r12
 call .Lwrite_exact
 mov edi, DWORD PTR [rbp+OBS+32]
 call hia_worker_seal
 test rax, rax
 jnz .Lrefused
.Lpeer_read_size:
 .endif
 mov [rbp+OBS+40], r12
 mov [rbp+OBS+56], r12
 add r12, 64
 mov [rbp+OBS_SIZE], r12
 jmp .Lnext

.Lfinish_peer:
 call .Ldeadline
 mov r13, rax
 call .Lpeer_index
 mov r14, rax
 mov rsi, r13
 mov rdi, r14
 call hia_worker_peer_finish
 mov [rbp+OBS+24], rax
 mov edi, DWORD PTR [r14+24]
 lea rsi, [rbp+FD_INFO]
 call hia_worker_fd_observe
 test rax, rax
 js .Lrefused
 cmp QWORD PTR [rbp+FD_INFO+24], 0
 jne .Lrefused
 mov edi, DWORD PTR [r14+24]
 mov eax, 3
 syscall
 jmp .Lnext
.ifdef WORKER_STORED_READ
.Lsend_peer:
 mov edi, DWORD PTR [rbp+STAGED]
 lea rsi, [rbp+FD_INFO]
 call hia_worker_fd_observe
 test rax, rax
 js .Lrefused
 mov r12, [rbp+FD_INFO+24]
 cmp r12, 8256
 ja .Lrefused
 mov edi, DWORD PTR [rbp+STAGED]
 lea rsi, [rbp+SCRATCH]
 mov rdx, r12
 xor r10d, r10d
 call .Lread_exact
 call .Ldeadline
 mov r14, rax
 call .Lpeer_index
 mov rdi, rax
 lea rsi, [rbp+SCRATCH]
 mov rdx, r12
 mov rcx, r14
 call hia_worker_peer_send
 test rax, rax
 jnz .Lrefused
 mov edi, DWORD PTR [rbp+STAGED]
 mov eax, 3
 syscall
 jmp .Lnext
.endif
.endif

.Lread:
 cmp QWORD PTR [rbp+COMMAND+40], 1
 jne .Lrefused
 mov rax, [rbp+COMMAND+64]
 mov [rbp+OBS+32], rax
 mov edi, eax
 lea rsi, [rbp+FD_INFO]
 call hia_worker_fd_observe
 test rax, rax
 js .Lrefused
 mov rax, [rbp+FD_INFO+24]
 mov [rbp+OBS+40], rax
 mov r10, [rbp+COMMAND+72]
 cmp r10, rax
 ja .Lrefused
 sub rax, r10
 mov rdx, [rbp+COMMAND+80]
 cmp rdx, 1024
 ja .Lrefused
 cmp rdx, rax
 ja .Lrefused
 mov [rbp+OBS+48], r10
 mov [rbp+OBS+56], rdx
 mov edi, DWORD PTR [rbp+OBS+32]
 lea rsi, [rbp+OBS+64]
 call .Lread_exact
 mov rax, [rbp+OBS+56]
 add rax, 64
 mov [rbp+OBS_SIZE], rax
 jmp .Lnext

.Lclock:
 .ifdef WORKER_ARTIFACT
 cmp QWORD PTR [rbp+COMMAND+144], 0
 je .Lclock_monotonic
 cmp QWORD PTR [rbp+COMMAND+144], 1
 jne .Lrefused
 xor edi, edi
 lea rsi, [rbp+CLOCK]
 mov eax, 228
 syscall
 test rax, rax
 js .Lrefused
 mov rax, [rbp+CLOCK]
 test rax, rax
 js .Lrefused
 mov ecx, 1000000000
 mul rcx
 test rdx, rdx
 jnz .Lrefused
 add rax, [rbp+CLOCK+8]
 jc .Lrefused
 jmp .Lclock_sample
.Lclock_monotonic:
 .endif
 call hia_worker_now
 test rax, rax
 js .Lrefused
 .ifdef WORKER_ARTIFACT
.Lclock_sample:
 .endif
 mov [rbp+OBS+64], rax
 mov QWORD PTR [rbp+OBS+40], 8
 mov QWORD PTR [rbp+OBS+56], 8
 mov QWORD PTR [rbp+OBS_SIZE], 72
 jmp .Lnext

.ifdef WORKER_INPUT
.Lrandom:
 mov r12, [rbp+COMMAND+144]
 test r12, r12
 jz .Lrefused
 cmp r12, 128
 ja .Lrefused
 lea rdi, [rbp+OBS+64]
 mov rsi, r12
 xor edx, edx
.Lrandom_more:
 mov eax, 318
 syscall
 cmp rax, -4
 je .Lrandom_more
 test rax, rax
 jle .Lrefused
 add rdi, rax
 sub rsi, rax
 jnz .Lrandom_more
 mov [rbp+OBS+40], r12
 mov [rbp+OBS+56], r12
 add r12, 64
 mov [rbp+OBS_SIZE], r12
 jmp .Lnext
.endif

.Lpublish:
 .ifdef WORKER_DISCOVERY
 mov rax, [rbp+COMMAND+40]
 dec rax
 cmp rax, 1
 ja .Lrefused
 .else
 cmp QWORD PTR [rbp+COMMAND+40], 1
 jne .Lrefused
 .endif
 mov edi, 1
 lea rsi, [rbp+COMMAND+HEADER]
 mov rdx, [rbp+COMMAND+48]
 call .Lwrite_exact
 .ifdef WORKER_DISCOVERY
 xor r12d, r12d
 lea r13, [rbp+COMMAND+64]
.Lpublish_fragment:
 mov edi, DWORD PTR [r13]
 mov rsi, [r13+8]
 mov rdx, [r13+16]
 .else
 mov edi, DWORD PTR [rbp+COMMAND+64]
 mov rsi, [rbp+COMMAND+72]
 mov rdx, [rbp+COMMAND+80]
 .endif
 mov ecx, 1
 lea r8, [rbp+SCRATCH]
 mov r9d, 16384
 call hia_worker_fragment_copy
 test rax, rax
 jnz .Lrefused
 .ifdef WORKER_DISCOVERY
 inc r12
 add r13, 24
 cmp r12, [rbp+COMMAND+40]
 jb .Lpublish_fragment
 .endif
 mov edi, 1
 call hia_worker_seal
 test rax, rax
 jnz .Lrefused
 jmp .Lnext

.ifdef WORKER_EXTERNAL_READ
.equ HAS_UNSIGNED_ARG, 1
.endif
.ifdef WORKER_DISCOVERY
.equ HAS_UNSIGNED_ARG, 1
.endif
.ifdef HAS_UNSIGNED_ARG
.Lparse_unsigned_word:
 cmp BYTE PTR [rsi], 0
 je .Lrefused
 xor eax, eax
 mov r9d, 10
.Lunsigned_digit:
 movzx ecx, BYTE PTR [rsi]
 test cl, cl
 jz .Lunsigned_ready
 sub ecx, 48
 cmp ecx, 9
 ja .Lrefused
 mul r9
 test rdx, rdx
 jnz .Lrefused
 add rax, rcx
 jc .Lrefused
 inc rsi
 jmp .Lunsigned_digit
.Lunsigned_ready:
 ret
.endif

.Lparse_fd:
 xor eax, eax
 xor ecx, ecx
.Lparse_digit:
 movzx edx, BYTE PTR [rsi]
 test dl, dl
 jz .Lparsed_fd
 sub edx, 48
 cmp edx, 9
 ja .Lrefused
 imul rax, rax, 10
 add rax, rdx
 cmp rax, 2147483647
 ja .Lrefused
 inc rsi
 jmp .Lparse_digit
.Lparsed_fd:
 cmp rax, 3
 jb .Lrefused
 cmp rax, 2147483647
 ja .Lrefused
 ret

.Lread_exact:
 test rdx, rdx
 jz .Lread_done
.Lread_now:
 mov eax, 17
 syscall
 cmp rax, -4
 je .Lread_now
 test rax, rax
 jle .Lrefused
 add rsi, rax
 add r10, rax
 sub rdx, rax
 jnz .Lread_now
.Lread_done:
 ret

.Lwrite_exact:
 test rdx, rdx
 jz .Lwrite_done
.Lwrite_now:
 mov eax, 1
 syscall
 cmp rax, -4
 je .Lwrite_now
 test rax, rax
 jle .Lrefused
 add rsi, rax
 sub rdx, rax
 jnz .Lwrite_now
.Lwrite_done:
 ret

.Lrefused:
 .ifdef WORKER_COST
 test rbp, rbp
 jz .Ldiagnose
 lea r12, [rbp+PEER]
 mov r13d, PEER_COUNT
.Labort_peer:
 cmp QWORD PTR [r12], 0
 je .Labort_next
 mov rdi, r12
 xor esi, esi
 call hia_worker_peer_finish
.Labort_next:
 add r12, 32
 dec r13d
 jnz .Labort_peer
.Ldiagnose:
 .endif
 lea rsi, [rip+.Ldiagnostic]
 mov edx, .Ldiagnostic_end-.Ldiagnostic
 mov edi, 2
 mov eax, 1
 syscall
 mov edi, 4
.Lexit:
 mov eax, 60
 syscall
 ud2

.Lentry_magic: .ascii "HIADRI01"
.Lcommand_magic: .ascii "HIADFC01"
.Lobservation_magic: .ascii "HIADFO01"
.ifdef WORKER_COST
.ifdef WORKER_STORED_READ
.ifdef WORKER_ARTIFACT
.Lmode: .asciz "--worker-artifact"
.else
.Lmode: .asciz "--own-store"
.endif
.else
.Lmode: .asciz "--own-cost"
.endif
.else
.ifdef WORKER_READ
.Lmode: .asciz "--worker-read"
.else
.Lmode: .asciz "--worker-describe"
.endif
.endif
.Lchild_name: .asciz "hia-worker-effect"
.ifdef WORKER_COST
.ifdef WORKER_STORED_READ
.ifdef WORKER_ARTIFACT
.Ldiagnostic: .ascii "native HIA Artifact Worker transport refused\n"
.else
.ifdef WORKER_DISCOVERY
.Ldiagnostic: .ascii "native HIA Discovery materialization transport refused\n"
.else
.ifdef WORKER_INPUT
.Ldiagnostic: .ascii "native HIA input materialization transport refused\n"
.else
.Ldiagnostic: .ascii "native HIA Read Store transport refused\n"
.endif
.endif
.endif
.else
.Ldiagnostic: .ascii "native HIA Worker cost transport refused\n"
.endif
.else
.ifdef WORKER_READ
.Ldiagnostic: .ascii "native HIA Read Worker transport refused\n"
.else
.Ldiagnostic: .ascii "native HIA Describe Worker transport refused\n"
.endif
.endif
.Ldiagnostic_end:
.section .note.GNU-stack,"",@progbits
