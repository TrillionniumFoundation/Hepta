.equ WORKER_COST, 1
.equ WORKER_STORED_READ, 1
.equ WORKER_EXTERNAL_READ, 1
/* Fixed Linux/SysV adapter for a sealed HIA Worker action stream.
 * The embedded HIA image owns every authorization, role selection, argument,
 * byte fragment, state/receipt transition and final publication decision.
 */
.intel_syntax noprefix
.text
.global _start, worker_policy_hole
.equ WORK, 0
.ifdef WORKER_EMIT
.global worker_emit_product_hole, worker_emit_proof_hole
.ifdef WORKER_ADOPT
.equ WORK_BYTES, 12288
.equ EMIT_DEFER_PRODUCT, 0xffffffed
.equ ADOPT_DEFER_FRONT, 0xffffffee
.else
.ifdef WORKER_VERIFY
.equ WORK_BYTES, 12288
.equ VERIFY_SECTION, EMIT_TEMP_FDS + 128
.equ VERIFY_NEEDS_PUBLICATION, 0xffffffe5
.equ VERIFY_NEEDS_FINITE, 0xffffffe2
.equ VERIFY_FINITE_READY, 0xffffffe7
.equ VERIFY_NEEDS_TERMINAL, 0xffffffe1
.else
.equ WORK_BYTES, 9216
.equ EMIT_DEFER_PRODUCT, 0xffffffe8
.endif
.endif
.equ EMIT_DEFER_PROOF, 0xffffffe9
.equ EMIT_PARENT, 41472
.equ EMIT_DIRECTORY, EMIT_PARENT + 8
.equ EMIT_NAME, EMIT_PARENT + 16
.equ EMIT_FILE, EMIT_NAME + 48
.equ EMIT_PATH, EMIT_FILE + 16
.equ EMIT_BEFORE, EMIT_PATH + 4096
.equ EMIT_AFTER, EMIT_BEFORE + 144
.equ EMIT_DIR_STAT, EMIT_AFTER + 144
.equ EMIT_STREAMS, 48000
.equ EMIT_TEMP_COUNT, EMIT_STREAMS + 16
.equ EMIT_TEMP_FDS, EMIT_TEMP_COUNT + 8
.equ EMIT_STREAM_LIMIT, 8388608
.else
.equ WORK_BYTES, 4096
.endif
.equ COMMAND, WORK_BYTES
.equ OBS, COMMAND + 4096
.equ SCRATCH, 65536
.equ ROLES, 32768
.ifdef WORKER_LAUNCHER
.equ ARGV, 104448
.equ CARRIED, 105216
.equ NUMBERS, 105600
.equ ARGV_LIMIT, 83
.equ COMMAND_LIMIT, 4096
.if ARGV + 8 * (ARGV_LIMIT + 2) > CARRIED || CARRIED + 4 * ARGV_LIMIT > NUMBERS
.error "Launcher argument storage overlaps the next buffer"
.endif
.else
.ifdef WORKER_EMIT
.equ ARGV, 35584
.equ CARRIED, 35840
.equ NUMBERS, 36096
.equ ARGV_LIMIT, 12
.else
.ifdef WORKER_INSPECTION
/* Forty descriptor roles occupy [32768, 33088). */
.equ ARGV, 33088
.else
.equ ARGV, 33024
.endif
.equ CARRIED, 33200
.equ NUMBERS, 33408
.equ ARGV_LIMIT, 12
.endif
.endif
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
.ifdef WORKER_BOOTSTRAP
.equ ROLE_OFFSET, 64
.else
.equ ROLE_OFFSET, 376
.endif
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
.ifdef WORKER_BOOTSTRAP
.equ ROLE_COUNT, 11
.equ EXTRA_ARGS, 4
.else
.ifdef WORKER_CONTEXT
.ifdef WORKER_INSPECTION
.ifdef WORKER_CANDIDATE
.equ ROLE_COUNT, 38
.else
.ifdef WORKER_ROLLBACK
.equ ROLE_COUNT, 35
.else
.ifdef WORKER_EMIT
.ifdef WORKER_ADOPT
.equ ROLE_COUNT, 73
.else
.ifdef WORKER_VERIFY
.equ ROLE_COUNT, 77
.else
.equ ROLE_COUNT, 70
.endif
.endif
.else
.equ ROLE_COUNT, 40
.endif
.endif
.endif
.else
.equ ROLE_COUNT, 31
.endif
.else
.equ ROLE_COUNT, 23
.endif
.equ EXTRA_ARGS, 6
.endif
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
.if ROLES + 8 * (FIRST_ROLE + ROLE_COUNT) > ARGV
.error "Worker descriptor roles overlap child arguments"
.endif
.ifdef WORKER_INPUT
.equ ENTRY_SIZE, ROLE_RECORD_END + 64
.else
.equ ENTRY_SIZE, ROLE_RECORD_END
.endif
.equ HEADER, 512
.ifndef WORKER_LAUNCHER
.equ COMMAND_LIMIT, 2048
.endif
.ifdef WORKER_INPUT
.equ HAS_RANDOM_PORT, 1
.endif
.ifdef WORKER_CONTEXT
.equ HAS_RANDOM_PORT, 1
.equ HAS_MAKE_PORT, 1
.endif
.ifdef WORKER_INPUT
.equ HAS_PATH_ENTRY, 1
.endif
.ifdef WORKER_BOOTSTRAP
.equ HAS_PATH_ENTRY, 1
.equ HAS_MAKE_PORT, 1
.equ BOOT_ROOT, 34992
.equ BOOT_STAT, 35000
.equ BOOT_NAMED_STAT, 35144
.endif
.ifdef WORKER_LAUNCHER
.equ HAS_PATH_ENTRY, 1
.equ HAS_MAKE_PORT, 1
.endif

_start:
 cld
 xor ebp, ebp
 mov r15, rsp
 .ifdef WORKER_LAUNCHER
 cmp QWORD PTR [r15], 5
 .else
 .ifdef WORKER_DISCOVERY
 cmp QWORD PTR [r15], ROLE_COUNT + EXTRA_ARGS + 2
 je .Ldiscovery_arity
 cmp QWORD PTR [r15], ROLE_COUNT + EXTRA_ARGS + 3
 .else
 .ifdef WORKER_INPUT
 cmp QWORD PTR [r15], ROLE_COUNT + EXTRA_ARGS + 1
 .else
 cmp QWORD PTR [r15], ROLE_COUNT + EXTRA_ARGS
 .endif
 .endif
 .endif
 jne .Lrefused
 .ifdef WORKER_DISCOVERY
.Ldiscovery_arity:
 .endif
 .ifdef HAS_PATH_ENTRY
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
 .ifdef WORKER_LAUNCHER
 jmp .Llauncher_entry
 .endif
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
 .ifdef HAS_PATH_ENTRY
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
 cmp QWORD PTR [r15], ROLE_COUNT + EXTRA_ARGS + 3
 jne .Ldiscovery_metadata_ready
 mov rsi, [r15+96]
 call .Lparse_fd
 mov [rbp+OBS+48], rax
 mov edi, eax
 lea rsi, [rbp+FD_INFO]
 call .Lhia_worker_fd_observe
 test rax, rax
 js .Lrefused
 cmp QWORD PTR [rbp+FD_INFO+8], 15
 jne .Lrefused
 mov rax, [rbp+FD_INFO+24]
 mov [rbp+OBS+56], rax
.Ldiscovery_metadata_ready:
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
 call .Lhia_worker_fd_observe
 test rax, rax
 js .Lrefused
 mov rax, [rbp+FD_INFO+24]
 mov [rbp+OBS+8], rax
 cmp QWORD PTR [rbp+FD_INFO+8], 15
 jne .Lrefused
 mov edi, 1
 lea rsi, [rbp+FD_INFO]
 call .Lhia_worker_fd_observe
 test rax, rax
 js .Lrefused
 cmp QWORD PTR [rbp+FD_INFO+8], 0
 jne .Lrefused
 cmp QWORD PTR [rbp+FD_INFO+24], 0
 jne .Lrefused
 .ifdef WORKER_BOOTSTRAP
 mov rsi, [r15+32]
 call .Lparse_fd
 mov [rbp+OBS+24], rax
 mov edi, eax
 lea rsi, [rbp+FD_INFO]
 call .Lhia_worker_fd_observe
 test rax, rax
 js .Lrefused
 mov rax, [rbp+FD_INFO+24]
 mov [rbp+OBS+32], rax
 mov rax, [rbp+FD_INFO+8]
 mov [rbp+OBS+40], rax
 .else
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
 call .Lhia_worker_fd_observe
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
 call .Lhia_worker_fd_observe
 test rax, rax
 js .Lrefused
 mov rax, [rbp+FD_INFO+8]
 mov [rbp+OBS+56], rax
 mov rax, [rbp+FD_INFO+24]
 mov [rbp+OBS+24], rax
 .endif
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
 call .Lhia_worker_fd_observe
 test rax, rax
 js .Lrefused
 add r13, 40
 inc r12
 jmp .Lentry_roles
.Lentry_ready:
 mov QWORD PTR [rbp+OBS_SIZE], ENTRY_SIZE

.Lnext:
.macro worker_policy_arguments
 lea rdi, [rbp+OBS]
 mov rsi, [rbp+OBS_SIZE]
 lea rdx, [rbp+COMMAND]
 mov ecx, COMMAND_LIMIT
 lea r8, [rbp+WORK]
 mov r9d, WORK_BYTES
.endm
 .ifdef WORKER_VERIFY
 mov r14d, 8
.Lverify_policy:
 mov r12, [rbp+VERIFY_SECTION]
 worker_policy_arguments
 cmp r12, 1
 je .Lverify_publication
 cmp r12, 2
 je .Lverify_finite
 .byte 0xe8
worker_policy_hole: .long 0
 cmp eax, VERIFY_NEEDS_PUBLICATION
 je .Lverify_to_publication
 cmp eax, VERIFY_NEEDS_FINITE
 je .Lverify_to_finite
 jmp .Lworker_policy_answer
.Lverify_publication:
 .byte 0xe8
worker_emit_product_hole: .long 0
 cmp eax, VERIFY_NEEDS_TERMINAL
 je .Lverify_to_front
 jmp .Lworker_policy_answer
.Lverify_finite:
 .byte 0xe8
worker_emit_proof_hole: .long 0
 cmp eax, VERIFY_FINITE_READY
 jne .Lworker_policy_answer
.Lverify_to_front:
 mov QWORD PTR [rbp+VERIFY_SECTION], 0
 jmp .Lverify_retry
.Lverify_to_publication:
 mov QWORD PTR [rbp+VERIFY_SECTION], 1
 jmp .Lverify_retry
.Lverify_to_finite:
 mov QWORD PTR [rbp+VERIFY_SECTION], 2
.Lverify_retry:
 dec r14d
 jz .Lrefused
 jmp .Lverify_policy
.Lworker_policy_answer:
 .else
 .ifdef WORKER_ADOPT
 mov r14d, 8
.Ladopt_policy:
 .endif
 worker_policy_arguments
 .byte 0xe8
worker_policy_hole: .long 0
 .ifdef WORKER_EMIT
 cmp eax, EMIT_DEFER_PRODUCT
 je .Lemit_product_policy
 cmp eax, EMIT_DEFER_PROOF
 je .Lemit_proof_policy
 jmp .Lworker_policy_answer
.Lemit_product_policy:
 worker_policy_arguments
 .byte 0xe8
worker_emit_product_hole: .long 0
 .ifdef WORKER_ADOPT
 cmp eax, ADOPT_DEFER_FRONT
 je .Ladopt_return_front
 .endif
 jmp .Lworker_policy_answer
.Lemit_proof_policy:
 worker_policy_arguments
 .byte 0xe8
worker_emit_proof_hole: .long 0
 .ifdef WORKER_ADOPT
 cmp eax, ADOPT_DEFER_FRONT
 jne .Lworker_policy_answer
.Ladopt_return_front:
 dec r14d
 jz .Lrefused
 jmp .Ladopt_policy
 .endif
.Lworker_policy_answer:
 .endif
 .endif
 cmp eax, HEADER
 jb .Lrefused
 cmp eax, COMMAND_LIMIT
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
 .ifdef WORKER_CONTEXT
 cmp QWORD PTR [rbp+COMMAND+136], 0
 jne .Lwide_command
 .endif
 cmp QWORD PTR [rbp+COMMAND+40], 3
 ja .Lrefused
 cmp QWORD PTR [rbp+COMMAND+56], HEADER
 jne .Lrefused
 .ifdef WORKER_LAUNCHER
 mov rax, [rbp+COMMAND+32]
 test rax, rax
 jnz .Llauncher_arg_extent
 .endif
 mov rax, [rbp+OUTPUT_END]
 sub rax, HEADER
 cmp QWORD PTR [rbp+COMMAND+48], rax
 jne .Lrefused
 .ifdef WORKER_LAUNCHER
 jmp .Llauncher_extent_ready
.Llauncher_arg_extent:
 cmp QWORD PTR [rbp+COMMAND+16], 1
 jne .Lrefused
 cmp rax, ARGV_LIMIT
 ja .Lrefused
 shl rax, 4
 add rax, 1024
 cmp rax, [rbp+OUTPUT_END]
 jne .Lrefused
 cmp QWORD PTR [rbp+COMMAND+48], 512
 ja .Lrefused
.Llauncher_extent_ready:
 .endif
 .ifdef WORKER_CONTEXT
 jmp .Lcommand_extent_ready
.Lwide_command:
 cmp QWORD PTR [rbp+COMMAND+136], 1
 jne .Lrefused
 cmp QWORD PTR [rbp+COMMAND+16], 1
 .ifdef WORKER_EMIT
 je .Lemit_wide_allowed
 cmp QWORD PTR [rbp+COMMAND+16], 11
 .endif
 jne .Lrefused
 .ifdef WORKER_EMIT
.Lemit_wide_allowed:
 .endif
 mov rax, [rbp+COMMAND+40]
 cmp rax, 32
 ja .Lrefused
 imul rax, 24
 add rax, HEADER
 mov rdx, [rbp+COMMAND+48]
 cmp rdx, 1536
 ja .Lrefused
 add rax, rdx
 cmp rax, [rbp+OUTPUT_END]
 jne .Lrefused
 cmp QWORD PTR [rbp+COMMAND+56], HEADER
 jne .Lrefused
.Lcommand_extent_ready:
 .endif
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
 .ifdef HAS_RANDOM_PORT
 cmp rax, 10
 je .Lrandom
 .endif
 .endif
 .endif
 .ifdef HAS_MAKE_PORT
 cmp rax, 11
 je .Lstage
 .endif
 .ifdef WORKER_CONTEXT
 cmp rax, 12
 je .Luname
 cmp rax, 13
 je .Lcpu
 .endif
 .ifdef WORKER_EMIT
 cmp rax, 22
 je .Lemit_prepare
 cmp rax, 23
 je .Lemit_snapshot
 cmp rax, 24
 je .Lemit_discard
 cmp rax, 25
 je .Lemit_append
 cmp rax, 26
 je .Lemit_seal_stream
 cmp rax, 27
 je .Lemit_release_temporaries
 .endif
 .ifdef WORKER_BOOTSTRAP
 cmp rax, 14
 je .Lboot_bind
 cmp rax, 15
 je .Lboot_path
 cmp rax, 16
 je .Lboot_entries
 cmp rax, 17
 je .Lboot_check
 .endif
 .ifdef WORKER_LAUNCHER
 cmp rax, 18
 je .Llauncher_open_release
 cmp rax, 19
 je .Llauncher_snapshot
 cmp rax, 20
 je .Llauncher_authorize
 cmp rax, 21
 je .Llauncher_read_request
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
 .ifdef WORKER_LAUNCHER
 cmp rax, 3
 jb .Lrefused
 cmp rax, 2147483647
 ja .Lrefused
 .else
 cmp rax, ROLE_COUNT + FIRST_ROLE
 jae .Lrefused
 mov rax, [rbp+ROLES+rax*8]
 .endif
 mov [rbp+PROCESS], rax
.Lstage:
 call .Lhia_worker_memfd
 test rax, rax
 js .Lrefused
 .ifdef WORKER_EMIT
.Lstage_write:
 .endif
 mov [rbp+STAGED], rax
 mov [rbp+PROCESS+8], rax
 mov edi, eax
 lea rsi, [rbp+COMMAND+HEADER]
 mov rdx, [rbp+COMMAND+48]
 call .Lwrite_exact
 xor r12d, r12d
 lea r13, [rbp+COMMAND+64]
 .ifdef WORKER_CONTEXT
 cmp QWORD PTR [rbp+COMMAND+136], 0
 je .Lfragments
 mov rax, [rbp+COMMAND+48]
 lea r13, [rbp+COMMAND+HEADER+rax]
 .endif
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
 call .Lhia_worker_fragment_copy
 test rax, rax
 jnz .Lrefused
 .ifdef WORKER_ARTIFACT
.Lfragment_done:
 .endif
 inc r12
 add r13, 24
 jmp .Lfragments
.Lseal_input:
 .ifdef WORKER_EMIT
 cmp QWORD PTR [rbp+CURRENT], 25
 je .Lemit_appended
 .endif
 mov edi, DWORD PTR [rbp+STAGED]
 call .Lhia_worker_seal
 test rax, rax
 jnz .Lrefused
 .ifdef WORKER_STORED_READ
 cmp QWORD PTR [rbp+CURRENT], 9
 je .Lsend_peer
 .ifdef HAS_MAKE_PORT
 cmp QWORD PTR [rbp+CURRENT], 11
 je .Lmade
 .endif
 .endif
 call .Lhia_worker_memfd
 test rax, rax
 js .Lrefused
 mov [rbp+PROCESS+16], rax
 call .Lhia_worker_memfd
 test rax, rax
 js .Lrefused
 mov [rbp+PROCESS+24], rax
 lea rax, [rip+.Lchild_name]
 .ifdef WORKER_LAUNCHER
 cmp QWORD PTR [rbp+COMMAND+168], 384
 jne .Lrefused
 lea rax, [rbp+COMMAND+384]
 lea rdi, [rbp+COMMAND+448]
 mov rsi, rax
 call .Llauncher_find_nul
 .endif
 .ifdef WORKER_CONTEXT
 mov rcx, [rbp+COMMAND+168]
 test rcx, rcx
 jz .Lchild_name_ready
 .ifdef WORKER_INSPECTION
 cmp rcx, 2
 je .Lquery_child_name
 cmp rcx, 3
 je .Lobject_child_name
 .ifdef WORKER_EMIT
 cmp rcx, 6
 je .Lemit_shared_inventory_name
 cmp rcx, 7
 je .Lemit_build_object_name
 cmp rcx, 8
 je .Lemit_build_shared_name
 .endif
 .ifdef WORKER_CANDIDATE
 cmp rcx, 4
 je .Lverify_core_name
 cmp rcx, 5
 je .Lverify_assembly_name
 .endif
 .endif
 cmp rcx, 1
 jne .Lrefused
 lea rax, [rip+.Lnominal_child_name]
 .ifdef WORKER_INSPECTION
 jmp .Lchild_name_ready
.Lquery_child_name:
 lea rax, [rip+.Lquery_name]
 jmp .Lchild_name_ready
.Lobject_child_name:
 lea rax, [rip+.Lobject_name]
 .ifdef WORKER_EMIT
 jmp .Lchild_name_ready
.Lemit_shared_inventory_name:
 lea rax, [rip+.Lemit_shared_inventory]
 jmp .Lchild_name_ready
.Lemit_build_object_name:
 lea rax, [rip+.Lemit_build_object]
 jmp .Lchild_name_ready
.Lemit_build_shared_name:
 lea rax, [rip+.Lemit_build_shared]
 .endif
 .ifdef WORKER_CANDIDATE
 jmp .Lchild_name_ready
.Lverify_core_name:
 lea rax, [rip+.Lverify_core]
 jmp .Lchild_name_ready
.Lverify_assembly_name:
 lea rax, [rip+.Lverify_assembly]
 .endif
 .endif
.Lchild_name_ready:
 .endif
 mov [rbp+ARGV], rax
 mov rax, [rbp+COMMAND+32]
 cmp rax, ARGV_LIMIT
 ja .Lrefused
 mov [rbp+LOCAL_ARGS], rax
 lea rax, [rbp+ARGV]
 mov [rbp+PROCESS+32], rax
 lea rax, [rbp+CARRIED]
 mov [rbp+PROCESS+40], rax
 mov QWORD PTR [rbp+PROCESS+48], 0
 xor r12d, r12d
 .ifdef WORKER_LAUNCHER
 lea r13, [rbp+COMMAND+1024]
 .else
 lea r13, [rbp+COMMAND+192]
 .endif
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
 .ifdef WORKER_EMIT
 cmp rax, 7
 je .Lemit_arg_product
 cmp rax, 8
 je .Lemit_arg_hex_fd
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
 .ifdef HAS_PATH_ENTRY
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
 .ifdef HAS_PATH_ENTRY
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
 call .Lhia_worker_fd_observe
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
.ifdef WORKER_EMIT
 jmp .Larg_store
.Lemit_arg_product:
 cmp QWORD PTR [rbp+EMIT_DIRECTORY], 3
 jb .Lrefused
 cmp rdx, 0
 jne .Lrefused
 lea rax, [rbp+EMIT_PATH]
 jmp .Larg_store
.Lemit_arg_hex_fd:
 cmp rdx, 3
 jb .Lrefused
 cmp rdx, 2147483647
 ja .Lrefused
 mov rcx, [rbp+PROCESS+48]
 mov DWORD PTR [rbp+CARRIED+rcx*4], edx
 inc QWORD PTR [rbp+PROCESS+48]
 imul rcx, r12, 24
 lea rsi, [rbp+NUMBERS+rcx+8]
 mov BYTE PTR [rsi], 0
 lea rdi, [rip+.Lemit_hex]
 mov ecx, 8
.Lemit_fd_digit:
 mov eax, edx
 and eax, 15
 dec rsi
 mov al, [rdi+rax]
 mov [rsi], al
 shr edx, 4
 dec ecx
 jnz .Lemit_fd_digit
 mov rax, rsi
.endif
.Larg_store:
 mov [rbp+ARGV+r12*8+8], rax
 inc r12
 add r13, 16
 jmp .Larguments
.Lexec:
 mov QWORD PTR [rbp+ARGV+r12*8+8], 0
 .ifdef WORKER_EMIT
 /* HIA may bind RUN to the unchanged wall-window deadline. Other
  * actions retain the existing relative platform transport lease. */
 cmp QWORD PTR [rbp+CURRENT], 1
 jne .Lrun_relative
 mov rax, [rbp+COMMAND+144]
 test rax, rax
 jnz .Lrun_bound_ready
.Lrun_relative:
 .endif
 call .Ldeadline
 .ifdef WORKER_EMIT
.Lrun_bound_ready:
 .endif
 mov [rbp+PROCESS+56], rax
 .ifdef WORKER_COST
 cmp QWORD PTR [rbp+CURRENT], 6
 je .Lstart_peer
 .endif
 .ifdef WORKER_EMIT
 /* The scalar compiler writes a private product. Do not let the
  * launcher's ambient umask make it writable by another identity. */
 mov r14d, -1
 mov rcx, [rbp+COMMAND+168]
 sub rcx, 7
 cmp rcx, 1
 ja .Lemit_run_ready
 mov edi, 63
 mov eax, 95                    /* umask(077) */
 syscall
 mov r14d, eax
.Lemit_run_ready:
 .endif
 lea rdi, [rbp+PROCESS]
 call .Lhia_worker_run
 mov [rbp+OBS+24], rax
 .ifdef WORKER_EMIT
 test r14d, r14d
 js .Lemit_run_restored
 mov edi, r14d
 mov eax, 95
 syscall
 mov rax, [rbp+OBS+24]
.Lemit_run_restored:
 cmp rax, -110
 jne .Lrun_complete
 cmp QWORD PTR [rbp+COMMAND+144], 0
 jne .Lemit_expired
.Lrun_complete:
 .endif
 mov edi, DWORD PTR [rbp+STAGED]
 mov eax, 3
 syscall
 mov edi, DWORD PTR [rbp+PROCESS+24]
 lea rsi, [rbp+FD_INFO]
 call .Lhia_worker_fd_observe
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
 call .Lhia_worker_fd_observe
 test rax, rax
 js .Lrefused
 mov rax, [rbp+FD_INFO+8]
 mov [rbp+OBS+48], rax
 .endif
 mov edi, DWORD PTR [rbp+PROCESS+16]
 call .Lhia_worker_seal
 test rax, rax
 jnz .Lrefused
 .ifdef HAS_MAKE_PORT
.Lobserve_output:
 .endif
 .ifdef WORKER_EMIT
 cmp QWORD PTR [rbp+CURRENT], 1
 jne .Lemit_observe_ordinary
 cmp QWORD PTR [rbp+COMMAND+184], 0
 je .Lemit_observe_ordinary
 cmp QWORD PTR [rbp+COMMAND+184], 1
 jne .Lrefused
 mov rcx, [rbp+EMIT_TEMP_COUNT]
 cmp rcx, 16
 jae .Lrefused
 mov rax, [rbp+PROCESS+16]
 mov [rbp+EMIT_TEMP_FDS+rcx*8], rax
 inc QWORD PTR [rbp+EMIT_TEMP_COUNT]
.Lemit_observe_ordinary:
 .endif
 mov edi, DWORD PTR [rbp+PROCESS+16]
 lea rsi, [rbp+FD_INFO]
 call .Lhia_worker_fd_observe
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

 .ifdef WORKER_EMIT
.Lemit_append:
 mov r12, [rbp+COMMAND+144]
 cmp r12, 1
 ja .Lrefused
 cmp QWORD PTR [rbp+COMMAND+176], EMIT_STREAM_LIMIT
 ja .Lrefused
 mov rax, [rbp+EMIT_STREAMS+r12*8]
 test rax, rax
 jnz .Lemit_stream_open
 call .Lhia_worker_memfd
 cmp rax, 3
 jl .Lrefused
 mov [rbp+EMIT_STREAMS+r12*8], rax
.Lemit_stream_open:
 mov edi, eax
 xor esi, esi
 mov edx, 1
 mov eax, 8
 syscall
 test rax, rax
 js .Lrefused
 mov rdx, [rbp+COMMAND+176]
 sub rdx, rax
 jc .Lrefused
 sub rdx, [rbp+COMMAND+48]
 jc .Lrefused
 xor ecx, ecx
 lea rsi, [rbp+COMMAND+64]
.Lemit_stream_extent:
 cmp rcx, [rbp+COMMAND+40]
 jae .Lemit_stream_exact
 sub rdx, [rsi+16]
 jc .Lrefused
 add rsi, 24
 inc rcx
 jmp .Lemit_stream_extent
.Lemit_stream_exact:
 test rdx, rdx
 jnz .Lrefused
 mov rax, [rbp+EMIT_STREAMS+r12*8]
 jmp .Lstage_write

.Lemit_appended:
 mov edi, DWORD PTR [rbp+STAGED]
 xor esi, esi
 mov edx, 1
 mov eax, 8
 syscall
 test rax, rax
 js .Lrefused
 cmp rax, EMIT_STREAM_LIMIT
 ja .Lrefused
 cmp rax, [rbp+COMMAND+176]
 jne .Lrefused
 mov [rbp+OBS+40], rax
 jmp .Lnext

.Lemit_seal_stream:
 cmp QWORD PTR [rbp+COMMAND+40], 0
 jne .Lrefused
 cmp QWORD PTR [rbp+COMMAND+48], 0
 jne .Lrefused
 mov r12, [rbp+COMMAND+144]
 cmp r12, 1
 ja .Lrefused
 mov rax, [rbp+EMIT_STREAMS+r12*8]
 cmp rax, 3
 jb .Lrefused
 mov [rbp+PROCESS+16], rax
 mov edi, eax
 lea rsi, [rbp+FD_INFO]
 call .Lhia_worker_fd_observe
 test rax, rax
 js .Lrefused
 mov rax, [rbp+FD_INFO+24]
 cmp rax, [rbp+COMMAND+176]
 jne .Lrefused
 mov edi, DWORD PTR [rbp+PROCESS+16]
 call .Lhia_worker_seal
 test rax, rax
 jnz .Lrefused
 mov QWORD PTR [rbp+EMIT_STREAMS+r12*8], 0
 jmp .Lobserve_output

.Lemit_release_temporaries:
 cmp QWORD PTR [rbp+COMMAND+40], 0
 jne .Lrefused
 cmp QWORD PTR [rbp+COMMAND+48], 0
 jne .Lrefused
 mov r12, [rbp+EMIT_TEMP_COUNT]
 cmp r12, 16
 ja .Lrefused
.Lemit_release_one:
 test r12, r12
 jz .Lemit_released
 dec r12
 mov edi, DWORD PTR [rbp+EMIT_TEMP_FDS+r12*8]
 mov eax, 3
 syscall
 test rax, rax
 jnz .Lrefused
 jmp .Lemit_release_one
.Lemit_released:
 mov QWORD PTR [rbp+EMIT_TEMP_COUNT], 0
 jmp .Lnext

.Lemit_expired:
 /* The status is an observation, never authority to use partial bytes. */
 mov edi, DWORD PTR [rbp+STAGED]
 mov eax, 3
 syscall
 mov edi, DWORD PTR [rbp+PROCESS+16]
 mov eax, 3
 syscall
 mov edi, DWORD PTR [rbp+PROCESS+24]
 mov eax, 3
 syscall
 mov QWORD PTR [rbp+OBS+32], 0
 mov QWORD PTR [rbp+OBS+40], 0
 mov QWORD PTR [rbp+OBS+48], 0
 mov QWORD PTR [rbp+OBS+56], 0
 mov QWORD PTR [rbp+OBS_SIZE], 64
 jmp .Lnext

/* The HIA request provides one unique leaf and a fixed output filename.
 * Retain the ordinary parent and child directories until the sealed snapshot
 * is complete. All pathname and cleanup operations stay relative to them. */
.Lemit_prepare:
 cmp QWORD PTR [rbp+EMIT_PARENT], 0
 jne .Lrefused
 cmp QWORD PTR [rbp+COMMAND+48], 51
 jne .Lrefused
 cmp QWORD PTR [rbp+COMMAND+40], 0
 jne .Lrefused
 lea rsi, [rbp+COMMAND+HEADER]
 cmp DWORD PTR [rsi], 0x696d652e
 jne .Lrefused
 cmp WORD PTR [rsi+4], 0x2d74
 jne .Lrefused
 cmp BYTE PTR [rsi+38], 0
 jne .Lrefused
 lea rdi, [rsi+6]
 lea rcx, [rsi+38]
.Lemit_name_digit:
 mov al, [rdi]
 sub al, 48
 cmp al, 9
 jbe .Lemit_name_digit_ok
 sub al, 49
 cmp al, 5
 ja .Lrefused
.Lemit_name_digit_ok:
 inc rdi
 cmp rdi, rcx
 jb .Lemit_name_digit
 /* Validate the common stem and the two exact closed suffixes. */
 cmp DWORD PTR [rsi+39], 0x676f7270
 jne .Lrefused
 cmp DWORD PTR [rsi+43], 0x2e6d6172
 jne .Lrefused
 mov eax, DWORD PTR [rsi+47]
 cmp eax, 0x0000006f
 je .Lemit_copy_names
 cmp eax, 0x00006f73
 jne .Lrefused
.Lemit_copy_names:
 cld
 lea rdi, [rbp+EMIT_NAME]
 mov ecx, 39
 rep movsb
 lea rdi, [rbp+EMIT_FILE]
 mov ecx, 12
 rep movsb
 mov rsi, [r15+24]
 lea rdi, [rbp+EMIT_PATH]
 lea rcx, [rdi+4044]
 cmp BYTE PTR [rsi], 47
 jne .Lrefused
.Lemit_root_copy:
 cmp rdi, rcx
 jae .Lrefused
 lodsb
 test al, al
 jz .Lemit_leaf_path
 stosb
 jmp .Lemit_root_copy
.Lemit_leaf_path:
 cmp BYTE PTR [rdi-1], 47
 je .Lrefused
 mov al, 47
 stosb
 lea rsi, [rbp+EMIT_NAME]
 mov ecx, 38
 rep movsb
 mov al, 47
 stosb
 lea rsi, [rbp+EMIT_FILE]
 mov ecx, 12
 rep movsb
 mov edi, -100
 mov rsi, [r15+24]
 mov edx, 720896               /* O_RDONLY | DIRECTORY | NOFOLLOW | CLOEXEC */
 xor r10d, r10d
 mov eax, 257
 syscall
 cmp rax, 3
 jl .Lrefused
 mov r12d, eax
 mov edi, eax
 lea rsi, [rbp+EMIT_NAME]
 mov edx, 448                  /* 0700 */
 mov eax, 258
 syscall
 test rax, rax
 js .Lrefused
 mov [rbp+EMIT_PARENT], r12
 mov edi, r12d
 lea rsi, [rbp+EMIT_NAME]
 mov edx, 720896
 xor r10d, r10d
 mov eax, 257
 syscall
 cmp rax, 3
 jl .Lrefused
 mov [rbp+EMIT_DIRECTORY], rax
 mov edi, eax
 lea rsi, [rbp+EMIT_DIR_STAT]
 mov eax, 5
 syscall
 test rax, rax
 js .Lrefused
 mov eax, 107
 syscall
 cmp eax, DWORD PTR [rbp+EMIT_DIR_STAT+28]
 jne .Lrefused
 mov eax, DWORD PTR [rbp+EMIT_DIR_STAT+24]
 and eax, 65535
 cmp eax, 16832                 /* directory 0700 */
 jne .Lrefused
 jmp .Lnext

.Lemit_snapshot:
 cmp QWORD PTR [rbp+COMMAND+40], 0
 jne .Lrefused
 cmp QWORD PTR [rbp+COMMAND+48], 0
 jne .Lrefused
 cmp QWORD PTR [rbp+EMIT_DIRECTORY], 3
 jb .Lrefused
 mov edi, DWORD PTR [rbp+EMIT_DIRECTORY]
 lea rsi, [rbp+EMIT_FILE]
 mov edx, 657408                /* CLOEXEC | NOFOLLOW | NONBLOCK */
 xor r10d, r10d
 mov eax, 257
 syscall
 cmp rax, 3
 jl .Lrefused
 mov r14d, eax
 mov edi, eax
 lea rsi, [rbp+EMIT_BEFORE]
 mov eax, 5
 syscall
 test rax, rax
 js .Lrefused
 mov eax, DWORD PTR [rbp+EMIT_BEFORE+24]
 test eax, 18
 jnz .Lrefused
 and eax, 61440
 cmp eax, 32768
 jne .Lrefused
 cmp QWORD PTR [rbp+EMIT_BEFORE+16], 1
 jne .Lrefused
 mov eax, 107
 syscall
 cmp eax, DWORD PTR [rbp+EMIT_BEFORE+28]
 jne .Lrefused
 mov rax, [rbp+EMIT_BEFORE+48]
 cmp rax, 64
 jb .Lrefused
 cmp rax, 67108864
 ja .Lrefused
 call .Lhia_worker_memfd
 test rax, rax
 js .Lrefused
 mov [rbp+PROCESS+16], rax
 mov ecx, eax
 mov edi, r14d
 xor esi, esi
 mov rdx, [rbp+EMIT_BEFORE+48]
 lea r8, [rbp+SCRATCH]
 mov r9d, 16384
 call .Lhia_worker_fragment_copy
 test rax, rax
 jnz .Lrefused
 mov edi, r14d
 lea rsi, [rbp+EMIT_AFTER]
 mov eax, 5
 syscall
 test rax, rax
 js .Lrefused
 call .Lemit_same_stat
 mov edi, DWORD PTR [rbp+EMIT_DIRECTORY]
 lea rsi, [rbp+EMIT_FILE]
 lea rdx, [rbp+EMIT_AFTER]
 mov r10d, 256                  /* AT_SYMLINK_NOFOLLOW */
 mov eax, 262
 syscall
 test rax, rax
 js .Lrefused
 call .Lemit_same_stat
 mov edi, r14d
 mov eax, 3
 syscall
 call .Lemit_cleanup
 test rax, rax
 js .Lrefused
 mov edi, DWORD PTR [rbp+PROCESS+16]
 call .Lhia_worker_seal
 test rax, rax
 jnz .Lrefused
 mov QWORD PTR [rbp+OBS+48], 15
 jmp .Lobserve_output

.Lemit_same_stat:
 lea rsi, [rbp+EMIT_BEFORE]
 lea rdi, [rbp+EMIT_AFTER]
 mov ecx, 4
 repe cmpsq
 jne .Lrefused
 mov rax, [rsi+16]
 cmp rax, [rdi+16]
 jne .Lrefused
 add rsi, 56
 add rdi, 56
 mov ecx, 4
 repe cmpsq
 jne .Lrefused
 ret

.Lemit_discard:
 cmp QWORD PTR [rbp+COMMAND+40], 0
 jne .Lrefused
 cmp QWORD PTR [rbp+COMMAND+48], 0
 jne .Lrefused
 cmp QWORD PTR [rbp+EMIT_PARENT], 3
 jb .Lrefused
 call .Lemit_cleanup
 test rax, rax
 js .Lrefused
 jmp .Lnext

.Lemit_cleanup:
 mov r8, [rbp+EMIT_DIRECTORY]
 cmp r8, 3
 jb .Lemit_remove_directory
 mov edi, r8d
 lea rsi, [rbp+EMIT_FILE]
 xor edx, edx
 mov eax, 263
 syscall
 test rax, rax
 jz .Lemit_close_directory
 cmp rax, -2
 jne .Lemit_cleanup_result
.Lemit_close_directory:
 call .Lemit_cleanup_stage
 test rax, rax
 js .Lemit_cleanup_result
 mov edi, DWORD PTR [rbp+EMIT_DIRECTORY]
 mov eax, 3
 syscall
 mov QWORD PTR [rbp+EMIT_DIRECTORY], 0
.Lemit_remove_directory:
 mov r8, [rbp+EMIT_PARENT]
 cmp r8, 3
 jb .Lemit_cleanup_empty
 mov rax, [rbp+EMIT_DIR_STAT+8]
 test rax, rax
 je .Lemit_unlink_directory
 mov edi, r8d
 lea rsi, [rbp+EMIT_NAME]
 lea rdx, [rbp+EMIT_AFTER]
 mov r10d, 256
 mov eax, 262
 syscall
 test rax, rax
 js .Lemit_cleanup_result
 mov rax, [rbp+EMIT_DIR_STAT]
 cmp rax, [rbp+EMIT_AFTER]
 jne .Lemit_cleanup_stale
 mov rax, [rbp+EMIT_DIR_STAT+8]
 cmp rax, [rbp+EMIT_AFTER+8]
 jne .Lemit_cleanup_stale
.Lemit_unlink_directory:
 mov edi, r8d
 lea rsi, [rbp+EMIT_NAME]
 mov edx, 512
 mov eax, 263
 syscall
 test rax, rax
 js .Lemit_cleanup_result
 mov edi, r8d
 mov eax, 3
 syscall
 mov QWORD PTR [rbp+EMIT_PARENT], 0
 mov QWORD PTR [rbp+EMIT_DIR_STAT+8], 0
.Lemit_cleanup_empty:
 xor eax, eax
.Lemit_cleanup_result:
 ret
.Lemit_cleanup_stale:
 mov rax, -116
 ret

/* The already-ended scalar publisher can leave one private staging
 * directory. Walk only its retained 0700 parent, never a user directory. */
.Lemit_cleanup_stage:
 push rbx
 push r12
 push r13
 mov edi, DWORD PTR [rbp+EMIT_DIRECTORY]
 xor esi, esi
 xor edx, edx
 mov eax, 8
 syscall
 test rax, rax
 js .Lemit_stage_return
.Lemit_stage_read:
 mov edi, DWORD PTR [rbp+EMIT_DIRECTORY]
 lea rsi, [rbp+SCRATCH]
 mov edx, 4096
 mov eax, 217
 syscall
 cmp rax, -4
 je .Lemit_stage_read
 test rax, rax
 jle .Lemit_stage_return
 lea r12, [rbp+SCRATCH]
 lea r13, [r12+rax]
 xor ebx, ebx
.Lemit_stage_entry:
 cmp r12, r13
 je .Lemit_stage_found
 mov rax, r13
 sub rax, r12
 cmp rax, 24
 jb .Lemit_stage_invalid
 movzx ecx, WORD PTR [r12+16]
 cmp rcx, 24
 jb .Lemit_stage_invalid
 cmp rcx, rax
 ja .Lemit_stage_invalid
 lea rsi, [r12+19]
 add r12, rcx
 cmp WORD PTR [rsi], 46
 je .Lemit_stage_entry
 cmp WORD PTR [rsi], 11822
 jne .Lemit_stage_name
 cmp BYTE PTR [rsi+2], 0
 je .Lemit_stage_entry
.Lemit_stage_name:
 test rbx, rbx
 jnz .Lemit_stage_invalid
 cmp ecx, 40
 jb .Lemit_stage_invalid
 cmp BYTE PTR [rsi-1], 4         /* DT_DIR */
 jne .Lemit_stage_invalid
 movabs rax, 0x7269642d6169682e  /* .hia-dir */
 cmp QWORD PTR [rsi], rax
 jne .Lemit_stage_invalid
 cmp DWORD PTR [rsi+8], 0x2d746365
 jne .Lemit_stage_invalid
 cmp BYTE PTR [rsi+20], 0
 jne .Lemit_stage_invalid
 xor ecx, ecx
.Lemit_stage_digit:
 mov al, [rsi+rcx+12]
 sub al, 48
 cmp al, 9
 jbe .Lemit_stage_next
 sub al, 49
 cmp al, 5
 ja .Lemit_stage_invalid
.Lemit_stage_next:
 inc ecx
 cmp ecx, 8
 jb .Lemit_stage_digit
 mov rbx, rsi
 jmp .Lemit_stage_entry
.Lemit_stage_found:
 xor eax, eax
 test rbx, rbx
 jz .Lemit_stage_return
 mov edi, DWORD PTR [rbp+EMIT_DIRECTORY]
 mov rsi, rbx
 mov edx, 720896
 xor r10d, r10d
 mov eax, 257
 syscall
 test rax, rax
 js .Lemit_stage_return
 mov r12d, eax
 mov edi, eax
 lea rsi, [rbp+EMIT_BEFORE]
 mov eax, 5
 syscall
 test rax, rax
 js .Lemit_stage_close
 mov rax, [rbx-19]
 cmp rax, [rbp+EMIT_BEFORE+8]
 jne .Lemit_stage_close_invalid
 cmp WORD PTR [rbp+EMIT_BEFORE+24], 16832
 jne .Lemit_stage_close_invalid
 mov eax, 107
 syscall
 cmp eax, DWORD PTR [rbp+EMIT_BEFORE+28]
 jne .Lemit_stage_close_invalid
 mov edi, r12d
 lea rsi, [rbp+EMIT_FILE]
 xor edx, edx
 mov eax, 263
 syscall
 cmp rax, -2
 jne .Lemit_stage_close
 xor eax, eax
.Lemit_stage_close:
 mov r13, rax
 mov edi, r12d
 mov eax, 3
 syscall
 mov rax, r13
 test rax, rax
 js .Lemit_stage_return
 mov edi, DWORD PTR [rbp+EMIT_DIRECTORY]
 mov rsi, rbx
 mov edx, 512
 mov eax, 263
 syscall
 jmp .Lemit_stage_return
.Lemit_stage_close_invalid:
 mov rax, -116
 jmp .Lemit_stage_close
.Lemit_stage_invalid:
 mov rax, -116
.Lemit_stage_return:
 pop r13
 pop r12
 pop rbx
 ret

 .endif

.Ldeadline:
 call .Lhia_worker_now
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
 call .Lhia_worker_peer_start
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
 call .Lhia_worker_peer_read
 test rax, rax
 jnz .Lrefused
 .ifdef WORKER_STORED_READ
 cmp QWORD PTR [rbp+COMMAND+184], 0
 je .Lpeer_read_size
 call .Lhia_worker_memfd
 test rax, rax
 js .Lrefused
 mov [rbp+OBS+32], rax
 mov edi, eax
 lea rsi, [rbp+OBS+64]
 mov rdx, r12
 call .Lwrite_exact
 mov edi, DWORD PTR [rbp+OBS+32]
 call .Lhia_worker_seal
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
 call .Lhia_worker_peer_finish
 mov [rbp+OBS+24], rax
 mov edi, DWORD PTR [r14+24]
 lea rsi, [rbp+FD_INFO]
 call .Lhia_worker_fd_observe
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
 call .Lhia_worker_fd_observe
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
 call .Lhia_worker_peer_send
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
 call .Lhia_worker_fd_observe
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
 .ifdef WORKER_CONTEXT
 cmp QWORD PTR [rbp+COMMAND+144], 2
 je .Lclock_raw
 .endif
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
 call .Lhia_worker_now
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

.ifdef HAS_MAKE_PORT
.Lmade:
 mov rax, [rbp+STAGED]
 mov [rbp+PROCESS+16], rax
 jmp .Lobserve_output
.endif

.ifdef WORKER_CONTEXT
.Lclock_raw:
 xor edi, edi
 lea rsi, [rbp+OBS+64]
 mov eax, 228
 syscall
 test rax, rax
 js .Lrefused
 mov edx, 16
 jmp .Lfixed_observation

.Luname:
 lea rdi, [rbp+SCRATCH]
 mov eax, 63
 syscall
 test rax, rax
 js .Lrefused
 lea rsi, [rbp+SCRATCH]
 lea rdi, [rbp+OBS+64]
 mov ecx, 65
 rep movsb
 lea rsi, [rbp+SCRATCH+260]
 mov ecx, 65
 rep movsb
 mov edx, 130
.Lfixed_observation:
 mov [rbp+OBS+40], rdx
 mov [rbp+OBS+56], rdx
 add rdx, 64
 mov [rbp+OBS_SIZE], rdx
 jmp .Lnext

.Lcpu:
 mov edi, -100
 lea rsi, [rip+.Lcpu_online]
 mov edx, 0xa0000
 xor r10d, r10d
 mov eax, 257
 syscall
 test rax, rax
 js .Lrefused
 mov edi, eax
 lea rsi, [rbp+SCRATCH]
 mov edx, 4096
.Lcpu_read:
 xor eax, eax
 syscall
 cmp rax, -4
 je .Lcpu_read
 mov r12, rax
 mov eax, 3
 syscall
 cmp r12, 2
 jl .Lrefused
 cmp r12, 4096
 jae .Lrefused
 call .Lhia_worker_memfd
 test rax, rax
 js .Lrefused
 mov [rbp+PROCESS+16], rax
 mov edi, eax
 lea rsi, [rbp+SCRATCH]
 mov rdx, r12
 call .Lwrite_exact
 mov edi, DWORD PTR [rbp+PROCESS+16]
 call .Lhia_worker_seal
 test rax, rax
 jnz .Lrefused
 jmp .Lobserve_output
.endif

.ifdef HAS_RANDOM_PORT
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

.ifdef WORKER_BOOTSTRAP
/* Linux conveys only observations and held descriptors. HIA chooses every
 * probe, decides whether the empty-state rules pass, and binds final custody. */
.Lboot_bind:
 mov edi, -100
 mov rsi, [r15+16]
 mov edx, 0xb0000
 xor r10d, r10d
.Lboot_open_root:
 mov eax, 257
 syscall
 cmp rax, -4
 je .Lboot_open_root
 cmp rax, 3
 jl .Lrefused
 mov [rbp+BOOT_ROOT], rax
 mov edi, eax
 mov esi, 6
.Lboot_flock:
 mov eax, 73
 syscall
 cmp rax, -4
 je .Lboot_flock
 test rax, rax
 jnz .Lrefused
.Lboot_check:
 mov edi, -100
 mov rsi, [r15+16]
 lea rdx, [rbp+BOOT_NAMED_STAT]
 mov r10d, 256
.Lboot_stat_root:
 mov eax, 262
 syscall
 cmp rax, -4
 je .Lboot_stat_root
 test rax, rax
 jnz .Lrefused
 mov rax, [rbp+BOOT_ROOT]
 jmp .Lboot_directory

.Lboot_path:
 mov rcx, [rbp+COMMAND+48]
 cmp rcx, 2
 jb .Lrefused
 cmp rcx, 32
 ja .Lrefused
 lea rsi, [rbp+COMMAND+HEADER]
 cmp BYTE PTR [rsi+rcx-1], 0
 jne .Lrefused
 xor edx, edx
.Lboot_component:
 inc rdx
 cmp rdx, rcx
 ja .Lrefused
 mov al, [rsi+rdx-1]
 cmp al, 47
 je .Lrefused
 test al, al
 jnz .Lboot_component
 /* The validated terminator is required at the declared extent. */
 cmp rdx, rcx
 jne .Lrefused
.Lboot_path_operation:
 mov edi, DWORD PTR [rbp+BOOT_ROOT]
 mov rax, [rbp+COMMAND+144]
 cmp rax, 1
 je .Lboot_file_probe
 cmp rax, 2
 je .Lboot_open_child
 cmp rax, 3
 jne .Lrefused
 mov edx, 448
.Lboot_mkdir:
 mov eax, 258
 syscall
 cmp rax, -4
 je .Lboot_mkdir
 jmp .Lboot_result
.Lboot_file_probe:
 lea rdx, [rbp+BOOT_STAT]
 mov r10d, 256
.Lboot_probe:
 mov eax, 262
 syscall
 cmp rax, -4
 je .Lboot_probe
 jmp .Lboot_result
.Lboot_open_child:
 mov edx, 0xb0000
 xor r10d, r10d
.Lboot_open:
 mov eax, 257
 syscall
 cmp rax, -4
 je .Lboot_open
 cmp rax, 3
 jge .Lboot_directory
 test rax, rax
 jns .Lrefused
.Lboot_result:
 test rax, rax
 jg .Lrefused
 neg rax
 mov [rbp+OBS+24], rax
 jmp .Lnext

.Lboot_directory:
 mov [rbp+OBS+32], rax
 mov edi, eax
 lea rsi, [rbp+BOOT_STAT]
.Lboot_stat:
 mov eax, 5
 syscall
 cmp rax, -4
 je .Lboot_stat
 test rax, rax
 jnz .Lrefused
 cmp QWORD PTR [rbp+CURRENT], 15
 je .Lboot_stat_bound
 mov rax, [rbp+BOOT_NAMED_STAT]
 cmp rax, [rbp+BOOT_STAT]
 jne .Lrefused
 mov rax, [rbp+BOOT_NAMED_STAT+8]
 cmp rax, [rbp+BOOT_STAT+8]
 jne .Lrefused
.Lboot_stat_bound:
 mov eax, 107
 syscall
 mov [rbp+OBS+64], rax
 mov rax, [rbp+BOOT_STAT]
 mov [rbp+OBS+72], rax
 mov rax, [rbp+BOOT_STAT+8]
 mov [rbp+OBS+80], rax
 mov eax, DWORD PTR [rbp+BOOT_STAT+24]
 mov [rbp+OBS+88], rax
 mov eax, DWORD PTR [rbp+BOOT_STAT+28]
 mov [rbp+OBS+96], rax
 mov eax, 40
 jmp .Lboot_payload

.Lboot_entries:
 mov rax, [rbp+COMMAND+72]
 cmp rax, 3
 jl .Lrefused
 cmp rax, 2147483647
 ja .Lrefused
 mov [rbp+OBS+32], rax
 mov edi, eax
 lea rsi, [rbp+OBS+64]
 mov edx, 1024
.Lboot_getdents:
 mov eax, 217
 syscall
 cmp rax, -4
 je .Lboot_getdents
 test rax, rax
 js .Lrefused
.Lboot_payload:
 mov [rbp+OBS+40], rax
 mov [rbp+OBS+56], rax
 add rax, 64
 mov [rbp+OBS_SIZE], rax
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
 call .Lhia_worker_fragment_copy
 test rax, rax
 jnz .Lrefused
 .ifdef WORKER_DISCOVERY
 inc r12
 add r13, 24
 cmp r12, [rbp+COMMAND+40]
 jb .Lpublish_fragment
 .endif
 .ifndef WORKER_LAUNCHER
 mov edi, 1
 call .Lhia_worker_seal
 test rax, rax
 jnz .Lrefused
 .endif
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
 .ifdef WORKER_EMIT
 test rbp, rbp
 jz .Lemit_no_scratch
 call .Lemit_cleanup
.Lemit_no_scratch:
 .endif
 .ifdef WORKER_COST
 test rbp, rbp
 jz .Ldiagnose
 .ifdef WORKER_LAUNCHER
 call .Llauncher_restore_input
 .endif
 lea r12, [rbp+PEER]
 mov r13d, PEER_COUNT
.Labort_peer:
 cmp QWORD PTR [r12], 0
 je .Labort_next
 mov rdi, r12
 xor esi, esi
 call .Lhia_worker_peer_finish
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
.ifdef WORKER_CONTEXT
.ifdef WORKER_INSPECTION
.ifdef WORKER_CANDIDATE
.Lmode: .asciz "--worker-candidate"
.else
.ifdef WORKER_ROLLBACK
.Lmode: .asciz "--worker-rollback"
.else
.ifdef WORKER_EMIT
.ifdef WORKER_ADOPT
.Lmode: .asciz "--worker-adopt"
.else
.ifdef WORKER_VERIFY
.Lmode: .asciz "--worker-verify"
.else
.Lmode: .asciz "--worker-emit"
.endif
.endif
.else
.Lmode: .asciz "--worker-inspection"
.endif
.endif
.endif
.else
.Lmode: .asciz "--worker-context"
.endif
.Lcpu_online: .asciz "/sys/devices/system/cpu/online"
.else
.Lmode: .asciz "--worker-artifact"
.endif
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
.ifdef WORKER_CONTEXT
.Lnominal_child_name: .asciz "hia-admit-agent-json"
.ifdef WORKER_INSPECTION
.ifdef WORKER_CANDIDATE
.Lquery_name: .asciz "hia-import-assembly"
.Lobject_name: .asciz "hia-patch-result"
.Lverify_core: .asciz "hia-verify-core-json"
.Lverify_assembly: .asciz "hia-check-assembly-accepted"
.else
.Lquery_name: .asciz "hia-prepare-agent-edit-query"
.Lobject_name: .asciz "hia-emit-object"
.ifdef WORKER_EMIT
.Lemit_shared_inventory: .asciz "hia-inspect-owned-shared"
.Lemit_build_object: .asciz "hia-build-object"
.Lemit_build_shared: .asciz "hia-build-shared"
.Lemit_hex: .ascii "0123456789abcdef"
.endif
.endif
.endif
.endif
.ifdef WORKER_LAUNCHER
.Ldiagnostic: .ascii "native HIA Worker launcher refused\n"
.else
.ifdef WORKER_COST
.ifdef WORKER_STORED_READ
.ifdef WORKER_ARTIFACT
.ifdef WORKER_BOOTSTRAP
.Ldiagnostic: .ascii "native HIA Discovery startup transport refused\n"
.else
.ifdef WORKER_CONTEXT
.ifdef WORKER_INSPECTION
.ifdef WORKER_CANDIDATE
.Ldiagnostic: .ascii "native HIA Candidate Worker transport refused\n"
.else
.ifdef WORKER_ROLLBACK
.Ldiagnostic: .ascii "native HIA Rollback Worker transport refused\n"
.else
.ifdef WORKER_EMIT
.ifdef WORKER_ADOPT
.Ldiagnostic: .ascii "native HIA Adopt Worker transport refused\n"
.else
.ifdef WORKER_VERIFY
.Ldiagnostic: .ascii "native HIA Verify Worker transport refused\n"
.else
.Ldiagnostic: .ascii "native HIA Emit Worker transport refused\n"
.endif
.endif
.else
.Ldiagnostic: .ascii "native HIA Inspection Worker transport refused\n"
.endif
.endif
.endif
.else
.Ldiagnostic: .ascii "native HIA Context Worker transport refused\n"
.endif
.else
.Ldiagnostic: .ascii "native HIA Artifact Worker transport refused\n"
.endif
.endif
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
.endif
.Ldiagnostic_end:
.section .note.GNU-stack,"",@progbits

/* Linux x86-64 descriptor observation and process transport for HIA Workers.
 * The HIA caller chooses the action, trusted descriptor table, argv, bytes,
 * required seals, report handling and deadline. This file handles only system
 * calls, staging bytes without seeking the source, and the original child.
 */
.intel_syntax noprefix
.text
.global hia_worker_fd_observe, hia_worker_memfd, hia_worker_seal
.global hia_worker_fragment_copy, hia_worker_now, hia_worker_run
.global hia_worker_spawn, hia_worker_wait
.protected hia_worker_now

/* fd, five-word observation: fd, seals, file type, size, first word.
 * As in fstat, metadata is an observation, not authorization. First word is
 * the four-byte ELF magic candidate, zero-extended, not a decoded ELF.
 */
hia_worker_fd_observe:
.Lhia_worker_fd_observe:
 push rbx
 push r12
 sub rsp, 152
 mov ebx, edi
 mov r12, rsi
 mov QWORD PTR [r12], rdi
 mov esi, 1034
 mov eax, 72
 syscall
 mov QWORD PTR [r12+8], rax
 mov edi, ebx
 mov rsi, rsp
 mov eax, 5
 syscall
 test rax, rax
 js .Lobserved
 mov eax, DWORD PTR [rsp+24]
 and eax, 61440
 mov [r12+16], rax
 mov rax, QWORD PTR [rsp+48]
 mov [r12+24], rax
 mov QWORD PTR [r12+32], 0
 cmp rax, 4
 jb .Lsmall_observation
 mov edi, ebx
 lea rsi, [r12+32]
 mov edx, 4
 xor r10d, r10d
.Lprobe:
 mov eax, 17
 syscall
 cmp rax, -4
 je .Lprobe
 cmp rax, 4
 je .Lsmall_observation
 test rax, rax
 js .Lobserved
 mov rax, -5
 jmp .Lobserved
.Lsmall_observation:
 xor eax, eax
.Lobserved:
 add rsp, 152
 pop r12
 pop rbx
 ret

hia_worker_memfd:
.Lhia_worker_memfd:
 lea rdi, [rip+.Lmemfd_name]
 mov esi, 3
.Lmemfd_retry:
 mov eax, 319
 syscall
 cmp rax, -4
 je .Lmemfd_retry
 ret

hia_worker_seal:
.Lhia_worker_seal:
 mov r8d, edi
 mov esi, 1034
 mov eax, 72
 syscall
 test rax, rax
 js .Lseal_done
 cmp rax, 15
 je .Lrewind
 test rax, rax
 jnz .Lseal_conflict
 mov edi, r8d
 mov esi, 1033
 mov edx, 15
 mov eax, 72
 syscall
 test rax, rax
 js .Lseal_done
.Lrewind:
 mov edi, r8d
 xor esi, esi
 xor edx, edx
 mov eax, 8
 syscall
.Lseal_done:
 ret
.Lseal_conflict:
 mov rax, -1
 ret

/* from fd, from offset, length, destination fd, scratch, scratch capacity.
 * Return an exact transfer or negative errno; short source is an I/O error.
 */
hia_worker_fragment_copy:
.Lhia_worker_fragment_copy:
 push rbx
 push r12
 push r13
 push r14
 push r15
 sub rsp, 16
 mov ebx, edi
 mov r12, rsi
 mov r13, rdx
 mov r14d, ecx
 mov r15, r8
 mov [rsp], r9
 test r9, r9
 jz .Lcopy_bad
.Lcopy_read:
 test r13, r13
 jz .Lcopy_ok
 mov rdx, r13
 cmp rdx, [rsp]
 cmova rdx, [rsp]
 mov edi, ebx
 mov rsi, r15
 mov r10, r12
 mov eax, 17
 syscall
 cmp rax, -4
 je .Lcopy_read
 test rax, rax
 js .Lcopy_done
 jz .Lcopy_eof
 add r12, rax
 sub r13, rax
 mov [rsp+8], rax
 mov rsi, r15
.Lcopy_write:
 mov edi, r14d
 mov rdx, [rsp+8]
 mov eax, 1
 syscall
 cmp rax, -4
 je .Lcopy_write
 test rax, rax
 js .Lcopy_done
 jz .Lcopy_eof
 add rsi, rax
 sub [rsp+8], rax
 jnz .Lcopy_write
 jmp .Lcopy_read
.Lcopy_ok:
 xor eax, eax
 jmp .Lcopy_done
.Lcopy_bad:
 mov rax, -22
 jmp .Lcopy_done
.Lcopy_eof:
 mov rax, -5
.Lcopy_done:
 add rsp, 16
 pop r15
 pop r14
 pop r13
 pop r12
 pop rbx
 ret

/* Monotonic clock (nanoseconds) or raw errno. */
hia_worker_now:
.Lhia_worker_now:
 sub rsp, 16
 mov edi, 1
 mov rsi, rsp
 mov eax, 228
 syscall
 test rax, rax
 js .Lnow_done
 imul rax, [rsp], 1000000000
 add rax, [rsp+8]
.Lnow_done:
 add rsp, 16
 ret

/* One original child. Control: executable, stdin, stdout, stderr, argv*,
 * carried fds (u32 array), carried count, absolute monotonic deadline.
 * Return raw wait status iff that child completed in the attested window.
 * A wait error or deadline never returns an apparent success.
 */
hia_worker_run:
.Lhia_worker_run:
 push rbx
 mov rbx, rdi
 call .Lhia_worker_now
 test rax, rax
 js .Llaunch_done
 cmp rax, [rbx+56]
 jae .Llaunch_expired
 mov rdi, rbx
 call .Lhia_worker_spawn
 test rax, rax
 js .Llaunch_done
 mov edi, eax
 mov rsi, [rbx+56]
 call .Lhia_worker_wait
 jmp .Llaunch_done
.Llaunch_expired:
 mov rax, -110
.Llaunch_done:
 pop rbx
 ret

/* Checked launch through the original inherited executable FD. */
hia_worker_spawn:
.Lhia_worker_spawn:
 .ifdef WORKER_LAUNCHER
 cmp QWORD PTR [rdi+48], ARGV_LIMIT
 .else
 cmp QWORD PTR [rdi+48], 32
 .endif
 ja .Llaunch_bad
 mov r8, rdi
 mov eax, 57
 syscall
 test rax, rax
 jnz .Lspawn_parent
 mov rbx, r8

 xor r12d, r12d
.Lrun_stdio:
 mov edi, DWORD PTR [rbx+8+r12*8]
 mov esi, r12d
 mov eax, 33
 syscall
 test rax, rax
 js .Lrun_child_fail
 inc r12d
 cmp r12d, 3
 jb .Lrun_stdio
 mov edi, 3
 mov esi, -1
 mov edx, 4                    /* CLOSE_RANGE_CLOEXEC */
 mov eax, 436
 syscall
 test rax, rax
 js .Lrun_child_fail
 xor r12d, r12d
 mov r13, [rbx+40]
.Lrun_carry:
 cmp r12, [rbx+48]
 jae .Lrun_exec
 mov edi, [r13+r12*4]
 mov esi, 2
 xor edx, edx
 mov eax, 72
 syscall
 test rax, rax
 js .Lrun_child_fail
 inc r12d
 jmp .Lrun_carry
.Lrun_exec:
 mov edi, DWORD PTR [rbx]
 lea rsi, [rip+.Lempty]
 mov rdx, [rbx+32]
 lea r10, [rip+.Lnoenv]
 mov r8d, 4096                  /* AT_EMPTY_PATH, the inherited sealed ELF */
 mov eax, 322
 syscall
.Lrun_child_fail:
 mov edi, 127
 mov eax, 60
 syscall
 ud2

.Lspawn_parent:
 ret
.Llaunch_bad:
 mov rax, -22
 ret

/* Wait only for an owned direct child, using the supplied absolute deadline. */
hia_worker_wait:
.Lhia_worker_wait:
 push rbx
 push r12
 push r13
 push r14
 push r15
 sub rsp, 32
 mov r12d, edi
 mov ebx, edi
 mov rax, rbx
 mov rbx, rsi
 mov edi, eax
 xor esi, esi
 mov eax, 434
 syscall
 test rax, rax
 js .Lrun_unwatched
 mov r13d, eax
 mov DWORD PTR [rsp], eax
 mov DWORD PTR [rsp+4], 1
.Lrun_watch:
 call .Lhia_worker_now
 test rax, rax
 js .Lrun_watched_error
 mov rcx, rbx
 sub rcx, rax
 jbe .Lrun_watched_timeout
 mov rax, rcx
 xor edx, edx
 mov ecx, 1000000
 div rcx
 test rdx, rdx
 jz .Lrun_millis
 inc rax
.Lrun_millis:
 cmp rax, 2147483647
 jbe .Lrun_poll
 mov eax, 2147483647
.Lrun_poll:
 mov edx, eax
 mov rdi, rsp
 mov esi, 1
 mov eax, 7
 syscall
 cmp rax, -4
 je .Lrun_watch
 test rax, rax
 js .Lrun_watched_error
 jz .Lrun_watch
 test WORD PTR [rsp+6], 1
 jz .Lrun_unexpected_poll
 call .Lhia_worker_now
 test rax, rax
 js .Lrun_watched_error
 cmp rax, rbx
 jae .Lrun_watched_timeout
 xor r15d, r15d
 jmp .Lrun_close_watch
.Lrun_unexpected_poll:
 mov rax, -5
 jmp .Lrun_watched_error
.Lrun_watched_timeout:
 mov rax, -110
.Lrun_watched_error:
 mov r15, rax
 mov edi, r13d
 mov esi, 9
 xor edx, edx
 xor r10d, r10d
.Lkill_pidfd:
 mov eax, 424
 syscall
 cmp rax, -4
 je .Lkill_pidfd
 test rax, rax
 jns .Lrun_close_watch
 cmp rax, -3
 je .Lrun_close_watch
 /* With SIGCHLD owned by this adapter, the unreaped child is still exact. */
 mov edi, r12d
 mov esi, 9
 mov eax, 62
 syscall
.Lrun_close_watch:
 mov edi, r13d
 mov eax, 3
 syscall
 jmp .Lrun_reap
.Lrun_unwatched:
 mov r15, rax
 /* This exact direct child is still unreaped, so its pid cannot be reused. */
 mov edi, r12d
 mov esi, 9
 mov eax, 62
 syscall
.Lrun_reap:
 mov edi, r12d
 lea rsi, [rsp+8]
 xor edx, edx
 xor r10d, r10d
 mov eax, 61
 syscall
 cmp rax, -4
 je .Lrun_reap
 test r15, r15
 jnz .Lrun_error
 cmp eax, r12d
 jne .Lrun_uncertain
 mov eax, DWORD PTR [rsp+8]
 jmp .Lrun_done
.Lrun_uncertain:
 mov rax, -10
 jmp .Lrun_done
.Lrun_error:
 mov rax, r15
 jmp .Lrun_done
.Lrun_done:
 add rsp, 32
 pop r15
 pop r14
 pop r13
 pop r12
 pop rbx
 ret

.text
.Lmemfd_name: .asciz "hia-worker-private"
.Lempty: .byte 0
.balign 8
.Lnoenv: .quad 0
.text

.text
/* Bounded duplex transport for one HIA-chosen child. No role or wire policy.
 * Peer words: pid, reply reader, command writer. State is caller-private and
 * only a successful spawn transfers handles to it.
 */
.intel_syntax noprefix
.text
.global hia_worker_peer_start, hia_worker_peer_read, hia_worker_peer_finish, hia_worker_peer_send

/* (launch control*, peer*) -> 0 or Linux errno. */
hia_worker_peer_start:
.Lhia_worker_peer_start:
 push rbx
 push r12
 push r13
 sub rsp, 16
 mov rbx, rdi
 mov r12, rsi
 cmp QWORD PTR [r12], 0
 jne .Lpeer_busy
 call .Lhia_worker_now
 test rax, rax
 js .Lpeer_start_done
 cmp rax, [rbx+56]
 jae .Lpeer_start_timeout
 mov rdi, rsp
 call .Lpeer_pipe
 test rax, rax
 js .Lpeer_start_done
 lea rdi, [rsp+8]
 call .Lpeer_pipe
 test rax, rax
 js .Lpeer_close_input
 mov eax, [rsp]
 mov [rbx+8], rax
 mov eax, [rsp+12]
 mov [rbx+16], rax
 mov rdi, rbx
 call .Lhia_worker_spawn
 test rax, rax
 js .Lpeer_close_all
 mov [r12], rax
 mov eax, [rsp+8]
 mov [r12+8], rax
 mov eax, [rsp+4]
 mov [r12+16], rax
 mov edi, [rsp]
 mov eax, 3
 syscall
 mov edi, [rsp+12]
 mov eax, 3
 syscall
 xor eax, eax
 jmp .Lpeer_start_done
.Lpeer_close_all:
 mov r13, rax
 mov edi, [rsp+8]
 mov eax, 3
 syscall
 mov edi, [rsp+12]
 mov eax, 3
 syscall
 mov rax, r13
.Lpeer_close_input:
 mov r13, rax
 mov edi, [rsp]
 mov eax, 3
 syscall
 mov edi, [rsp+4]
 mov eax, 3
 syscall
 mov rax, r13
 jmp .Lpeer_start_done
.Lpeer_busy:
 mov rax, -16
 jmp .Lpeer_start_done
.Lpeer_start_timeout:
 mov rax, -110
.Lpeer_start_done:
 add rsp, 16
 pop r13
 pop r12
 pop rbx
 ret

.Lpeer_pipe:
 mov esi, 524288              /* O_CLOEXEC; children keep only declared fds */
.Lpeer_pipe_retry:
 mov eax, 293
 syscall
 cmp rax, -4
 je .Lpeer_pipe_retry
 ret

/* (peer*, destination, exact byte count, monotonic deadline) -> 0 or errno. */
hia_worker_peer_read:
.Lhia_worker_peer_read:
 push rbx
 push r12
 push r13
 push r14
 push r15
 sub rsp, 16
 cmp QWORD PTR [rdi], 0
 je .Lpeer_read_invalid
 mov ebx, [rdi+8]
 mov r12, rsi
 mov r13, rdx
 mov r14, rcx
 mov DWORD PTR [rsp], ebx
 mov WORD PTR [rsp+4], 1
.Lpeer_read_next:
 test r13, r13
 jz .Lpeer_read_complete
 mov rdi, rsp
 mov rsi, r14
 call .Lpeer_poll_deadline
 test rax, rax
 js .Lpeer_read_done
 mov edi, ebx
 mov rsi, r12
 mov rdx, r13
 xor eax, eax
 syscall
 cmp rax, -4
 je .Lpeer_read_next
 test rax, rax
 js .Lpeer_read_done
 jz .Lpeer_read_short
 add r12, rax
 sub r13, rax
 jmp .Lpeer_read_next
.Lpeer_read_invalid:
 mov rax, -22
 jmp .Lpeer_read_done
.Lpeer_read_short:
 mov rax, -5
 jmp .Lpeer_read_done
.Lpeer_read_complete:
 xor eax, eax
.Lpeer_read_done:
 add rsp, 16
 pop r15
 pop r14
 pop r13
 pop r12
 pop rbx
 ret


/* (peer*, immutable bytes, exact length, deadline) -> zero or a refusal.
 * No other actor can write this private channel during this transfer.
 * Each write is at most PIPE_BUF, after observing a writable pipe.
 */
hia_worker_peer_send:
.Lhia_worker_peer_send:
 push rbx
 push r12
 push r13
 push r14
 push r15
 sub rsp, 16
 cmp QWORD PTR [rdi], 0
 je .Lsend_invalid
 mov ebx, [rdi+16]
 mov r12, rsi
 mov r13, rdx
 mov r14, rcx
 mov DWORD PTR [rsp], ebx
 mov WORD PTR [rsp+4], 4
.Lsend_next:
 test r13, r13
 jz .Lsend_complete
 mov rdi, rsp
 mov rsi, r14
 call .Lpeer_poll_deadline
 test rax, rax
 js .Lsend_done
 mov edi, ebx
 mov rsi, r12
 mov edx, 4096
 cmp r13, rdx
 cmovb rdx, r13
 mov eax, 1
 syscall
 cmp rax, -4
 je .Lsend_next
 test rax, rax
 js .Lsend_done
 jz .Lsend_short
 add r12, rax
 sub r13, rax
 jmp .Lsend_next
.Lsend_invalid:
 mov rax, -22
 jmp .Lsend_done
.Lsend_short:
 mov rax, -5
 jmp .Lsend_done
.Lsend_complete:
 xor eax, eax
.Lsend_done:
 add rsp, 16
 pop r15
 pop r14
 pop r13
 pop r12
 pop rbx
 ret

/* (pollfd*, absolute monotonic deadline) -> 0 or an exact transport error. */
.Lpeer_poll_deadline:
 push rbx
 push r12
 sub rsp, 8
 mov rbx, rdi
 mov r12, rsi
.Lpoll_again:
 call .Lhia_worker_now
 test rax, rax
 js .Lpoll_done
 mov rcx, r12
 sub rcx, rax
 jbe .Lpoll_timeout
 mov rax, rcx
 xor edx, edx
 mov ecx, 1000000
 div rcx
 test rdx, rdx
 jz .Lpoll_millis
 inc rax
.Lpoll_millis:
 cmp rax, 2147483647
 jbe .Lpoll_kernel
 mov eax, 2147483647
.Lpoll_kernel:
 mov edx, eax
 mov rdi, rbx
 mov esi, 1
 mov eax, 7
 syscall
 cmp rax, -4
 je .Lpoll_again
 test rax, rax
 js .Lpoll_done
 jz .Lpoll_again
 mov ax, [rbx+4]
 test WORD PTR [rbx+6], ax
 jz .Lpoll_unready
 call .Lhia_worker_now
 test rax, rax
 js .Lpoll_done
 cmp rax, r12
 jae .Lpoll_timeout
 xor eax, eax
 jmp .Lpoll_done
.Lpoll_unready:
 mov rax, -5
 jmp .Lpoll_done
.Lpoll_timeout:
 mov rax, -110
.Lpoll_done:
 add rsp, 8
 pop r12
 pop rbx
 ret

/* (peer*, deadline) -> exact raw wait status. Deadline 0 aborts and reaps. */
hia_worker_peer_finish:
.Lhia_worker_peer_finish:
 push rbx
 push r12
 push r13
 mov rbx, rdi
 mov r12, rsi
 mov r13, [rbx]
 test r13, r13
 jz .Lpeer_already_closed
 mov edi, DWORD PTR [rbx+16]
 mov eax, 3
 syscall
 mov edi, r13d
 mov rsi, r12
 call .Lhia_worker_wait
 mov r13, rax
 mov edi, DWORD PTR [rbx+8]
 mov eax, 3
 syscall
 mov QWORD PTR [rbx], 0
 mov QWORD PTR [rbx+8], 0
 mov QWORD PTR [rbx+16], 0
 mov rax, r13
 jmp .Lpeer_finish_done
.Lpeer_already_closed:
 mov rax, -22
.Lpeer_finish_done:
 pop r13
 pop r12
 pop rbx
 ret
.text
