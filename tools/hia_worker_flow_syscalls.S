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
.equ SCRATCH, 16384
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
.equ MAP_BYTES, 65536
.ifdef WORKER_READ
.equ ROLE_COUNT, 19
.equ EXTRA_ARGS, 5
.else
.equ ROLE_COUNT, 22
.equ EXTRA_ARGS, 6
.endif
.equ ENTRY_SIZE, 376 + 40 * ROLE_COUNT
.equ HEADER, 512

_start:
 cld
 mov r15, rsp
 cmp QWORD PTR [r15], ROLE_COUNT + EXTRA_ARGS
 jne .Lrefused
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
 mov edi, 1
 mov esi, 1034
 mov eax, 72
 syscall
 test rax, rax
 jnz .Lrefused
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
 xor r12d, r12d
 lea r13, [rbp+OBS+376]
.Lentry_roles:
 cmp r12, ROLE_COUNT
 jae .Lentry_ready
 mov rsi, [r15+r12*8+8*(EXTRA_ARGS+1)]
 call .Lparse_fd
 mov [rbp+ROLES+r12*8], rax
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
 cmp rax, 5
 jne .Lrefused
 xor edi, edi
 jmp .Lexit

.Lrun:
 mov rax, [rbp+COMMAND+24]
 cmp rax, ROLE_COUNT
 jae .Lrefused
 mov rax, [rbp+ROLES+rax*8]
 mov [rbp+PROCESS], rax
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
 mov edi, DWORD PTR [r13]
 mov rsi, [r13+8]
 mov rdx, [r13+16]
 mov ecx, DWORD PTR [rbp+STAGED]
 lea r8, [rbp+SCRATCH]
 mov r9d, 16384
 call hia_worker_fragment_copy
 test rax, rax
 jnz .Lrefused
 inc r12
 add r13, 24
 jmp .Lfragments
.Lseal_input:
 mov edi, DWORD PTR [rbp+STAGED]
 call hia_worker_seal
 test rax, rax
 jnz .Lrefused
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
 cmp rdx, 2
 jb .Lrefused
 cmp rdx, 3
 ja .Lrefused
 mov rax, [r15+rdx*8+8]
 jmp .Larg_store
.Larg_literal:
 cmp rdx, 136
 jb .Lrefused
 cmp rdx, 176
 jae .Lrefused
 lea rax, [rbp+COMMAND+rdx]
 lea rdi, [rbp+COMMAND+192]
 mov rsi, rax
.Lliteral_end:
 cmp rsi, rdi
 jae .Lrefused
 cmp BYTE PTR [rsi], 0
 je .Larg_store
 inc rsi
 jmp .Lliteral_end
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
 call hia_worker_now
 test rax, rax
 js .Lrefused
 mov rcx, [rbp+COMMAND+152]
 test rcx, rcx
 jz .Lrefused
 add rax, rcx
 jc .Lrefused
 js .Lrefused
 mov [rbp+PROCESS+56], rax
 lea rdi, [rbp+PROCESS]
 call hia_worker_run
 mov [rbp+OBS+24], rax
 mov edi, DWORD PTR [rbp+STAGED]
 mov eax, 3
 syscall
 mov edi, DWORD PTR [rbp+PROCESS+24]
 mov eax, 3
 syscall
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
 call hia_worker_now
 test rax, rax
 js .Lrefused
 mov [rbp+OBS+64], rax
 mov QWORD PTR [rbp+OBS+40], 8
 mov QWORD PTR [rbp+OBS+56], 8
 mov QWORD PTR [rbp+OBS_SIZE], 72
 jmp .Lnext

.Lpublish:
 cmp QWORD PTR [rbp+COMMAND+40], 1
 jne .Lrefused
 mov edi, DWORD PTR [rbp+COMMAND+64]
 mov rsi, [rbp+COMMAND+72]
 mov rdx, [rbp+COMMAND+80]
 mov ecx, 1
 lea r8, [rbp+SCRATCH]
 mov r9d, 16384
 call hia_worker_fragment_copy
 test rax, rax
 jnz .Lrefused
 mov edi, 1
 call hia_worker_seal
 test rax, rax
 jnz .Lrefused
 jmp .Lnext

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
 cmp ecx, 10
 jae .Lrefused
 imul rax, rax, 10
 add rax, rdx
 inc rsi
 inc ecx
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
.ifdef WORKER_READ
.Lmode: .asciz "--worker-read"
.else
.Lmode: .asciz "--worker-describe"
.endif
.Lchild_name: .asciz "hia-worker-effect"
.ifdef WORKER_READ
.Ldiagnostic: .ascii "native HIA Read Worker transport refused\n"
.else
.Ldiagnostic: .ascii "native HIA Describe Worker transport refused\n"
.endif
.Ldiagnostic_end:
.section .note.GNU-stack,"",@progbits
