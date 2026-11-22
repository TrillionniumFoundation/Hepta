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
 lea rdi, [rip+.Lmemfd_name]
 mov esi, 3
.Lmemfd_retry:
 mov eax, 319
 syscall
 cmp rax, -4
 je .Lmemfd_retry
 ret

hia_worker_seal:
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
 push rbx
 mov rbx, rdi
 call hia_worker_now
 test rax, rax
 js .Llaunch_done
 cmp rax, [rbx+56]
 jae .Llaunch_expired
 mov rdi, rbx
 call hia_worker_spawn
 test rax, rax
 js .Llaunch_done
 mov edi, eax
 mov rsi, [rbx+56]
 call hia_worker_wait
 jmp .Llaunch_done
.Llaunch_expired:
 mov rax, -110
.Llaunch_done:
 pop rbx
 ret

/* Checked launch through the original inherited executable FD. */
hia_worker_spawn:
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
 call hia_worker_now
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
 call hia_worker_now
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

.section .rodata
.Lmemfd_name: .asciz "hia-worker-private"
.Lempty: .byte 0
.balign 8
.Lnoenv: .quad 0
.section .note.GNU-stack,"",@progbits
