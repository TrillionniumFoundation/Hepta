/* Bounded duplex transport for one HIA-chosen child. No role or wire policy.
 * Peer words: pid, reply reader, command writer. State is caller-private and
 * only a successful spawn transfers handles to it.
 */
.intel_syntax noprefix
.text
.global hia_worker_peer_start, hia_worker_peer_read, hia_worker_peer_finish, hia_worker_peer_send

/* (launch control*, peer*) -> 0 or Linux errno. */
hia_worker_peer_start:
 push rbx
 push r12
 push r13
 sub rsp, 16
 mov rbx, rdi
 mov r12, rsi
 cmp QWORD PTR [r12], 0
 jne .Lpeer_busy
 call hia_worker_now
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
 call hia_worker_spawn
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
 call hia_worker_now
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
 call hia_worker_now
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
 call hia_worker_wait
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
.section .note.GNU-stack,"",@progbits
