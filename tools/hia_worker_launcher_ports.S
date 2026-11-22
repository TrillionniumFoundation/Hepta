/* Linux x86-64 transport for the installed HIA Worker launcher. The HIA
 * state machine selects all names, leases, roles, records and publication.
 */
.intel_syntax noprefix
.text
.global worker_authority_hole

.equ LAUNCH_STAT, 108000
.equ LAUNCH_AFTER_STAT, LAUNCH_STAT + 144
.equ LAUNCH_NAMED_STAT, LAUNCH_AFTER_STAT + 144
.equ LAUNCH_AUTH_WORK, 109000
.equ LAUNCH_POLL, 110096
.equ LAUNCH_WAIT, LAUNCH_POLL + 8
.equ LAUNCH_FLAGS, LAUNCH_WAIT + 16
.equ LAUNCH_RESTORE, LAUNCH_FLAGS + 8

.Llauncher_entry:
 mov rax, [r15+32]
 cmp BYTE PTR [rax], 47
 jne .Lrefused
 mov rsi, [r15+40]
 lea rdi, [rbp+OBS+8]
 mov ecx, 64
.Llauncher_pin_byte:
 lodsb
 test al, al
 jz .Lrefused
 stosb
 dec ecx
 jnz .Llauncher_pin_byte
 cmp BYTE PTR [rsi], 0
 jne .Lrefused
 mov rax, [rip+.Llauncher_magic]
 mov [rbp+OBS], rax
 mov QWORD PTR [rbp+OBS_SIZE], 72
 jmp .Lnext

.Llauncher_find_nul:
 cmp rsi, rdi
 jae .Lrefused
 cmp BYTE PTR [rsi], 0
 je .Llauncher_nul_found
 inc rsi
 jmp .Llauncher_find_nul
.Llauncher_nul_found:
 ret

.Llauncher_open_release:
 mov edi, -100                  /* AT_FDCWD */
 mov rsi, [r15+24]
 mov edx, 720896                /* CLOEXEC | NOFOLLOW | DIRECTORY */
 xor r10d, r10d
 mov eax, 257                   /* openat */
 syscall
 cmp rax, 3
 jl .Lrefused
 mov [rbp+OBS+32], rax
 mov edi, eax
 lea rsi, [rbp+LAUNCH_STAT]
 mov eax, 5
 syscall
 test rax, rax
 js .Lrefused
 mov eax, 107                   /* geteuid */
 syscall
 mov [rbp+OBS+64], rax
 mov eax, DWORD PTR [rbp+LAUNCH_STAT+28]
 mov [rbp+OBS+72], rax
 mov eax, DWORD PTR [rbp+LAUNCH_STAT+24]
 mov [rbp+OBS+80], rax
 mov eax, 24
 jmp .Llauncher_payload

.Llauncher_snapshot:
 mov r12, [rbp+COMMAND+144]
 test r12, r12
 jnz .Llauncher_role_path
 mov r12d, -100
 mov r13, [r15+32]
 jmp .Llauncher_capture
.Llauncher_role_path:
 mov rcx, [rbp+COMMAND+48]
 cmp rcx, 2
 jb .Lrefused
 cmp rcx, 64
 ja .Lrefused
 lea r13, [rbp+COMMAND+HEADER]
 cmp BYTE PTR [r13+rcx-1], 0
 jne .Lrefused
 lea rdi, [r13+rcx-1]
 mov rsi, r13
.Llauncher_path_byte:
 cmp rsi, rdi
 je .Llauncher_capture
 cmp BYTE PTR [rsi], 0
 je .Lrefused
 cmp BYTE PTR [rsi], 47
 je .Lrefused
 inc rsi
 jmp .Llauncher_path_byte
.Llauncher_capture:
 mov edi, r12d
 mov rsi, r13
 mov edx, 657408                /* CLOEXEC | NOFOLLOW | NONBLOCK */
 xor r10d, r10d
 mov eax, 257
 syscall
 cmp rax, 3
 jl .Lrefused
 mov r14d, eax
 mov edi, eax
 lea rsi, [rbp+LAUNCH_STAT]
 mov eax, 5
 syscall
 test rax, rax
 js .Lrefused
 mov eax, DWORD PTR [rbp+LAUNCH_STAT+24]
 test eax, 18
 jnz .Lrefused
 and eax, 61440
 cmp eax, 32768
 jne .Lrefused
 cmp QWORD PTR [rbp+LAUNCH_STAT+16], 1
 jne .Lrefused
 mov eax, 107
 syscall
 mov ecx, DWORD PTR [rbp+LAUNCH_STAT+28]
 test ecx, ecx
 jz .Llauncher_capture_extent
 cmp eax, ecx
 jne .Lrefused
.Llauncher_capture_extent:
 mov rdx, [rbp+LAUNCH_STAT+48]
 cmp rdx, 2
 jb .Lrefused
 cmp rdx, [rbp+COMMAND+152]
 ja .Lrefused
 cmp rdx, 8388608
 ja .Lrefused
 call hia_worker_memfd
 test rax, rax
 js .Lrefused
 mov [rbp+PROCESS+16], rax
 mov ecx, eax
 mov edi, r14d
 xor esi, esi
 mov rdx, [rbp+LAUNCH_STAT+48]
 lea r8, [rbp+SCRATCH]
 mov r9d, 16384
 call hia_worker_fragment_copy
 test rax, rax
 jnz .Lrefused
 mov edi, r14d
 lea rsi, [rbp+LAUNCH_AFTER_STAT]
 mov eax, 5
 syscall
 test rax, rax
 js .Lrefused
 mov edi, r12d
 mov rsi, r13
 lea rdx, [rbp+LAUNCH_NAMED_STAT]
 mov r10d, 256                  /* AT_SYMLINK_NOFOLLOW */
 mov eax, 262                   /* newfstatat */
 syscall
 test rax, rax
 js .Lrefused
 lea rdx, [rbp+LAUNCH_AFTER_STAT]
 call .Llauncher_same_stat
 lea rdx, [rbp+LAUNCH_NAMED_STAT]
 call .Llauncher_same_stat
 mov edi, r14d
 mov eax, 3
 syscall
 jmp .Llauncher_sealed_output

.Llauncher_same_stat:
 lea rsi, [rbp+LAUNCH_STAT]
 mov rdi, rdx
 mov ecx, 4                     /* device, inode, link count, mode/uid */
 repe cmpsq
 jne .Lrefused
 mov rax, [rsi+16]              /* size */
 cmp rax, [rdi+16]
 jne .Lrefused
 add rsi, 56
 add rdi, 56
 mov ecx, 4                     /* modification and status-change times */
 repe cmpsq
 jne .Lrefused
 ret

.Llauncher_authorize:
 cmp QWORD PTR [rbp+COMMAND+48], 88
 jne .Lrefused
 mov edi, DWORD PTR [rbp+COMMAND+144]
 lea rsi, [rbp+FD_INFO]
 call hia_worker_fd_observe
 test rax, rax
 js .Lrefused
 cmp QWORD PTR [rbp+FD_INFO+8], 15
 jne .Lrefused
 mov r13, [rbp+FD_INFO+24]
 cmp r13, [rbp+COMMAND+HEADER+80]
 jne .Lrefused
 cmp r13, 2
 jb .Lrefused
 cmp r13, 8388608
 ja .Lrefused
 xor edi, edi
 mov rsi, r13
 mov edx, 1                     /* PROT_READ */
 mov r10d, 2                    /* MAP_PRIVATE */
 mov r8d, DWORD PTR [rbp+COMMAND+144]
 xor r9d, r9d
 mov eax, 9
 syscall
 cmp rax, -4095
 jae .Lrefused
 mov r12, rax
 mov rdi, rax
 lea rdx, [rbp+COMMAND+HEADER]
 mov ecx, 88
 lea r8, [rbp+LAUNCH_AUTH_WORK]
 mov r9d, 1088
 .byte 0xe8
worker_authority_hole: .long 0
 mov [rbp+OBS+64], rax
 mov rdi, r12
 mov rsi, r13
 mov eax, 11                    /* munmap */
 syscall
 test rax, rax
 js .Lrefused
 mov eax, 8
 jmp .Llauncher_payload

.Llauncher_read_request:
 call hia_worker_memfd
 test rax, rax
 js .Lrefused
 mov [rbp+PROCESS+16], rax
 call hia_worker_now
 test rax, rax
 js .Lrefused
 mov r12, QWORD PTR [rbp+COMMAND+152]
 add r12, rax
 jc .Lrefused
 xor edi, edi
 mov esi, 3                     /* F_GETFL */
 mov eax, 72
 syscall
 test rax, rax
 js .Lrefused
 mov [rbp+LAUNCH_FLAGS], rax
 mov edx, eax
 or edx, 2048                   /* O_NONBLOCK */
 mov esi, 4                     /* F_SETFL */
 mov eax, 72
 syscall
 test rax, rax
 js .Lrefused
 mov QWORD PTR [rbp+LAUNCH_RESTORE], 1
 xor r13d, r13d
.Llauncher_read_wait:
 call hia_worker_now
 test rax, rax
 js .Lrefused
 cmp rax, r12
 jae .Lrefused
 mov rdx, rax
 mov rax, r12
 sub rax, rdx
 xor edx, edx
 mov ecx, 1000000000
 div rcx
 mov [rbp+LAUNCH_WAIT], rax
 mov [rbp+LAUNCH_WAIT+8], rdx
 mov QWORD PTR [rbp+LAUNCH_POLL], 0
 mov WORD PTR [rbp+LAUNCH_POLL+4], 17 /* stdin, POLLIN|POLLHUP */
 lea rdi, [rbp+LAUNCH_POLL]
 mov esi, 1
 lea rdx, [rbp+LAUNCH_WAIT]
 xor r10d, r10d
 xor r8d, r8d
 mov eax, 271                   /* ppoll */
 syscall
 cmp rax, -4
 je .Llauncher_read_wait
 cmp rax, 1
 jne .Lrefused
 test WORD PTR [rbp+LAUNCH_POLL+6], 17
 jz .Lrefused
 xor edi, edi
 lea rsi, [rbp+SCRATCH]
 mov edx, 16384
 xor eax, eax
 syscall
 cmp rax, -4
 je .Llauncher_read_wait
 cmp rax, -11
 je .Llauncher_read_wait
 test rax, rax
 js .Lrefused
 jz .Llauncher_request_eof
 add r13, rax
 cmp r13, 8388608
 ja .Lrefused
 mov rdx, rax
 mov edi, DWORD PTR [rbp+PROCESS+16]
 call .Lwrite_exact
 jmp .Llauncher_read_wait
.Llauncher_request_eof:
 call .Llauncher_restore_input
 test rax, rax
 js .Lrefused
.Llauncher_sealed_output:
 mov edi, DWORD PTR [rbp+PROCESS+16]
 call hia_worker_seal
 test rax, rax
 jnz .Lrefused
 jmp .Lobserve_output

.Llauncher_restore_input:
 xor eax, eax
 cmp QWORD PTR [rbp+LAUNCH_RESTORE], 0
 je .Llauncher_restored
 mov QWORD PTR [rbp+LAUNCH_RESTORE], 0
 xor edi, edi
 mov esi, 4
 mov edx, DWORD PTR [rbp+LAUNCH_FLAGS]
 mov eax, 72
 syscall
.Llauncher_restored:
 ret

.Llauncher_payload:
 mov [rbp+OBS+40], rax
 mov [rbp+OBS+56], rax
 add rax, 64
 mov [rbp+OBS_SIZE], rax
 jmp .Lnext

.Llauncher_magic: .ascii "HIALEN01"
