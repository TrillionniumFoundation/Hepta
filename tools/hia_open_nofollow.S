/* Mechanical Linux openat2 transport for the existing HIA-owned operations.
 * The kernel implementation is always attempted first. Only ENOSYS admits the
 * bounded equivalent subset used by these owners: no-link directory capture,
 * or one HIA-admitted child component below an already held directory FD.
 * This helper never authorizes an owner, mode, filename, write or transaction.
 * It preserves all syscall argument/callee-saved registers. RAX is the result.
 */
.intel_syntax noprefix
.text
.global hia_open_nofollow, hia_open_nofollow_end
hia_open_nofollow:
.Lhia_open_nofollow_entry:
 mov eax,437
 syscall
 cmp rax,-38
 jne hia_open_nofollow_return
 push rbx
 push rbp
 push r12
 push r13
 push r14
 push r15
 push rdi
 push rsi
 push rdx
 push r8
 push r9
 push r10
 sub rsp,4304
 mov rbp,rsp
 mov r12,rdi
 mov r13,rsi
 mov r15,-1
 cmp r10,24
 jne hia_open_invalid
 mov rax,[rdx]
 mov [rbp+4248],rax
 mov rax,[rdx+8]
 mov [rbp+4256],rax
 mov rbx,[rdx+16]
 cmp rbx,6
 je hia_open_copy
 cmp rbx,14
 jne hia_open_unsupported
hia_open_copy:
 xor ecx,ecx
hia_open_copy_byte:
 cmp rcx,4096
 jae hia_open_too_long
 mov al,[r13+rcx]
 mov [rbp+rcx],al
 test al,al
 jz hia_open_copied
 inc rcx
 jmp hia_open_copy_byte
hia_open_copied:
 test rcx,rcx
 jz hia_open_missing
 mov r14,rcx
 cmp rbx,14
 jne hia_open_directory_capture
 /* The HIA namespace/loader owners already admit exactly one child name.
  * An atomic nofollow openat of that component cannot traverse out of dirfd.
  * Do not emulate general BENEATH using a racy multi-component path walk. */
 cmp rcx,255
 ja hia_open_too_long
 cmp BYTE PTR [rbp],47
 je hia_open_escape
 xor ecx,ecx
hia_open_child_scan:
 cmp rcx,r14
 je hia_open_child_name
 cmp BYTE PTR [rbp+rcx],47
 je hia_open_escape
 inc rcx
 jmp hia_open_child_scan
hia_open_child_name:
 cmp r14,1
 jne hia_open_child_two
 cmp BYTE PTR [rbp],46
 je hia_open_escape
hia_open_child_two:
 cmp r14,2
 jne hia_open_child_flags
 cmp WORD PTR [rbp],0x2e2e
 je hia_open_escape
hia_open_child_flags:
 mov rdx,[rbp+4248]
 /* Known legacy open flags; reject bits openat would silently ignore. */
 mov rax,rdx
 and rax,-2097092                 /* ~0x1fffc3: excludes O_PATH/O_TMPFILE */
 jnz hia_open_invalid
 mov r10,[rbp+4256]
 mov rax,r10
 and rax,-4096
 jnz hia_open_invalid
 test rdx,0x40
 jnz hia_open_child_select
 test r10,r10
 jnz hia_open_invalid
hia_open_child_select:
 test rdx,0x20000
 jnz hia_open_child_call
 /* O_CREAT|O_EXCL is itself an atomic no-link create and preserves the
  * original observable file flags without inventing O_NOFOLLOW. */
 mov rax,rdx
 and eax,0xc0
 cmp eax,0xc0
 je hia_open_child_call
 /* The initializer also requests an existing directory without the
  * redundant NOFOLLOW bit. Capture the one component as O_PATH|NOFOLLOW,
  * reject links by fstat, then reopen "." below that held directory.
  * This retains the exact requested F_GETFL bits and survives renames. */
 cmp rdx,0x90000
 jne hia_open_unsupported
 mov rdi,r12
 mov rsi,rbp
 mov edx,0x2a0000
 xor r10d,r10d
 mov eax,257
 syscall
 test rax,rax
 js hia_open_finish
 mov r15,rax
 mov rdi,rax
 lea rsi,[rbp+4096]
 mov eax,5
 syscall
 test rax,rax
 js hia_open_finish
 mov eax,[rbp+4120]
 and eax,0xf000
 cmp eax,0xa000
 je hia_open_implied_link
 cmp eax,0x4000
 jne hia_open_implied_not_directory
 mov rdi,r15
 lea rsi,[rip+hia_open_dot]
 mov rdx,[rbp+4248]
 mov r10,[rbp+4256]
 mov eax,257
 syscall
 jmp hia_open_finish
hia_open_implied_link:
 mov rax,-40
 jmp hia_open_finish
hia_open_implied_not_directory:
 mov rax,-20
 jmp hia_open_finish
hia_open_child_call:
 mov rdi,r12
 mov rsi,rbp
 mov eax,257
 syscall
 jmp hia_open_finish

hia_open_directory_capture:
 /* The only NO_SYMLINKS-only request is the read-only parent directory. */
 cmp QWORD PTR [rbp+4248],0xb0000
 jne hia_open_unsupported
 cmp QWORD PTR [rbp+4256],0
 jne hia_open_invalid
 mov r13,rbp
 cmp BYTE PTR [r13],47
 jne hia_open_relative
 mov edi,-100
 lea rsi,[rip+hia_open_root]
 jmp hia_open_anchor_call
hia_open_relative:
 cmp r12,-100
 jne hia_open_duplicate
 mov edi,-100
 lea rsi,[rip+hia_open_dot]
hia_open_anchor_call:
 mov edx,0x2b0000                /* O_PATH|DIRECTORY|NOFOLLOW|CLOEXEC */
 xor r10d,r10d
 mov eax,257
 syscall
 cmp rax,-4
 je hia_open_anchor_call
 test rax,rax
 js hia_open_finish
 mov r15,rax
 jmp hia_open_component
hia_open_duplicate:
 mov rdi,r12
 mov esi,1030                    /* F_DUPFD_CLOEXEC */
 xor edx,edx
 mov eax,72
 syscall
 cmp rax,-4
 je hia_open_duplicate
 test rax,rax
 js hia_open_finish
 mov r15,rax
hia_open_component:
 cmp BYTE PTR [r13],47
 jne hia_open_component_start
 inc r13
 jmp hia_open_component
hia_open_component_start:
 cmp BYTE PTR [r13],0
 je hia_open_final_dot
 mov rbx,r13
hia_open_component_scan:
 cmp BYTE PTR [rbx],0
 je hia_open_component_end
 cmp BYTE PTR [rbx],47
 je hia_open_component_end
 inc rbx
 jmp hia_open_component_scan
hia_open_component_end:
 mov rcx,rbx
 sub rcx,r13
 cmp rcx,255
 ja hia_open_too_long
 cmp rcx,2
 jne hia_open_component_dispatch
 cmp WORD PTR [r13],0x2e2e
 je hia_open_escape
hia_open_component_dispatch:
 cmp BYTE PTR [rbx],0
 je hia_open_final_component
 mov BYTE PTR [rbx],0
 inc rbx
hia_open_intermediate:
 mov rdi,r15
 mov rsi,r13
 mov edx,0x2a0000                /* Hold links themselves; fstat rejects. */
 xor r10d,r10d
 mov eax,257
 syscall
 cmp rax,-4
 je hia_open_intermediate
 test rax,rax
 js hia_open_finish
 mov r12,rax
hia_open_intermediate_stat:
 mov rdi,r12
 lea rsi,[rbp+4096]
 mov eax,5
 syscall
 cmp rax,-4
 je hia_open_intermediate_stat
 test rax,rax
 js hia_open_bad_child
 mov eax,[rbp+4120]
 and eax,0xf000
 cmp eax,0xa000
 je hia_open_child_link
 cmp eax,0x4000
 jne hia_open_child_not_directory
 mov rdi,r15
 mov eax,3
 syscall
 test rax,rax
 js hia_open_parent_close_failed
 mov r15,r12
 mov r13,rbx
 jmp hia_open_component
hia_open_child_link:
 mov rax,-40
 jmp hia_open_bad_child
hia_open_child_not_directory:
 mov rax,-20
hia_open_bad_child:
 mov r14,rax
 mov rdi,r12
 mov eax,3
 syscall
 mov rax,r14
 jmp hia_open_finish
hia_open_parent_close_failed:
 mov r14,rax
 mov r15,-1                     /* close must not be retried on Linux. */
 mov rdi,r12
 mov eax,3
 syscall
 mov rax,r14
 jmp hia_open_finish
hia_open_final_dot:
 lea r13,[rip+hia_open_dot]
hia_open_final_component:
 mov rdi,r15
 mov rsi,r13
 mov rdx,[rbp+4248]
 mov r10,[rbp+4256]
 mov eax,257
 syscall
 /* Preserve the actual kernel O_DIRECTORY|O_NOFOLLOW error, including
  * ENOTDIR for a final directory symlink. Never try following it. */
 jmp hia_open_finish
hia_open_invalid:
 mov rax,-22
 jmp hia_open_finish
hia_open_unsupported:
 mov rax,-95
 jmp hia_open_finish
hia_open_too_long:
 mov rax,-36
 jmp hia_open_finish
hia_open_missing:
 mov rax,-2
 jmp hia_open_finish
hia_open_escape:
 mov rax,-18
hia_open_finish:
 mov r14,rax
 cmp r15,-1
 je hia_open_restore
 mov rdi,r15
 mov eax,3
 syscall
 test rax,rax
 jns hia_open_restore
 test r14,r14
 js hia_open_restore
 mov r12,rax
 mov rdi,r14
 mov eax,3
 syscall
 mov r14,r12
hia_open_restore:
 mov rax,r14
 add rsp,4304
 pop r10
 pop r9
 pop r8
 pop rdx
 pop rsi
 pop rdi
 pop r15
 pop r14
 pop r13
 pop r12
 pop rbp
 pop rbx
hia_open_nofollow_return:
 ret
hia_open_root: .asciz "/"
hia_open_dot: .asciz "."
hia_open_nofollow_end:
