/* Direct Linux argument and descriptor transport for the linked HIA policy. */
.intel_syntax noprefix
.text
.global _start
.type _start,@function
.equ PLAN,  0x41000
.equ BYTES, 0x62000
.equ MAX_READ, 0x800001
.equ CAPTURE_TAG, 0x3130504143414948

_start:
 mov r15,rsp
 cmp QWORD PTR [r15],4
 jne usage
 xor edi,edi
 mov esi,BYTES+MAX_READ
 mov edx,3                    /* PROT_READ | PROT_WRITE */
 mov r10d,0x22                /* MAP_PRIVATE | MAP_ANONYMOUS */
 mov r8,-1
 xor r9d,r9d
 mov eax,9                    /* mmap */
 syscall
 cmp rax,-4095
 jae io_error
 mov rbp,rax
 mov QWORD PTR [rbp],1
 mov edi,13
 mov rsi,rbp
 xor edx,edx
 mov r10d,8
 mov eax,13                   /* rt_sigaction(SIGPIPE, SIG_IGN) */
 syscall
 test rax,rax
 js io_error
 mov rax,CAPTURE_TAG
 mov [rbp],rax
 mov QWORD PTR [rbp+8],1
 lea rdi,[rbp+40]
 mov rsi,[r15+16]
 mov edx,131071
 call append_argument
 mov [rbp+16],rax
 mov rsi,[r15+24]
 mov edx,131071
 call append_argument
 mov [rbp+24],rax
 mov rsi,[r15+32]
 mov edx,7
 call append_argument
 mov [rbp+32],rax
 mov rsi,rdi
 sub rsi,rbp
 call authorize
 test eax,eax
 jnz policy_exit

 mov rsi,[r15+16]
open_root:
 mov edi,-100                /* AT_FDCWD */
 mov edx,0xb0000              /* O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC */
 xor r10d,r10d
 mov eax,257                  /* openat */
 syscall
 cmp rax,-4
 je open_root
 test rax,rax
 js path_error
 mov r12d,eax
 lea rbx,[rbp+PLAN+16]
 mov rcx,[rbp+PLAN+8]
 cmp rcx,BYTES-PLAN-16
 ja usage
 lea r15,[rbx+rcx]
open_component:
 mov r14,rbx
find_end:
 cmp r14,r15
 jae usage
 mov al,[r14]
 inc r14
 test al,al
 jnz find_end
 mov edx,0xb0000
 cmp r14,r15
 jne open_below
 mov edx,0xa0800              /* O_NOFOLLOW | O_CLOEXEC | O_NONBLOCK */
open_below:
 mov edi,r12d
 mov rsi,rbx
 xor r10d,r10d
 mov eax,257
 syscall
 cmp rax,-4
 je open_below
 test rax,rax
 js component_error
 mov r13d,eax
 mov edi,r12d
 mov eax,3                    /* close; Linux releases the descriptor on EINTR */
 syscall
 mov r12d,r13d
 mov rbx,r14
 cmp r14,r15
 jne open_component

 mov QWORD PTR [rbp+8],2
 mov rax,[rbp+PLAN]
 mov [rbp+16],rax
before_metadata:
 mov edi,r12d
 lea rsi,[rbp+24]
 mov eax,5                    /* fstat */
 syscall
 cmp rax,-4
 je before_metadata
 test rax,rax
 js file_error
 mov esi,168
 call authorize
 test eax,eax
 jnz policy_exit
 mov rdx,[rbp+16]
 cmp rdx,MAX_READ-1
 ja usage
 inc rdx
 mov edi,r12d
 lea rsi,[rbp+BYTES]
 call capture_read_to_limit
 test rax,rax
 js file_error
 mov r13,rax
 mov [rbp+16],rax
 mov QWORD PTR [rbp+8],3
after_metadata:
 mov edi,r12d
 lea rsi,[rbp+168]
 mov eax,5
 syscall
 cmp rax,-4
 je after_metadata
 test rax,rax
 js file_error
 mov esi,312
 call authorize
 test eax,eax
 jnz policy_exit
 lea rsi,[rbp+BYTES]
 mov rdx,r13
publish:
 test rdx,rdx
 jz success
 mov edi,1
 mov eax,1                    /* write */
 syscall
 cmp rax,-4
 je publish
 test rax,rax
 jle io_error
 add rsi,rax
 sub rdx,rax
 jmp publish

append_argument:
 xor eax,eax
append_next:
 mov cl,[rsi+rax]
 test cl,cl
 jz appended
 cmp rax,rdx
 jae usage
 mov [rdi+rax],cl
 inc rax
 jmp append_next
appended:
 add rdi,rax
 ret

authorize:
 mov rdi,rbp
 lea rdx,[rbp+PLAN]
 mov ecx,BYTES-PLAN
 xor r8d,r8d
 xor r9d,r9d
 sub rsp,8
 call pager_hia_entry
 add rsp,8
 ret
component_error:
 cmp r14,r15
 je file_error
path_error:
 mov edi,70
 jmp exit
file_error:
 mov edi,71
 jmp exit
usage:
 mov edi,64
 jmp exit
io_error:
 mov edi,74
 jmp exit
policy_exit:
 mov edi,eax
 jmp exit
success:
 xor edi,edi
exit:
 mov eax,60
 syscall
 ud2
.size _start,.-_start
.section .note.GNU-stack,"",@progbits
