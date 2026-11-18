/* Linux x86-64 transport for the HIA page image. Input is an immutable,
 * sealed descriptor, not a caller-supplied path or a writable buffer. */
.intel_syntax noprefix
.text
.global _start
.type _start,@function
.equ MIN_INPUT,24
.equ MAX_INPUT,(64<<20)+32+512
.equ OUTPUT,40+69+4*((65536+2)/3)
.equ WORKSPACE,512+4128

_start:
 cmp QWORD PTR [rsp],1
 jne bad_frame
 sub rsp,160
 xor edi,edi
 mov esi,1034                       /* F_GET_SEALS */
 mov eax,72                        /* fcntl */
 syscall
 test rax,rax
 js bad_frame
 and eax,15
 cmp eax,15
 jne bad_frame
 xor edi,edi
 mov rsi,rsp
 mov eax,5                         /* fstat */
 syscall
 test rax,rax
 jnz io_failure
 mov r13,[rsp+48]                   /* x86-64 struct stat.st_size */
 cmp r13,MIN_INPUT
 jb bad_frame
 cmp r13,MAX_INPUT
 ja bad_frame
 xor edi,edi
 mov rsi,r13
 mov edx,1                         /* PROT_READ */
 mov r10d,2                        /* MAP_PRIVATE */
 xor r8d,r8d
 xor r9d,r9d
 mov eax,9                         /* mmap */
 syscall
 cmp rax,-4095
 jae io_failure
 mov r12,rax

 xor edi,edi
 mov esi,OUTPUT+WORKSPACE
 mov edx,3
 mov r10d,34                       /* MAP_PRIVATE|MAP_ANONYMOUS */
 mov r8,-1
 xor r9d,r9d
 mov eax,9
 syscall
 cmp rax,-4095
 jae io_failure
 mov r14,rax
 mov rdi,r12
 mov rsi,r13
 mov rdx,r14
 mov ecx,OUTPUT
 lea r8,[r14+OUTPUT]
 mov r9d,WORKSPACE
 call agent_read_page_start
 cmp rax,40
 jb bad_frame
 cmp rax,OUTPUT
 ja bad_frame
 mov rdx,rax
 mov rsi,r14
write_page:
 mov edi,1
 mov eax,1
 syscall
 cmp rax,-4
 je write_page
 test rax,rax
 jle io_failure
 add rsi,rax
 sub rdx,rax
 jne write_page
 xor edi,edi
 jmp exit_process
bad_frame:
 mov edi,2
 jmp exit_process
io_failure:
 mov edi,4
exit_process:
 mov eax,60
 syscall
 ud2
.size _start,.-_start
.section .note.GNU-stack,"",@progbits
