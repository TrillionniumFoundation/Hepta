/* Fixed Linux x86-64 borrowed-buffer transport. The linked HIA image owns
 * every component decision. Scratch is private to one process and retains
 * its original extent and bytes between calls; output starts zero each time.
 */
.intel_syntax noprefix
.text
.global _start
.type _start,@function
.equ INPUT_LIMIT,  0x10000000
.equ OUTPUT_LIMIT, 0x04000000
.equ SCRATCH_LIMIT,0x04000000
.equ REQUEST_MAGIC,0x3130434353414948   /* HIASCC01 */
.equ REPLY_MAGIC,  0x3130524353414948   /* HIASCR01 */

.ifdef HIA_COMPONENT_EMBEDDED_OBJECTS
.set pager_hia_entry, component_image_start
.endif
_start:
.ifdef HIA_COMPONENT_EMBEDDED_OBJECTS
 add rsp,8                      /* Undo the static linker's entry call. */
.endif
 cmp QWORD PTR [rsp],1
 jne invalid
 sub rsp,48
 xor edi,edi
 mov esi,INPUT_LIMIT+OUTPUT_LIMIT+SCRATCH_LIMIT
 mov edx,3                       /* PROT_READ | PROT_WRITE */
 mov r10d,0x22                   /* MAP_PRIVATE | MAP_ANONYMOUS */
 mov r8,-1
 xor r9d,r9d
 mov eax,9                       /* mmap */
 syscall
 cmp rax,-4095
 jae io_error
 mov r12,rax
 lea r13,[rax+INPUT_LIMIT]
 lea r14,[r13+OUTPUT_LIMIT]
 mov r15,-1
 /* Turn a disconnected output consumer into a bounded I/O failure. */
 mov QWORD PTR [rsp],1
 mov QWORD PTR [rsp+8],0
 mov QWORD PTR [rsp+16],0
 mov QWORD PTR [rsp+24],0
 mov edi,13                      /* SIGPIPE */
 mov rsi,rsp
 xor edx,edx
 mov r10d,8
 mov eax,13                      /* rt_sigaction */
 syscall
 test rax,rax
 js io_error

next_call:
 mov rsi,rsp
 mov edx,32
 call read_request
 test eax,eax
 jz success
 mov rax,REQUEST_MAGIC
 cmp [rsp],rax
 jne invalid
 cmp QWORD PTR [rsp+8],INPUT_LIMIT
 ja invalid
 cmp QWORD PTR [rsp+16],OUTPUT_LIMIT
 ja invalid
 mov rax,[rsp+24]
 cmp rax,SCRATCH_LIMIT
 ja invalid
 cmp r15,-1
 jne check_scratch
 mov r15,rax
check_scratch:
 cmp r15,rax
 jne invalid
 mov rsi,r12
 mov rdx,[rsp+8]
 call read_request
 test eax,eax
 jz invalid
 mov rsi,[rsp+16]
 test rsi,rsi
 jz invoke
 mov rdi,r13
 mov edx,4                       /* MADV_DONTNEED, page-aligned private output */
 mov eax,28                      /* madvise */
 syscall
 test rax,rax
 js io_error
invoke:
 mov rdi,r12
 mov rsi,[rsp+8]
 mov rdx,r13
 mov rcx,[rsp+16]
 mov r8,r14
 mov r9,r15
 call pager_hia_entry
 mov eax,eax
 mov [rsp+8],rax
 mov rax,REPLY_MAGIC
 mov [rsp],rax
 mov rsi,rsp
 mov edx,32
 call write_exact
 mov rsi,r13
 mov rdx,[rsp+16]
 call write_exact
 mov rsi,r14
 mov rdx,r15
 call write_exact
 jmp next_call

/* Align the nested syscall adapter call like the HIA entry call. */
read_request:
 sub rsp,8
 call component_read_exact
 add rsp,8
 cmp eax,-1
 je io_error
 cmp eax,-2
 je invalid
 ret
write_exact:
 test rdx,rdx
 jz written
 mov eax,1
 mov edi,1
 syscall
 cmp rax,-4
 je write_exact
 test rax,rax
 jle io_error
 add rsi,rax
 sub rdx,rax
 jmp write_exact
written:
 ret
invalid:
 mov edi,64
 jmp exit
io_error:
 mov edi,74
 jmp exit
success:
 xor edi,edi
exit:
 mov eax,60
 syscall
 ud2
.size _start,.-_start
.section .note.GNU-stack,"",@progbits
