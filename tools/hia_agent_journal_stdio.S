/* Linux x86-64 transport for the six-argument HIA journal image.
 * The image owns the state transitions. This process sees only one sealed
 * request and returns the affected byte ranges, never a writable Store fd. */
.intel_syntax noprefix
.text
.global _start
.type _start,@function
.equ LIMIT,8<<20
.equ STATE,512
.equ PRIVATE,32768
.equ OUT,2*LIMIT+STATE
.equ FRAME,64
.equ REPLY,48
.equ ENVELOPE,192
.equ ENVELOPE_SCRATCH,8+STATE
.equ MAX_TAGS,262144
.equ MIN_SCRATCH,4256+PRIVATE
.equ MAX_SCRATCH,LIMIT+56*262144+64+PRIVATE+MAX_TAGS

_start:
 /* The static linker calls this entry, leaving argc one word above rsp. */
 cmp QWORD PTR [rsp+8],1
 jne bad_frame
 sub rsp,168
 xor edi,edi
 mov esi,1034                    /* F_GET_SEALS */
 mov eax,72
 syscall
 test rax,rax
 js bad_frame
 and eax,15
 cmp eax,15
 jne bad_frame
 xor edi,edi
 mov rsi,rsp
 mov eax,5                       /* fstat */
 syscall
 test rax,rax
 jnz io_error
 mov r13,[rsp+48]                 /* st_size */
 cmp r13,FRAME+STATE
 jb bad_frame
 mov rsi,r13
 xor r8d,r8d                     /* stdin */
 mov edx,1                       /* PROT_READ */
 mov r10d,2                      /* MAP_PRIVATE */
 call map
 mov r12,rax
 movabs rax,0x31304e494a414948   /* HIAJIN01 */
 cmp [r12],rax
 jne bad_frame
 cmp QWORD PTR [r12+56],0
 jne bad_frame
 mov rbx,[r12+48]                 /* foreign-type tag count */
 cmp rbx,MAX_TAGS
 ja bad_frame
 sub r13,FRAME+STATE
 sub r13,rbx
 jb bad_frame
 cmp r13,[r12+8]                  /* exactly the raw input tail */
 jne bad_frame
 mov r15,[r12+16]                 /* scratch capacity */
 mov rax,[r12+24]                 /* journal stage */
 cmp rax,14
 ja bad_frame
 cmp QWORD PTR [r12+40],1         /* data profile bit */
 ja bad_frame
 cmp rax,13
 jae envelope_frame
 cmp rax,10
 je transition_frame
 cmp r13,LIMIT
 ja bad_frame
transition_frame:
 lea rcx,[rbx+MIN_SCRATCH]
 cmp r15,rcx
 jb bad_frame
 cmp r15,MAX_SCRATCH
 ja bad_frame
 test rax,rax
 jz allocate
 test rbx,rbx
 jnz bad_frame
 jmp allocate
envelope_frame:
 cmp r15,ENVELOPE_SCRATCH
 jne bad_frame
 cmp r13,LIMIT
 ja bad_frame
 test rbx,rbx
 jnz bad_frame
allocate:
 lea rsi,[r15+OUT]
 mov r8,-1
 mov edx,3
 mov r10d,34                     /* MAP_PRIVATE | MAP_ANONYMOUS */
 call map
 mov r14,rax
 lea rdx,[r14+OUT]                /* scratch */
 mov rax,[r12+24]
 mov [rdx],rax
 cmp rax,13
 jae prepare_envelope
 mov rax,[r12+32]
 mov [rdx+8],rax
 lea rdi,[rdx+r15-PRIVATE]
 /* Write tags and the carried state into distinct portions of scratch. */
 lea rsi,[r12+FRAME]
 mov ecx,STATE/8
 rep movsq
 mov [rdi-STATE+336],rbx
 mov rax,[r12+40]
 mov [rdi-STATE+344],rax
 lea rdi,[rdx+r15-PRIVATE]
 sub rdi,rbx
 lea rsi,[r12+FRAME+STATE]
 mov rcx,rbx
 rep movsb
 mov ecx,OUT
 jmp invoke
prepare_envelope:
 lea rdi,[rdx+8]
 lea rsi,[r12+FRAME]
 mov ecx,STATE/8
 rep movsq
 mov ecx,ENVELOPE
invoke:
 lea rdi,[r12+rbx+FRAME+STATE]
 mov rsi,r13
 mov r8,rdx
 mov rdx,r14
 mov r9,r15
 call agent_journal_start
 /* Return status even when it denotes an HIA diagnostic. Only transport
  * faults exit nonzero. Validate every length before writing any output. */
 movabs rdx,0x3130554f4a414948   /* HIAJOU01 */
 mov [rsp],rdx
 mov [rsp+8],rax
 xor edx,edx
 mov [rsp+16],rdx                 /* response or envelope size */
 mov [rsp+24],rdx                 /* cost size */
 mov [rsp+32],rdx                 /* state / diagnostic size */
 mov [rsp+40],rdx                 /* cached arena size */
 cmp QWORD PTR [r12+24],13
 jb transition_output
 cmp rax,ENVELOPE
 ja send_output
 mov [rsp+16],rax
 jmp send_output
transition_output:
 mov QWORD PTR [rsp+32],STATE
 cmp rax,0x7fffffff
 ja send_output
 mov rdx,[r14+2*LIMIT+272]
 cmp rdx,LIMIT
 ja bad_frame
 mov [rsp+16],rdx
 mov rdx,[r14+2*LIMIT+280]
 cmp rdx,LIMIT
 ja bad_frame
 mov [rsp+24],rdx
 cmp QWORD PTR [r12+24],3
 jne send_output
 mov rdx,[r14+OUT+32]
 cmp rdx,64
 jb bad_frame
 lea rcx,[r15-PRIVATE]
 cmp rdx,rcx
 ja bad_frame
 mov [rsp+40],rdx
send_output:
 mov rsi,rsp
 mov edx,REPLY
 call write_all
 mov rsi,r14
 mov rdx,[rsp+16]
 call write_all
 lea rsi,[r14+LIMIT]
 mov rdx,[rsp+24]
 call write_all
 lea rsi,[r14+2*LIMIT]
 mov rdx,[rsp+32]
 call write_all
 lea rsi,[r14+OUT]
 mov rdx,[rsp+40]
 call write_all
 xor edi,edi
 jmp exit_process
map:
 xor edi,edi
 xor r9d,r9d
 mov eax,9
 syscall
 cmp rax,-4095
 jae io_error
 ret
write_all:
 test rdx,rdx
 je write_done
 mov edi,1
 mov eax,1
 syscall
 cmp rax,-4
 je write_all
 test rax,rax
 jle io_error
 add rsi,rax
 sub rdx,rax
 jmp write_all
write_done:
 ret
bad_frame:
 mov edi,2
 jmp exit_process
io_error:
 mov edi,4
exit_process:
 mov eax,60
 syscall
 ud2
.size _start,.-_start
.section .note.GNU-stack,"",@progbits
