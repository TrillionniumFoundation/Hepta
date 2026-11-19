/* Linux x86-64 transport for the six-argument HIA journal image.
 * One-shot mode admits an existing sealed frame. Session mode receives
 * sealed frame descriptors and carries only the state returned by HIA.
 * HIA validates the wire frame and prepares each reply. Neither mode
 * receives a writable Store descriptor. */
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
.equ LOCAL_BYTES,920
.equ SESSION_MODE,144
.equ INPUT_EXTENT,152
.equ INPUT_FD,160
.equ HELD_STATE,168
.equ MARKER,680
.equ IOV,688
.equ MESSAGE,704
.equ CONTROL,760
.equ PREFIX,784
.equ NEXT_SEQUENCE,792
.equ TRANSFER,800
.equ CARRY_STATE,824

_start:
 /* The static linker calls this entry, leaving argc one word above rsp. */
 cmp QWORD PTR [rsp+8],1
 je single_frame
 cmp QWORD PTR [rsp+8],2
 jne bad_frame
 mov rdx,[rsp+24]
 movabs rax,0x6f69737365732d2d /* "--sessio" */
 cmp QWORD PTR [rdx],rax
 jne bad_frame
 cmp WORD PTR [rdx+8],0x006e   /* "n\0" */
 jne bad_frame
 sub rsp,LOCAL_BYTES
 mov QWORD PTR [rsp+SESSION_MODE],1
 mov QWORD PTR [rsp+PREFIX],FRAME
 mov QWORD PTR [rsp+NEXT_SEQUENCE],1
 lea rdi,[rsp+HELD_STATE]
 mov ecx,STATE/8
 xor eax,eax
 rep stosq
 jmp receive_frame

single_frame:
 sub rsp,LOCAL_BYTES
 mov QWORD PTR [rsp+SESSION_MODE],0
 mov QWORD PTR [rsp+PREFIX],FRAME+STATE
 mov QWORD PTR [rsp+NEXT_SEQUENCE],0
 mov QWORD PTR [rsp+INPUT_FD],0
 jmp admit_frame

receive_frame:
 /* recvmsg on stdin: one byte and one SCM_RIGHTS file descriptor.
  * Check kernel output lengths and refuse any truncated ancillary data. */
 lea rdi,[rsp+MESSAGE]
 mov ecx,56/8
 xor eax,eax
 rep stosq
 lea rax,[rsp+MARKER]
 mov [rsp+IOV],rax
 mov QWORD PTR [rsp+IOV+8],1
 lea rax,[rsp+IOV]
 mov [rsp+MESSAGE+16],rax
 mov QWORD PTR [rsp+MESSAGE+24],1
 lea rax,[rsp+CONTROL]
 mov [rsp+MESSAGE+32],rax
 mov QWORD PTR [rsp+MESSAGE+40],24
 xor edi,edi
 lea rsi,[rsp+MESSAGE]
 mov edx,0x40000000              /* MSG_CMSG_CLOEXEC */
 mov eax,47                      /* recvmsg */
 syscall
 cmp rax,-4
 je receive_frame
 test rax,rax
 jz session_end
 cmp rax,1
 jne bad_frame
 cmp BYTE PTR [rsp+MARKER],0x4a /* 'J' */
 jne bad_frame
 test DWORD PTR [rsp+MESSAGE+48],40 /* MSG_TRUNC | MSG_CTRUNC */
 jnz bad_frame
 cmp QWORD PTR [rsp+MESSAGE+40],24
 jne bad_frame
 cmp QWORD PTR [rsp+CONTROL],20  /* CMSG_LEN(sizeof(int)) */
 jne bad_frame
 cmp DWORD PTR [rsp+CONTROL+8],1 /* SOL_SOCKET */
 jne bad_frame
 cmp DWORD PTR [rsp+CONTROL+12],1 /* SCM_RIGHTS */
 jne bad_frame
 mov eax,[rsp+CONTROL+16]
 test eax,eax
 js bad_frame
 mov [rsp+INPUT_FD],rax

admit_frame:
 mov rdi,[rsp+INPUT_FD]
 mov esi,1034                    /* F_GET_SEALS */
 mov eax,72
 syscall
 test rax,rax
 js bad_frame
 and eax,15
 cmp eax,15
 jne bad_frame
 mov rdi,[rsp+INPUT_FD]
 mov rsi,rsp
 mov eax,5                       /* fstat */
 syscall
 test rax,rax
 jnz io_error
 mov r13,[rsp+48]                 /* st_size */
 cmp r13,[rsp+PREFIX]
 jb bad_frame
 mov [rsp+INPUT_EXTENT],r13
 mov rsi,r13
 mov r8,[rsp+INPUT_FD]
 mov edx,1                       /* PROT_READ */
 mov r10d,2                      /* MAP_PRIVATE */
 call map
 mov r12,rax
 cmp QWORD PTR [rsp+SESSION_MODE],0
 je admit_header
 mov rdi,[rsp+INPUT_FD]
 mov eax,3                       /* close; mapping retains the sealed file */
 syscall
 test rax,rax
 jne io_error

admit_header:
 mov QWORD PTR [rsp+TRANSFER],15
 mov rax,[rsp+NEXT_SEQUENCE]
 mov [rsp+TRANSFER+8],rax
 mov rdi,r12
 mov rsi,r13
 xor edx,edx
 xor ecx,ecx
 lea r8,[rsp+TRANSFER]
 mov r9d,24
 call agent_journal_start
 cmp eax,1
 jne bad_frame
 mov rbx,[r12+48]                 /* foreign-type tag count */
 sub r13,[rsp+PREFIX]
 sub r13,rbx
 mov r15,[r12+16]                 /* scratch capacity */
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
 lea rax,[rsp+HELD_STATE]
 cmp QWORD PTR [rsp+SESSION_MODE],0
 cmovne rsi,rax
 mov ecx,STATE/8
 rep movsq
 mov [rdi-STATE+336],rbx
 mov rax,[r12+40]
 mov [rdi-STATE+344],rax
 lea rdi,[rdx+r15-PRIVATE]
 sub rdi,rbx
 mov rsi,[rsp+PREFIX]
 add rsi,r12
 mov rcx,rbx
 rep movsb
 mov ecx,OUT
 jmp invoke
prepare_envelope:
 lea rdi,[rdx+8]
 lea rsi,[r12+FRAME]
 lea rax,[rsp+HELD_STATE]
 cmp QWORD PTR [rsp+SESSION_MODE],0
 cmovne rsi,rax
 mov ecx,STATE/8
 rep movsq
 mov ecx,ENVELOPE
invoke:
 mov rdi,[rsp+PREFIX]
 add rdi,r12
 add rdi,rbx
 mov rsi,r13
 mov r8,rdx
 mov rdx,r14
 mov r9,r15
 call agent_journal_start
 /* Let HIA validate the payload extents and stage the complete header
  * before any bytes are written. */
 mov QWORD PTR [rsp+TRANSFER],16
 mov [rsp+TRANSFER+8],rax
 mov rax,[r12+24]
 mov [rsp+TRANSFER+16],rax
 mov rdi,r14
 lea rsi,[r15+OUT]
 mov rdx,rsp
 mov ecx,REPLY
 lea r8,[rsp+TRANSFER]
 mov r9d,24
 call agent_journal_start
 cmp eax,1
 ja bad_frame
 mov [rsp+CARRY_STATE],rax
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
 cmp QWORD PTR [rsp+SESSION_MODE],0
 je session_end
 cmp QWORD PTR [rsp+CARRY_STATE],0
 je release_frame
 lea rdi,[rsp+HELD_STATE]
 lea rsi,[r14+2*LIMIT]
 mov ecx,STATE/8
 rep movsq
release_frame:
 mov rdi,r12
 mov rsi,[rsp+INPUT_EXTENT]
 mov eax,11                      /* munmap */
 syscall
 test rax,rax
 jne io_error
 mov rdi,r14
 lea rsi,[r15+OUT]
 mov eax,11
 syscall
 test rax,rax
 jne io_error
 inc QWORD PTR [rsp+NEXT_SEQUENCE]
 jz bad_frame
 jmp receive_frame
session_end:
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
.asciz "hepta.hia.agent-journal.session.v1"
.section .note.GNU-stack,"",@progbits
