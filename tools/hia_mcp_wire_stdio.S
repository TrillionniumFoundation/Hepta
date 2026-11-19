/* Native wire kernel for one sealed MCP request or response frame. The
 * caller retains transport and effect authority. Return a status word and
 * either the successful request descriptor or the full response line.
 */
.intel_syntax noprefix
.text
.global _start
.type _start,@function
.equ INPUT_MAX, 8<<20
.ifdef MCP_STREAM_RESULT
.equ SCRATCH, INPUT_MAX+32
.else
.equ SCRATCH, 4<<20
.endif
.equ ARENA, 64+(262144*72)+INPUT_MAX
.ifdef MCP_NEGOTIATE
.equ DESCRIPTOR, 112
.else
.ifdef MCP_URI
.equ DESCRIPTOR, 24
.else
.equ DESCRIPTOR, 88
.endif
.endif

_start:
 cmp QWORD PTR [rsp+8],1                  /* _start is called by HIALNK01. */
 jne bad_frame
 sub rsp,168
 xor edi,edi
 mov esi,1034                             /* F_GET_SEALS */
 mov eax,72                               /* fcntl */
 syscall
 test rax,rax
 js bad_frame
 and eax,15
 cmp eax,15
 jne bad_frame

 xor edi,edi
 mov rsi,rsp
 mov eax,5                                /* fstat */
 syscall
 test rax,rax
 jne io_error
 mov r13,[rsp+48]                         /* Linux x86-64 stat.st_size */
 cmp r13,2
 jb bad_frame
 cmp r13,INPUT_MAX
 ja bad_frame

 xor edi,edi
 mov rsi,r13
 mov edx,1                                /* PROT_READ */
 mov r10d,2                               /* MAP_PRIVATE */
 xor r8d,r8d                              /* stdin */
 xor r9d,r9d
 mov eax,9                                /* mmap */
 syscall
 cmp rax,-4095
 jae io_error
 mov r12,rax

 xor edi,edi
 mov esi,8+SCRATCH+ARENA
 mov edx,3                                /* PROT_READ | PROT_WRITE */
 mov r10d,34                              /* MAP_PRIVATE | MAP_ANONYMOUS */
 mov r8,-1
 xor r9d,r9d
 mov eax,9
 syscall
 cmp rax,-4095
 jae io_error
 mov r14,rax

 mov rdi,r12
 mov rsi,r13
 lea rdx,[r14+8]
 mov ecx,SCRATCH
 lea r8,[r14+8+SCRATCH]
 mov r9d,ARENA
.ifdef MCP_REPLY
 call mcp_reply_wire_start
.else
 .ifdef MCP_NEGOTIATE
 call mcp_negotiation_start
 .else
  .ifdef MCP_CATALOG
 call mcp_catalog_wire_start
  .else
   .ifdef MCP_URI
 call mcp_resource_uri_start
   .else
 call mcp_request_route_start
   .endif
  .endif
 .endif
.endif
 mov eax,eax                              /* Export u32, never a stale high word. */
 mov [r14],rax
 mov rsi,r14
 mov edx,8
.ifdef MCP_STREAM_RESULT
 cmp eax,2
 jb write_result
 cmp eax,SCRATCH
 ja write_result
 add edx,eax
.else
 cmp eax,DESCRIPTOR
 jne write_result
 add edx,DESCRIPTOR
.endif
write_result:
 mov edi,1
 mov eax,1                                /* write */
 syscall
 cmp rax,-4
 je write_result
 test rax,rax
 jle io_error
 add rsi,rax
 sub rdx,rax
 jne write_result
 xor edi,edi
 jmp exit_process
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
