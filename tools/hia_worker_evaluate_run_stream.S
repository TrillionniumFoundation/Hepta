/* Spool one HIA-selected peer frame into a sealed file, retaining a fixed
 * observation window. The HIA owner supplies the exact length and deadline. */
.text
.Lrun_receive_sealed:
 cmp QWORD PTR [rbp+COMMAND+40],0
 jne .Lrefused
 mov r12,[rbp+COMMAND+144]
 test r12,r12
 jz .Lrefused
 cmp r12,67108864
 ja .Lrefused
 call .Ldeadline
 mov r14,rax
 call .Lpeer_index
 mov [rbp+TEMP+56],rax
 call hia_worker_memfd
 cmp rax,3
 jl .Lrefused
 mov r13,rax
.Lrun_stream_block:
 mov ecx,8192
 cmp r12,rcx
 cmovb rcx,r12
 mov [rbp+TEMP+64],rcx
 mov rdi,[rbp+TEMP+56]
 lea rsi,[rbp+SCRATCH]
 mov rdx,rcx
 mov rcx,r14
 call hia_worker_peer_read
 test rax,rax
 jnz .Lrefused
 mov edi,r13d
 lea rsi,[rbp+SCRATCH]
 mov rdx,[rbp+TEMP+64]
 call .Lwrite_exact
 sub r12,[rbp+TEMP+64]
 jnz .Lrun_stream_block
 mov edi,r13d
 call hia_worker_seal
 test rax,rax
 jnz .Lrefused
 mov [rbp+PROCESS+16],r13
 jmp .Lobserve_output
