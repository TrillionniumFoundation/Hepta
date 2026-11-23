/* Stateful framing transport for the HIA execution-budget owner. Standard input
 * and output carry length-prefixed frames. The HIA state never leaves memory. */
.intel_syntax noprefix
.text
.global _start, budget_call_hole
.equ INBUF,16
.equ OUTBUF,4736
.equ STATE,18048
.equ FRAME,31616
_start:
    cmp qword ptr [rsp],1
    jne refuse
    sub rsp,FRAME
    mov rbp,rsp
    lea rdi,[rbp+STATE]
    xor eax,eax
    mov ecx,1696                 /* 13568 bytes of private initial state */
    rep stosq
next_frame:
    mov rsi,rbp
    mov edx,8
    call read_exact
    test eax,eax
    jz finished
    js refuse
    mov rdx,[rbp]
    cmp rdx,128
    jb refuse
    cmp rdx,4700
    ja refuse
    lea rsi,[rbp+INBUF]
    call read_exact
    cmp eax,1
    jne refuse
    lea rdi,[rbp+INBUF]
    mov rsi,[rbp]
    lea rdx,[rbp+OUTBUF]
    mov ecx,13312
    lea r8,[rbp+STATE]
    mov r9d,13568
    .byte 0xe8
budget_call_hole: .long 0
    cmp eax,128
    jb refuse
    cmp eax,13312
    ja refuse
    mov eax,eax
    mov [rbp+OUTBUF-8],rax
    lea rdx,[rax+8]
    lea rsi,[rbp+OUTBUF-8]
write_more:
    mov eax,1
    mov edi,1
    syscall
    cmp rax,-4
    je write_more
    test rax,rax
    jle refuse
    add rsi,rax
    sub rdx,rax
    jne write_more
    jmp next_frame
/* Return one for a complete frame, zero for clean EOF and -1 for an error
 * or truncated frame. rsi/rdx advance only after confirmed reads. */
read_exact:
    mov r8,rdx
read_more:
    xor eax,eax
    xor edi,edi
    syscall
    cmp rax,-4
    je read_more
    test rax,rax
    js read_error
    jz read_eof
    add rsi,rax
    sub rdx,rax
    jne read_more
    mov eax,1
    ret
read_eof:
    cmp rdx,r8
    jne read_error
    ret
read_error:
    mov eax,-1
    ret
finished:
    xor edi,edi
    jmp exit
refuse:
    mov edi,4
exit:
    mov eax,60
    syscall
