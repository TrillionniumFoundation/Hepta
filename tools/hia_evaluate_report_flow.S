/* Descriptor transport for HIA's paid Evaluate document continuation.
 * All roles, fragment order, byte spans, branches and publication are HIA
 * decisions. The shared Worker ports below own descriptor seals and children.
 */
.intel_syntax noprefix
.text
.global _start,report_flow_call_hole
.equ WORK,50331648
.equ OUT,33554432
.equ D,35651584
.equ FD,0
.equ MAP,176
.equ PROC,352
.equ INFO,416
.equ ARGV,456
.equ COMMAND,480
.equ PRIVATE,488
.equ COPYBUF,496
.equ ERRFD,504
.equ JOBFD,512
.equ RESULTFD,520
.equ DEST,528
.equ CURSOR,536
.equ CHOICE,544
_start:
    cld
    cmp QWORD PTR [rsp],1
    jne .Ldoc_fail
    sub rsp,608
    mov rbp,rsp
    mov rdi,rbp
    mov ecx,75
    xor eax,eax
    rep stosq
    mov edi,17
    lea rsi,[rbp+PROC]
    xor edx,edx
    mov r10d,8
    mov eax,13
    syscall
    test rax,rax
    jne .Ldoc_fail
    mov esi,WORK
    call .Ldoc_allocate
    mov [rbp+PRIVATE],rax
    lea r15,[rax+D]
    mov esi,OUT
    call .Ldoc_allocate
    mov [rbp+COMMAND],rax
    mov esi,65536
    call .Ldoc_allocate
    mov [rbp+COPYBUF],rax
    lea rax,[rip+.Ldoc_label]
    mov [rbp+ARGV],rax
    mov r12d,3
.Ldoc_inputs:
    mov [rbp+FD+8*r12],r12
    mov edi,r12d
    lea rsi,[rbp+INFO]
    call hia_worker_fd_observe
    test rax,rax
    jne .Ldoc_fail
    cmp QWORD PTR [rbp+INFO+8],15
    jne .Ldoc_fail
    cmp QWORD PTR [rbp+INFO+16],32768
    jne .Ldoc_fail
    mov rax,[rbp+INFO+24]
    test rax,rax
    jle .Ldoc_fail
    cmp rax,805306368
    ja .Ldoc_fail
    mov [r15+512+8*r12],rax
    inc r12
    cmp r12,13
    jb .Ldoc_inputs
    mov r12d,12
.Ldoc_enter:
    mov [rbp+CHOICE],r12
    call hia_worker_now
    test rax,rax
    js .Ldoc_fail
    mov [r15+8],rax
    mov r12,[rbp+CHOICE]
    mov rdi,[rbp+MAP+8*r12]
    test rdi,rdi
    jnz .Ldoc_mapped
    mov rsi,[r15+512+8*r12]
    xor edi,edi
    mov edx,1
    mov r10d,2
    mov r8,[rbp+FD+8*r12]
    xor r9d,r9d
    mov eax,9
    syscall
    test rax,rax
    js .Ldoc_fail
    mov [rbp+MAP+8*r12],rax
    mov rdi,rax
.Ldoc_mapped:
    mov rsi,[r15+512+8*r12]
    mov rdx,[rbp+COMMAND]
    mov ecx,OUT
    mov r8,[rbp+PRIVATE]
    mov r9d,WORK
    .byte 0xe8
report_flow_call_hole: .long 0
    mov r14,[rbp+COMMAND]
    cmp eax,1
    je .Ldoc_select
    cmp eax,2
    je .Ldoc_job
    cmp eax,3
    jne .Ldoc_fail
    mov QWORD PTR [rbp+DEST],0
    jmp .Ldoc_compose
.Ldoc_select:
    mov r12,[r14]
    cmp r12,3
    jb .Ldoc_fail
    cmp r12,19
    ja .Ldoc_fail
    cmp QWORD PTR [rbp+FD+8*r12],0
    je .Ldoc_fail
    jmp .Ldoc_enter
.Ldoc_job:
    mov rax,[r14+8]
    cmp rax,13
    jb .Ldoc_fail
    cmp rax,19
    ja .Ldoc_fail
    cmp QWORD PTR [rbp+FD+8*rax],0
    jne .Ldoc_fail
    mov [rbp+DEST],rax
    mov rax,[r14]
    cmp rax,8
    jb .Ldoc_fail
    cmp rax,11
    ja .Ldoc_fail
.Ldoc_compose:
    cmp QWORD PTR [r14+16],16
    ja .Ldoc_fail
    call hia_worker_memfd
    test rax,rax
    js .Ldoc_fail
    mov [rbp+JOBFD],rax
    mov QWORD PTR [rbp+CURSOR],0
.Ldoc_part:
    mov rax,[rbp+CURSOR]
    cmp rax,[r14+16]
    jae .Ldoc_full
    lea r13,[rax+rax*2]
    lea r13,[r14+64+r13*8]
    mov rax,[r13]
    mov rsi,[r13+8]
    mov rdx,[r13+16]
    test rax,rax
    jz .Ldoc_inline
    cmp rax,3
    jb .Ldoc_fail
    cmp rax,19
    ja .Ldoc_fail
    mov rdi,[rbp+FD+8*rax]
    test rdi,rdi
    jle .Ldoc_fail
    mov rax,[r15+512+8*rax]
    cmp rsi,rax
    ja .Ldoc_fail
    sub rax,rsi
    cmp rdx,rax
    ja .Ldoc_fail
    mov ecx,[rbp+JOBFD]
    mov r8,[rbp+COPYBUF]
    mov r9d,65536
    call hia_worker_fragment_copy
    test rax,rax
    jne .Ldoc_fail
    jmp .Ldoc_next
.Ldoc_inline:
    cmp rsi,1024
    jb .Ldoc_fail
    cmp rsi,4096
    ja .Ldoc_fail
    mov eax,4096
    sub rax,rsi
    cmp rdx,rax
    ja .Ldoc_fail
    add rsi,r14
    mov edi,[rbp+JOBFD]
    call .Ldoc_write
.Ldoc_next:
    inc QWORD PTR [rbp+CURSOR]
    jmp .Ldoc_part
.Ldoc_full:
    mov edi,[rbp+JOBFD]
    call hia_worker_seal
    test rax,rax
    jne .Ldoc_fail
    cmp QWORD PTR [rbp+DEST],0
    je .Ldoc_publish
    mov r12,[r14+24]
    test r12,r12
    jz .Ldoc_process
    cmp r12,16
    jne .Ldoc_fail
    cmp QWORD PTR [rbp+FD+8*r12],0
    jne .Ldoc_fail
    mov edi,[rbp+JOBFD]
    lea rsi,[rbp+INFO]
    call hia_worker_fd_observe
    test rax,rax
    jne .Ldoc_fail
    mov rax,[rbp+JOBFD]
    mov [rbp+FD+8*r12],rax
    mov rax,[rbp+INFO+24]
    mov [r15+512+8*r12],rax
.Ldoc_process:
    call hia_worker_memfd
    test rax,rax
    js .Ldoc_fail
    mov [rbp+RESULTFD],rax
    call hia_worker_memfd
    test rax,rax
    js .Ldoc_fail
    mov [rbp+ERRFD],rax
    mov [rbp+PROC+24],rax
    mov rax,[r14]
    mov rax,[rbp+FD+rax*8]
    mov [rbp+PROC],rax
    mov rax,[rbp+JOBFD]
    mov [rbp+PROC+8],rax
    mov rax,[rbp+RESULTFD]
    mov [rbp+PROC+16],rax
    lea rax,[rbp+ARGV]
    mov [rbp+PROC+32],rax
    mov QWORD PTR [rbp+PROC+40],0
    mov QWORD PTR [rbp+PROC+48],0
    mov rax,[r14+32]
    mov [rbp+PROC+56],rax
    lea rdi,[rbp+PROC]
    call hia_worker_run
    test rax,rax
    jne .Ldoc_fail
    mov edi,[rbp+ERRFD]
    lea rsi,[rbp+INFO]
    call hia_worker_fd_observe
    test rax,rax
    jne .Ldoc_fail
    cmp QWORD PTR [rbp+INFO+24],0
    jne .Ldoc_fail
    mov edi,[rbp+ERRFD]
    mov eax,3
    syscall
    cmp QWORD PTR [r14+24],0
    jne .Ldoc_result
    mov edi,[rbp+JOBFD]
    mov eax,3
    syscall
.Ldoc_result:
    mov edi,[rbp+RESULTFD]
    call hia_worker_seal
    test rax,rax
    jne .Ldoc_fail
    mov edi,[rbp+RESULTFD]
    lea rsi,[rbp+INFO]
    call hia_worker_fd_observe
    test rax,rax
    jne .Ldoc_fail
    mov rax,[rbp+INFO+24]
    test rax,rax
    jle .Ldoc_fail
    cmp rax,33554432
    ja .Ldoc_fail
    mov r12,[rbp+DEST]
    mov [r15+512+8*r12],rax
    mov rax,[rbp+RESULTFD]
    mov [rbp+FD+8*r12],rax
    jmp .Ldoc_enter
.Ldoc_publish:
    mov edi,[rbp+JOBFD]
    lea rsi,[rbp+INFO]
    call hia_worker_fd_observe
    test rax,rax
    jne .Ldoc_fail
    mov edi,[rbp+JOBFD]
    xor esi,esi
    mov rdx,[rbp+INFO+24]
    mov ecx,1
    mov r8,[rbp+COPYBUF]
    mov r9d,65536
    call hia_worker_fragment_copy
    test rax,rax
    jne .Ldoc_fail
    xor edi,edi
    jmp .Ldoc_exit
.Ldoc_write:
    test rdx,rdx
    jz .Ldoc_written
.Ldoc_more:
    mov eax,1
    syscall
    cmp rax,-4
    je .Ldoc_more
    test rax,rax
    jle .Ldoc_fail
    add rsi,rax
    sub rdx,rax
    jnz .Ldoc_more
.Ldoc_written:
    ret
.Ldoc_allocate:
    xor edi,edi
    mov edx,3
    mov r10d,34
    mov r8,-1
    xor r9d,r9d
    mov eax,9
    syscall
    test rax,rax
    js .Ldoc_fail
    ret
.Ldoc_fail:
    mov edi,2
.Ldoc_exit:
    mov eax,60
    syscall
.Ldoc_label: .asciz "hia-evaluate-report"
