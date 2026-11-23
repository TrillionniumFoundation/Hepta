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
.equ INPUT_ARGV,552
.ifdef LEDGER_FLOW
.equ LAST_INPUT,8
.equ STACK,13632
.equ STATE_PATH,768
.equ RELEASE_PATH,4864
.equ ARTIFACT_PATH,8960
.equ FD_LABEL,13056
.equ ORIGINAL_STAT,13120
.equ PATH_STAT,13264
.equ ROLE_ARGV,13408
.else
.equ LAST_INPUT,12
.equ STACK,608
.endif
_start:
    cld
    xor r13d,r13d
    cmp QWORD PTR [rsp],1
    je .Ldoc_args
    cmp QWORD PTR [rsp],LAST_INPUT-1
    jne .Ldoc_fail
    lea r13,[rsp+16]
.Ldoc_args:
    sub rsp,STACK
    mov rbp,rsp
    mov rdi,rbp
    mov ecx,STACK/8
    xor eax,eax
    rep stosq
    mov [rbp+INPUT_ARGV],r13
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
    mov rax,r12
    mov rsi,[rbp+INPUT_ARGV]
    test rsi,rsi
    jz .Ldoc_input_number
    mov rsi,[rsi+8*r12-24]
.ifdef LEDGER_FLOW
    cmp r12,7
    jb .Ldoc_parse_fd
    cmp BYTE PTR [rsi],47
    jne .Ldoc_parse_fd
    mov rdi,rsi
    mov esi,720896                 /* O_CLOEXEC | O_NOFOLLOW | O_DIRECTORY */
    xor edx,edx
    mov eax,2
    syscall
    test rax,rax
    js .Ldoc_fail
    jmp .Ldoc_input_number
.Ldoc_parse_fd:
.endif
    call .Ldoc_number
.Ldoc_input_number:
    mov [rbp+FD+8*r12],rax
    mov edi,eax
.ifdef LEDGER_FLOW
    cmp r12,7
    jb .Ldoc_regular
    lea rsi,[rbp+STATE_PATH]
    cmp r12,7
    je .Ldoc_dir
    lea rsi,[rbp+RELEASE_PATH]
.Ldoc_dir:
    call .Ldoc_dir_name
    jmp .Ldoc_next_input
.Ldoc_regular:
.endif
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
.Ldoc_next_input:
    inc r12
    cmp r12,LAST_INPUT+1
    jb .Ldoc_inputs
.ifdef LEDGER_FLOW
    mov r12d,3
.else
    mov r12d,12
.endif
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
.ifdef LEDGER_FLOW
    cmp rax,4
    jb .Ldoc_fail
    cmp rax,6
.else
    cmp rax,8
    jb .Ldoc_fail
    cmp rax,11
.endif
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
.ifdef LEDGER_FLOW
    mov rcx,[r14]
    cmp rcx,4
    je .Ldoc_argv_ready
    call .Ldoc_verify_dirs
    mov rcx,[r14]
    lea rax,[rbp+ROLE_ARGV]
    cmp rcx,5
    jne .Ldoc_artifact_argv
    lea rdx,[rip+.Lledger_store]
    mov [rax],rdx
    lea rdx,[rbp+STATE_PATH]
    mov [rax+8],rdx
    lea rdx,[rip+.Lledger_stem]
    mov [rax+16],rdx
    lea rdx,[rbp+RELEASE_PATH]
    mov [rax+24],rdx
    jmp .Ldoc_argv_ready
.Ldoc_artifact_argv:
    lea rdx,[rip+.Lledger_artifact]
    mov [rax],rdx
    lea rdx,[rip+.Lledger_fetch]
    mov [rax+8],rdx
    lea rdx,[rbp+ARTIFACT_PATH]
    mov [rax+16],rdx
    lea rdx,[r14+4096]
    mov [rax+24],rdx
.Ldoc_argv_ready:
.endif
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
.ifdef LEDGER_FLOW
    cmp rax,805306368
.else
    cmp rax,33554432
.endif
    ja .Ldoc_fail
    mov r12,[rbp+DEST]
    mov [r15+512+8*r12],rax
    mov rax,[rbp+RESULTFD]
    mov [rbp+FD+8*r12],rax
    jmp .Ldoc_enter
.Ldoc_publish:
.ifdef LEDGER_FLOW
    call .Ldoc_verify_dirs
.endif
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
.Ldoc_number:
    xor eax,eax
    cmp BYTE PTR [rsi],48
    je .Ldoc_fail
.Ldoc_digit:
    movzx ecx,BYTE PTR [rsi]
    test ecx,ecx
    jz .Ldoc_number_end
    sub ecx,48
    cmp ecx,9
    ja .Ldoc_fail
    imul rax,10
    add rax,rcx
    cmp rax,2147483647
    ja .Ldoc_fail
    inc rsi
    jmp .Ldoc_digit
.Ldoc_number_end:
    cmp eax,3
    jb .Ldoc_fail
    ret

.ifdef LEDGER_FLOW
/* The Store verifier accepts the release and state as real directory names.
 * Recover those names from caller-held directories, then require their stat
 * identities to match. No additional descriptors enter a Store child. */
.Ldoc_dir_name:
    mov r13d,edi
    mov r14,rsi
    lea rsi,[rbp+ORIGINAL_STAT]
    mov eax,5
    syscall
    test rax,rax
    jne .Ldoc_fail
    mov eax,[rbp+ORIGINAL_STAT+24]
    and eax,61440
    cmp eax,16384
    jne .Ldoc_fail
    lea rsi,[rip+.Lproc_fds]
    lea rdi,[rbp+FD_LABEL]
    mov ecx,14
    rep movsb
    mov eax,r13d
    mov r8d,10
    lea r9,[rbp+FD_LABEL+48]
    mov rsi,r9
.Ldoc_fd_digits:
    xor edx,edx
    div r8d
    add dl,48
    dec rsi
    mov [rsi],dl
    test eax,eax
    jnz .Ldoc_fd_digits
    mov rcx,r9
    sub rcx,rsi
    rep movsb
    mov BYTE PTR [rdi],0
    lea rdi,[rbp+FD_LABEL]
    mov rsi,r14
    mov edx,4084
    mov eax,89
    syscall
    test rax,rax
    jle .Ldoc_fail
    cmp rax,4084
    jae .Ldoc_fail
    cmp BYTE PTR [r14],47
    jne .Ldoc_fail
    mov BYTE PTR [r14+rax],0
    cmp r12,7
    jne .Ldoc_same_dir
    mov rcx,rax
    mov rsi,r14
    lea rdi,[rbp+ARTIFACT_PATH]
    rep movsb
    lea rsi,[rip+.Lledger_objects]
    mov ecx,11
    rep movsb
.Ldoc_same_dir:
    mov rdi,r14
    lea rsi,[rbp+PATH_STAT]
    mov eax,4
    syscall
    test rax,rax
    jne .Ldoc_fail
    mov rax,[rbp+PATH_STAT]
    cmp rax,[rbp+ORIGINAL_STAT]
    jne .Ldoc_fail
    mov rax,[rbp+PATH_STAT+8]
    cmp rax,[rbp+ORIGINAL_STAT+8]
    jne .Ldoc_fail
    ret
.Ldoc_verify_dirs:
    push r14
    mov edi,[rbp+FD+56]
    lea r14,[rbp+STATE_PATH]
    call .Ldoc_verify_dir
    mov edi,[rbp+FD+64]
    lea r14,[rbp+RELEASE_PATH]
    call .Ldoc_verify_dir
    pop r14
    ret
.Ldoc_verify_dir:
    lea rsi,[rbp+ORIGINAL_STAT]
    mov eax,5
    syscall
    test rax,rax
    jne .Ldoc_fail
    jmp .Ldoc_same_dir
.Lproc_fds: .ascii "/proc/self/fd/"
.Lledger_objects: .asciz "/artifacts"
.Lledger_store: .asciz "hia-agent-store"
.Lledger_artifact: .asciz "hia-artifact"
.Lledger_fetch: .asciz "store-get"
.Lledger_stem: .asciz "store"
.endif
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
