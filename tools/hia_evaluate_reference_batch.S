/* Standalone Linux x86-64 transport for four already admitted, sealed FDs:
 * 3 canonical Core, 4 workload, 5 projector ELF, 6 owned reference ELF.
 * The HIA entry owns case planning and all interpreter request construction.
 * Child replies are archived privately before any batch bytes reach stdout.
 */
.intel_syntax noprefix
.text
.global _start,batch_case_call_hole
.equ CORE,8388608
.equ PACKET,33554432
.equ WORK,67108864
.equ LIMIT,67108864
.equ INPUT,0
.equ INPUT_LEN,8
.equ CORE_LEN,16
.equ PLAN,24
.equ PLAN_LEN,32
.equ PRIVATE,40
.equ JOIN,48
.equ PACK,56
.equ IDX,64
.equ COUNT,72
.equ IFD,80
.equ OFD,88
.equ BFD,96
.equ BUFFER,104
.equ CURSOR,112
.equ CHILD,120
.equ STATUS,128
.equ STAT,160
.equ FRAME,344
.equ COMPLETE,392

_start:
    cmp QWORD PTR [rsp],1
    jne refuse
    sub rsp,512
    mov rbp,rsp
    /* A parent may have ignored SIGCHLD. Own normal waitable children. */
    xor eax,eax
    lea rdi,[rbp+FRAME]
    mov ecx,4
    rep stosq
    mov edi,17
    lea rsi,[rbp+FRAME]
    xor edx,edx
    mov r10d,8
    mov eax,13
    syscall
    test rax,rax
    jne refuse
    mov edi,4
    xor esi,esi
    xor edx,edx
    xor r10d,r10d
    xor r8d,r8d
    mov eax,157
    syscall
    test rax,rax
    jne refuse
    mov edi,3
sealed:
    mov eax,72
    mov esi,1034
    syscall
    test rax,rax
    js refuse
    and eax,15
    cmp eax,15
    jne refuse
    inc edi
    cmp edi,7
    jne sealed
    mov esi,2*CORE+3
    call allocate
    mov [rbp+INPUT],rax
    mov BYTE PTR [rax],91
    lea rsi,[rax+1]
    mov edi,3
    mov edx,CORE
    call original
    mov [rbp+CORE_LEN],rax
    mov rsi,[rbp+INPUT]
    lea rsi,[rsi+rax+1]
    mov BYTE PTR [rsi],44
    inc rsi
    mov edi,4
    mov edx,CORE
    call original
    add rax,[rbp+CORE_LEN]
    add rax,3
    mov [rbp+INPUT_LEN],rax
    mov rdi,[rbp+INPUT]
    mov BYTE PTR [rdi+rax-1],93
    mov esi,PACKET
    call allocate
    mov [rbp+PLAN],rax
    mov esi,WORK
    call allocate
    mov [rbp+PRIVATE],rax
    mov esi,2*PACKET+8
    call allocate
    mov [rbp+JOIN],rax
    mov esi,PACKET
    call allocate
    mov [rbp+PACK],rax
    call scratch
    mov [rbp+IFD],rax
    call scratch
    mov [rbp+OFD],rax
    call scratch
    mov [rbp+BFD],rax
    mov QWORD PTR [rbp+IDX],0
    mov QWORD PTR [rbp+COUNT],0
    mov QWORD PTR [rbp+CURSOR],24
    mov QWORD PTR [rbp+COMPLETE],0
    mov edi,[rbp+BFD]
    lea rsi,[rbp+FRAME]
    mov edx,24
    call write_all
per_case:
    mov r8,[rbp+PRIVATE]
    mov rax,[rbp+IDX]
    mov [r8+WORK-8],rax
    mov rdi,[rbp+INPUT]
    mov rsi,[rbp+INPUT_LEN]
    mov rdx,[rbp+PLAN]
    call plan
    cmp eax,96
    jb refuse
    cmp eax,PACKET
    ja refuse
    mov [rbp+PLAN_LEN],rax
    mov r13,[rbp+PLAN]
    movabs rcx,0x3130425245414948
    cmp [r13],rcx
    jne refuse
    mov rax,[r13+8]
    test rax,rax
    jz refuse
    cmp rax,512
    ja refuse
    cmp QWORD PTR [rbp+IDX],0
    jne verify_count
    mov [rbp+COUNT],rax
verify_count:
    cmp [rbp+COUNT],rax
    jne refuse
    mov rax,[rbp+IDX]
    cmp [r13+16],rax
    jne refuse
    mov r12,[rbp+PACK]
    mov rdi,r12
    mov rsi,[rbp+INPUT]
    mov rcx,[rbp+CORE_LEN]
    inc rcx
    rep movsb
    mov BYTE PTR [rdi],44
    inc rdi
    mov rcx,[r13+32]
    cmp rcx,130
    ja refuse
    mov rax,[r13+24]
    cmp rax,[rbp+INPUT_LEN]
    jae refuse
    mov rdx,[rbp+INPUT_LEN]
    sub rdx,rax
    cmp rcx,rdx
    ja refuse
    mov rsi,[rbp+INPUT]
    add rsi,rax
    rep movsb
    mov DWORD PTR [rdi],0x7572742c
    mov WORD PTR [rdi+4],0x5d65
    lea rdx,[rdi+6]
    sub rdx,r12
    mov edi,5
    mov rsi,r12
    call run_role
    cmp rax,PACKET
    ja refuse
    mov r12,[rbp+JOIN]
    mov [r12],rax
    mov r14,rax
    lea rsi,[r12+8]
    mov edx,eax
    mov edi,[rbp+OFD]
    call read_exact
    lea rdi,[r12+r14+8]
    mov rsi,[rbp+PLAN]
    mov rcx,[rbp+PLAN_LEN]
    rep movsb
    mov rsi,rdi
    sub rsi,r12
    mov rdi,r12
    mov rdx,[rbp+PACK]
    mov r8,[rbp+PRIVATE]
    mov QWORD PTR [r8+WORK-8],-1
    call plan
    cmp eax,88
    jb refuse
    cmp eax,PACKET
    ja refuse
    mov edx,eax
    mov edi,6
    mov rsi,[rbp+PACK]
    call run_role
    cmp rax,144
    jb refuse
    cmp rax,PACKET
    ja refuse
    mov r14,rax
    mov rsi,[rbp+PACK]
    mov edx,eax
    mov edi,[rbp+OFD]
    call read_exact
    mov r8,[rbp+PRIVATE]
    mov QWORD PTR [r8+WORK-8],-2
    mov rax,[rbp+PLAN]
    mov rcx,[rax+48]
    mov [r8+WORK-16],rcx
    mov rcx,[rax+72]
    mov [r8+WORK-24],rcx
    mov rdx,rax
    mov rdi,[rbp+PACK]
    mov rsi,r14
    call plan
    cmp eax,1
    jb refuse
    cmp eax,2
    ja refuse
    mov [rbp+COMPLETE],rax
    mov rax,[rbp+CURSOR]
    lea rax,[rax+r14+16]
    cmp rax,LIMIT
    ja refuse
    mov [rbp+CURSOR],rax
    mov rax,[rbp+IDX]
    mov [rbp+FRAME],rax
    mov [rbp+FRAME+8],r14
    mov edi,[rbp+BFD]
    lea rsi,[rbp+FRAME]
    mov edx,16
    call write_all
    mov edi,[rbp+BFD]
    mov rsi,[rbp+PACK]
    mov rdx,r14
    call write_all
    inc QWORD PTR [rbp+IDX]
    cmp QWORD PTR [rbp+COMPLETE],2
    je archive
    mov rax,[rbp+IDX]
    cmp rax,[rbp+COUNT]
    jb per_case
archive:
    movabs rax,0x3130544245414948  /* HIAEBT01 */
    mov [rbp+FRAME],rax
    mov rax,[rbp+COUNT]
    mov [rbp+FRAME+8],rax
    mov rax,[rbp+IDX]
    mov [rbp+FRAME+16],rax
    mov edi,[rbp+BFD]
    call rewind
    mov edi,[rbp+BFD]
    lea rsi,[rbp+FRAME]
    mov edx,24
    call write_all
    mov edi,[rbp+BFD]
    call rewind
    mov r12,[rbp+CURSOR]
publish:
    mov edi,1
    mov esi,[rbp+BFD]
    xor edx,edx
    mov r10,r12
    mov eax,40                  /* sendfile */
    syscall
    cmp rax,-4
    je publish
    test rax,rax
    jle refuse
    sub r12,rax
    jne publish
    xor edi,edi
    jmp exit
plan:
    sub rsp,8
    mov ecx,PACKET
    mov r9d,WORK
    .byte 0xe8
batch_case_call_hole: .long 0
    add rsp,8
    ret
original:
    push rsi
    push rdx
    lea rsi,[rbp+STAT]
    mov eax,5
    syscall
    pop rdx
    pop rsi
    test rax,rax
    jne refuse
    mov rax,[rbp+STAT+48]
    test rax,rax
    jle refuse
    cmp rax,rdx
    ja refuse
    mov rdx,rax
    push rax
    call read_exact
    pop rax
    ret
read_exact:
    xor r10d,r10d
read_more:
    mov eax,17                  /* pread64, independent descriptor offset */
    syscall
    cmp rax,-4
    je read_more
    test rax,rax
    jle refuse
    add rsi,rax
    add r10,rax
    sub rdx,rax
    jne read_more
    ret
write_all:
    mov eax,1
    syscall
    cmp rax,-4
    je write_all
    test rax,rax
    jle refuse
    add rsi,rax
    sub rdx,rax
    jne write_all
    ret
rewind:
    xor esi,esi
    xor edx,edx
    mov eax,8
    syscall
    test rax,rax
    jne refuse
    ret
clear_file:
    xor esi,esi
    mov eax,77
    syscall
    test rax,rax
    jne refuse
    jmp rewind
scratch:
    lea rdi,[rip+label]
    mov esi,1
    mov eax,319
    syscall
    test rax,rax
    js refuse
    ret
allocate:
    xor edi,edi
    mov edx,3
    mov r10d,34
    mov r8,-1
    xor r9d,r9d
    mov eax,9
    syscall
    test rax,rax
    js refuse
    ret
run_role:
    push rdi
    push rsi
    push rdx
    mov edi,[rbp+IFD]
    call clear_file
    mov edi,[rbp+OFD]
    call clear_file
    pop rdx
    pop rsi
    mov edi,[rbp+IFD]
    call write_all
    mov edi,[rbp+IFD]
    call rewind
    pop r12
    mov eax,39
    syscall
    mov r13,rax
    mov eax,57
    syscall
    test rax,rax
    js refuse
    jz child
    mov [rbp+CHILD],rax
wait_child:
    mov rdi,[rbp+CHILD]
    lea rsi,[rbp+STATUS]
    xor edx,edx
    xor r10d,r10d
    mov eax,61
    syscall
    cmp rax,-4
    je wait_child
    cmp rax,[rbp+CHILD]
    jne refuse
    cmp DWORD PTR [rbp+STATUS],0
    jne refuse
    mov edi,[rbp+OFD]
    lea rsi,[rbp+STAT]
    mov eax,5
    syscall
    test rax,rax
    jne refuse
    mov rax,[rbp+STAT+48]
    ret
child:
    mov edi,1
    mov esi,9
    xor edx,edx
    xor r10d,r10d
    xor r8d,r8d
    mov eax,157
    syscall
    test rax,rax
    jne refuse
    mov eax,110
    syscall
    cmp rax,r13
    jne refuse
    mov edi,[rbp+IFD]
    xor esi,esi
    mov eax,33
    syscall
    test rax,rax
    jne refuse
    mov edi,[rbp+OFD]
    mov esi,1
    mov eax,33
    syscall
    cmp rax,1
    jne refuse
    mov edi,3
hide_inputs:
    mov esi,2                   /* F_SETFD, FD_CLOEXEC */
    mov edx,1
    mov eax,72
    syscall
    test rax,rax
    js refuse
    inc edi
    cmp edi,7
    jne hide_inputs
    /* Empty environment carries no role selectors or executable path. */
    lea rax,[rip+label]
    mov [rbp+FRAME],rax
    mov QWORD PTR [rbp+FRAME+8],0
    mov rdi,r12
    lea rsi,[rip+empty]
    lea rdx,[rbp+FRAME]
    lea r10,[rbp+FRAME+8]
    mov r8d,4096
    mov eax,322
    syscall
refuse:
    mov edi,2
exit:
    mov eax,60
    syscall
label: .asciz "hia-evaluate-reference"
empty: .byte 0
