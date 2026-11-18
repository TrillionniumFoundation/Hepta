/* Linux x86-64 transport for the owned-buffer HIA reference. The native
 * planner admits the packet and determines exact anonymous mapping sizes;
 * the executor owns all program state and resource operations. */
.intel_syntax noprefix
.text
.global _start, owned_plan_call_hole, owned_run_call_hole
.equ MAX_INPUT, 33554432
.equ RESULT_SIZE, 112
.equ PLAN, 128
.equ RESULT, 0x3130525053414948

_start:
    cmp QWORD PTR [rsp],1
    jne usage
    sub rsp,224
    mov esi,MAX_INPUT+1
    call map_bytes
    mov r12,rax
    xor r13d,r13d
read_input:
    xor eax,eax
    xor edi,edi
    lea rsi,[r12+r13]
    mov edx,MAX_INPUT+1
    sub rdx,r13
    syscall
    cmp rax,-4
    je read_input
    test rax,rax
    js io
    jz plan
    add r13,rax
    cmp r13,MAX_INPUT
    ja space
    jmp read_input
plan:
    mov [rsp],r12
    mov [rsp+8],r13
    mov rdi,r12
    mov rsi,r13
    lea rdx,[rsp+PLAN]
    mov ecx,96
    lea r8,[rsp+120]
    xor r9d,r9d
    .byte 0xe8
owned_plan_call_hole: .long 0
    cmp eax,96
    jne invalid
    xor ebx,ebx
    lea r14,[rsp+16]
map_plan:
    mov rsi,[rsp+PLAN+48+rbx*8]
    mov [r14+8],rsi
    xor eax,eax
    test rsi,rsi
    je map_ready
    call map_bytes
map_ready:
    mov [r14],rax
    add r14,16
    inc ebx
    cmp ebx,6
    jne map_plan
invoke:
    mov QWORD PTR [rsp+RESULT_SIZE],0
    mov rdi,rsp
    lea rsi,[rsp+RESULT_SIZE]
    .byte 0xe8
owned_run_call_hole: .long 0
    mov rbp,[rsp+RESULT_SIZE]
    lea eax,[rbp+0x100]
    cmp eax,1
    jb terminal
    cmp eax,5
    jbe grow_state
terminal:
    cmp ebp,-2
    je space
    cmp rbp,144
    jb invalid
    cmp rbp,[rsp+24]
    ja invalid
    mov r15,[rsp+16]
    movabs rdx,RESULT
    cmp [r15],rdx
    jne invalid
write_output:
    mov eax,1
    mov edi,1
    mov rsi,r15
    mov rdx,rbp
    syscall
    cmp rax,-4
    je write_output
    test rax,rax
    jle io
    add r15,rax
    sub rbp,rax
    jne write_output
    xor edi,edi
    jmp finish
grow_state:
    /* This program has no external capability. Discarding all private state
     * and replaying the same immutable request is observationally exact. */
    mov r14d,eax
    mov r15,[rsp+PLAN+r14*8]
    shl r14,4
    lea r14,[rsp+r14+16]
    mov rdi,[r14]
    mov rsi,[r14+8]
    cmp rsi,r15
    jae space
    lea rdx,[rsi+rsi]
    cmp rdx,r15
    cmova rdx,r15
    mov r15,rdx
    mov eax,25
    mov r10d,1
    syscall
    cmp rax,-12
    je space
    cmp rax,-4095
    jae io
    mov [r14],rax
    mov [r14+8],r15
    lea r14,[rsp+16]
    mov ebx,6
discard_state:
    mov rdi,[r14]
    mov rsi,[r14+8]
    test rsi,rsi
    je discard_next
    mov eax,28
    mov edx,4
    syscall
    test rax,rax
    js io
discard_next:
    add r14,16
    dec ebx
    jne discard_state
    jmp invoke
map_bytes:
    xor edi,edi
    mov edx,3
    mov r10d,0x22
    mov r8,-1
    xor r9d,r9d
    mov eax,9
    syscall
    cmp rax,-12
    je space
    cmp rax,-4095
    jae io
    ret
usage:
    mov edi,64
    jmp finish
invalid:
    mov edi,2
    jmp finish
space:
    mov edi,3
    jmp finish
io:
    mov edi,4
finish:
    mov eax,60
    syscall
    ud2
