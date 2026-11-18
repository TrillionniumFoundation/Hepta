/* Linux x86-64 stdin/stdout and growable scratch transport for HIA.
 * The compiler-built HIA image owns packet semantics, execution and replies. */
.intel_syntax noprefix
.text
.global _start, reference_call_hole
.equ MAX_INPUT, 33554432
.equ OUTPUT, MAX_INPUT+4096
.equ MAX_OUTPUT, 4194336
.equ FRAME_STRIDE, (524288+1)*8
.equ INITIAL_WORK, 64+FRAME_STRIDE
.equ MAX_WORK, 64+256*FRAME_STRIDE
.equ PROGRAM, 0x3130475053414948
.equ RESULT, 0x3130525053414948

_start:
    cmp QWORD PTR [rsp],1
    jne usage
    mov esi,OUTPUT+MAX_OUTPUT
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
    jz input_complete
    add r13,rax
    cmp r13,MAX_INPUT
    ja space
    jmp read_input
input_complete:
    cmp r13,72
    jb invalid
    mov rax,PROGRAM
    cmp [r12],rax
    jne invalid
    mov ebp,INITIAL_WORK
    mov esi,ebp
    call map_bytes
    mov r14,rax
    xor ebx,ebx
invoke:
    mov rdi,r12
    mov rsi,r13
    lea rdx,[r12+OUTPUT]
    mov ecx,MAX_OUTPUT
    mov r8,r14
    mov r9,rbp
    .byte 0xe8
reference_call_hole: .long 0
    cmp eax,-2
    je space
    cmp eax,32
    jb invalid
    cmp eax,MAX_OUTPUT
    ja invalid
    lea r15,[r12+OUTPUT]
    movabs rdx,RESULT
    cmp [r15],rdx
    jne invalid
    mov rdx,[r15+16]
    cmp rdx,rbx
    jb invalid
    cmp QWORD PTR [r15+8],14
    je grow_workspace
    cmp QWORD PTR [r15+8],11
    ja invalid
    mov ebp,eax
write_output:
    test rbp,rbp
    jz success
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
    jmp write_output
grow_workspace:
    cmp eax,32
    jne invalid
    cmp rdx,rbx
    jbe invalid
    mov rbx,rdx
    mov rdx,[r15+24]
    cmp rdx,rbp
    jbe invalid
    cmp rdx,MAX_WORK
    ja space
    lea rax,[rbp+rbp]
    cmp rax,MAX_WORK
    jbe growth_bounded
    mov eax,MAX_WORK
growth_bounded:
    cmp rdx,rax
    cmovb rdx,rax
    mov r15,rdx
    mov rdi,r14
    mov rsi,rbp
    mov r10d,1
    mov eax,25
    syscall
    cmp rax,-12
    je memory_limit
    cmp rax,-4095
    jae io
    mov r14,rax
    mov rbp,r15
    jmp invoke
memory_limit:
    lea r15,[r12+OUTPUT]
    mov QWORD PTR [r15+8],12
    mov QWORD PTR [r15+24],0
    mov ebp,32
    jmp write_output
map_bytes:
    xor edi,edi
    mov edx,3
    mov r10d,0x22
    mov r8,-1
    xor r9d,r9d
    mov eax,9
    syscall
    cmp rax,-4095
    jae io
    ret
success:
    xor edi,edi
    jmp finish
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
