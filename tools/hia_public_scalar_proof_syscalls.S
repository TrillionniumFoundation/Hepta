/* Mechanical public-proof transport. HIA owns normalization, custody,
 * deadlines, verification and receipt authority. Fixed six-word roles,
 * requested syscalls and bounded immutable-image byte snapshots only. */
.intel_syntax noprefix
.text
.global _start, public_policy_hole, embedded_roles
.set input_max,17039552
.set input_cap,18874368
.set output_cap,67108864
.set work_offset,85983232
.set work_cap,637534208
.set mapping_cap,723517440
_start:
.image_anchor:
    cmp qword ptr [rsp],1
    jne .usage
    sub rsp,160
    xor edi,edi
    mov esi,mapping_cap
    mov edx,3
    mov r10d,0x22
    mov r8,-1
    xor r9d,r9d
    mov eax,9
    syscall
    cmp rax,-4095
    jae .io
    mov r12,rax
    xor r13d,r13d
    lea r14,[r12+work_offset]
    lea rbx,[rip+.image_anchor-176]
    xor r15d,r15d
.read:
    xor eax,eax
    xor edi,edi
    lea rsi,[r12+r13]
    mov edx,input_max+1
    sub rdx,r13
    syscall
    cmp rax,-4
    je .read
    test rax,rax
    js .io
    jz .freeze
    add r13,rax
    cmp r13,input_max
    ja .space
    jmp .read
.freeze:
    mov rdi,r12
    mov esi,input_cap
    mov edx,1
    mov eax,10
    syscall
    test rax,rax
    jnz .io
    mov [r14+72],r14
    mov [r14+80],rbx
    mov rax,[rbx+96]
    cmp rax,16777216
    ja .invalid
    cmp rax,176
    jb .invalid
    mov [r14+88],rax
    lea r11,[rip+.role_table]
    lea rax,[r11+80]
    mov rcx,[rax]
    add rcx,r11
    sub rcx,rbx
    mov [r14+96],rcx
    mov rcx,[rax+8]
    mov [r14+104],rcx
    mov rcx,[rax+16]
    add rcx,r11
    sub rcx,rbx
    mov [r14+112],rcx
    mov rcx,[rax+24]
    mov [r14+120],rcx
    mov qword ptr [rsp],0
    mov [rsp+8],r14
    mov [rsp+16],r12
    mov [rsp+24],rbx
.plan:
    mov rdi,r12
    mov rsi,r13
    lea rdx,[r12+input_cap]
    mov ecx,output_cap
    mov r8,r14
    mov r9d,work_cap
    .byte 0xe8
public_policy_hole:
    .long 0
    test eax,eax
    je .answer
    cmp eax,3
    je .plan
    cmp eax,1
    je .syscall
    cmp eax,4
    je .image_copy
    cmp eax,2
    jne .invalid
    mov rax,[r14+128]
    cmp rax,1
    jb .invalid
    cmp rax,4
    ja .invalid
    shl rax,4
    lea r11,[rip+.role_table]
    add rax,r11
    mov rbp,[rax]
    add rbp,r11
    mov rax,[rax+8]
    test rax,rax
    jz .invalid
    cmp rax,1048576
    ja .invalid
    mov rax,[r14+16]
    cmp rax,0
    je .input_source
    cmp rax,1
    je .work_source
    cmp rax,2
    jne .invalid
    mov rdi,rbx
    mov rdx,[r14+88]
    jmp .source_range
.input_source:
    mov rdi,r12
    mov rdx,r13
    jmp .source_range
.work_source:
    mov rdi,r14
    mov edx,work_cap
.source_range:
    mov rax,[r14+24]
    cmp rax,rdx
    ja .invalid
    sub rdx,rax
    mov rsi,[r14+32]
    cmp rsi,rdx
    ja .invalid
    add rdi,rax
    mov rdx,[r14+40]
    cmp rdx,1024
    jb .invalid
    mov rcx,[r14+48]
    mov rax,work_cap
    sub rax,rdx
    jc .invalid
    cmp rcx,rax
    ja .invalid
    add rdx,r14
    mov r8,[r14+56]
    cmp r8,1024
    jb .invalid
    mov r9,[r14+64]
    mov rax,work_cap
    sub rax,r8
    jc .invalid
    cmp r9,rax
    ja .invalid
    add r8,r14
    call rbp
    mov eax,eax
    jmp .feedback
.image_copy:
    mov rsi,[r14+24]
    mov rcx,[r14+32]
    cmp rcx,65536
    ja .invalid
    mov rax,[r14+88]
    sub rax,rsi
    jc .invalid
    cmp rcx,rax
    ja .invalid
    add rsi,rbx
    mov rdi,[r14+40]
    cmp rdi,1024
    jb .invalid
    mov rax,work_cap
    sub rax,rdi
    jc .invalid
    cmp rcx,rax
    ja .invalid
    add rdi,r14
    cld
    rep movsb
    xor eax,eax
    jmp .feedback
.syscall:
    lea rbp,[r12+input_cap]
    mov r10,[rbp+8]
    xor ecx,ecx
.translate:
    mov rax,[rbp+16+rcx*8]
    mov r11,r10
    and r11d,3
    add rax,[rsp+r11*8]
    mov [rsp+32+rcx*8],rax
    shr r10,2
    inc ecx
    cmp ecx,6
    jb .translate
    mov rdi,[rsp+32]
    mov rsi,[rsp+40]
    mov rdx,[rsp+48]
    mov r10,[rsp+56]
    mov r8,[rsp+64]
    mov r9,[rsp+72]
    mov rax,[rbp]
    syscall
.feedback:
    mov [r14+8],rax
    jmp .plan
.answer:
    mov rdx,[r14+704]
    cmp rdx,64
    jb .invalid
    cmp rdx,output_cap
    ja .invalid
    lea rsi,[r12+input_cap]
.write:
    test rdx,rdx
    jz .done
    mov eax,1
    mov edi,1
    syscall
    cmp rax,-4
    je .write
    test rax,rax
    jle .io
    add rsi,rax
    sub rdx,rax
    jmp .write
.done:
    xor edi,edi
    jmp .exit
.invalid:
    mov edi,65
    jmp .exit
.space:
    mov edi,3
    jmp .exit
.io:
    mov edi,74
    jmp .exit
.usage:
    mov edi,64
.exit:
    mov eax,60
    syscall
    ud2
.balign 8
embedded_roles:
.role_table:
    .zero 112
.section .note.GNU-stack,"",@progbits
