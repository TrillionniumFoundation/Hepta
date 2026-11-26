/* Mechanical Linux ABI for fixed native HIA compiler capture.
 * HIA chooses process creation, arguments, file quotas, deadlines, ownership
 * observation, the single group signal, reaping, UTF-8 policy and retirement.
 * The sole platform lookup captures libc's actual inherited environ.
 */
.intel_syntax noprefix
.text
.global hia_clang_capture
.global clang_capture_owner_hole, clang_capture_admit_hole
.global clang_capture_child_hole, clang_capture_streams_hole
.global clang_capture_storage_hole, hia_clang_capture_bridge_end
.extern dlsym
.type hia_clang_capture,@function
hia_clang_capture:
    push rbp
    push rbx
    push r12
    push r13
    push r14
    push r15
    sub rsp,200
    mov r12,rdi
    mov r13,rsi
    mov r14,rdx
    mov r15,rcx
    mov rbx,r8
    mov rbp,r9
    test r12,r12
    jz .Lbad
    test r14,r14
    jz .Lbad
    test rbx,rbx
    jz .Lbad
    test rbx,7
    jnz .Lbad
    cmp r13,128
    jb .Lbad
    cmp r15,256
    jb .Lbad
    cmp rbp,4096
    jb .Lbad
    mov rax,r12
    add rax,r13
    jc .Lbad
    mov [rsp+80],rax
    mov rax,r14
    add rax,r15
    jc .Lbad
    mov [rsp+64],rax
    mov rax,rbx
    add rax,rbp
    jc .Lbad
    mov [rsp+72],rax
    cmp r12,[rsp+64]
    jae .Lsource_output_ok
    cmp r14,[rsp+80]
    jb .Lbad
.Lsource_output_ok:
    cmp r12,[rsp+72]
    jae .Lsource_work_ok
    cmp rbx,[rsp+80]
    jb .Lbad
.Lsource_work_ok:
    cmp r14,[rsp+72]
    jae .Loutput_work_ok
    cmp rbx,[rsp+64]
    jb .Lbad
.Loutput_work_ok:
    mov rax,3544421147972028744
    cmp [r12],rax
    jne .Lbad
    mov rax,[r12+8]
    test rax,rax
    jz .Linitialize
    cmp rax,1
    jne .Lbad
    cmp r13,128
    jne .Lbad
    mov rax,3544428844553423176
    cmp [rbx+616],rax
    jne .Lbad
    cmp [rbx+352],rbx
    jne .Lbad
    cmp [rbx+384],rbp
    jne .Lbad
    mov ecx,16
.Lrelease_header:
    cmp QWORD PTR [r12+rcx],0
    jne .Lbad
    add ecx,8
    cmp ecx,128
    jb .Lrelease_header
    mov eax,39
    syscall
    cmp rax,[rbx+688]
    jne .Lbad
    mov QWORD PTR [rbx],700
    jmp .Lcapture_views
.Linitialize:
    cmp QWORD PTR [rbx+616],0
    jne .Lbad
    mov rdi,rbx
    mov ecx,4096
    xor eax,eax
    cld
    rep stosb
.Lcapture_views:
    mov [rbx+360],r12
    mov [rbx+368],r14
    mov [rbx+376],rbx
    mov [rbx+384],rbp
.Lowner:
    mov rdi,r12
    mov rsi,r13
    mov rdx,r14
    mov rcx,r15
    mov r8,rbx
    mov r9,rbp
    .byte 0xe8
clang_capture_owner_hole: .long 0
.Ldispatch:
    test eax,eax
    jz .Lreturn
    cmp eax,1
    je .Lsyscall
    cmp eax,5
    je .Lenviron
    cmp eax,6
    je .Lpeek
    cmp eax,10
    je .Lowner
    cmp eax,11
    je .Ladmit
    cmp eax,12
    je .Lchild
    cmp eax,13
    je .Lstreams
    cmp eax,14
    je .Lpath_copy
    cmp eax,15
    je .Lpath_make
    cmp eax,16
    je .Lstorage
    jmp .Lbad
.Ladmit:
    mov rdi,r12
    mov rsi,r13
    mov rdx,r14
    mov rcx,r15
    mov r8,rbx
    mov r9,rbp
    .byte 0xe8
clang_capture_admit_hole: .long 0
    jmp .Ldispatch
.Lchild:
    mov rdi,r12
    mov rsi,r13
    mov rdx,r14
    mov rcx,r15
    jmp .Lchild_call
.Lpath_copy:
    mov rdi,[rbx+288]
    mov rsi,[rbx+296]
    mov rdx,[rbx+312]
    mov rcx,[rbx+320]
    test rdi,rdi
    jz .Lbad
    test rdx,rdx
    jz .Lbad
    cmp rsi,rcx
    jae .Lbad
    jmp .Lchild_call
.Lpath_make:
    mov rdi,r12
    mov rsi,r13
    mov rdx,[rbx+312]
    mov rcx,[rbx+320]
    test rdx,rdx
    jz .Lbad
.Lchild_call:
    mov r8,rbx
    mov r9,rbp
    .byte 0xe8
clang_capture_child_hole: .long 0
    jmp .Ldispatch
.Lstreams:
    mov rax,[rbx+496]
    cmp rax,1
    ja .Lbad
    lea rax,[rax+rax*2]
    shl rax,3
    mov rdi,[rbx+400+rax]
    mov rsi,[rbx+408+rax]
    mov rdx,[rbx+448+rax]
    mov rcx,[rbx+464+rax]
    test rdi,rdi
    jz .Lbad
    test rdx,rdx
    jz .Lbad
    mov r8,rbx
    mov r9,rbp
    .byte 0xe8
clang_capture_streams_hole: .long 0
    jmp .Ldispatch
.Lstorage:
    mov rdi,r12
    mov rsi,r13
    mov rdx,r14
    mov rcx,r15
    mov r8,rbx
    mov r9,rbp
    .byte 0xe8
clang_capture_storage_hole: .long 0
    jmp .Ldispatch
.Lsyscall:
    xor ecx,ecx
    mov r10,[r14+56]
.Largument:
    mov rax,[r14+8+rcx*8]
    mov rdx,r10
    and edx,3
    shr r10,2
    test edx,edx
    jz .Largument_ready
    cmp edx,1
    jne .Largument_output
    cmp rax,r13
    jae .Lbad
    add rax,r12
    jmp .Largument_ready
.Largument_output:
    cmp edx,2
    jne .Largument_work
    cmp rax,r15
    jae .Lbad
    add rax,r14
    jmp .Largument_ready
.Largument_work:
    cmp rax,rbp
    jae .Lbad
    add rax,rbx
.Largument_ready:
    mov [rsp+rcx*8],rax
    inc ecx
    cmp ecx,6
    jb .Largument
    test r10,r10
    jnz .Lbad
    mov rax,[r14]
    mov rdi,[rsp]
    mov rsi,[rsp+8]
    mov rdx,[rsp+16]
    mov r10,[rsp+24]
    mov r8,[rsp+32]
    mov r9,[rsp+40]
    syscall
    mov [rbx+8],rax
    jmp .Lowner
.Lenviron:
    xor edi,edi
    lea rsi,[rip+.Lenviron_name]
    call dlsym
    test rax,rax
    jz .Lbad
    mov rax,[rax]
    mov [rbx+8],rax
    jmp .Lowner
.Lpeek:
    mov rax,[r14]
    test rax,rax
    jz .Lbad
    cmp QWORD PTR [r14+8],1
    je .Lpeek_byte
    cmp QWORD PTR [r14+8],8
    jne .Lbad
    mov rax,[rax]
    jmp .Lpeek_done
.Lpeek_byte:
    movzx eax,BYTE PTR [rax]
.Lpeek_done:
    mov [rbx+8],rax
    jmp .Lowner
.Lbad:
    mov eax,0xfffffffd
.Lreturn:
    add rsp,200
    pop r15
    pop r14
    pop r13
    pop r12
    pop rbx
    pop rbp
    ret
.Lenviron_name: .asciz "environ"
hia_clang_capture_bridge_end:
.size hia_clang_capture,.-hia_clang_capture
.section .note.GNU-stack,"",@progbits
