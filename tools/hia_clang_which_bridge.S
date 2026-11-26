/* Mechanical views, actual libc environ reads and Linux syscalls.
 * All PATH search, access decisions and mapping retirement execute in HIA. */
.intel_syntax noprefix
.text
.global hia_clang_which
.global clang_which_owner_hole,clang_which_copy_hole
.extern dlsym
.global hia_clang_which_bridge_end
.type hia_clang_which,@function
hia_clang_which:
 push rbp
 push rbx
 push r12
 push r13
 push r14
 push r15
 sub rsp,104
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
 cmp r13,32
 jb .Lbad
 cmp r15,128
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
 jae .Lso_ok
 cmp r14,[rsp+80]
 jb .Lbad
.Lso_ok:
 cmp r12,[rsp+72]
 jae .Lsw_ok
 cmp rbx,[rsp+80]
 jb .Lbad
.Lsw_ok:
 cmp r14,[rsp+72]
 jae .Low_ok
 cmp rbx,[rsp+64]
 jb .Lbad
.Low_ok:
 mov rax,0x3130485743414948
 cmp [r12],rax
 jne .Lbad
 cmp QWORD PTR [r12+8],1
 je .Lretire
 cmp QWORD PTR [r12+8],0
 ja .Lbad
 cmp QWORD PTR [rbx+48],0
 jne .Lbad
 mov rdi,rbx
 mov ecx,4096
 xor eax,eax
 cld
 rep stosb
 mov [rbx+64],rbx
 mov [rbx+56],rbp
 jmp .Lowner
.Lretire:
 cmp r13,32
 jne .Lbad
 mov ecx,16
.Lreserved:
 cmp QWORD PTR [r12+rcx],0
 jne .Lbad
 add ecx,8
 cmp ecx,32
 jb .Lreserved
 mov rax,0x3130575743414948
 cmp [rbx+48],rax
 jne .Lbad
 cmp [rbx+32],rbx
 jne .Lbad
 cmp [rbx+56],rbp
 jne .Lbad
 mov eax,39
 syscall
 cmp rax,[rbx+40]
 jne .Lbad
 mov QWORD PTR [rbx],900
 mov QWORD PTR [rbx+16],0
 mov QWORD PTR [rbx+24],0
 mov QWORD PTR [rbx+288],1
 mov QWORD PTR [rbx+304],0
 mov QWORD PTR [rbx+312],0
.Lowner:
 mov rdi,r12
 mov rsi,r13
 mov rdx,r14
 mov rcx,r15
 mov r8,rbx
 mov r9,rbp
 .byte 0xe8
clang_which_owner_hole: .long 0
.Ldispatch:
 test eax,eax
 jz .Lreturn
 cmp eax,10
 je .Lowner
 cmp eax,1
 je .Lsyscall
 cmp eax,5
 je .Lenviron
 cmp eax,6
 je .Lpeek
 cmp eax,14
 je .Lborrow
 cmp eax,15
 je .Lappend
 jmp .Lbad
.Lborrow:
 mov rdi,[rbx+320]
 mov rsi,[rbx+328]
 mov rdx,[rbx+336]
 mov rcx,[rbx+344]
 test rdi,rdi
 jz .Lbad
 test rdx,rdx
 jz .Lbad
 mov rax,rdi
 add rax,rsi
 jc .Lbad
 mov rax,rdx
 add rax,rcx
 jc .Lbad
 jmp .Lcall_borrow
.Lappend:
 mov rdi,r12
 mov rsi,r13
 mov rdx,[rbx+216]
 mov rcx,[rbx+224]
 test rdx,rdx
 jz .Lbad
.Lcall_borrow:
 mov r8,rbx
 mov r9,rbp
 .byte 0xe8
clang_which_copy_hole: .long 0
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
 add rsp,104
 pop r15
 pop r14
 pop r13
 pop r12
 pop rbx
 pop rbp
 ret
.Lenviron_name: .asciz "environ"
hia_clang_which_bridge_end:
.size hia_clang_which,.-hia_clang_which
.section .note.GNU-stack,"",@progbits
