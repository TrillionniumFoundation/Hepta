/* Mechanical six-word views, syscalls and fixed file/SHA calls only.
 * Source catalog identity and resource retirement policy execute in HIA. */
.intel_syntax noprefix
.text
.global hia_clang_implementation_identity
.global clang_implementation_identity_owner_hole,clang_implementation_identity_file_hole,clang_implementation_identity_sha_hole
.global hia_clang_implementation_identity_bridge_end
.type hia_clang_implementation_identity,@function
hia_clang_implementation_identity:
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
 cmp rbp,2097152
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
 mov rax,0x3130514449414948
 cmp [r12],rax
 jne .Lbad
 cmp QWORD PTR [r12+8],1
 je .Lretire
 cmp QWORD PTR [r12+8],0
 jne .Lbad
 cmp QWORD PTR [rbx+48],0
 jne .Lbad
 mov rdi,rbx
 mov ecx,65536
 xor eax,eax
 cld
 rep stosb
 mov [rbx+56],rbx
 mov [rbx+64],rbp
 mov [rbx+72],r12
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
 mov rax,0x3130574449414948
 cmp [rbx+48],rax
 jne .Lbad
 cmp [rbx+32],rbx
 jne .Lbad
 cmp [rbx+64],rbp
 jne .Lbad
 mov eax,39
 syscall
 cmp rax,[rbx+40]
 jne .Lbad
 mov QWORD PTR [rbx],900
 mov QWORD PTR [rbx+16],0
 mov QWORD PTR [rbx+24],0
 mov QWORD PTR [rbx+168],1
 mov QWORD PTR [rbx+192],0
 mov QWORD PTR [rbx+200],0
.Lowner:
 mov rdi,r12
 mov rsi,r13
 mov rdx,r14
 mov rcx,r15
 mov r8,rbx
 mov r9,rbp
 .byte 0xe8
clang_implementation_identity_owner_hole: .long 0
.Ldispatch:
 test eax,eax
 jz .Lreturn
 cmp eax,10
 je .Lowner
 cmp eax,1
 je .Lsyscall
 cmp eax,2
 je .Lfile
 cmp eax,3
 je .Lsha
 jmp .Lreturn
.Lsha:
 lea rdi,[rbx+8191]
 mov rsi,[rbx+160]
 cmp rsi,16385
 ja .Lbad
 lea rdx,[rbx+256]
 mov ecx,32
 lea r8,[rbx+32768]
 mov r9d,4096
 .byte 0xe8
clang_implementation_identity_sha_hole: .long 0
 mov eax,eax
 mov [rbx+8],rax
 jmp .Lowner
.Lfile:
 cmp QWORD PTR [rbx+184],0
 jne .Lfile_retire
 mov rax,[rbx+88]
 cmp rax,r13
 ja .Lbad
 mov rsi,[rbx+96]
 mov rcx,r13
 sub rcx,rax
 cmp rsi,rcx
 ja .Lbad
 lea rdi,[r12+rax]
 jmp .Lfile_call
.Lfile_retire:
 lea rdi,[rbx+512]
 mov esi,192
.Lfile_call:
 lea rdx,[rbx+1024]
 mov ecx,256
 lea r8,[rbx+65536]
 mov r9d,1056768
 .byte 0xe8
clang_implementation_identity_file_hole: .long 0
 mov eax,eax
 mov [rbx+8],rax
 jmp .Lowner
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
hia_clang_implementation_identity_bridge_end:
.size hia_clang_implementation_identity,.-hia_clang_implementation_identity
.section .note.GNU-stack,"",@progbits
