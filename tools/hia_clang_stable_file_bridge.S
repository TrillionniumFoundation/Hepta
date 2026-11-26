/* Mechanical six-word view, syscall and fixed SHA dispatch only.
 * All stable file and retirement policy executes in HIA. */
.intel_syntax noprefix
.text
.global hia_clang_stable_file
.global clang_stable_file_owner_hole,clang_stable_file_copy_hole,clang_stable_file_sha_hole
.global hia_clang_stable_file_bridge_end
.type hia_clang_stable_file,@function
hia_clang_stable_file:
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
 cmp r13,192
 jb .Lbad
 cmp r15,256
 jb .Lbad
 cmp rbp,1056768
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
 mov rax,0x31304c4653414948
 cmp [r12],rax
 jne .Lbad
 cmp QWORD PTR [r12+8],3
 je .Lretire
 cmp QWORD PTR [r12+8],2
 ja .Lbad
 cmp QWORD PTR [rbx+48],0
 jne .Lbad
 mov rdi,rbx
 mov ecx,8192
 xor eax,eax
 cld
 rep stosb
 mov [rbx+608],rbx
 mov [rbx+616],rbp
 jmp .Lowner
.Lretire:
 cmp r13,192
 jne .Lbad
 mov ecx,16
.Lreserved:
 cmp QWORD PTR [r12+rcx],0
 jne .Lbad
 add ecx,8
 cmp ecx,192
 jb .Lreserved
 mov rax,0x3130574653414948
 cmp [rbx+48],rax
 jne .Lbad
 cmp [rbx+32],rbx
 jne .Lbad
 cmp [rbx+616],rbp
 jne .Lbad
 mov eax,39
 syscall
 cmp rax,[rbx+40]
 jne .Lbad
 mov QWORD PTR [rbx],900
 mov QWORD PTR [rbx+16],0
 mov QWORD PTR [rbx+24],0
 mov QWORD PTR [rbx+144],0
 mov QWORD PTR [rbx+176],1
 mov QWORD PTR [rbx+208],0
 mov QWORD PTR [rbx+216],0
.Lowner:
 mov rdi,r12
 mov rsi,r13
 mov rdx,r14
 mov rcx,r15
 mov r8,rbx
 mov r9,rbp
 .byte 0xe8
clang_stable_file_owner_hole: .long 0
.Ldispatch:
 test eax,eax
 jz .Lreturn
 cmp eax,10
 je .Lowner
 cmp eax,1
 je .Lsyscall
 cmp eax,2
 je .Lsha
 cmp eax,3
 je .Lcopy
 jmp .Lreturn
.Lsha:
 lea rdi,[rbx+8191]
 mov rsi,[rbx+184]
 cmp rsi,1048577
 ja .Lbad
 lea rdx,[rbx+560]
 mov ecx,32
 lea r8,[rbx+1024]
 mov r9d,4096
 .byte 0xe8
clang_stable_file_sha_hole: .long 0
 mov eax,eax
 mov [rbx+8],rax
 jmp .Lowner
.Lcopy:
 lea rdi,[rbx+8192]
 mov rsi,[rbx+192]
 mov rdx,[rbx+112]
 test rdx,rdx
 jz .Lbad
 mov rcx,[rbx+120]
 mov rax,[rbx+128]
 cmp rax,rcx
 ja .Lbad
 sub rcx,rax
 add rdx,rax
 jc .Lbad
 cmp rsi,rcx
 ja .Lbad
 cmp rsi,1048576
 ja .Lbad
 mov r8,rbx
 mov r9,rbp
 .byte 0xe8
clang_stable_file_copy_hole: .long 0
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
hia_clang_stable_file_bridge_end:
.size hia_clang_stable_file,.-hia_clang_stable_file
.section .note.GNU-stack,"",@progbits
