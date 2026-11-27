# Fixed installed-frontend entry stubs and pure syscall/copy/call mechanics.
.intel_syntax noprefix
.text
.global hia_generation_runtime_frontend_proxy_bind
.global hia_generation_runtime_frontend_proxy_options
.global hia_generation_runtime_frontend_proxy_verify
.global hia_generation_runtime_frontend_proxy_directory
.global hia_generation_runtime_frontend_proxy_policy
.global hia_generation_runtime_factory_proxy
hia_generation_runtime_frontend_proxy_bind:
 mov eax,0
 jmp .Lentry
 .balign 16
hia_generation_runtime_frontend_proxy_options:
 mov eax,1
 jmp .Lentry
 .balign 16
hia_generation_runtime_frontend_proxy_verify:
 mov eax,2
 jmp .Lentry
 .balign 16
hia_generation_runtime_frontend_proxy_directory:
 mov eax,3
 jmp .Lentry
 .balign 16
hia_generation_runtime_frontend_proxy_policy:
 mov eax,4
 jmp .Lentry
 .balign 16
hia_generation_runtime_factory_proxy:
 mov eax,5
 jmp .Lentry
 .balign 16
.Lentry:
 push rbx
 push rbp
 push r12
 push r13
 push r14
 push r15
 sub rsp,8408
 mov [rsp+88],rax
 mov [rsp+96],r11
 mov r12,rdi
 mov r15,rsi
 mov r13,rdx
 mov rbp,rcx
 mov r14,r8
 mov rbx,r9
 test r12,r12
 jz .Lbad
 test r13,r13
 jz .Lbad
 test r14,r14
 jz .Lbad
 mov rax,r12
 add rax,r15
 jc .Lbad
 mov rax,r13
 add rax,rbp
 jc .Lbad
 mov rax,r14
 add rax,rbx
 jc .Lbad
 mov rax,[rsp+88]
 test eax,eax
 jz .Lroot
 cmp eax,1
 je .Loptions
 cmp eax,2
 je .Lverify
 cmp eax,5
 je .Lfactory
 mov rdx,[rsp+96]
 cmp rdx,512
 jb .Lbad
 sub rdx,512
 xor ecx,ecx
 jmp .Lfacts
.Loptions:
 cmp rbx,8192
 jne .Lbad
 cmp r14,4096
 jb .Lbad
 lea rcx,[r14-4096]
 mov rdx,[rcx+24]
 jmp .Lfacts
.Lverify:
 cmp rbx,8192
 jne .Lbad
 cmp r14,16384
 jb .Lbad
 lea rcx,[r14-16384]
 mov rdx,[rcx+24]
 jmp .Lfacts
.Lfactory:
 cmp rbx,1048576
 jne .Lbad
 mov rcx,r14
 mov rdx,[rcx+24]
 jmp .Lfacts
.Lroot:
 cmp rbx,2048
 jne .Lbad
 mov rdx,r14
 mov rcx,r13
.Lfacts:
 test rdx,rdx
 jz .Lbad
 test rdx,7
 jnz .Lbad
 mov [rsp+80],rdx
 mov [rsp+104],rcx
 lea rdi,[rsp+192]
 xor eax,eax
 mov ecx,1024
 cld
 rep stosq
 lea r10,[rsp+192]
 mov rax,[rsp+88]
 mov [r10+512],rax
 mov [r10+520],r12
 mov [r10+528],r15
 mov [r10+536],r13
 mov [r10+544],rbp
 mov [r10+552],r14
 mov [r10+560],rbx
 mov rax,[rsp+80]
 mov [r10+568],rax
 mov rax,[rsp+104]
 mov [r10+576],rax
 .byte 0x48,0x8d,0x05
root_address_hole:
 .long 0
 mov [r10+584],rax
 .byte 0x48,0x8d,0x05
value_address_hole:
 .long 0
 mov [r10+592],rax
 .byte 0x48,0x8d,0x05
install_address_hole:
 .long 0
 mov [r10+600],rax
 .byte 0x48,0x8d,0x05
factory_address_hole:
 .long 0
 mov [r10+688],rax
 mov qword ptr [rsp],0
 mov rax,[rsp+80]
 mov [rsp+8],rax
 mov [rsp+16],r12
 mov [rsp+24],r10
.Lloop:
 mov rdi,r12
 mov rsi,r15
 lea rdx,[rsp+192]
 mov ecx,8192
 mov r8,[rsp+80]
 mov r9d,2048
 .byte 0xe8
policy_hole:
 .long 0
 test eax,eax
 je .Ldone
 cmp eax,1
 je .Lsyscall
 cmp eax,2
 je .Latom
 cmp eax,3
 je .Lunlock
 cmp eax,4
 je .Lagain
 cmp eax,7
 je .Lcopy
 cmp eax,10
 je .Lchild
 jmp .Lbad
.Latom:
 mov rdx,[rsp+80]
 xor eax,eax
 mov ecx,1
 lock cmpxchg dword ptr [rdx+64],ecx
 pause
 jmp .Lfeedback
.Lunlock:
 mov rdx,[rsp+80]
 mov qword ptr [rdx+64],0
 xor eax,eax
 jmp .Lfeedback
.Lagain:
 xor eax,eax
 jmp .Lfeedback
.Lcopy:
 lea r10,[rsp+192]
 mov rcx,[r10+32]
 test rcx,rcx
 jz .Lcopy_done
 mov rdx,[r10]
 cmp rdx,3
 ja .Lbad
 mov rsi,[r10+8]
 add rsi,[rsp+rdx*8]
 jc .Lbad
 test rsi,rsi
 jz .Lbad
 mov rax,rsi
 add rax,rcx
 jc .Lbad
 mov rdx,[r10+16]
 cmp rdx,3
 ja .Lbad
 mov rdi,[r10+24]
 add rdi,[rsp+rdx*8]
 jc .Lbad
 test rdi,rdi
 jz .Lbad
 mov rax,rdi
 add rax,rcx
 jc .Lbad
 cld
 rep movsb
.Lcopy_done:
 xor eax,eax
 jmp .Lfeedback
.Lchild:
 mov rdi,r12
 mov rsi,r15
 mov rdx,r13
 mov rcx,rbp
 mov r8,r14
 mov r9,rbx
 mov r11,[rsp+80]
 add r11,512
 call qword ptr [rsp+824]
 mov eax,eax
 jmp .Lfeedback
.Lsyscall:
 lea r11,[rsp+192]
 mov r10,[r11+8]
 xor ecx,ecx
.Ltranslate:
 mov rax,[r11+16+rcx*8]
 mov rdx,r10
 and edx,3
 add rax,[rsp+rdx*8]
 mov [rsp+32+rcx*8],rax
 shr r10,2
 inc ecx
 cmp ecx,6
 jb .Ltranslate
 mov rax,[r11]
 mov rdi,[rsp+32]
 mov rsi,[rsp+40]
 mov rdx,[rsp+48]
 mov r10,[rsp+56]
 mov r8,[rsp+64]
 mov r9,[rsp+72]
 syscall
.Lfeedback:
 mov [rsp+328],rax
 jmp .Lloop
.Ldone:
 mov eax,dword ptr [rsp+816]
 jmp .Lreturn
.Lbad:
 mov eax,0xfffffffd
.Lreturn:
 add rsp,8408
 pop r15
 pop r14
 pop r13
 pop r12
 pop rbp
 pop rbx
 ret
.section .note.GNU-stack,"",@progbits
