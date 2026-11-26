# Fixed ABI transport only. Policy and retirement decisions are HIA.
.intel_syntax noprefix
.text
.global hia_future_resource_finalizer_adapter
.type hia_future_resource_finalizer_adapter,@function
hia_future_resource_finalizer_adapter:
.Lstart:
 push rbx
 push rbp
 push r12
 push r13
 push r14
 push r15
 sub rsp,4168
 cmp rcx,128
 jb .Lshort
 cmp rsi,128
 jne .Lbad
 cmp r9,256
 jne .Lbad
 test rdi,rdi
 jz .Lbad
 test rdx,rdx
 jz .Lbad
 test r8,r8
 jz .Lbad
 test r8,7
 jnz .Lbad
 mov rax,rdi
 add rax,rsi
 jc .Lbad
 mov r10,rdx
 add r10,rcx
 jc .Lbad
 mov r11,r8
 add r11,r9
 jc .Lbad
 cmp rax,rdx
 jbe .Lso
 cmp r10,rdi
 ja .Lbad
.Lso:
 cmp rax,r8
 jbe .Lsc
 cmp r11,rdi
 ja .Lbad
.Lsc:
 cmp r10,r8
 jbe .Loc
 cmp r11,rdx
 ja .Lbad
.Loc:
 mov r12,rdi
 mov r15,rsi
 mov [rsp+32],rdx
 mov [rsp+40],rcx
 mov r14,r8
 mov rbx,r9
 lea r13,[rsp+64]
 mov ebp,4096
 mov qword ptr [rsp],0
 mov [rsp+8],r14
 mov [rsp+16],r12
 mov [rsp+24],r13
 mov qword ptr [r13+128],0
.Lloop:
 mov rdi,r12
 mov rsi,r15
 mov rdx,r13
 mov rcx,rbp
 mov r8,r14
 mov r9,rbx
 .byte 0xe8
policy_hole:
 .long 0
 test eax,eax
 je .Lcomplete
 cmp eax,10
 je .Lloop
 cmp eax,1
 je .Lsyscall
 cmp eax,8
 je .Lcopy
 cmp eax,12
 je .Lprovider
 cmp eax,15
 je .Lfacts
 jmp .Lreturn
.Lsyscall:
 cmp qword ptr [r13],39
 jne .Lbad
 mov eax,39
 syscall
 jmp .Lfeedback
.Lcopy:
 mov rax,[r13]
 cmp rax,3
 ja .Lbad
 mov rsi,[r13+8]
 add rsi,[rsp+rax*8]
 mov rax,[r13+16]
 cmp rax,3
 ja .Lbad
 mov rdi,[r13+24]
 add rdi,[rsp+rax*8]
 mov rcx,[r13+32]
 cld
 rep movsb
 xor eax,eax
 jmp .Lfeedback
.Lprovider:
 lea rdi,[r13+512]
 mov esi,128
 lea rdx,[r13+768]
 mov ecx,128
 mov r8,[r14+40]
 mov r9d,512
 .byte 0xe8
provider_hole:
 .long 0
 jmp .Lfeedback
.Lfacts:
 mov [r13+152],r14
 lea rax,[rip+.Lstart]
 mov [r13+160],rax
 lea rax,[rip+provider_hole+4]
 movsxd rdx,dword ptr [rip+provider_hole]
 add rax,rdx
 mov [r13+168],rax
 .byte 0x48,0x8d,0x05
values_hole:
 .long 0
 mov [r13+176],rax
 xor eax,eax
.Lfeedback:
 mov [r13+136],rax
 jmp .Lloop
.Lcomplete:
 mov rdi,[rsp+32]
 mov rsi,r13
 mov ecx,16
 cld
 rep movsq
 xor eax,eax
 jmp .Lreturn
.Lshort:
 mov eax,0xfffffffe
 jmp .Lreturn
.Lbad:
 mov eax,0xfffffffd
.Lreturn:
 add rsp,4168
 pop r15
 pop r14
 pop r13
 pop r12
 pop rbp
 pop rbx
 ret
.size hia_future_resource_finalizer_adapter,.-hia_future_resource_finalizer_adapter
.section .note.GNU-stack,"",@progbits
