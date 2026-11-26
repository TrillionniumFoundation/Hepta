# Fixed transport only. Callback semantics and ownership are HIA.
.intel_syntax noprefix
.text
.global hia_future_callable_adapter
.type hia_future_callable_adapter,@function
hia_future_callable_adapter:
.Lstart:
 push rbx
 push rbp
 push r12
 push r13
 push r14
 push r15
 sub rsp,65608
 cmp rcx,288
 jb .Lshort
 cmp rsi,192
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
 mov ebp,65536
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
 cmp eax,12
 je .Lvalues
 cmp eax,15
 je .Lfacts
 jmp .Lreturn
.Lsyscall:
 cmp qword ptr [r13],39
 jne .Lbad
 mov eax,39
 syscall
 jmp .Lfeedback
.Lvalues:
 lea rdi,[r13+512]
 mov esi,128
 lea rdx,[r13+16384]
 mov ecx,32768
 mov r8,[r14+112]
 mov r9d,256
 .byte 0xe8
values_call_hole:
 .long 0
 jmp .Lfeedback
.Lfacts:
 mov [r13+176],r14
 .byte 0x48,0x8d,0x05
values_fact_hole:
 .long 0
 mov [r13+184],rax
 xor eax,eax
.Lfeedback:
 mov [r13+136],rax
 jmp .Lloop
.Lcomplete:
 mov rdi,[rsp+32]
 mov rsi,r13
 mov ecx,36
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
 add rsp,65608
 pop r15
 pop r14
 pop r13
 pop r12
 pop rbp
 pop rbx
 ret
.size hia_future_callable_adapter,.-hia_future_callable_adapter
.section .note.GNU-stack,"",@progbits
