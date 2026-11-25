# Fixed native identity-ledger facts; all ownership and arithmetic are HIA.
.intel_syntax noprefix
.text
.global hia_mv_runtime_identity
.type hia_mv_runtime_identity,@function
hia_mv_runtime_identity:
 push rbx
 push rbp
 push r12
 push r13
 push r14
 push r15
 sub rsp,136
 mov r12,rdi
 mov r15,rsi
 mov r13,rdx
 mov rbp,rcx
 mov r14,r8
 mov rbx,r9
 cmp rbp,4096
 jb .Lbad
 cmp rbx,32768
 jb .Lbad
 mov qword ptr [r13+128],0
 mov qword ptr [rsp],0
 mov [rsp+8],r14
 mov [rsp+16],r12
 mov [rsp+24],r13
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
 je .Lreturn
 cmp eax,10
 je .Lloop
 cmp eax,1
 je .Lsyscall
 cmp eax,2
 je .Lcas
 cmp eax,3
 je .Lexchange
 cmp eax,8
 je .Lcopy
 cmp eax,11
 je .Lnumbers
 cmp eax,12
 je .Lvalues
.Lbad:
 mov eax,0xfffffffd
 jmp .Lreturn
.Lsyscall:
 mov r10,[r13+8]
 xor ecx,ecx
.Ltranslate:
 mov rax,[r13+16+rcx*8]
 mov r11,r10
 and r11d,3
 add rax,[rsp+r11*8]
 mov [rsp+32+rcx*8],rax
 shr r10,2
 inc ecx
 cmp ecx,6
 jb .Ltranslate
 mov rdi,[rsp+32]
 mov rsi,[rsp+40]
 mov rdx,[rsp+48]
 mov r10,[rsp+56]
 mov r8,[rsp+64]
 mov r9,[rsp+72]
 mov rax,[r13]
 syscall
 jmp .Lfeedback
.Lcas:
 cmp qword ptr [r13],30024
 jne .Lbad
 lea rdx,[r14+30024]
 mov eax,[r13+8]
 mov ecx,[r13+16]
 lock cmpxchg dword ptr [rdx],ecx
 jmp .Lfeedback
.Lexchange:
 cmp qword ptr [r13],30024
 jne .Lbad
 lea rdx,[r14+30024]
 mov eax,[r13+8]
 xchg dword ptr [rdx],eax
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
.Lviews:
 mov rdi,[r13]
 add rdi,r13
 mov rsi,[r13+8]
 mov rdx,[r13+16]
 add rdx,r13
 mov rcx,[r13+24]
 mov r8,[r13+32]
 add r8,r14
 mov r9,[r13+40]
 ret
.Lnumbers:
 call .Lviews
 .byte 0xe8
numbers_hole:
 .long 0
 jmp .Lfeedback
.Lvalues:
 call .Lviews
 .byte 0xe8
values_hole:
 .long 0
.Lfeedback:
 mov [r13+136],rax
 jmp .Lloop
.Lreturn:
 add rsp,136
 pop r15
 pop r14
 pop r13
 pop r12
 pop rbp
 pop rbx
 ret
.size hia_mv_runtime_identity,.-hia_mv_runtime_identity
.section .note.GNU-stack,"",@progbits
