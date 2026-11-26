# GenerationLease lifecycle over the source-bound native MV carrier.
# The source request carries only an operation and opaque registered capability.
# All policy and registry decisions are HIA; this prefix supplies fixed roles.
.intel_syntax noprefix
.text
.global hia_generation_lease_lifecycle
.type hia_generation_lease_lifecycle,@function
hia_generation_lease_lifecycle:
 push rbx
 push rbp
 push r12
 push r13
 push r14
 push r15
 sub rsp,8
 mov r12,rdi
 mov r15,rsi
 mov r13,rdx
 mov rbp,rcx
 mov r14,r8
 mov rbx,r9
 # Reject null, undersized, wrapping and overlapping views before any write.
 test r12,r12
 jz .Llease_bad
 test r13,r13
 jz .Llease_bad
 test r14,r14
 jz .Llease_bad
 cmp r15,64
 jne .Llease_bad
 cmp rbp,100679680
 jb .Llease_bad
 cmp rbx,128
 jb .Llease_bad
 test r14b,7
 jnz .Llease_bad
 mov rax,r12
 add rax,r15
 jc .Llease_bad
 mov rdx,r13
 add rdx,rbp
 jc .Llease_bad
 mov rcx,r14
 add rcx,rbx
 jc .Llease_bad
 cmp rax,r13
 jbe .Llease_so_ok
 cmp rdx,r12
 ja .Llease_bad
.Llease_so_ok:
 cmp rax,r14
 jbe .Llease_sw_ok
 cmp rcx,r12
 ja .Llease_bad
.Llease_sw_ok:
 cmp rdx,r14
 jbe .Llease_ow_ok
 cmp rcx,r13
 ja .Llease_bad
.Llease_ow_ok:
 mov qword ptr [r13+256],0
.Llease_loop:
 mov rdi,r12
 mov rsi,r15
 mov rdx,r13
 mov rcx,rbp
 mov r8,r14
 mov r9,rbx
 .byte 0xe8
lease_policy_hole:
 .long 0
 test eax,eax
 je .Llease_return
 cmp eax,10
 je .Llease_loop
 cmp eax,1
 je .Llease_getpid
 cmp eax,12
 jne .Llease_return
 lea rdi,[r13+4096]
 mov rsi,[r13]
 lea rdx,[r13+16384]
 mov ecx,100663296
 mov r8,[r14+16]
 mov r9,[r14+24]
 call qword ptr [r14+8]
.Llease_feedback:
 mov [r13+384],rax
 jmp .Llease_loop
.Llease_getpid:
 mov eax,39
 syscall
 jmp .Llease_feedback
.Llease_bad:
 mov eax,0xfffffffd
.Llease_return:
 add rsp,8
 pop r15
 pop r14
 pop r13
 pop r12
 pop rbp
 pop rbx
 ret
.size hia_generation_lease_lifecycle,.-hia_generation_lease_lifecycle


.balign 16,0x90
.section .note.GNU-stack,"",@progbits
