# Source-bound carrier finalizer; policy owns every ownership decision.
.intel_syntax noprefix
.text
.global hia_generation_lease_owner_finalizer
.type hia_generation_lease_owner_finalizer,@function
hia_generation_lease_owner_finalizer:
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
 test r12,r12
 jz .Lbad
 test r13,r13
 jz .Lbad
 test r14,r14
 jz .Lbad
 cmp r15,128
 jne .Lbad
 cmp rbp,128
 jb .Lbad
 cmp rbx,256
 jne .Lbad
 test r14b,7
 jnz .Lbad
 mov rax,r12
 add rax,r15
 jc .Lbad
 mov rdx,r13
 add rdx,rbp
 jc .Lbad
 mov rcx,r14
 add rcx,rbx
 jc .Lbad
 cmp rax,r13
 jbe .Lsource_output
 cmp rdx,r12
 ja .Lbad
.Lsource_output:
 cmp rax,r14
 jbe .Lsource_context
 cmp rcx,r12
 ja .Lbad
.Lsource_context:
 cmp rdx,r14
 jbe .Loutput_context
 cmp rcx,r13
 ja .Lbad
.Loutput_context:
 mov qword ptr [r13+96],0
.Lpolicy:
 mov rdi,r12
 mov rsi,r15
 mov rdx,r13
 mov rcx,rbp
 mov r8,r14
 mov r9,rbx
 .byte 0xe8
.global owner_finalizer_policy_hole
owner_finalizer_policy_hole:
 .long 0
 test eax,eax
 je .Ldone
 cmp eax,1
 je .Lpid
 cmp eax,2
 je .Llock
 cmp eax,3
 je .Lunlock
 cmp eax,4
 je .Lfacts
 cmp eax,5
 je .Lwait
 cmp eax,6
 je .Lwake
 cmp eax,12
 je .Lcarrier
 jmp .Lbad
.Lpid:
 mov eax,39
 syscall
 jmp .Lfeedback
.Llock:
 xor eax,eax
 mov ecx,1
 lock cmpxchg dword ptr [r14+8],ecx
 jmp .Lfeedback
.Lunlock:
 xor eax,eax
 xchg dword ptr [r14+8],eax
 jmp .Lfeedback
.Lwait:
 lea rdi,[r14+8]
 mov esi,128
 mov edx,1
 xor r10d,r10d
 xor r8d,r8d
 xor r9d,r9d
 mov eax,202
 syscall
 jmp .Lfeedback
.Lwake:
 lea rdi,[r14+8]
 mov esi,129
 mov edx,2147483647
 xor r10d,r10d
 xor r8d,r8d
 xor r9d,r9d
 mov eax,202
 syscall
 jmp .Lfeedback
.Lfacts:
 mov [r13+80],r14
 .byte 0x48,0x8d,0x05
.global owner_finalizer_carrier_address_hole
owner_finalizer_carrier_address_hole:
 .long 0
 mov [r13+88],rax
 xor eax,eax
 jmp .Lfeedback
.Lcarrier:
 lea rdi,[r14+128]
 mov esi,128
 mov rdx,[r14+32]
 mov rcx,[r14+40]
 mov r8,[r14+48]
 mov r9d,256
 .byte 0xe8
.global owner_finalizer_carrier_call_hole
owner_finalizer_carrier_call_hole:
 .long 0
 mov [rsp],rax
 mov rsi,[r14+32]
 lea rdi,[r14+128]
 mov ecx,128
 cld
 rep movsb
 mov rax,[rsp]
.Lfeedback:
 mov [r13+104],rax
 jmp .Lpolicy
.Lbad:
 mov eax,0xfffffffd
.Ldone:
 add rsp,8
 pop r15
 pop r14
 pop r13
 pop r12
 pop rbp
 pop rbx
 ret
.size hia_generation_lease_owner_finalizer,.-hia_generation_lease_owner_finalizer
.section .note.GNU-stack,"",@progbits
