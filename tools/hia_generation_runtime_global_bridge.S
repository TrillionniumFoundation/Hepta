# Fixed native global initializer. Work is the actual sole root owner.
.intel_syntax noprefix
.text
.global hia_generation_runtime_global
.type hia_generation_runtime_global,@function
hia_generation_runtime_global:
.Lentry:
 push rbx
 push rbp
 push r12
 push r13
 push r14
 push r15
 sub rsp,168
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
 test r14,7
 jnz .Lbad
 cmp r15,128
 jne .Lbad
 cmp rbp,147456
 jb .Lbad
 cmp rbx,2048
 jne .Lbad
 mov rax,r12
 add rax,r15
 jc .Lbad
 mov [rsp+128],rax
 mov rax,r13
 add rax,rbp
 jc .Lbad
 mov [rsp+136],rax
 mov rax,r14
 add rax,rbx
 jc .Lbad
 mov [rsp+144],rax
 cmp r12,[rsp+136]
 jae .Loverlap2
 cmp r13,[rsp+128]
 jb .Lbad
.Loverlap2:
 cmp r12,[rsp+144]
 jae .Loverlap3
 cmp r14,[rsp+128]
 jb .Lbad
.Loverlap3:
 cmp r13,[rsp+144]
 jae .Lwire
 cmp r14,[rsp+136]
 jb .Lbad
.Lwire:
 movabs rax,0x3151494747414948
 cmp [r12],rax
 jne .Lbad
 mov r10,[r12+8]
 cmp r10,4
 ja .Lbad
 mov ecx,16
.Lreserved:
 cmp r10,3
 jne .Lzero
 cmp ecx,24
 jb .Lzero
 cmp ecx,40
 jbe .Lnext
.Lzero:
 cmp qword ptr [r12+rcx],0
 jne .Lbad
.Lnext:
 add ecx,8
 cmp ecx,128
 jb .Lreserved
 mov eax,39
 syscall
 test rax,rax
 jle .Lbad
 movabs r11,0x31574f4c47414948
 cmp [r14],r11
 jne .Lbad
 cmp [r14+8],rax
 jne .Lbad
 cmp [r14+16],r14
 jne .Lbad
 cmp qword ptr [r14+80],1
 jne .Lbad
 .byte 0x48,0x8d,0x05
root_address_hole:
 .long 0
 cmp [r14+24],rax
 jne .Lbad
 mov [rsp+152],rax
 .byte 0x48,0x8d,0x05
value_address_hole:
 .long 0
 cmp [r14+40],rax
 jne .Lbad
 mov [rsp+160],rax
 lea rax,[r14+512]
 cmp [r14+48],rax
 jne .Lbad
 cmp qword ptr [r14+56],256
 jne .Lbad
 mov qword ptr [rsp],0
 mov [rsp+8],r14
 mov [rsp+16],r12
 mov [rsp+24],r13
 mov qword ptr [r13+128],0
 mov [r13+512],r14
 lea rax,[rip+.Lentry]
 mov [r13+520],rax
 .byte 0x48,0x8d,0x05
resources_address_hole:
 .long 0
 mov [r13+528],rax
 mov rax,[rsp+152]
 mov [r13+536],rax
 mov rax,[rsp+160]
 mov [r13+544],rax
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
 je .Ldone
 cmp eax,1
 je .Lsyscall
 cmp eax,2
 je .Latom
 cmp eax,3
 je .Lunlock
 cmp eax,7
 je .Lcopy
 cmp eax,10
 je .Lresource
 jmp .Lbad
.Latom:
 xor eax,eax
 mov ecx,1
 lock cmpxchg dword ptr [r14+64],ecx
 pause
 jmp .Lfeedback
.Lunlock:
 mov qword ptr [r14+64],0
 xor eax,eax
 jmp .Lfeedback
.Lcopy:
 mov rcx,[r13+32]
 test rcx,rcx
 jz .Lcopy_done
 mov rdx,[r13]
 cmp rdx,3
 ja .Lbad
 mov rsi,[r13+8]
 add rsi,[rsp+rdx*8]
 jc .Lbad
 test rsi,rsi
 jz .Lbad
 mov rax,rsi
 add rax,rcx
 jc .Lbad
 mov rdx,[r13+16]
 cmp rdx,3
 ja .Lbad
 mov rdi,[r13+24]
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
.Lresource:
 lea rdi,[r13+4096]
 mov esi,128
 lea rdx,[r13+16384]
 mov ecx,131072
 mov r8,[r14+1088]
 mov r9,[r14+1096]
 test r8,r8
 jz .Lbad
 cmp r9,8388608
 jne .Lbad
 .byte 0xe8
resources_call_hole:
 .long 0
 mov eax,eax
 jmp .Lfeedback
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
.Lfeedback:
 mov [r13+136],rax
 jmp .Lloop
.Ldone:
 xor eax,eax
 jmp .Lreturn
.Lbad:
 mov eax,0xfffffffd
.Lreturn:
 add rsp,168
 pop r15
 pop r14
 pop r13
 pop r12
 pop rbp
 pop rbx
 ret
.size hia_generation_runtime_global,.-hia_generation_runtime_global
.section .note.GNU-stack,"",@progbits
