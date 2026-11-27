# Native binding to the sole installed root and actual fixed frontend roles.
.intel_syntax noprefix
.text
.global hia_generation_runtime_frontend_child_bind
.type hia_generation_runtime_frontend_child_bind,@function
hia_generation_runtime_frontend_child_bind:
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
 cmp rbp,1048576
 jne .Lbad
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
 movabs rax,0x3151425452414948
 cmp [r12],rax
 jne .Lbad
 cmp qword ptr [r12+8],1
 ja .Lbad
 mov ecx,16
.Lzero:
 cmp qword ptr [r12+rcx],0
 jne .Lbad
 add ecx,8
 cmp ecx,128
 jb .Lzero
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
 mov r10,[r14+1088]
 test r10,r10
 jz .Lbad
 cmp qword ptr [r14+1096],8388608
 jne .Lbad
 add r10,7341568
 jc .Lbad
 movabs rax,0x314d415452414948
 cmp [r10],rax
 jne .Lbad
 cmp [r10+16],r14
 jne .Lbad
 cmp qword ptr [r10+48],2
 jne .Lbad
 cmp qword ptr [r10+64],0
 jne .Lbad
 cmp qword ptr [r10+72],0
 je .Lbad
 mov rax,[r14+664]
 cmp [r10+232],rax
 jne .Lbad
 mov [rsp+80],r10
 mov rax,[r10+368]
 cmp [r14+24],rax
 jne .Lbad
 mov [rsp+152],rax
 mov rax,[r10+352]
 cmp [r14+40],rax
 jne .Lbad
 mov [rsp+160],rax
 lea rax,[r14+512]
 cmp [r14+48],rax
 jne .Lbad
 cmp qword ptr [r14+56],256
 jne .Lbad
 cmp qword ptr [r12+8],0
 jne .Lold
 xor ecx,ecx
.Lempty:
 cmp qword ptr [r13+rcx],0
 jne .Lbad
 add ecx,8
 cmp ecx,256
 jb .Lempty
 jmp .Lcapture
.Lold:
 movabs rax,0x3143465452414948
 cmp [r13],rax
 jne .Lbad
 cmp [r13+16],r13
 jne .Lbad
 cmp [r13+24],r14
 jne .Lbad
.Lcapture:
 mov qword ptr [rsp],0
 mov [rsp+8],r14
 mov [rsp+16],r12
 mov [rsp+24],r13
 mov qword ptr [r13+256],0
 mov [r13+512],r14
 mov [r13+520],r13
 mov rax,[rsp+152]
 mov [r13+528],rax
 mov rax,[rsp+160]
 mov [r13+536],rax
 mov rax,[rsp+80]
 mov rax,[rax+336]
 mov [r13+544],rax
 .byte 0x48,0x8d,0x05
verify_address_hole:
 .long 0
 mov [r13+552],rax
 .byte 0x48,0x8d,0x05
transport_address_hole:
 .long 0
 mov [r13+560],rax
 .byte 0x48,0x8d,0x05
json_address_hole:
 .long 0
 mov [r13+568],rax
 .byte 0x48,0x8d,0x05
process_address_hole:
 .long 0
 mov [r13+576],rax
 .byte 0x48,0x8d,0x05
typed_address_hole:
 .long 0
 mov [r13+584],rax
 .byte 0x48,0x8d,0x05
freeze_address_hole:
 .long 0
 mov [r13+592],rax
 .byte 0x48,0x8d,0x05
raw_address_hole:
 .long 0
 mov [r13+600],rax
 .byte 0x48,0x8d,0x05
freezeraw_address_hole:
 .long 0
 mov [r13+608],rax
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
 cmp eax,10
 je .Lvalue
 cmp eax,11
 je .Lglobal
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
.Lvalue:
 lea rdi,[r13+32768]
 mov esi,128
 lea rdx,[r13+262144]
 mov ecx,16384
 lea r8,[r14+512]
 mov r9d,256
 call qword ptr [r13+536]
 mov eax,eax
 jmp .Lfeedback
.Lglobal:
 lea rdi,[r13+32768]
 mov esi,128
 lea rdx,[r13+262144]
 mov ecx,147456
 mov r8,r14
 mov r9d,2048
 call qword ptr [r13+544]
 mov eax,eax
 jmp .Lfeedback
.Lsyscall:
 mov r10,[r13+776]
 xor ecx,ecx
.Ltranslate:
 mov rax,[r13+784+rcx*8]
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
 mov rax,[r13+768]
 syscall
.Lfeedback:
 mov [r13+264],rax
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
.size hia_generation_runtime_frontend_child_bind,.-hia_generation_runtime_frontend_child_bind
.section .note.GNU-stack,"",@progbits
