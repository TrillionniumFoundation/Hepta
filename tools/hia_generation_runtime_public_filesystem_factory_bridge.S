# Fixed native public Runtime construction over one already bound frontend.
.intel_syntax noprefix
.text
.global hia_generation_runtime_public_filesystem_factory
.type hia_generation_runtime_public_filesystem_factory,@function
hia_generation_runtime_public_filesystem_factory:
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
 cmp r15,256
 jne .Lbad
 cmp rbp,1048576
 jb .Lbad
 cmp rbx,1048576
 jne .Lbad
 mov rax,r12
 add rax,r15
 jc .Lbad
 mov [rsp+144],rax
 mov rax,r13
 add rax,rbp
 jc .Lbad
 mov [rsp+152],rax
 mov rax,r14
 add rax,rbx
 jc .Lbad
 mov [rsp+160],rax
 cmp r12,[rsp+152]
 jae .Loverlap2
 cmp r13,[rsp+144]
 jb .Lbad
.Loverlap2:
 cmp r12,[rsp+160]
 jae .Loverlap3
 cmp r14,[rsp+144]
 jb .Lbad
.Loverlap3:
 cmp r13,[rsp+160]
 jae .Lwire
 cmp r14,[rsp+152]
 jb .Lbad
.Lwire:
 movabs rax,0x3151435452414948
 cmp [r12],rax
 jne .Lbad
 cmp qword ptr [r12+8],1
 ja .Lbad
 mov ecx,16
.Lzeros:
 cmp qword ptr [r12+8],0
 jne .Lzero_field
 cmp ecx,24
 jb .Lzero_field
 cmp ecx,184
 jbe .Lzero_next
.Lzero_field:
 cmp qword ptr [r12+rcx],0
 jne .Lbad
.Lzero_next:
 add ecx,8
 cmp ecx,256
 jb .Lzeros
 cmp qword ptr [r12+8],0
 jne .Lfront
 cmp qword ptr [r12+24],0
 je .Lbad
 cmp qword ptr [r12+48],0
 je .Lbad
.Lfront:
 movabs rax,0x3143465452414948
 cmp [r14],rax
 jne .Lbad
 cmp [r14+16],r14
 jne .Lbad
 mov eax,39
 syscall
 cmp [r14+8],rax
 jne .Lbad
 mov [rsp+152],rax
 cmp qword ptr [r14+128],1
 jne .Lbad
 mov r10,[r14+24]
 test r10,r10
 jz .Lbad
 movabs rax,0x31574f4c47414948
 cmp [r10],rax
 jne .Lbad
 cmp [r10+16],r10
 jne .Lbad
 mov rax,[rsp+152]
 cmp [r10+8],rax
 jne .Lbad
 cmp qword ptr [r10+80],1
 jne .Lbad
 mov rax,[r14+32]
 cmp [r10+40],rax
 jne .Lbad
 mov rax,[r14+40]
 cmp [r10+48],rax
 jne .Lbad
 mov rax,[r14+160]
 cmp [r10+664],rax
 jne .Lbad
 mov [rsp+88],r10
 mov r11,[r10+1088]
 test r11,r11
 jz .Lbad
 cmp qword ptr [r10+1096],8388608
 jne .Lbad
 add r11,7341568
 jc .Lbad
 movabs rax,0x314d415452414948
 cmp [r11],rax
 jne .Lbad
 cmp [r11+16],r10
 jne .Lbad
 cmp qword ptr [r11+48],2
 jne .Lbad
 cmp qword ptr [r11+64],0
 jne .Lbad
 cmp qword ptr [r11+72],0
 je .Lbad
 mov rax,[r14+160]
 cmp [r11+232],rax
 jne .Lbad
 mov [rsp+80],r11
 mov rax,[r11+192]
 test rax,rax
 jz .Lbad
 mov [rsp+96],rax
 mov rax,[r11+200]
 test rax,rax
 jz .Lbad
 mov [rsp+104],rax
 mov rax,[r14+32]
 mov [rsp+112],rax
 mov rax,[r14+16424]
 test rax,rax
 jz .Lbad
 mov [rsp+120],rax
 mov rax,[r14+16432]
 test rax,rax
 jz .Lbad
 mov [rsp+128],rax
 cmp qword ptr [r14+16440],256
 jne .Lbad
 mov r10,[rsp+88]
 mov rax,[r10+32]
 mov [rsp+136],rax
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
 je .Ldone
 cmp eax,1
 je .Lsyscall
 cmp eax,4
 je .Lloop
 cmp eax,7
 je .Lmemory
 cmp eax,10
 je .Loptions
 cmp eax,11
 je .Lverify
 cmp eax,12
 je .Lpayload
 cmp eax,13
 je .Lvalue
 cmp eax,14
 je .Lcarrier
 cmp eax,15
 je .Lledger
 cmp eax,16
 je .Lprivate_carrier
 cmp eax,17
 je .Lvalue_external
 cmp eax,18
 je .Lstrerror
 jmp .Lbad
.Loptions:
 lea rdi,[r13+4096]
 mov esi,256
 lea rdx,[r13+8192]
 mov ecx,32768
 lea r8,[r14+4096]
 mov r9d,8192
 call qword ptr [rsp+96]
 mov eax,eax
 jmp .Lfeedback
.Lverify:
 lea rdi,[r13+4096]
 mov esi,128
 lea rdx,[r13+8192]
 mov ecx,524288
 lea r8,[r14+16384]
 mov r9d,8192
 call qword ptr [rsp+104]
 mov eax,eax
 jmp .Lfeedback
.Lpayload:
 lea rdi,[r13+4096]
 mov esi,128
 lea rdx,[r13+8192]
 mov ecx,8192
 mov r8,[rsp+128]
 mov r9d,256
 call qword ptr [rsp+120]
 mov eax,eax
 jmp .Lfeedback
.Lvalue:
 lea rdi,[r13+4096]
 mov rsi,[r13+144]
 lea rdx,[r13+8192]
 mov ecx,16384
 mov r8,[r14+40]
 mov r9d,256
 call qword ptr [rsp+112]
 mov eax,eax
 jmp .Lfeedback
.Lvalue_external:
 mov rdi,[r14+524320]
 mov rsi,[r13+144]
 lea rdx,[r13+8192]
 mov ecx,16384
 mov r8,[r14+40]
 mov r9d,256
 call qword ptr [rsp+112]
 mov eax,eax
 jmp .Lfeedback
.Lcarrier:
 mov rdi,[r14+524320]
 mov rsi,[r14+524760]
 jmp .Lcarrier_arguments
.Lprivate_carrier:
 lea rdi,[r13+4096]
 mov esi,128
.Lcarrier_arguments:
 mov rdx,[r14+524320]
 add rdx,16777216
 mov ecx,100663296
 mov r8,[rsp+88]
 add r8,256
 mov r9d,256
 call qword ptr [rsp+136]
 mov eax,eax
 jmp .Lfeedback
.Lledger:
 lea rdi,[r13+4096]
 mov esi,128
 mov rdx,[r14+524320]
 add rdx,16777216
 mov ecx,100696064
 mov r8,[rsp+88]
 mov r9d,2048
 .byte 0xe8
ledger_hole:
 .long 0
 mov eax,eax
 jmp .Lfeedback
.Lstrerror:
 xor edi,edi
 lea rsi,[rip+.Lstrerror_name]
 .byte 0xe8
strerror_dlsym_hole:
 .long 0
 test rax,rax
 jz .Lstrerror_no_symbol
 mov r11,rax
 mov edi,[r14+525232]
 lea rsi,[r13+524288]
 mov edx,131072
 call r11
 jmp .Lfeedback
.Lstrerror_no_symbol:
 xor eax,eax
 jmp .Lfeedback
.Lmemory:
 mov rcx,[r13+32]
 test rcx,rcx
 jz .Lmemory_done
 mov rax,[r13]
 cmp rax,3
 ja .Lbad
 mov rsi,[r13+8]
 add rsi,[rsp+rax*8]
 jc .Lbad
 test rsi,rsi
 jz .Lbad
 mov rax,rsi
 add rax,rcx
 jc .Lbad
 mov rax,[r13+16]
 cmp rax,3
 ja .Lbad
 mov rdi,[r13+24]
 add rdi,[rsp+rax*8]
 jc .Lbad
 test rdi,rdi
 jz .Lbad
 mov rax,rdi
 add rax,rcx
 jc .Lbad
 cld
 rep movsb
.Lmemory_done:
 xor eax,eax
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
.size hia_generation_runtime_public_filesystem_factory,.-hia_generation_runtime_public_filesystem_factory
.section .note.GNU-stack,"",@progbits

.text
.Lstrerror_name:
.asciz "strerror_r"
