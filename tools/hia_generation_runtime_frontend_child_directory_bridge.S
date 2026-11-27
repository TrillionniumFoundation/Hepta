# Fixed private Runtime Path policy. All ownership and sequencing is HIA.
.intel_syntax noprefix
.text
.global hia_generation_runtime_frontend_child_directory
.type hia_generation_runtime_frontend_child_directory,@function
hia_generation_runtime_frontend_child_directory:
 push rbx
 push rbp
 push r12
 push r13
 push r14
 push r15
 sub rsp,104
 mov [rsp+96],r11
 mov r12,rdi
 mov r15,rsi
 mov r13,rdx
 mov rbp,rcx
 mov r14,r8
 mov rbx,r9
 cmp r15,128
 jne .Lbad
 cmp rbp,32768
 jb .Lbad
 cmp rbx,524288
 jne .Lbad
 movabs rax,0x3151445452414948
 cmp [r12],rax
 jne .Lbad
 mov rax,[r12+8]
 cmp rax,1
 ja .Lbad
 test rax,rax
 jnz .Lwire
 cmp qword ptr [r12+24],0
 je .Lbad
.Lwire:
 mov ecx,16
.Lwire_loop:
 test rax,rax
 jnz .Lwire_zero
 cmp ecx,24
 jb .Lwire_zero
 cmp ecx,40
 jbe .Lwire_next
.Lwire_zero:
 cmp qword ptr [r12+rcx],0
 jne .Lbad
.Lwire_next:
 add ecx,8
 cmp ecx,128
 jb .Lwire_loop
 mov qword ptr [rsp],0
 mov [rsp+8],r14
 mov [rsp+16],r12
 mov [rsp+24],r13
 cmp qword ptr [r14],0
 je .Lnew_context
 movabs rax,0x3157445452414948
 cmp [r14],rax
 jne .Lbad
 cmp [r14+144],r14
 jne .Lbad
 mov rax,[rsp+96]
 cmp [r14+48],rax
 jne .Lbad
 mov eax,39
 syscall
 cmp [r14+8],rax
 jne .Lbad
.Lnew_context:
 mov qword ptr [r14+256],0
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
 cmp eax,10
 je .Lloop
 cmp eax,1
 je .Lsyscall
 cmp eax,2
 je .Lrole
 cmp eax,4
 je .Lfacts
 jmp .Lreturn
.Lfacts:
 mov r10,[rsp+96]
 test r10,r10
 jz .Lbad
 lea rax,[r10-512]
 movabs rdx,0x31574f4c47414948
 cmp [rax],rdx
 jne .Lbad
 cmp [rax+48],r10
 jne .Lbad
 cmp qword ptr [rax+56],256
 jne .Lbad
 cmp qword ptr [rax+80],1
 jne .Lbad
 movabs rdx,0x3158435347414948
 cmp [rax+1136],rdx
 jne .Lbad
 cmp qword ptr [rax+1144],2
 jne .Lbad
 cmp qword ptr [rax+1208],0
 je .Lbad
 mov rdx,[rax+1152]
 test rdx,rdx
 je .Lbad
 add rdx,4096
 mov rcx,[rax+1088]
 test rcx,rcx
 jz .Lbad
 cmp qword ptr [rax+1096],8388608
 jne .Lbad
 add rcx,7341568
 jc .Lbad
 movabs r11,0x314d415452414948
 cmp [rcx],r11
 jne .Lbad
 cmp [rcx+16],rax
 jne .Lbad
 cmp qword ptr [rcx+48],2
 jne .Lbad
 cmp qword ptr [rcx+64],0
 jne .Lbad
 cmp qword ptr [rcx+72],0
 je .Lbad
 mov r11,[rax+664]
 cmp [rcx+232],r11
 jne .Lbad
 mov r11,[rcx+376]
 test r11,r11
 jz .Lbad
 mov [rsp+80],r11
 mov r11,[rcx+384]
 test r11,r11
 jz .Lbad
 mov [rsp+88],r11
 mov rcx,[rcx+352]
 cmp [rax+40],rcx
 jne .Lbad
 mov [r13+128],r14
 mov [r13+136],rcx
 mov [r13+144],r10
 mov [r13+152],rdx
 xor eax,eax
 jmp .Lfeedback
.Lrole:
 mov rdi,[r14+328]
 mov rsi,[r14+336]
 mov rdx,[r14+344]
 mov rcx,[r14+352]
 mov r8,[r14+360]
 mov r9,[r14+368]
 mov eax,[r14+320]
 test eax,eax
 je .Lcopy
 cmp eax,1
 je .Lvalue
 cmp eax,2
 je .Labsolute
 cmp eax,3
 je .Ltempdir
 cmp eax,4
 je .Lpure
 cmp eax,5
 je .Lwindows
 jmp .Lbad
.Lcopy:
 mov rax,rdi
 mov rdi,rdx
 mov rcx,rsi
 mov rsi,rax
 cld
 rep movsb
 xor eax,eax
 jmp .Lfeedback
.Lvalue:
 mov r8,[rsp+96]
 mov r9d,256
 call qword ptr [r14+40]
 jmp .Lfeedback
.Labsolute:
 call qword ptr [rsp+80]
 jmp .Lfeedback
.Ltempdir:
 mov rax,[rsp+96]
 mov r8,[rax+640]
 add r8,4096
 mov r9d,204800
 call qword ptr [rsp+88]
 jmp .Lfeedback
.Lpure:
 .byte 0xe8
 pure_hole:
 .long 0
 jmp .Lfeedback
.Lwindows:
 .byte 0xe8
 windows_hole:
 .long 0
 jmp .Lfeedback
.Lsyscall:
 mov r10,[r13+56]
 xor ecx,ecx
.Lsys_translate:
 mov rax,[r13+8+rcx*8]
 mov r11,r10
 and r11d,3
 add rax,[rsp+r11*8]
 mov [rsp+32+rcx*8],rax
 shr r10,2
 inc ecx
 cmp ecx,6
 jb .Lsys_translate
 mov rdi,[rsp+32]
 mov rsi,[rsp+40]
 mov rdx,[rsp+48]
 mov r10,[rsp+56]
 mov r8,[rsp+64]
 mov r9,[rsp+72]
 mov rax,[r13]
 syscall
.Lfeedback:
 mov [r14+264],rax
 jmp .Lloop
.Ldone:
 xor eax,eax
 jmp .Lreturn
.Lbad:
 mov eax,0xfffffffd
.Lreturn:
 add rsp,104
 pop r15
 pop r14
 pop r13
 pop r12
 pop rbp
 pop rbx
 ret
.size hia_generation_runtime_frontend_child_directory,.-hia_generation_runtime_frontend_child_directory
.section .note.GNU-stack,"",@progbits
