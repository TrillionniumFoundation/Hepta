# Fixed native global initializer. Work is the actual sole root owner.
.intel_syntax noprefix
.text
.global hia_generation_background_bind
.type hia_generation_background_bind,@function
hia_generation_background_bind:
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
 je .Lsize_ok
 cmp r15,192
 jne .Lbad
.Lsize_ok:
 cmp rbp,3145728
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
 mov qword ptr [rsp],0
 mov [rsp+8],r14
 mov [rsp+16],r12
 mov [rsp+24],r13
 mov qword ptr [r13+2097280],0
 mov [r13+2097664],r14
 lea rax,[rip+.Lentry]
 mov [r13+2097672],rax
 .byte 0x48,0x8d,0x05
root_address_hole:
 .long 0
 mov [r13+2097680],rax
 .byte 0x48,0x8d,0x05
value_address_hole:
 .long 0
 mov [r13+2097688],rax
 .byte 0x48,0x8d,0x05
global_address_hole:
 .long 0
 mov [r13+2097696],rax
 .byte 0x48,0x8d,0x05
loader_address_hole:
 .long 0
 mov [r13+2097704],rax
 .byte 0x48,0x8d,0x05
finalizer_address_hole:
 .long 0
 mov [r13+2097712],rax
 .byte 0x48,0x8d,0x05
sidecar_address_hole:
 .long 0
 mov [r13+2097720],rax
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
 cmp eax,4
 je .Lagain
 cmp eax,10
 je .Lglobal
 cmp eax,11
 je .Lloader
 cmp eax,12
 je .Lvalue
 cmp eax,13
 je .Lcontext
 cmp eax,14
 je .Lpublic
 cmp eax,15
 je .Lbackground_finalizer
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
 mov rcx,[r13+2097184]
 test rcx,rcx
 jz .Lcopy_done
 mov rdx,[r13+2097152]
 cmp rdx,3
 ja .Lbad
 mov rsi,[r13+2097160]
 add rsi,[rsp+rdx*8]
 jc .Lbad
 test rsi,rsi
 jz .Lbad
 mov rax,rsi
 add rax,rcx
 jc .Lbad
 mov rdx,[r13+2097168]
 cmp rdx,3
 ja .Lbad
 mov rdi,[r13+2097176]
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
.Lagain:
 xor eax,eax
 jmp .Lfeedback
.Lglobal:
 lea rdi,[r13+2101248]
 mov esi,128
 lea rdx,[r13+2113536]
 mov ecx,147456
 mov r8,r14
 mov r9d,2048
 .byte 0xe8
global_call_hole:
 .long 0
 mov eax,eax
 jmp .Lfeedback
.Lloader:
 lea rdi,[r13+2101248]
 mov esi,128
 lea rdx,[r13+2113536]
 mov ecx,131072
 mov r8,[r13+2098208]
 add r8,4096
 mov r9d,26214400
 .byte 0xe8
loader_call_hole:
 .long 0
 mov eax,eax
 jmp .Lfeedback
.Lvalue:
 lea rdi,[r13+2101248]
 mov esi,128
 lea rdx,[r13+2113536]
 mov ecx,8192
 lea r8,[r14+512]
 mov r9d,256
 .byte 0xe8
value_call_hole:
 .long 0
 mov eax,eax
 jmp .Lfeedback
.Lcontext:
 lea rdi,[r13+2101248]
 mov rsi,[r13+2097152]
 lea rdx,[r13+2113536]
 mov ecx,16384
 mov r8,[r13+2098208]
 mov r9d,512
 call qword ptr [r13+2098368]
 mov eax,eax
 jmp .Lfeedback
.Lpublic:
 mov rdi,r12
 mov rsi,r15
 mov rdx,r13
 mov ecx,2097152
 mov r8,[r13+2098208]
 mov r9d,512
 call qword ptr [r13+2098360]
 mov eax,eax
 jmp .Lfeedback
.Lbackground_finalizer:
 mov rdi,r12
 mov esi,128
 mov rdx,r13
 mov ecx,1048576
 mov r8,[r13+2098208]
 mov r9d,512
 call qword ptr [r13+2098376]
 mov eax,eax
 jmp .Lfeedback
.Lsyscall:
 mov r10,[r13+2097160]
 xor ecx,ecx
.Ltranslate:
 mov rax,[r13+2097168+rcx*8]
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
 mov rax,[r13+2097152]
 syscall
.Lfeedback:
 mov [r13+2097288],rax
 jmp .Lloop
.Ldone:
 mov eax,dword ptr [r13+2097368]
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
.size hia_generation_background_bind,.-hia_generation_background_bind
.section .note.GNU-stack,"",@progbits
