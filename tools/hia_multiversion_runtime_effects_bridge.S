# Fixed native multiversion runtime effects. All sequencing is HIA.
.intel_syntax noprefix
.text
.global hia_mv_runtime_effects
.type hia_mv_runtime_effects,@function
hia_mv_runtime_effects:
 push rbx
 push rbp
 push r12
 push r13
 push r14
 push r15
 sub rsp,152
 mov r12,rdi
 mov r15,rsi
 mov r13,rdx
 mov rbp,rcx
 mov r14,r8
 mov rbx,r9
 cmp rbp,41943040
 jb .Lbad
 cmp rbx,131072
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
 effects_hole:
 .long 0
 test eax,eax
 je .Ldone
 cmp eax,10
 je .Lloop
 cmp eax,1
 je .Lsyscall
 cmp eax,2
 je .Lcas
 cmp eax,3
 je .Lexchange
 cmp eax,4
 je .Laddress
 cmp eax,6
 je .Lallocate
 cmp eax,7
 je .Lfree
 cmp eax,8
 je .Lcopy
 cmp eax,21
 je .Lnative
 cmp eax,12
 jb .Lreturn
 cmp eax,20
 ja .Lreturn
 mov [rsp+80],eax
 xor ecx,ecx
.Lrole_translate:
 mov rax,[r13+rcx*8]
 cmp rax,3
 ja .Lbad
 mov rdx,[r13+8+rcx*8]
 add rdx,[rsp+rax*8]
 mov [rsp+88+rcx*8],rdx
 add ecx,3
 cmp ecx,9
 jb .Lrole_translate
 mov rdi,[rsp+88]
 mov rsi,[r13+16]
 mov rdx,[rsp+112]
 mov rcx,[r13+40]
 mov r8,[rsp+136]
 mov r9,[r13+64]
 mov eax,[rsp+80]
 cmp eax,12
 je .Lgeneration
 cmp eax,13
 je .Lidentity
 cmp eax,14
 je .Lstate
 cmp eax,15
 je .Lretention
 cmp eax,16
 je .Lfuture
 cmp eax,17
 je .Lcall
 cmp eax,18
 je .Lmeasure
 cmp eax,19
 je .Ldirectory
 .byte 0xe8
 typed_hole:
 .long 0
 jmp .Lfeedback
.Lgeneration:
 .byte 0xe8
 generation_hole:
 .long 0
 jmp .Lfeedback
.Lidentity:
 .byte 0xe8
 identity_hole:
 .long 0
 jmp .Lfeedback
.Lstate:
 .byte 0xe8
 state_hole:
 .long 0
 jmp .Lfeedback
.Lretention:
 .byte 0xe8
 retention_hole:
 .long 0
 jmp .Lfeedback
.Lfuture:
 .byte 0xe8
 future_hole:
 .long 0
 jmp .Lfeedback
.Lcall:
 .byte 0xe8
 call_hole:
 .long 0
 jmp .Lfeedback
.Lmeasure:
 .byte 0xe8
 measure_hole:
 .long 0
 jmp .Lfeedback
.Ldirectory:
 .byte 0xe8
 directory_hole:
 .long 0
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
 jmp .Lfeedback
.Lcas:
 mov rdx,[r13]
 mov eax,[r13+8]
 mov ecx,[r13+16]
 lock cmpxchg dword ptr [rdx],ecx
 jmp .Lfeedback
.Lexchange:
 mov rdx,[r13]
 mov eax,[r13+8]
 xchg dword ptr [rdx],eax
 jmp .Lfeedback
.Laddress:
 mov rax,[r13]
 add rax,r14
 jmp .Lfeedback
.Lallocate:
 mov rdi,[r13]
 call malloc
 jmp .Lfeedback
.Lfree:
 mov rdi,[r13]
 call free
 xor eax,eax
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
.Lnative:
 mov r11,[r13]
 cmp qword ptr [r13+8],16
 ja .Lbad
 mov r10,[r13+16]
 add r10,r13
 sub rsp,80
 xor ecx,ecx
.Lnative_stack:
 mov rax,[r10+48+rcx*8]
 mov [rsp+rcx*8],rax
 inc ecx
 cmp ecx,10
 jb .Lnative_stack
 mov rdi,[r10]
 mov rsi,[r10+8]
 mov rdx,[r10+16]
 mov rcx,[r10+24]
 mov r8,[r10+32]
 mov r9,[r10+40]
 call r11
 add rsp,80
.Lfeedback:
 mov [r13+136],rax
 jmp .Lloop
.Ldone:
 mov eax,[r13+8]
 jmp .Lreturn
.Lbad:
 mov eax,0xfffffffd
.Lreturn:
 add rsp,152
 pop r15
 pop r14
 pop r13
 pop r12
 pop rbp
 pop rbx
 ret
.size hia_mv_runtime_effects,.-hia_mv_runtime_effects
.section .note.GNU-stack,"",@progbits
