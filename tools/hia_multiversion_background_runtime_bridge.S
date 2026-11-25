# Fixed BG provider transport. All state and lifetime policy resides in HIA.
.intel_syntax noprefix
.text
.global hia_mv_background_runtime
.type hia_mv_background_runtime,@function
hia_mv_background_runtime:
 push rbx
 push rbp
 push r12
 push r13
 push r14
 push r15
 sub rsp,4296
 cmp rcx,128
 jb .Lshort
 cmp r9,1024
 jb .Lbad
 mov r12,rdi
 mov r15,rsi
 mov [rsp+32],rdx
 mov [rsp+40],rcx
 lea r13,[rsp+192]
 mov ebp,4096
 mov r14,r8
 mov rbx,r9
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
 provider_hole:
 .long 0
 test eax,eax
 je .Lcomplete
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
 cmp eax,12
 jb .Lreturn
 cmp eax,14
 ja .Lreturn
 mov [rsp+96],eax
 xor ecx,ecx
.Lrole_translate:
 mov rax,[r13+rcx*8]
 cmp rax,4
 ja .Lbad
 mov rdx,[r13+8+rcx*8]
 add rdx,[rsp+rax*8]
 mov [rsp+104+rcx*8],rdx
 add ecx,3
 cmp ecx,9
 jb .Lrole_translate
 mov rdi,[rsp+104]
 mov rsi,[r13+16]
 mov rdx,[rsp+128]
 mov rcx,[r13+40]
 mov r8,[rsp+152]
 mov r9,[r13+64]
 mov eax,[rsp+96]
 cmp eax,12
 je .Lhandles
 cmp eax,13
 je .Lpayload
 .byte 0xe8
 effects_hole:
 .long 0
 jmp .Lfeedback
.Lhandles:
 .byte 0xe8
 handles_hole:
 .long 0
 jmp .Lfeedback
.Lpayload:
 .byte 0xe8
 payload_hole:
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
 mov [rsp+48+rcx*8],rax
 shr r10,2
 inc ecx
 cmp ecx,6
 jb .Ltranslate
 mov rdi,[rsp+48]
 mov rsi,[rsp+56]
 mov rdx,[rsp+64]
 mov r10,[rsp+72]
 mov r8,[rsp+80]
 mov r9,[rsp+88]
 mov rax,[r13]
 syscall
 jmp .Lfeedback
.Lcas:
 cmp qword ptr [r13],24
 jne .Lbad
 lea rdx,[r14+24]
 mov eax,[r13+8]
 mov ecx,[r13+16]
 lock cmpxchg dword ptr [rdx],ecx
 jmp .Lfeedback
.Lexchange:
 cmp qword ptr [r13],24
 jne .Lbad
 lea rdx,[r14+24]
 mov eax,[r13+8]
 xchg dword ptr [rdx],eax
 jmp .Lfeedback
.Laddress:
 mov rax,[r13]
 cmp rax,4
 ja .Lbad
 mov rdx,[r13+8]
 add rdx,[rsp+rax*8]
 mov rax,rdx
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
 cmp rax,4
 ja .Lbad
 mov rsi,[r13+8]
 add rsi,[rsp+rax*8]
 mov rax,[r13+16]
 cmp rax,4
 ja .Lbad
 mov rdi,[r13+24]
 add rdi,[rsp+rax*8]
 mov rcx,[r13+32]
 cld
 rep movsb
 xor eax,eax
.Lfeedback:
 mov [r13+136],rax
 jmp .Lloop
.Lcomplete:
 mov rdi,[rsp+32]
 mov rsi,r13
 mov ecx,16
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
 add rsp,4296
 pop r15
 pop r14
 pop r13
 pop r12
 pop rbp
 pop rbx
 ret
.size hia_mv_background_runtime,.-hia_mv_background_runtime
.section .note.GNU-stack,"",@progbits
