# Fixed native syscall/copy transport for recursive owned-directory cleanup.
.intel_syntax noprefix
.text
.global hia_native_owned_directory_cleanup
.type hia_native_owned_directory_cleanup,@function
hia_native_owned_directory_cleanup:
 push rbx
 push rbp
 push r12
 push r13
 push r14
 push r15
 sub rsp,65736
 cmp rcx,128
 jb .Lshort
 cmp r9,4096
 jne .Lbad
 cmp rsi,128
 jb .Lbad
 test rdi,rdi
 jz .Lbad
 test rdx,rdx
 jz .Lbad
 test r8,r8
 jz .Lbad
 test r8,7
 jnz .Lbad
 mov rax,rdi
 add rax,rsi
 jc .Lbad
 mov r10,rdx
 add r10,rcx
 jc .Lbad
 mov r11,r8
 add r11,r9
 jc .Lbad
 cmp rax,rdx
 jbe .Lsource_output
 cmp r10,rdi
 ja .Lbad
.Lsource_output:
 cmp rax,r8
 jbe .Lsource_context
 cmp r11,rdi
 ja .Lbad
.Lsource_context:
 cmp r10,r8
 jbe .Loutput_context
 cmp r11,rdx
 ja .Lbad
.Loutput_context:
 mov r12,rdi
 mov r15,rsi
 mov [rsp+32],rdx
 mov [rsp+40],rcx
 lea r13,[rsp+192]
 mov ebp,65536
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
.global native_owned_directory_cleanup_policy_hole
native_owned_directory_cleanup_policy_hole:
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
 cmp eax,8
 je .Lcopy
 cmp eax,15
 jne .Lreturn
 mov [r13+200],r14
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
 xor eax,eax
 mov ecx,1
 lock cmpxchg dword ptr [r14+24],ecx
 jmp .Lfeedback
.Lexchange:
 xor eax,eax
 xchg dword ptr [r14+24],eax
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
 add rsp,65736
 pop r15
 pop r14
 pop r13
 pop r12
 pop rbp
 pop rbx
 ret
.size hia_native_owned_directory_cleanup,.-hia_native_owned_directory_cleanup
.section .note.GNU-stack,"",@progbits
