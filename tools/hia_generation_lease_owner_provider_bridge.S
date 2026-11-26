# Trusted sole-owner BG provider transport.
# HIA owns admission, shared-registry custody and prepare/rollback/commit policy.
# The fixed role holes are linked by the enclosing native packer.
# malloc/free are platform allocator bindings for this component construction;
# enclosing standalone-native qualification must bind the shared native allocator.
.intel_syntax noprefix
.text
.global hia_generation_lease_owner_provider
.type hia_generation_lease_owner_provider,@function
hia_generation_lease_owner_provider:
.Lprovider_start:
 push rbx
 push rbp
 push r12
 push r13
 push r14
 push r15
 sub rsp,4296
 cmp rcx,128
 jb .Lshort
 cmp r9,768
 jne .Lbad
 test rdi,rdi
 jz .Lbad
 test rdx,rdx
 jz .Lbad
 test r8,r8
 jz .Lbad
 test r8,7
 jnz .Lbad
 cmp rsi,128
 jb .Lbad
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
 jbe .Lsource_output_ok
 cmp r10,rdi
 ja .Lbad
.Lsource_output_ok:
 cmp rax,r8
 jbe .Lsource_context_ok
 cmp r11,rdi
 ja .Lbad
.Lsource_context_ok:
 cmp r10,r8
 jbe .Loutput_context_ok
 cmp r11,rdx
 ja .Lbad
.Loutput_context_ok:
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
 cmp eax,15
 je .Lfacts
 cmp eax,12
 jb .Lreturn
 cmp eax,16
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
 cmp eax,16
 je .Lvalues
 mov r11,[r14+88]
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
.Lvalues:
 .byte 0xe8
 values_hole:
 .long 0
 jmp .Lfeedback
.Lfacts:
 mov [r13+896],r14
 lea rax,[r14-1280]
 mov [r13+904],rax
 lea rax,[rip+.Lprovider_start]
 mov [r13+912],rax
 lea rax,[rip+handles_hole+4]
 movsxd rdx,dword ptr [rip+handles_hole]
 add rax,rdx
 mov [r13+920],rax
 lea rax,[rip+effects_hole+4]
 movsxd rdx,dword ptr [rip+effects_hole]
 add rax,rdx
 mov [r13+928],rax
 lea rax,[rip+payload_hole+4]
 movsxd rdx,dword ptr [rip+payload_hole]
 add rax,rdx
 mov [r13+936],rax
 lea rax,[rip+values_hole+4]
 movsxd rdx,dword ptr [rip+values_hole]
 add rax,rdx
 mov [r13+944],rax
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
.size hia_generation_lease_owner_provider,.-hia_generation_lease_owner_provider
.section .note.GNU-stack,"",@progbits
