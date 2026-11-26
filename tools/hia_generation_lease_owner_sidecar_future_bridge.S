# Trusted sole-owner sidecar transport. All state decisions are native HIA.
.intel_syntax noprefix
.text
.global hia_generation_lease_owner_sidecar_future
.type hia_generation_lease_owner_sidecar_future,@function
hia_generation_lease_owner_sidecar_future:
.Lsidecar_future_start:
 push rbx
 push rbp
 push r12
 push r13
 push r14
 push r15
 sub rsp,98504
 cmp rcx,128
 jb .Lshort
 cmp r9,2048
 jne .Lbad
 cmp rsi,128
 jne .Lbad
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
 mov ebp,98304
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
.global sidecar_future_policy_hole
sidecar_future_policy_hole:
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
 je .Lfacts
 cmp eax,12
 jb .Lreturn
 cmp eax,17
 ja .Lreturn
 mov [rsp+96],eax
 xor ecx,ecx
.Lrole_translate:
 mov rax,[r13+rcx*8]
 cmp rax,3
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
 je .Lvalue
 cmp eax,13
 je .Lcode
 cmp eax,16
 je .Lfuture
 cmp eax,17
 je .Lprovider
 call .Ltempdir_entry
 jmp .Lfeedback
.Lcode:
 call .Lcode_entry
 jmp .Lfeedback
.Lfuture:
 .byte 0xe8
.global sidecar_future_future_call_hole
sidecar_future_future_call_hole:
 .long 0
 jmp .Lfeedback
.Lprovider:
 call .Lprovider_entry
 jmp .Lfeedback
.Lvalue:
 .byte 0xe8
.global sidecar_future_values_call_hole
sidecar_future_values_call_hole:
 .long 0
 jmp .Lfeedback
.Lfacts:
 mov [r13+512],r14
 .byte 0x48,0x8d,0x05
.global sidecar_future_core_address_hole
sidecar_future_core_address_hole:
 .long 0
 mov [r13+520],rax
 .byte 0x48,0x8d,0x05
.global sidecar_future_values_address_hole
sidecar_future_values_address_hole:
 .long 0
 mov [r13+528],rax
 lea rax,[rip+.Lcode_entry]
 mov [r13+536],rax
 lea rax,[rip+.Ltempdir_entry]
 mov [r13+544],rax
 .byte 0x48,0x8d,0x05
.global sidecar_future_finalizer_address_hole
sidecar_future_finalizer_address_hole:
 .long 0
 mov [r13+552],rax
 lea rax,[rip+.Lsidecar_future_start]
 mov [r13+560],rax
 .byte 0x48,0x8d,0x05
.global sidecar_future_future_address_hole
sidecar_future_future_address_hole:
 .long 0
 mov [r13+568],rax
 lea rax,[rip+.Lprovider_delta+4]
 movsxd rdx,dword ptr [rip+.Lprovider_delta]
 add rax,rdx
 mov [r13+576],rax
 .byte 0x48,0x8d,0x05
.global sidecar_future_registry_address_hole
sidecar_future_registry_address_hole:
 .long 0
 mov [r13+584],rax
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
 lock cmpxchg dword ptr [r14+64],ecx
 jmp .Lfeedback
.Lexchange:
 xor eax,eax
 xchg dword ptr [r14+64],eax
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
 add rsp,98504
 pop r15
 pop r14
 pop r13
 pop r12
 pop rbp
 pop rbx
 ret
.p2align 4
.global sidecar_future_code_export
sidecar_future_code_export:
.Lcode_entry:
 .byte 0xe9
.global sidecar_future_code_hole
sidecar_future_code_hole:
 .long 0
.p2align 4
.global sidecar_future_tempdir_export
sidecar_future_tempdir_export:
.Ltempdir_entry:
 .byte 0xe9
.global sidecar_future_tempdir_hole
sidecar_future_tempdir_hole:
 .long 0
.p2align 4
.global sidecar_future_provider_export
sidecar_future_provider_export:
.Lprovider_entry:
 .byte 0xe9
.global sidecar_future_provider_hole
sidecar_future_provider_hole:
.Lprovider_delta:
 .long 0
.global hia_generation_lease_owner_sidecar_future_end
hia_generation_lease_owner_sidecar_future_end:
.size hia_generation_lease_owner_sidecar_future,.-hia_generation_lease_owner_sidecar_future
.section .note.GNU-stack,"",@progbits
