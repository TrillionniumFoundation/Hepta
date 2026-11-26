# Fixed Clang prepare mechanics. All policy and resource decisions are HIA.
.intel_syntax noprefix
.text
.global hia_generation_lease_clang_prepare
.global hia_generation_lease_clang_prepare_bind
.global hia_generation_lease_clang_prepare_exception
.type hia_generation_lease_clang_prepare,@function
hia_generation_lease_clang_prepare:
.Lprepare_entry:
 mov r10d,1
 jmp .Lcommon
hia_generation_lease_clang_prepare_bind:
.Lprepare_bind_entry:
 xor r10d,r10d
 jmp .Lcommon
hia_generation_lease_clang_prepare_exception:
 mov r10d,2
.Lcommon:
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
 mov [rsp+152],r10
 test r12,r12
 jz .Lbad
 test r13,r13
 jz .Lbad
 test r14,r14
 jz .Lbad
 test r14,7
 jnz .Lbad
 cmp rbx,536870912
 jne .Lbad
 cmp rbp,128
 jb .Lbad
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
 jae .Lsource_work
 cmp r13,[rsp+128]
 jb .Lbad
.Lsource_work:
 cmp r12,[rsp+144]
 jae .Loutput_work
 cmp r14,[rsp+128]
 jae .Loutput_work
 lea rax,[r14+503316480]
 cmp r12,rax
 jne .Lbad
 cmp r15,10485760
 ja .Lbad
.Loutput_work:
 cmp r13,[rsp+144]
 jae .Lwire
 cmp r14,[rsp+136]
 jae .Lwire
 lea rax,[r14+402653184]
 cmp r13,rax
 jne .Lbad
 cmp rbp,2097152
 ja .Lbad
.Lwire:
 mov r10,[rsp+152]
 test r10,r10
 je .Lbind_wire
 cmp r10,2
 je .Lex_wire
 cmp r15,256
 jb .Lbad
 cmp rbp,2048
 jb .Lbad
 movabs rax,0x324647564d414948
 cmp [r12],rax
 jne .Lbad
 mov rax,[r12+8]
 cmp rax,2
 ja .Lbad
 test rax,rax
 je .Lrun_wire
 cmp r15,256
 jne .Lbad
 mov ecx,16
.Lret_zero:
 cmp qword ptr [r12+rcx],0
 jne .Lbad
 add ecx,8
 cmp ecx,256
 jb .Lret_zero
 jmp .Lidentity
.Lrun_wire:
 cmp rbp,1050624
 jb .Lbad
 cmp qword ptr [r12+16],0
 jne .Lbad
 cmp qword ptr [r12+24],0
 je .Lbad
 test qword ptr [r12+32],7
 jnz .Lbad
 cmp qword ptr [r12+64],0
 je .Lbad
 cmp qword ptr [r12+88],0
 jne .Lbad
 mov rax,[r12+40]
 test rax,rax
 jz .Lbad
 cmp rax,8388608
 ja .Lbad
 mov rcx,[r12+48]
 cmp rcx,336
 jb .Lbad
 cmp rcx,5136
 ja .Lbad
 add rax,rcx
 jc .Lbad
 mov rcx,[r12+56]
 test rcx,rcx
 jz .Lbad
 cmp rcx,4095
 ja .Lbad
 add rax,rcx
 jc .Lbad
 add rax,256
 jc .Lbad
 cmp rax,r15
 jne .Lbad
 mov ecx,96
.Lrun_zero:
 cmp qword ptr [r12+rcx],0
 jne .Lbad
 add ecx,8
 cmp ecx,256
 jb .Lrun_zero
 jmp .Lidentity
.Lbind_wire:
 cmp r15,128
 jne .Lbad
 movabs rax,0x314247564d414948
 cmp [r12],rax
 jne .Lbad
 cmp qword ptr [r12+8],0
 je .Lbad
 cmp qword ptr [r12+16],0
 je .Lbad
 test qword ptr [r12+16],7
 jnz .Lbad
 cmp qword ptr [r12+24],256
 jne .Lbad
 cmp qword ptr [r12+32],0
 je .Lbad
 cmp qword ptr [r12+40],2147483647
 ja .Lbad
 mov ecx,48
 jmp .Lsmall_zero
.Lex_wire:
 cmp r15,128
 jne .Lbad
 movabs rax,0x314547564d414948
 cmp [r12],rax
 jne .Lbad
 cmp qword ptr [r12+8],1
 ja .Lbad
 mov ecx,16
.Lsmall_zero:
 cmp qword ptr [r12+rcx],0
 jne .Lbad
 add ecx,8
 cmp ecx,128
 jb .Lsmall_zero
.Lidentity:
 mov eax,39
 syscall
 test rax,rax
 jle .Lbad
 mov [rsp+160],rax
 cmp qword ptr [r14+419430416],0
 je .Lfresh
 movabs r11,0x325747564d414948
 cmp [r14+419430416],r11
 jne .Lbad
 cmp [r14+419430424],r14
 jne .Lbad
 cmp [r14+419430432],rax
 jne .Lbad
 lea rax,[rip+.Lprepare_entry]
 cmp [r14+419430440],rax
 jne .Lbad
 cmp qword ptr [rsp+152],0
 je .Lbad
 jmp .Lclaim
.Lfresh:
 cmp qword ptr [rsp+152],0
 jne .Lbad
.Lclaim:
 xor eax,eax
 mov ecx,1
 lock cmpxchg dword ptr [r14+419430712],ecx
 test eax,eax
 jne .Lbad
 mov rax,[r14+419430400]
 mov [rsp+88],rax
 mov rax,[r14+419430408]
 mov [rsp+96],rax
 mov rax,[r14+419430448]
 mov [rsp+104],rax
 mov qword ptr [rsp],0
 mov [rsp+8],r14
 mov [rsp+16],r12
 mov [rsp+24],r13
 mov qword ptr [r14+419430400],0
 mov qword ptr [r14+419430408],0
 mov rax,[rsp+152]
 mov [r14+419430448],rax
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
 je .Laddress
 cmp eax,3
 je .Lentry
 cmp eax,11
 je .Lpid
 cmp eax,4
 jb .Lbad_busy
 cmp eax,10
 ja .Lbad_busy
 mov [rsp+80],eax
 mov rdi,[r13]
 mov rsi,[r13+8]
 mov rax,rdi
 add rax,rsi
 jc .Lbad_busy
 cmp rax,rbx
 ja .Lbad_busy
 add rdi,r14
 mov rdx,[r13+16]
 mov rcx,[r13+24]
 mov rax,rdx
 add rax,rcx
 jc .Lbad_busy
 cmp rax,rbx
 ja .Lbad_busy
 add rdx,r14
 mov r8,[r13+32]
 mov r9,[r13+40]
 cmp dword ptr [rsp+80],10
 je .Lvalue
 cmp dword ptr [rsp+80],6
 jbe .Lclang_work
 mov rax,r8
 add rax,r9
 jc .Lbad_busy
 cmp rax,rbx
 ja .Lbad_busy
 add r8,r14
 cmp dword ptr [rsp+80],7
 je .Limage
 cmp dword ptr [rsp+80],8
 je .Lprobe
 .byte 0xe8
retire_hole:
 .long 0
 jmp .Lrole_done
.Limage:
 .byte 0xe8
image_hole:
 .long 0
 jmp .Lrole_done
.Lprobe:
 .byte 0xe8
probe_hole:
 .long 0
 jmp .Lrole_done
.Lclang_work:
 cmp r9,538968064
 jne .Lbad_busy
 mov r8,[r14+419430504]
 test r8,r8
 jz .Lbad_busy
 cmp dword ptr [rsp+80],4
 je .Lclang_bind
 cmp dword ptr [rsp+80],5
 je .Lclang_compile
 .byte 0xe8
clang_exception_hole:
 .long 0
 jmp .Lrole_done
.Lclang_bind:
 .byte 0xe8
clang_bind_hole:
 .long 0
 jmp .Lrole_done
.Lclang_compile:
 .byte 0xe8
clang_compile_hole:
 .long 0
 jmp .Lrole_done
.Lvalue:
 cmp r9,256
 jne .Lbad_busy
 mov r8,[r14+419430472]
 mov r11,[r14+419430464]
 test r8,r8
 jz .Lbad_busy
 test r11,r11
 jz .Lbad_busy
 call r11
.Lrole_done:
 mov eax,eax
 jmp .Lfeedback
.Laddress:
 mov rax,r14
 jmp .Lfeedback
.Lentry:
 lea rax,[rip+.Lprepare_entry]
 jmp .Lfeedback
.Lpid:
 mov rax,[rsp+160]
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
 mov [r14+419430408],rax
 jmp .Lloop
.Ldone:
 xor eax,eax
 jmp .Lrelease
.Lbad_busy:
 cmp qword ptr [r14+419430400],0
 jne .Lbad_after_action
 mov rax,[rsp+88]
 mov [r14+419430400],rax
 mov rax,[rsp+96]
 mov [r14+419430408],rax
 mov rax,[rsp+104]
 mov [r14+419430448],rax
.Lbad_after_action:
 mov eax,0xfffffffd
.Lrelease:
 mov qword ptr [r14+419430712],0
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

.global hia_generation_lease_clang_prepare_bind_owner
hia_generation_lease_clang_prepare_bind_owner:
 push rbx
 push r12
 push r13
 push r14
 sub rsp,264
 mov r12,rdx
 mov r13,rcx
 mov r14,r8
 test rdi,rdi
 jz .Lowner_bad
 cmp rsi,32
 jne .Lowner_bad
 movabs rax,0x31424f5047414948
 cmp [rdi],rax
 jne .Lowner_bad
 cmp qword ptr [rdi+8],2147483647
 ja .Lowner_bad
 cmp qword ptr [rdi+16],0
 jne .Lowner_bad
 cmp qword ptr [rdi+24],0
 jne .Lowner_bad
 mov rax,[rdi+8]
 mov [rsp+256],rax
 test r12,r12
 jz .Lowner_bad
 test r12,7
 jnz .Lowner_bad
 cmp r13,536870912
 jne .Lowner_bad
 test r14,r14
 jz .Lowner_bad
 cmp r9,2048
 jne .Lowner_bad
 mov rax,r12
 add rax,r13
 jc .Lowner_bad
 mov rcx,r14
 add rcx,r9
 jc .Lowner_bad
 cmp r12,rcx
 jae .Lowner_identity
 cmp r14,rax
 jb .Lowner_bad
.Lowner_identity:
 movabs rax,0x31574f4c47414948
 cmp [r14],rax
 jne .Lowner_bad
 cmp [r14+16],r14
 jne .Lowner_bad
 cmp qword ptr [r14+24],0
 je .Lowner_bad
 cmp qword ptr [r14+80],1
 jne .Lowner_bad
 mov eax,39
 syscall
 cmp rax,[r14+8]
 jne .Lowner_bad
 lea rax,[r14+512]
 cmp [r14+48],rax
 jne .Lowner_bad
 cmp qword ptr [r14+56],256
 jne .Lowner_bad
 mov rdi,rsp
 mov ecx,256
 xor eax,eax
 cld
 rep stosb
 movabs rax,0x314247564d414948
 mov [rsp],rax
 mov rax,[r14+40]
 mov [rsp+8],rax
 mov rax,[r14+48]
 mov [rsp+16],rax
 mov rax,[r14+56]
 mov [rsp+24],rax
 mov rax,[r14+664]
 mov [rsp+32],rax
 mov rax,[rsp+256]
 mov [rsp+40],rax
 mov rdi,rsp
 mov esi,128
 lea rdx,[rsp+128]
 mov ecx,128
 mov r8,r12
 mov r9,r13
 call .Lprepare_bind_entry
 test eax,eax
 jne .Lowner_return
 movabs rax,0x524247564d414948
 cmp [rsp+128],rax
 jne .Lowner_error
 cmp qword ptr [rsp+136],0
 jne .Lowner_error
 cmp qword ptr [rsp+216],1
 jne .Lowner_error
 cmp qword ptr [rsp+224],1
 jne .Lowner_error
 xor eax,eax
 jmp .Lowner_return
.Lowner_error:
 mov eax,0xfffffffb
 jmp .Lowner_return
.Lowner_bad:
 mov eax,0xfffffffd
.Lowner_return:
 add rsp,264
 pop r14
 pop r13
 pop r12
 pop rbx
 ret

.size hia_generation_lease_clang_prepare,.-hia_generation_lease_clang_prepare
.section .note.GNU-stack,"",@progbits
