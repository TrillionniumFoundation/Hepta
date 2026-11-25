# Fixed native MV generation stages; all sequencing and admission is HIA.
.intel_syntax noprefix
.text
.global hia_mv_runtime_generation
.type hia_mv_runtime_generation,@function
hia_mv_runtime_generation:
 push rbx
 push rbp
 push r12
 push r13
 push r14
 push r15
 sub rsp,136
 mov r12,rdi
 mov r15,rsi
 mov r13,rdx
 mov rbp,rcx
 mov r14,r8
 mov rbx,r9
 cmp rbx,536870912
 jb .Lbad
 cmp rbp,4096
 jb .Lbad
 mov qword ptr [r14+524288000],0
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
 policy_hole:
 .long 0
 test eax,eax
 je .Ldone
 cmp eax,1
 je .Lsyscall
 cmp eax,2
 jb .Lreturn
 cmp eax,8
 ja .Lreturn
 mov rdi,[r13]
 add rdi,r14
 mov rsi,[r13+8]
 mov rdx,[r13+16]
 add rdx,r14
 mov rcx,[r13+24]
 mov r8,[r13+32]
 add r8,r14
 mov r9,[r13+40]
 cmp eax,2
 je .Lintake
 cmp eax,3
 je .Lproof
 cmp eax,4
 je .Lprepare
 cmp eax,5
 je .Lcapture
 cmp eax,6
 je .Limage
 cmp eax,7
 je .Lprobe
 .byte 0xe8
 retirement_hole:
 .long 0
 jmp .Lfeedback
.Lintake:
 .byte 0xe8
 intake_hole:
 .long 0
 jmp .Lfeedback
.Lproof:
 .byte 0xe8
 proof_hole:
 .long 0
 jmp .Lfeedback
.Lprepare:
 .byte 0xe8
 prepare_hole:
 .long 0
 jmp .Lfeedback
.Lcapture:
 .byte 0xe8
 capture_hole:
 .long 0
 jmp .Lfeedback
.Limage:
 .byte 0xe8
 image_hole:
 .long 0
 jmp .Lfeedback
.Lprobe:
 .byte 0xe8
 probe_hole:
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
.Lfeedback:
 mov [r14+524288008],rax
 jmp .Lloop
.Ldone:
 mov eax,[r13+8]
 jmp .Lreturn
.Lbad:
 mov eax,0xfffffffd
.Lreturn:
 add rsp,136
 pop r15
 pop r14
 pop r13
 pop r12
 pop rbp
 pop rbx
 ret
.size hia_mv_runtime_generation,.-hia_mv_runtime_generation
.section .note.GNU-stack,"",@progbits
