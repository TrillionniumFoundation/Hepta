# Fixed mechanics for HIA component admission and retained loader custody.
.intel_syntax noprefix
.text
.global hia_background_rank_proof_resource
.type hia_background_rank_proof_resource,@function
hia_background_rank_proof_resource:
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
 jne .Lbad
 cmp rbp,131072
 jb .Lbad
 cmp rbx,8388608
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
 movabs rax,0x3151525042414948
 cmp [r12],rax
 jne .Lbad
 mov r10,[r12+8]
 cmp r10,4
 ja .Lbad
 xor ecx,ecx
 mov ecx,16
.Lreserved:
 cmp r10,3
 jne .Lzero
 cmp ecx,24
 jb .Lzero
 cmp ecx,40
 jbe .Lnext
.Lzero:
 cmp qword ptr [r12+rcx],0
 jne .Lbad
.Lnext:
 add ecx,8
 cmp ecx,128
 jb .Lreserved
.Lidentity:
 mov eax,39
 syscall
 test rax,rax
 jle .Lbad
 mov [rsp+160],rax
 cmp qword ptr [r14],0
 je .Lfresh
 movabs r11,0x3157525042414948
 cmp [r14],r11
 jne .Lbad
 cmp [r14+8],r14
 jne .Lbad
 cmp [r14+16],rax
 jne .Lbad
 lea rax,[rip+.Lentry]
 cmp [r14+24],rax
 jne .Lbad
 jmp .Lready
.Lfresh:
 cmp qword ptr [r12+8],0
 jne .Lbad
.Lready:
 mov qword ptr [rsp],0
 mov [rsp+8],r14
 mov [rsp+16],r12
 mov [rsp+24],r13
 mov qword ptr [r13+128],0
 mov [r13+512],r14
 lea rax,[rip+.Lentry]
 mov [r13+520],rax
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
 cmp eax,5
 je .Lorigin
 cmp eax,6
 je .Lpeek
 cmp eax,7
 je .Lcopy
 cmp eax,10
 jb .Lbad
 cmp eax,12
 jbe .Lrole
 cmp eax,15
 je .Lloop
 jmp .Lbad
.Latom:
 xor eax,eax
 mov ecx,1
 lock cmpxchg dword ptr [r14+40],ecx
 pause
 jmp .Lfeedback
.Lunlock:
 mov qword ptr [r14+40],0
 xor eax,eax
 jmp .Lfeedback
.Lorigin:
 xor edi,edi
 lea rsi,[rip+.Ldladdr_name]
 call dlsym@PLT
 test rax,rax
 jz .Lfeedback
 mov r11,rax
 lea rdi,[rip+.Lentry]
 lea rsi,[r14+3200]
 call r11
 mov eax,eax
 jmp .Lfeedback
.Lpeek:
 mov rax,[r13]
 test rax,rax
 jz .Lbad
 movzx eax,byte ptr [rax]
 jmp .Lfeedback
.Lcopy:
 mov rcx,[r13+32]
 test rcx,rcx
 jz .Lcopy_done
 mov rdx,[r13]
 cmp rdx,3
 ja .Lbad
 mov rsi,[r13+8]
 add rsi,[rsp+rdx*8]
 jc .Lbad
 test rsi,rsi
 jz .Lbad
 mov rax,rsi
 add rax,rcx
 jc .Lbad
 mov rdx,[r13+16]
 cmp rdx,3
 ja .Lbad
 mov rdi,[r13+24]
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
.Lrole:
 mov [rsp+152],eax
 mov rdi,[r13]
 mov rsi,[r13+8]
 mov rax,rdi
 add rax,rsi
 jc .Lbad
 cmp rax,rbx
 ja .Lbad
 add rdi,r14
 mov rdx,[r13+16]
 mov rcx,[r13+24]
 mov rax,rdx
 add rax,rcx
 jc .Lbad
 cmp rax,rbx
 ja .Lbad
 add rdx,r14
 mov r8,[r13+32]
 mov r9,[r13+40]
 mov rax,r8
 add rax,r9
 jc .Lbad
 cmp rax,rbx
 ja .Lbad
 add r8,r14
 cmp dword ptr [rsp+152],10
 je .Lcatalog
 cmp dword ptr [rsp+152],11
 je .Lstable
 jmp .Lsha
.Lcatalog:
 .byte 0xe8
catalog_hole:
 .long 0
 jmp .Lrole_feedback
.Lstable:
 .byte 0xe8
stable_hole:
 .long 0
 jmp .Lrole_feedback
.Lsha:
 .byte 0xe8
sha_hole:
 .long 0
.Lrole_feedback:
 mov eax,eax
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
.Ldladdr_name:
 .asciz "dladdr"
.size hia_background_rank_proof_resource,.-hia_background_rank_proof_resource
.section .note.GNU-stack,"",@progbits
