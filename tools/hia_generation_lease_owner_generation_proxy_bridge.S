# Fixed native GEN proxy; child identity and custody decisions remain HIA.
.intel_syntax noprefix
.text
.global hia_generation_lease_owner_generation_proxy
.type hia_generation_lease_owner_generation_proxy,@function
hia_generation_lease_owner_generation_proxy:
.Lproxy_base:
 xor r10d,r10d
 jmp .Lentry
.global hia_generation_lease_owner_generation_proxy_close
hia_generation_lease_owner_generation_proxy_close:
 mov r10d,1
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
 mov [rsp+152],r11
 mov [rsp+144],r10
 test r12,r12
 je .Lbad
 test r13,r13
 je .Lbad
 test r14,r14
 je .Lbad
 test r14,7
 jne .Lbad
 cmp rbx,536870912
 jne .Lbad
 cmp rbp,128
 jb .Lbad
 test r10,r10
 jne .Lextents
 cmp rbp,4096
 jb .Lbad
.Lextents:
 mov rax,r12
 add rax,r15
 jc .Lbad
 mov rcx,r13
 add rcx,rbp
 jc .Lbad
 mov rdx,r14
 add rdx,rbx
 jc .Lbad
 cmp r12,rcx
 jae .Lnoso
 cmp r13,rax
 jb .Lbad
.Lnoso:
 cmp r12,rdx
 jae .Lnosw
 cmp r14,rax
 jb .Lbad
.Lnosw:
 cmp r13,rdx
 jae .Lidentity
 cmp r14,rcx
 jb .Lbad
.Lidentity:
 mov eax,39
 syscall
 test rax,rax
 jle .Lbad
 mov [rsp+160],rax
 cmp qword ptr [r14+533725240],0
 je .Llock
 movabs rdx,0x3157585047414948
 cmp [r14+533725240],rdx
 jne .Lbad
 cmp [r14+533725224],rax
 jne .Lbad
 cmp [r14+533725216],r14
 jne .Lbad
 lea rax,[rip+.Lproxy_base]
 cmp [r14+533725232],rax
 jne .Lbad
.Llock:
 xor eax,eax
 mov ecx,1
 lock cmpxchg [r14+533725280],ecx
 test eax,eax
 jne .Lbad
 mov rax,[r14+533725184]
 mov [rsp+88],rax
 mov rax,[r14+533725192]
 mov [rsp+96],rax
 mov rax,[r14+533725200]
 mov [rsp+104],rax
 mov qword ptr [r14+533725184],0
 mov qword ptr [r14+533725192],0
 mov rax,[rsp+144]
 mov [r14+533725200],rax
.Lloop:
 mov rdi,r12
 mov rsi,r15
 mov rdx,r13
 mov rcx,rbp
 mov r8,r14
 mov r9,rbx
 .byte 0xe8
 proxy_policy_hole:
 .long 0
 test eax,eax
 je .Ldone
 cmp eax,2
 je .Lcapture
 cmp eax,3
 je .Lbind
 cmp eax,4
 je .Lgeneration
 cmp eax,5
 je .Lclose
 cmp eax,6
 je .Lpass
 jmp .Lfailed
.Lcapture:
 mov [r14+533725216],r14
 mov rax,[rsp+160]
 mov [r14+533725224],rax
 lea rax,[rip+.Lproxy_base]
 mov [r14+533725232],rax
 mov rax,[rsp+152]
 cmp rax,512
 jb .Lno_parent
 sub rax,512
 jmp .Lfeedback
.Lno_parent:
 xor eax,eax
 jmp .Lfeedback
.Lbind:
 lea rdi,[r14+532676608]
 mov esi,16
 mov rdx,r14
 mov rcx,rbx
 mov r8,[r14+533725248]
 mov r9d,2048
 .byte 0xe8
 proxy_bind_hole:
 .long 0
 jmp .Lfeedback
.Lgeneration:
 mov rdi,r12
 mov rsi,r15
 mov rdx,r13
 mov rcx,rbp
 mov r8,r14
 mov r9,rbx
 .byte 0xe8
 proxy_generation_hole:
 .long 0
 jmp .Lfeedback
.Lclose:
 mov rdi,r12
 mov rsi,r15
 mov rdx,r13
 mov rcx,rbp
 mov r8,r14
 mov r9,rbx
 .byte 0xe8
 proxy_close_hole:
 .long 0
.Lfeedback:
 mov [r14+533725192],rax
 jmp .Lloop
.Lpass:
 mov eax,[r14+533725256]
 jmp .Lunlock
.Ldone:
 xor eax,eax
 jmp .Lunlock
.Lfailed:
 mov rax,[rsp+88]
 mov [r14+533725184],rax
 mov rax,[rsp+96]
 mov [r14+533725192],rax
 mov rax,[rsp+104]
 mov [r14+533725200],rax
 mov eax,0xfffffffd
.Lunlock:
 mov qword ptr [r14+533725280],0
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
.size hia_generation_lease_owner_generation_proxy,.-hia_generation_lease_owner_generation_proxy

# Private fixture/enclosing capture: source actual GX frame, second span GEN
# 512 MiB, third span actual enclosing owner/2048. Output at GEN+384 MiB.
.global hia_generation_lease_owner_generation_proxy_owner
.type hia_generation_lease_owner_generation_proxy_owner,@function
hia_generation_lease_owner_generation_proxy_owner:
 push rbx
 push r12
 push r13
 push r14
 sub rsp,4104
 mov rbx,rdi
 mov r12,rsi
 mov r13,rdx
 mov r14,r8
 test rbx,rbx
 je .LBbad
 test r13,r13
 je .LBbad
 cmp rcx,536870912
 jne .LBbad
 test r14,r14
 je .LBbad
 cmp r9,2048
 jne .LBbad
 movabs rax,0x31574f4c47414948
 cmp [r14],rax
 jne .LBbad
 cmp [r14+16],r14
 jne .LBbad
 cmp qword ptr [r14+24],0
 je .LBbad
 cmp qword ptr [r14+80],1
 jne .LBbad
 mov eax,39
 syscall
 cmp rax,[r14+8]
 jne .LBbad
 lea rax,[r14+512]
 cmp [r14+48],rax
 jne .LBbad
 cmp qword ptr [r14+56],256
 jne .LBbad
 mov rdi,rbx
 mov rsi,r12
 mov rdx,rsp
 mov ecx,4096
 mov r8,r13
 mov r9d,536870912
 mov r11,[r14+48]
 call .Lproxy_base
 cmp eax,0xfffffffd
 je .LBreturn
 mov rbx,rax
 lea rdi,[r13+402653184]
 mov rsi,rsp
 mov ecx,4096
 cld
 rep movsb
 mov rax,rbx
 jmp .LBreturn
.LBbad:
 mov eax,0xfffffffd
.LBreturn:
 add rsp,4104
 pop r14
 pop r13
 pop r12
 pop rbx
 ret
.size hia_generation_lease_owner_generation_proxy_owner,.-hia_generation_lease_owner_generation_proxy_owner
.section .note.GNU-stack,"",@progbits
