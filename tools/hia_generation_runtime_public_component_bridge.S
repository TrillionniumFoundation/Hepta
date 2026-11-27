# Native fixed per-generation component parent. All custody decisions are HIA.
.intel_syntax noprefix
.text
.global hia_generation_lease_owner_component
.type hia_generation_lease_owner_component,@function
hia_generation_lease_owner_component:
.Lcomponent_base:
 mov r10d,1
 jmp .Lentry
.global hia_generation_lease_owner_component_bind
hia_generation_lease_owner_component_bind:
.Lcomponent_bind:
 xor r10d,r10d
 jmp .Lentry
.global hia_generation_lease_owner_component_prepare
hia_generation_lease_owner_component_prepare:
 mov r10d,2
 jmp .Lentry
.global hia_generation_lease_owner_component_exception
hia_generation_lease_owner_component_exception:
 mov r10d,3
 jmp .Lentry
.global hia_generation_lease_owner_component_generation
hia_generation_lease_owner_component_generation:
 mov r10d,4
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
 mov [rsp+152],r10
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
 jae .Lno_so
 cmp r13,[rsp+128]
 jb .Lbad
.Lno_so:
 cmp r12,[rsp+144]
 jae .Lno_sw
 cmp r14,[rsp+128]
 jae .Lno_sw
 lea rax,[r14+503316480]
 cmp r12,rax
 jne .Lbad
 cmp r15,20971520
 ja .Lbad
.Lno_sw:
 cmp r13,[rsp+144]
 jae .Lno_ow
 cmp r14,[rsp+136]
 jae .Lno_ow
 lea rax,[r14+402653184]
 cmp r13,rax
 jne .Lbad
 cmp rbp,2097152
 ja .Lbad
.Lno_ow:
 mov r10,[rsp+152]
 cmp r10,4
 je .Lgeneration_guard
 cmp r10,2
 je .Lforward_guard
 cmp r15,128
 jne .Lbad
 test r10,r10
 je .Lbind_guard
 cmp r10,3
 je .Lex_guard
 movabs rax,0x3151425047414948
 cmp [r12],rax
 jne .Lbad
 cmp qword ptr [r12+8],1
 jb .Lbad
 cmp qword ptr [r12+8],2
 ja .Lbad
 mov ecx,16
 jmp .Lzero_guard
.Lex_guard:
 movabs rax,0x314547564d414948
 cmp [r12],rax
 jne .Lbad
 cmp qword ptr [r12+8],1
 ja .Lbad
 mov ecx,16
 jmp .Lzero_guard
.Lbind_guard:
 movabs rax,0x3149425047414948
 cmp [r12],rax
 jne .Lbad
 cmp qword ptr [r12+8],0
 je .Lbad
 cmp qword ptr [r12+16],0
 je .Lbad
 cmp qword ptr [r12+32],256
 jne .Lbad
 cmp qword ptr [r12+40],0
 je .Lbad
 mov ecx,48
.Lzero_guard:
 cmp qword ptr [r12+rcx],0
 jne .Lbad
 add ecx,8
 cmp ecx,128
 jb .Lzero_guard
 jmp .Lidentity
.Lgeneration_guard:
 cmp r15,256
 jb .Lbad
 cmp rbp,4096
 jb .Lbad
 movabs rax,0x315847564d414948
 cmp [r12],rax
 je .Lgeneration_op
 movabs rax,0x325847564d414948
 cmp [r12],rax
 je .Lgeneration_op
 movabs rax,0x335847564d414948
 cmp [r12],rax
 jne .Lbad
.Lgeneration_op:
 cmp qword ptr [r12+8],6
 ja .Lbad
 jmp .Lidentity
.Lforward_guard:
 cmp r15,256
 jb .Lbad
 cmp rbp,2048
 jb .Lbad
 movabs rax,0x324647564d414948
 cmp [r12],rax
 jne .Lbad
 cmp qword ptr [r12+8],2
 ja .Lbad
.Lidentity:
 mov eax,39
 syscall
 test rax,rax
 jle .Lbad
 mov [rsp+160],rax
 cmp qword ptr [r14+535822352],0
 je .Lnew
 movabs r11,0x3157425047414948
 cmp [r14+535822352],r11
 jne .Lbad
 cmp [r14+535822360],r14
 jne .Lbad
 cmp [r14+535822368],rax
 jne .Lbad
 lea rax,[rip+.Lcomponent_base]
 cmp [r14+535822376],rax
 jne .Lbad
 cmp qword ptr [rsp+152],0
 je .Lbad
 jmp .Llock
.Lnew:
 cmp qword ptr [rsp+152],0
 jne .Lbad
.Llock:
 xor eax,eax
 mov ecx,1
 lock cmpxchg [r14+535822592],ecx
 test eax,eax
 jne .Lbad
 mov rax,[r14+535822336]
 mov [rsp+88],rax
 mov rax,[r14+535822344]
 mov [rsp+96],rax
 mov rax,[r14+535822384]
 mov [rsp+104],rax
 mov qword ptr [rsp],0
 mov [rsp+8],r14
 mov [rsp+16],r12
 mov [rsp+24],r13
 mov qword ptr [r14+535822336],0
 mov qword ptr [r14+535822344],0
 mov rax,[rsp+152]
 mov [r14+535822384],rax
.Lloop:
 mov rdi,r12
 mov rsi,r15
 mov rdx,r13
 mov rcx,rbp
 mov r8,r14
 mov r9,rbx
 .byte 0xe8
 component_policy_hole:
 .long 0
 test eax,eax
 je .Ldone
 cmp eax,1
 je .Lsyscall
 cmp eax,2
 je .Lself
 cmp eax,3
 je .Laddress
 cmp eax,4
 je .Lpid
 cmp eax,9
 je .Lforward
 cmp eax,10
 je .Lexception
 cmp eax,11
 je .Lpass
 cmp eax,12
 je .Lgeneration
 cmp eax,13
 je .Lrole_begin
 cmp eax,5
 jb .Lfailed
 cmp eax,8
 ja .Lfailed
.Lrole_begin:
 mov [rsp+80],eax
 mov rdi,[r13]
 mov rsi,[r13+8]
 mov rax,rdi
 add rax,rsi
 jc .Lfailed
 cmp rax,rbx
 ja .Lfailed
 add rdi,r14
 mov rdx,[r13+16]
 mov rcx,[r13+24]
 mov rax,rdx
 add rax,rcx
 jc .Lfailed
 cmp rax,rbx
 ja .Lfailed
 add rdx,r14
 cmp dword ptr [rsp+80],5
 je .Lvalue
 cmp dword ptr [rsp+80],6
 je .Lloader
 mov r8,r14
 mov r9,rbx
 cmp dword ptr [rsp+80],13
 je .Lchild_exception
 cmp dword ptr [rsp+80],7
 jne .Lchild_retire
 mov r11,[r14+535822616]
 test r11,r11
 je .Lfailed
 call r11
 jmp .Lfeedback
.Lchild_exception:
 mov r11,[r14+535822624]
 test r11,r11
 je .Lfailed
 call r11
 jmp .Lfeedback
.Lchild_retire:
 mov r11,[r14+535822608]
 test r11,r11
 je .Lfailed
 call r11
 jmp .Lfeedback
.Lvalue:
 mov r8,[r14+535822416]
 mov r9d,256
 mov r11,[r14+535822408]
 test r8,r8
 je .Lfailed
 test r11,r11
 je .Lfailed
 call r11
 jmp .Lfeedback
.Lloader:
 mov r8,[r14+535822440]
 mov r9d,26214400
 test r8,r8
 je .Lfailed
 .byte 0xe8
 component_loader_hole:
 .long 0
 jmp .Lfeedback
.Lgeneration:
 mov r11,[r14+535822664]
 jmp .Loriginal
.Lforward:
 mov r11,[r14+535822608]
 jmp .Loriginal
.Lexception:
 mov r11,[r14+535822624]
.Loriginal:
 test r11,r11
 je .Lfailed
 mov rdi,r12
 mov rsi,r15
 mov rdx,r13
 mov rcx,rbp
 mov r8,r14
 mov r9,rbx
 call r11
 jmp .Lfeedback
.Lself:
 mov rax,r14
 jmp .Lfeedback
.Laddress:
 lea rax,[rip+.Lcomponent_base]
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
 mov [r14+535822344],rax
 jmp .Lloop
.Lpass:
 mov eax,[r14+535822656]
 jmp .Lunlock
.Ldone:
 xor eax,eax
 jmp .Lunlock
.Lfailed:
 mov rax,[rsp+88]
 mov [r14+535822336],rax
 mov rax,[rsp+96]
 mov [r14+535822344],rax
 mov rax,[rsp+104]
 mov [r14+535822384],rax
 mov eax,0xfffffffd
.Lunlock:
 mov qword ptr [r14+535822592],0
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
.size hia_generation_lease_owner_component,.-hia_generation_lease_owner_component

# Private parent initializer: input HIAGPBO1/16, output is actual 512 MiB
# generation span, third span is actual enclosing owner/2048.
.global hia_generation_lease_owner_component_bind_owner
.type hia_generation_lease_owner_component_bind_owner,@function
hia_generation_lease_owner_component_bind_owner:
 push rbx
 push r12
 push r13
 push r14
 sub rsp,264
 mov r12,rdx
 mov r13,rcx
 mov r14,r8
 test rdi,rdi
 je .LBbad
 cmp rsi,16
 jne .LBbad
 movabs rax,0x314f425047414948
 cmp [rdi],rax
 jne .LBbad
 cmp qword ptr [rdi+8],0
 jne .LBbad
 test r12,r12
 je .LBbad
 test r12,7
 jne .LBbad
 cmp r13,536870912
 jne .LBbad
 test r14,r14
 je .LBbad
 cmp r9,2048
 jne .LBbad
 mov rax,r12
 add rax,r13
 jc .LBbad
 mov rcx,r14
 add rcx,r9
 jc .LBbad
 cmp r12,rcx
 jae .LBspans
 cmp r14,rax
 jb .LBbad
.LBspans:
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
 mov rdi,rsp
 mov ecx,256
 xor eax,eax
 cld
 rep stosb
 movabs rax,0x3149425047414948
 mov [rsp],rax
 mov [rsp+8],r14
 mov rax,[r14+40]
 mov [rsp+16],rax
 mov rax,[r14+48]
 mov [rsp+24],rax
 mov rax,[r14+56]
 mov [rsp+32],rax
 mov rax,[r14+664]
 mov [rsp+40],rax
 mov rdi,rsp
 mov esi,128
 lea rdx,[rsp+128]
 mov ecx,128
 mov r8,r12
 mov r9,r13
 call .Lcomponent_bind
 test eax,eax
 jne .LBreturn
 movabs rax,0x3152425047414948
 cmp [rsp+128],rax
 jne .LBfailure
 cmp qword ptr [rsp+136],0
 jne .LBfailure
 cmp qword ptr [rsp+216],1
 jne .LBfailure
 cmp qword ptr [rsp+224],1
 jne .LBfailure
 xor eax,eax
 jmp .LBreturn
.LBfailure:
 mov eax,0xfffffffb
 jmp .LBreturn
.LBbad:
 mov eax,0xfffffffd
.LBreturn:
 add rsp,264
 pop r14
 pop r13
 pop r12
 pop rbx
 ret
.size hia_generation_lease_owner_component_bind_owner,.-hia_generation_lease_owner_component_bind_owner
.section .note.GNU-stack,"",@progbits
