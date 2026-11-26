.intel_syntax noprefix
.text
.globl hia_program_llvm_public_log
.type hia_program_llvm_public_log,@function
hia_program_llvm_public_log:
.Llog_entry:
 mov eax,1
 jmp .Llog_common
.Llog_bind:
 xor eax,eax
.Llog_common:
 push rbx
 push rbp
 push r12
 push r13
 push r14
 push r15
 sub rsp,88
 mov [rsp],rax
 mov r12,rdi
 mov r13,rsi
 mov r14,rdx
 mov r15,rcx
 mov rbx,r8
 mov rbp,r9
 cmp rbp,65536
 jb .Llog_bad_unlocked
 cmp r15,128
 jb .Llog_bad_unlocked
 test rbx,rbx
 jz .Llog_bad_unlocked
 test r14,r14
 jz .Llog_bad_unlocked
 mov rax,rbx
 add rax,rbp
 jc .Llog_bad_unlocked
 mov rdx,r14
 add rdx,r15
 jc .Llog_bad_unlocked
 cmp rbx,rdx
 jae .Llog_ow_ok
 cmp r14,rax
 jb .Llog_bad_unlocked
.Llog_ow_ok:
 mov rdx,r12
 add rdx,r13
 jc .Llog_bad_unlocked
 test r13,r13
 jz .Llog_bad_unlocked
 test r12,r12
 jz .Llog_bad_unlocked
 cmp r12,rax
 jae .Llog_sw_ok
 cmp rbx,rdx
 jb .Llog_bad_unlocked
.Llog_sw_ok:
 mov rax,r14
 add rax,r15
 cmp r12,rax
 jae .Llog_so_ok
 cmp r14,rdx
 jb .Llog_bad_unlocked
.Llog_so_ok:
 xor eax,eax
 mov edx,1
 lock cmpxchg dword ptr [rbx+120],edx
 jnz .Llog_busy_unlocked
 cmp qword ptr [rsp],0
 jne .Llog_existing
 cmp r13,128
 jne .Llog_bad
 movabs rax,0x3142564c4c414948
 cmp [r12],rax
 jne .Llog_bad
 mov ecx,64
.Llog_bind_reserved:
 cmp qword ptr [r12+rcx],0
 jne .Llog_bad
 add ecx,8
 cmp ecx,128
 jb .Llog_bind_reserved
 cmp qword ptr [r12+8],0
 je .Llog_bad
 cmp qword ptr [r12+16],0
 je .Llog_bad
 cmp qword ptr [r12+24],256
 jne .Llog_bad
 cmp qword ptr [r12+32],0
 je .Llog_bad
 xor ecx,ecx
.Llog_blank:
 cmp ecx,120
 je .Llog_blank_next
 cmp qword ptr [rbx+rcx],0
 jne .Llog_bad
.Llog_blank_next:
 add ecx,8
 cmp ecx,65536
 jb .Llog_blank
 mov eax,39
 syscall
 test rax,rax
 jle .Llog_bad
 mov [rbx+16],rax
 movabs rax,0x3157564c4c414948
 mov [rbx],rax
 mov [rbx+8],rbx
 mov [rbx+24],rbp
 lea rax,[rip+.Llog_entry]
 mov [rbx+32],rax
 mov rax,[r12+8]
 mov [rbx+40],rax
 mov rax,[r12+16]
 mov [rbx+48],rax
 mov qword ptr [rbx+56],256
 mov rax,[r12+32]
 mov [rbx+64],rax
 jmp .Llog_start
.Llog_existing:
 movabs rax,0x3157564c4c414948
 cmp [rbx],rax
 jne .Llog_bad
 cmp [rbx+8],rbx
 jne .Llog_bad
 cmp [rbx+24],rbp
 jne .Llog_bad
 lea rax,[rip+.Llog_entry]
 cmp [rbx+32],rax
 jne .Llog_bad
 cmp qword ptr [rbx+40],0
 je .Llog_bad
 cmp qword ptr [rbx+48],0
 je .Llog_bad
 cmp qword ptr [rbx+56],256
 jne .Llog_bad
 cmp qword ptr [rbx+64],0
 je .Llog_bad
 mov eax,39
 syscall
 cmp [rbx+16],rax
 jne .Llog_bad
.Llog_start:
 mov rax,[rsp]
 mov [rbx+112],rax
 mov [rbx+312],rbx
 mov [rbx+320],r12
 mov [rbx+328],r13
 mov [rbx+336],r14
 mov [rbx+344],r15
 mov qword ptr [rbx+256],0
 mov qword ptr [rbx+264],0
.Llog_loop:
 mov rdi,r12
 mov rsi,r13
 mov rdx,r14
 mov rcx,r15
 mov r8,rbx
 mov r9,rbp
 call hia_program_llvm_public_log_policy_hole
 test eax,eax
 jz .Llog_return
 cmp eax,10
 je .Llog_loop
 cmp eax,1
 je .Llog_syscall
 cmp eax,2
 jne .Llog_bad
 mov rax,[rbx+160]
 test rax,rax
 jz .Llog_copy
 cmp rax,1
 jne .Llog_bad
 cmp qword ptr [rbx+192],16384
 jne .Llog_bad
 lea rax,[rbx+4096]
 cmp [rbx+184],rax
 jne .Llog_bad
 cmp qword ptr [rbx+200],0
 jne .Llog_bad
 cmp qword ptr [rbx+208],0
 jne .Llog_bad
 mov rax,[rbx+168]
 mov rdx,[rbx+176]
 call .Llog_read_range
 jc .Llog_bad
 mov rdi,[rbx+168]
 mov rsi,[rbx+176]
 lea rdx,[rbx+4096]
 mov ecx,16384
 mov r8,[rbx+48]
 mov r9,[rbx+56]
 call qword ptr [rbx+40]
 mov eax,eax
 mov [rbx+264],rax
 jmp .Llog_loop
.Llog_copy:
 mov rax,[rbx+176]
 cmp rax,[rbx+192]
 ja .Llog_bad
 mov rax,[rbx+168]
 mov rdx,[rbx+176]
 call .Llog_read_range
 jc .Llog_bad
 mov rax,[rbx+184]
 mov rdx,[rbx+176]
 call .Llog_write_range
 jc .Llog_bad
 mov rsi,[rbx+168]
 mov rdi,[rbx+184]
 mov rcx,[rbx+176]
 cmp rdi,rsi
 je .Llog_copy_done
 mov rax,rsi
 add rax,rcx
 cmp rdi,rax
 jae .Llog_copy_ok
 mov rax,rdi
 add rax,rcx
 cmp rsi,rax
 jb .Llog_bad
.Llog_copy_ok:
 cld
 rep movsb
.Llog_copy_done:
 mov qword ptr [rbx+264],0
 jmp .Llog_loop
.Llog_syscall:
 cmp qword ptr [r14+56],0
 jne .Llog_bad
 mov rdi,[r14+8]
 mov rsi,[r14+16]
 mov rdx,[r14+24]
 mov r10,[r14+32]
 mov r8,[r14+40]
 mov r9,[r14+48]
 mov rax,[r14]
 syscall
 mov [rbx+264],rax
 jmp .Llog_loop
.Llog_bad:
 mov eax,0xfffffffd
.Llog_return:
 mov [rsp],eax
 xor eax,eax
 xchg dword ptr [rbx+120],eax
 mov eax,[rsp]
 jmp .Llog_epilogue
.Llog_bad_unlocked:
 mov eax,0xfffffffd
 jmp .Llog_epilogue
.Llog_busy_unlocked:
 mov eax,0xfffffffc
.Llog_epilogue:
 add rsp,88
 pop r15
 pop r14
 pop r13
 pop r12
 pop rbp
 pop rbx
 ret
.Llog_read_range:
 mov r10,rax
 add r10,rdx
 jc .Llog_range_bad
 cmp rax,r12
 jb .Llog_work_range
 mov r11,r12
 add r11,r13
 cmp r10,r11
 jbe .Llog_range_ok
.Llog_work_range:
 cmp rax,rbx
 jb .Llog_map_range
 mov r11,rbx
 add r11,rbp
 cmp r10,r11
 jbe .Llog_range_ok
.Llog_map_range:
 mov r11,[rbx+352]
 test r11,r11
 jz .Llog_range_bad
 cmp rax,r11
 jb .Llog_range_bad
 add r11,[rbx+360]
 jc .Llog_range_bad
 cmp r10,r11
 jbe .Llog_range_ok
.Llog_range_bad:
 stc
 ret
.Llog_range_ok:
 clc
 ret
.Llog_write_range:
 mov r10,rax
 add r10,rdx
 jc .Llog_range_bad
 jmp .Llog_work_range
.size hia_program_llvm_public_log,.-hia_program_llvm_public_log

.globl hia_program_llvm_public_log_bind_owner
.type hia_program_llvm_public_log_bind_owner,@function
hia_program_llvm_public_log_bind_owner:
 push rbx
 push rbp
 push r12
 push r13
 push r14
 push r15
 sub rsp,280
 mov r12,rdi
 mov r13,rsi
 mov r14,rdx
 mov r15,rcx
 mov rbx,r8
 mov rbp,r9
 cmp r13,64
 jne .Lbind_bad_unlocked
 cmp r15,65536
 jb .Lbind_bad_unlocked
 cmp rbp,2048
 jb .Lbind_bad_unlocked
 test r12,r12
 jz .Lbind_bad_unlocked
 test r14,r14
 jz .Lbind_bad_unlocked
 test rbx,rbx
 jz .Lbind_bad_unlocked
 mov rax,r14
 add rax,r15
 jc .Lbind_bad_unlocked
 mov rdx,rbx
 add rdx,rbp
 jc .Lbind_bad_unlocked
 cmp r14,rdx
 jae .Lbind_ow_ok
 cmp rbx,rax
 jb .Lbind_bad_unlocked
.Lbind_ow_ok:
 mov rcx,r12
 add rcx,64
 jc .Lbind_bad_unlocked
 cmp r12,rax
 jae .Lbind_os_ok
 cmp r14,rcx
 jb .Lbind_bad_unlocked
.Lbind_os_ok:
 cmp r12,rdx
 jae .Lbind_sw_ok
 cmp rbx,rcx
 jb .Lbind_bad_unlocked
.Lbind_sw_ok:
 movabs rax,0x314f424c4c414948
 cmp [r12],rax
 jne .Lbind_bad_unlocked
 cmp qword ptr [r12+8],0
 jne .Lbind_bad_unlocked
 cmp qword ptr [r12+40],0
 jne .Lbind_bad_unlocked
 cmp qword ptr [r12+48],0
 jne .Lbind_bad_unlocked
 cmp qword ptr [r12+56],0
 jne .Lbind_bad_unlocked
 xor eax,eax
 mov edx,1
 lock cmpxchg dword ptr [rbx+64],edx
 jnz .Lbind_busy_unlocked
 movabs rax,0x31574f4c47414948
 cmp [rbx],rax
 jne .Lbind_bad
 cmp [rbx+16],rbx
 jne .Lbind_bad
 cmp qword ptr [rbx+24],0
 je .Lbind_bad
 cmp qword ptr [rbx+40],0
 je .Lbind_bad
 lea rax,[rbx+512]
 cmp [rbx+48],rax
 jne .Lbind_bad
 cmp qword ptr [rbx+56],256
 jne .Lbind_bad
 cmp qword ptr [rbx+80],1
 jne .Lbind_bad
 cmp qword ptr [rbx+664],0
 je .Lbind_bad
 mov eax,39
 syscall
 cmp [rbx+8],rax
 jne .Lbind_bad
 xor eax,eax
 mov rdi,rsp
 mov ecx,32
 cld
 rep stosq
 movabs rax,0x3142564c4c414948
 mov [rsp],rax
 mov rax,[rbx+40]
 mov [rsp+8],rax
 mov rax,[rbx+48]
 mov [rsp+16],rax
 mov qword ptr [rsp+24],256
 mov rax,[rbx+664]
 mov [rsp+32],rax
 mov rax,[r12+16]
 mov [rsp+40],rax
 mov rax,[r12+24]
 mov [rsp+48],rax
 mov rax,[r12+32]
 mov [rsp+56],rax
 mov rdi,rsp
 mov esi,128
 lea rdx,[rsp+128]
 mov ecx,128
 mov r8,r14
 mov r9,r15
 call .Llog_bind
 mov [rsp+256],eax
 cmp eax,0
 jne .Lbind_unlock
 movabs rax,0x3152564c4c414948
 cmp [rsp+128],rax
 jne .Lbind_unlock
 lea rsi,[rsp+128]
 lea rdi,[r14+1024]
 mov ecx,16
 cld
 rep movsq
 jmp .Lbind_unlock
.Lbind_bad:
 mov dword ptr [rsp+256],0xfffffffd
.Lbind_unlock:
 xor eax,eax
 xchg dword ptr [rbx+64],eax
 lea rdi,[rbx+64]
 mov esi,129
 mov edx,2147483647
 xor r10d,r10d
 xor r8d,r8d
 xor r9d,r9d
 mov eax,202
 syscall
 cmp rax,-4095
 jb .Lbind_done
 cmp dword ptr [rsp+256],0
 jne .Lbind_done
 movabs rdx,0x3152564c4c414948
 cmp [r14+1024],rdx
 jne .Lbind_done
 cmp qword ptr [r14+1032],0
 jne .Lbind_done
 mov qword ptr [r14+1032],11
 neg rax
 mov [r14+1040],rax
.Lbind_done:
 mov eax,[rsp+256]
 jmp .Lbind_epilogue
.Lbind_bad_unlocked:
 mov eax,0xfffffffd
 jmp .Lbind_epilogue
.Lbind_busy_unlocked:
 mov eax,0xfffffffc
.Lbind_epilogue:
 add rsp,280
 pop r15
 pop r14
 pop r13
 pop r12
 pop rbp
 pop rbx
 ret
.size hia_program_llvm_public_log_bind_owner,.-hia_program_llvm_public_log_bind_owner
.section .note.GNU-stack,"",@progbits
