/* Mechanical bridge for the independently emitted complete HIA reference VM.
 * plan: six SysV borrowed-view words -> original Core word-array ABI.
 * run: the existing owned-reference adapter already supplies word/result arrays.
 * Memory primitives and abort carry no VM or language operation semantics. */
.intel_syntax noprefix
.section .entry,"ax",@progbits
.global cold_reference_plan,cold_reference_run
.type cold_reference_plan,@function
cold_reference_plan:
 push rbp
 mov rbp,rsp
 sub rsp,64
 mov [rsp],rdi
 mov [rsp+8],rsi
 mov [rsp+16],rdx
 mov [rsp+24],rcx
 mov [rsp+32],r8
 mov [rsp+40],r9
 mov qword ptr [rsp+48],0
 mov rdi,rsp
 lea rsi,[rsp+48]
 call __hia_native_fn_0
 mov eax,[rsp+48]
 leave
 ret
.size cold_reference_plan,.-cold_reference_plan
.type cold_reference_run,@function
cold_reference_run:
 jmp __hia_native_fn_3
.size cold_reference_run,.-cold_reference_run
.section .text,"ax",@progbits
.global memcpy,memset,abort
.type memcpy,@function
memcpy:
 mov rax,rdi
 mov rcx,rdx
 cld
 rep movsb
 ret
.size memcpy,.-memcpy
.type memset,@function
memset:
 mov r8,rdi
 mov rcx,rdx
 mov eax,esi
 cld
 rep stosb
 mov rax,r8
 ret
.size memset,.-memset
.type abort,@function
abort:
 sub rsp,64
 xor eax,eax
 mov [rsp],rax
 mov [rsp+8],rax
 mov [rsp+16],rax
 mov [rsp+24],rax
 mov qword ptr [rsp+32],32
 mov edi,1
 lea rsi,[rsp+32]
 xor edx,edx
 mov r10d,8
 mov eax,14
 syscall
 mov edi,6
 mov rsi,rsp
 xor edx,edx
 mov r10d,8
 mov eax,13
 syscall
 mov eax,39
 syscall
 mov edi,eax
 mov eax,186
 syscall
 mov esi,eax
 mov edx,6
 mov eax,234
 syscall
 mov edi,134
 mov eax,231
 syscall
 ud2
.size abort,.-abort
.section .note.GNU-stack,"",@progbits
