/* Fixed original reference-VM mechanical memory and SIGABRT primitives.
 * No VM instruction or language policy is implemented here.
 * The generated HIA closed linker embeds these exact bytes.
 */
.intel_syntax noprefix
.section .text,"ax",@progbits
.global _start,cold_reference_text
_start:
 jmp cold_reference_text
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
 .p2align 4
cold_reference_text:
.section .note.GNU-stack,"",@progbits
