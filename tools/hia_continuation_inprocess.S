
.intel_syntax noprefix
.text
.equ PW,4096
.equ PW_BYTES,65536
.equ UNIT_WORK,69632
.equ TOTAL_WORK,1118208
.global _start,policy_hole,metadata_hole,metadata_size_hole
_start:
.Lentry_base:
 push rbp
 push rbx
 push r12
 push r13
 push r14
 push r15
 sub rsp,56
 mov [rsp],rdi
 mov [rsp+8],rsi
 mov [rsp+16],rdx
 mov [rsp+24],rcx
 mov [rsp+32],r8
 mov [rsp+40],r9
 cmp rsi,128
 jne abi_refuse
 cmp rcx,1048576
 jb abi_refuse
 cmp r9,TOTAL_WORK
 jb abi_refuse
 test rdi,rdi
 jz abi_refuse
 test rdx,rdx
 jz abi_refuse
 test r8,r8
 jz abi_refuse
 mov rbx,r8
 lea r12,[rip+.Lentry_base]
 cmp QWORD PTR [rbx+PW],0
 jne resume
 mov QWORD PTR [rbx+PW+16],1
 mov rdi,r12
 .byte 0x48,0x81,0xc7
metadata_hole:.long 0
 .byte 0xbe
metadata_size_hole:.long 0
 jmp policy_next
resume:
 lea rdi,[rbx]
 xor esi,esi
policy_next:
 call policy_call
 cmp rax,1
 je image_call
 cmp rax,2
 je use_packet
 cmp rax,3
 je return_event
 jmp finish
image_call:
 mov rax,r12
 add rax,[rbx+PW+136]
 mov rdi,[rsp]
 cmp QWORD PTR [rbx+PW+168],0
 je image_input_ready
 lea rdi,[rbx+PW+2048]
image_input_ready:
 mov rsi,[rbx+PW+144]
 mov rdx,[rsp+16]
 mov rcx,[rbx+PW+152]
 lea r8,[rbx+UNIT_WORK]
 mov r9,[rbx+PW+160]
 call rax
 mov [rbx+PW+8],rax
 mov rdi,[rsp+16]
 mov rsi,[rbx+PW+152]
 jmp policy_next
use_packet:
 mov rdi,[rsp]
 mov rsi,[rsp+8]
 jmp policy_next
return_event:
 mov rax,[rbx+8]
 test rax,rax
 jnz finish
 /* Commit the HIA-chosen terminal phase before the caller sees a result. */
 lea rdi,[rbx]
 xor esi,esi
 call policy_call
 jmp finish
policy_call:
 lea rdx,[rbx]
 mov ecx,128
 lea r8,[rbx+PW]
 mov r9d,PW_BYTES
 sub rsp,8
 .byte 0xe8
policy_hole:.long 0
 add rsp,8
 ret
abi_refuse:
 mov eax,17
finish:
 add rsp,56
 pop r15
 pop r14
 pop r13
 pop r12
 pop rbx
 pop rbp
 ret
