# Mechanical Linux/libc/SysV adapter for a HIA-owned scalar export observer.
# HIA owns wire admission, resource values, call order, names, arguments and
# response bytes. This fixed adapter never parses JSON or decides expected values.
.intel_syntax noprefix
.text
.global _start, policy_hole
.type _start,@function
_start:
 xor ebp, ebp
 mov r9, rdx
 pop rsi
 mov rdx, rsp
 and rsp, -16
 push rax
 push rsp
 xor r8d, r8d
 xor ecx, ecx
 lea rdi, [rip+main]
 call __libc_start_main@PLT
 ud2
.size _start, .-_start
main:
 sub rsp, 184
 mov [rsp+24], rdi
 xor r12d, r12d
 xor r15d, r15d
 xor ebx, ebx
 mov qword ptr [rsp], 0
 mov qword ptr [rsp+16], -1
 mov esi, 69632
 call map_rw
 cmp rax, -4095
 jae bridge_failure
 mov r14, rax
 lea r13, [rax+65536]
 mov rax, [rsp+24]
 mov [r14+8], rax
policy_loop:
 mov rdi, r12
 mov rsi, [rsp]
 mov rdx, r13
 mov ecx, 512
 mov r8, r14
 mov r9d, 65536
 .byte 0xe8
policy_hole:
 .long 0
 cmp eax, 0
 je policy_exit
 cmp eax, 1
 je initialize
 cmp eax, 2
 je seal_image
 cmp eax, 3
 je open_image
 cmp eax, 4
 je find_entry
 cmp eax, 5
 je call_scalar
 cmp eax, 6
 je publish
 cmp eax, 7
 je loader_diagnostic
 jmp bridge_failure
feedback:
 mov [r14+16], rax
 jmp policy_loop
initialize:
 mov edi, 4
 mov rsi, [r13+24]
 call set_limit
 test rax, rax
 jne feedback
 xor edi, edi
 mov rsi, [r13+8]
 call set_limit
 test rax, rax
 jne feedback
 mov edi, 9
 mov rsi, [r13+16]
 call set_limit
 test rax, rax
 jne feedback
 mov rsi, [r13]
 call map_rw
 cmp rax, -4095
 jae feedback
 mov r12, rax
read_frame:
 mov rdx, [r13]
 sub rdx, [rsp]
 je read_complete
 mov rsi, r12
 add rsi, [rsp]
 xor edi, edi
 xor eax, eax
 syscall
 cmp rax, -4
 je read_frame
 test rax, rax
 js feedback
 je read_complete
 add [rsp], rax
 jmp read_frame
read_complete:
 xor eax, eax
 jmp feedback
seal_image:
 lea rdi, [rip+image_name]
 mov rsi, [r13+16]
 mov eax, 319
 syscall
 test rax, rax
 js feedback
 mov [rsp+16], rax
 mov [r14+24], rax
 mov rdi, rax
 mov rsi, r12
 add rsi, [r13]
 mov rdx, [r13+8]
 call write_all_fd
 test rax, rax
 jne feedback
 mov rdi, [rsp+16]
 mov esi, 1033
 mov rdx, [r13+24]
 mov eax, 72
 syscall
 test rax, rax
 jne feedback
 mov rdi, [rsp+16]
 mov esi, 1034
 xor edx, edx
 mov eax, 72
 syscall
 mov [r14+32], rax
 test rax, rax
 js feedback
 xor eax, eax
 jmp feedback
open_image:
 lea rdi, [r13+64]
 mov rsi, [r13]
 call dlopen@PLT
 mov r15, rax
 jmp feedback
find_entry:
 mov rdi, r15
 lea rsi, [r13+64]
 call dlsym@PLT
 mov rbx, rax
 jmp feedback
call_scalar:
 # Fixed SysV layout: six register arguments, ten stack arguments. HIA has
 # already checked argc0..16 and supplied zero in every unused physical slot.
 # Always reserving all ten slots preserves16-byte alignment for every argc.
 sub rsp, 80
 mov rax, [r13+48]
 mov [rsp], rax
 mov rax, [r13+56]
 mov [rsp+8], rax
 mov rax, [r13+64]
 mov [rsp+16], rax
 mov rax, [r13+72]
 mov [rsp+24], rax
 mov rax, [r13+80]
 mov [rsp+32], rax
 mov rax, [r13+88]
 mov [rsp+40], rax
 mov rax, [r13+96]
 mov [rsp+48], rax
 mov rax, [r13+104]
 mov [rsp+56], rax
 mov rax, [r13+112]
 mov [rsp+64], rax
 mov rax, [r13+120]
 mov [rsp+72], rax
 mov rdi, [r13]
 mov rsi, [r13+8]
 mov rdx, [r13+16]
 mov rcx, [r13+24]
 mov r8, [r13+32]
 mov r9, [r13+40]
 xor eax, eax
 call rbx
 add rsp, 80
 mov [r14+56], rax
 xor eax, eax
 jmp feedback
publish:
 mov edi, 1
 mov rsi, r14
 add rsi, [r13]
 mov rdx, [r13+8]
 call write_all_fd
 jmp feedback
loader_diagnostic:
 call dlerror@PLT
 test rax, rax
 je diagnostic_done
 mov rsi, rax
 xor edx, edx
diagnostic_length:
 cmp byte ptr [rsi+rdx], 0
 je diagnostic_write
 inc rdx
 jmp diagnostic_length
diagnostic_write:
 mov edi, 2
 call write_all_fd
 test rax, rax
 jne feedback
 mov edi, 2
 lea rsi, [rip+newline]
 mov edx, 1
 call write_all_fd
 jmp feedback
diagnostic_done:
 xor eax, eax
 jmp feedback
policy_exit:
 mov rdi, [r13]
 jmp libc_exit
bridge_failure:
 mov edi, 70
libc_exit:
 and rsp, -16
 call exit@PLT
 ud2
set_limit:
 mov [rsp-16], rsi
 mov [rsp-8], rsi
 mov esi, edi
 xor edi, edi
 lea rdx, [rsp-16]
 xor r10d, r10d
 mov eax, 302
 syscall
 ret
map_rw:
 xor edi, edi
 mov edx, 3
 mov r10d, 34
 mov r8, -1
 xor r9d, r9d
 mov eax, 9
 syscall
 ret
write_all_fd:
 test rdx, rdx
 je write_done
 mov eax, 1
 syscall
 cmp rax, -4
 je write_all_fd
 test rax, rax
 js write_return
 je write_zero
 add rsi, rax
 sub rdx, rax
 jmp write_all_fd
write_zero:
 mov rax, -5
 ret
write_done:
 xor eax, eax
write_return:
 ret
image_name:
 .asciz "hia-cold-export-target"
newline:
 .byte 10
.section .note.GNU-stack,"",@progbits
