.intel_syntax noprefix
.text
.global _start, policy_hole, dlopen_hole, dlsym_hole, dlclose_hole
# Fixed Linux/SysV transport for the HIA continuation policy. The policy owns
# frame admission, limits, control flow and response bytes. The three GOT
# entries are resolved by the ordinary system dynamic loader; the payload is
# the exact GNU-ld-produced shared object, never substituted with flat code.
_start:
 mov rax, [rsp]
 sub rsp, 256
 mov [rsp+24], rax
 xor r12d, r12d
 xor r15d, r15d
 xor ebx, ebx
 xor ebp, ebp
 mov qword ptr [rsp], 0
 mov qword ptr [rsp+8], 0
 mov qword ptr [rsp+16], -1
 mov esi, 4096
 call map_rw
 cmp rax, -4095
 jae bridge_failure
 mov r14, rax
 lea r13, [rax+512]
 mov rax, [rsp+24]
 mov [r14+8], rax
policy_loop:
 mov rdi, r12
 mov rsi, [rsp]
 mov rdx, r13
 mov ecx, 512
 mov r8, r14
 mov r9d, 512
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
 je prepare_buffers
 cmp eax, 6
 je call_entry
 cmp eax, 7
 je write_observation
 cmp eax, 8
 je close_image
 jmp bridge_failure
feedback:
 mov [r14+16], rax
 jmp policy_loop
initialize:
 mov edi, 4
 mov rsi, [r13+56]
 mov eax, 157
 syscall
 test rax, rax
 jne feedback
 mov edi, 3
 mov eax, 157
 syscall
 test rax, rax
 jne feedback
 mov edi, 4
 mov rsi, [r13+48]
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
 mov edi, 3
 mov rsi, [r13+24]
 call set_limit
 test rax, rax
 jne feedback
 mov edi, 1
 mov rsi, [r13+32]
 call set_limit
 test rax, rax
 jne feedback
 mov edi, 7
 mov rsi, [r13+40]
 call set_limit
 test rax, rax
 jne feedback
 mov rsi, [r13]
 call map_rw
 cmp rax, -4095
 jae feedback
 mov r12, rax
 mov qword ptr [rsp], 0
read_frame:
 mov rdx, [r13]
 sub rdx, [rsp]
 je read_complete
 lea rsi, [r12]
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
 xor eax, eax
 jmp feedback
open_image:
 lea rdi, [r13+64]
 mov rsi, [r13]
 .byte 0xff, 0x15
dlopen_hole:
 .long 0
 mov r15, rax
 jmp feedback
find_entry:
 mov rdi, r15
 lea rsi, [r13+64]
 .byte 0xff, 0x15
dlsym_hole:
 .long 0
 mov rbx, rax
 mov [r14+32], rax
 mov rdi, [rsp+16]
 mov eax, 3
 syscall
 mov qword ptr [rsp+16], -1
 jmp feedback
prepare_buffers:
 mov rsi, [r13+8]
 test rsi, rsi
 jne workspace_extent
 inc rsi
workspace_extent:
 call map_rw
 cmp rax, -4095
 jae feedback
 mov [rsp+8], rax
 mov rdi, rax
 mov rcx, [r13+8]
 mov al, byte ptr [r13+16]
 cld
 rep stosb
 mov rsi, [r13]
 test rsi, rsi
 jne output_extent
 inc rsi
output_extent:
 cmp qword ptr [r13+40], 0
 jne private_output
 xor edi, edi
 mov edx, 3
 mov r10d, 1
 mov r8, [r13+24]
 xor r9d, r9d
 mov eax, 9
 syscall
 cmp rax, -4095
 jae feedback
 mov rbp, rax
 xor eax, eax
 jmp feedback
private_output:
 call map_rw
 cmp rax, -4095
 jae feedback
 mov rbp, rax
 mov rdi, rax
 mov rcx, [r13]
 mov al, byte ptr [r13+32]
 cld
 rep stosb
 xor eax, eax
 jmp feedback
call_entry:
 mov edi, 1
 lea rsi, [rsp+128]
 mov eax, 228
 syscall
 test rax, rax
 jne feedback
 mov rdi, r12
 add rdi, [r13]
 mov rsi, [r13+8]
 mov rdx, rbp
 mov rcx, [r13+16]
 mov r8, [rsp+8]
 mov r9, [r13+24]
 call rbx
 mov [r14+56], rax
 mov edi, 1
 lea rsi, [rsp+144]
 mov eax, 228
 syscall
 test rax, rax
 jne feedback
 mov rax, [rsp+128]
 mov [r14+24], rax
 mov rax, [rsp+136]
 mov [r14+32], rax
 mov rax, [rsp+144]
 mov [r14+40], rax
 mov rax, [rsp+152]
 mov [r14+48], rax
 xor eax, eax
 jmp feedback
write_observation:
 mov edi, 1
 lea rsi, [r13+128]
 mov edx, 24
 call write_all_fd
 test rax, rax
 jne feedback
 mov edi, 1
 mov rsi, r12
 add rsi, [r13]
 mov rdx, [r13+8]
 call write_all_fd
 test rax, rax
 jne feedback
 mov edi, 1
 mov rsi, rbp
 mov rdx, [r13+16]
 call write_all_fd
 test rax, rax
 jne feedback
 mov edi, 1
 mov rsi, [rsp+8]
 mov rdx, [r13+24]
 call write_all_fd
 jmp feedback
close_image:
 mov rdi, r15
 .byte 0xff, 0x15
dlclose_hole:
 .long 0
 jmp feedback
policy_exit:
 mov rdi, [r13]
 jmp exit
bridge_failure:
 mov edi, 70
exit:
 mov eax, 60
 syscall
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
 js write_done
 je short_write
 add rsi, rax
 sub rdx, rax
 jmp write_all_fd
short_write:
 mov rax, -5
 ret
write_done:
 test rdx, rdx
 jne write_return
 xor eax, eax
write_return:
 ret
image_name:
 .asciz "hia-linked-image"
