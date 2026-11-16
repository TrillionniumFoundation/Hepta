# Independent GNU assembler oracle for the fixed Linux/SysV foreign bridge.
# The HIA policy owns admission, limits, actions and terminal status. The HIA
# packer embeds actual policy bytes and emits the complete relocatable object.
# This assembly is a test/authoring reference, never read by an observer child.
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
 mov eax, edi
 sub rsp, 264
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
 je commit_snapshot
 cmp eax, 9
 je loader_diagnostic
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
 # Both the full signed syscall result and seals reach the HIA continuation.
 # No negative errno is masked into a superficially valid seal word.
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
commit_snapshot:
 # HIA selected this action only after f0 returned and the ending clock was
 # captured. Publish the full payload before the capacity+1 completion marker.
 mov rdi, [r13+32]
 mov rsi, rbp
 mov rdx, [r13+16]
 mov r10d, 8
 call pwrite_all_fd
 test rax, rax
 jne feedback
 mov rax, [r13+40]
 mov [rsp+160], rax
 mov rdi, [r13+32]
 lea rsi, [rsp+160]
 mov edx, 8
 xor r10d, r10d
 call pwrite_all_fd
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
loader_diagnostic:
 call dlerror@PLT
 test rax, rax
 je diagnostic_close
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
 test rax, rax
 jne feedback
diagnostic_close:
 cmp qword ptr [rsp+16], -1
 je diagnostic_complete
 mov rdi, [rsp+16]
 mov eax, 3
 syscall
 mov qword ptr [rsp+16], -1
 jmp feedback
diagnostic_complete:
 xor eax, eax
 jmp feedback
policy_exit:
 mov rdi, [r13]
 jmp native_exit
bridge_failure:
 mov edi, 70
native_exit:
 # No early dlclose and no terminal exit syscall. libc retains the registered
 # rtld finalizer, DSO lifetime, process exit callbacks and real exit signals.
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
pwrite_all_fd:
 test rdx, rdx
 je pwrite_done
 mov eax, 18
 syscall
 cmp rax, -4
 je pwrite_all_fd
 test rax, rax
 js pwrite_done
 je short_pwrite
 add rsi, rax
 add r10, rax
 sub rdx, rax
 jmp pwrite_all_fd
short_pwrite:
 mov rax, -5
 ret
pwrite_done:
 test rdx, rdx
 jne pwrite_return
 xor eax, eax
pwrite_return:
 ret
image_name:
 .asciz "hia-linked-image"
newline:
 .byte 10
.section .note.GNU-stack,"",@progbits
