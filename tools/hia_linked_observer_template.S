.intel_syntax noprefix
.text
.global _start
_start:
 cmp qword ptr [rsp], 1
 jne bad_argument
 sub rsp, 256
 # Match the retained disposable Python loader's actual resource limits.
 mov edi, 4
 xor esi, esi
 mov eax, 157
 syscall
 test rax, rax
 jne io_error
 mov edi, 3
 mov eax, 157
 syscall
 test rax, rax
 jne io_error
 mov edi, 4
 xor esi, esi
 call set_limit
 mov edi, 0
 mov esi, 10
 call set_limit
 mov edi, 9
 mov esi, 268435456
 call set_limit
 mov edi, 3
 mov esi, 8388608
 call set_limit
 mov edi, 1
 mov esi, 16777216
 call set_limit
 mov edi, 7
 mov esi, 32
 call set_limit
 mov esi, 6291456
 call map_rw
 mov r12, rax
 xor ebx, ebx
reading:
 xor eax, eax
 xor edi, edi
 lea rsi, [r12+rbx]
 mov edx, 5242937
 sub rdx, rbx
 syscall
 cmp rax, -4
 je reading
 test rax, rax
 js io_error
 je read_done
 add rbx, rax
 cmp rbx, 5242936
 ja capacity_error
 jmp reading
read_done:
 cmp rbx, 56
 jb invalid_frame
 mov rax, 0x313053444c414948
 cmp [r12], rax
 jne invalid_frame
 mov rax, [r12+8]
 test rax, rax
 je invalid_frame
 cmp rax, 4194304
 ja invalid_frame
 mov [rsp+16], rax
 mov rcx, [r12+16]
 cmp rcx, 1048576
 ja invalid_frame
 mov [rsp+24], rcx
 add rax, rcx
 add rax, 56
 cmp rax, rbx
 jne invalid_frame
 mov rax, [r12+24]
 cmp rax, 1048576
 ja invalid_frame
 mov [rsp+32], rax
 mov rax, [r12+32]
 cmp rax, 1048576
 ja invalid_frame
 mov [rsp+40], rax
 cmp qword ptr [r12+40], 255
 ja invalid_frame
 mov rax, [r12+48]
 cmp rax, -1
 je valid_output_fd
 cmp rax, 3
 jb invalid_frame
 cmp rax, 2147483647
 ja invalid_frame
valid_output_fd:
 # Load the exact supplied ELF bytes through the system dynamic loader.
 # The memfd is sealed against all writes and extent changes before dlopen.
 lea rdi, [rip+image_name]
 mov esi, 2
 mov eax, 319
 syscall
 test rax, rax
 js io_error
 mov [rsp+120], rax
 lea rsi, [r12+56]
 mov rdx, [rsp+16]
image_write:
 mov rdi, [rsp+120]
 mov eax, 1
 syscall
 cmp rax, -4
 je image_write
 test rax, rax
 jle io_error
 add rsi, rax
 sub rdx, rax
 jne image_write
 mov rdi, [rsp+120]
 mov esi, 1033
 mov edx, 15
 mov eax, 72
 syscall
 test rax, rax
 jne io_error
 mov rdi, [rsp+120]
 mov esi, 1034
 xor edx, edx
 mov eax, 72
 syscall
 test rax, rax
 js io_error
 and eax, 15
 cmp eax, 15
 jne io_error
 # Decimal path in private stack storage; fd is nonnegative and below 32.
 lea rdi, [rsp+160]
 lea rsi, [rip+proc_prefix]
 mov ecx, 14
 cld
 rep movsb
 mov rax, [rsp+120]
 xor edx, edx
 mov ecx, 10
 div rcx
 test rax, rax
 je one_digit
 add al, 48
 stosb
one_digit:
 mov eax, edx
 add al, 48
 stosb
 xor eax, eax
 stosb
 lea rdi, [rsp+160]
 mov esi, 2
 call qword ptr [rip+dlopen_slot]
 test rax, rax
 je loader_error
 mov rdi, rax
 lea rsi, [rip+entry_name]
 call qword ptr [rip+dlsym_slot]
 test rax, rax
 je loader_error
 mov r13, rax
 mov rdi, [rsp+120]
 mov eax, 3
 syscall
 test rax, rax
 jne io_error
 mov esi, 1048576
 call map_rw
 mov r15, rax
 mov rsi, [rsp+32]
 test rsi, rsi
 jne output_extent
 inc rsi
output_extent:
 mov r8, [r12+48]
 cmp r8, -1
 jne output_shared
 call map_rw
 mov r14, rax
 mov rdi, r14
 mov rcx, [rsp+32]
 mov al, 165
 rep stosb
 jmp output_ready
output_shared:
 xor edi, edi
 mov edx, 3
 mov r10d, 1
 xor r9d, r9d
 mov eax, 9
 syscall
 cmp rax, -4095
 jae io_error
 mov r14, rax
output_ready:
 mov rdi, r15
 mov rcx, [rsp+40]
 mov al, [r12+40]
 rep stosb
 mov edi, 1
 lea rsi, [rsp+64]
 mov eax, 228
 syscall
 test rax, rax
 jne io_error
 # Fresh native image, standard six-argument public byte ABI.
 mov rdi, [rsp+16]
 lea rdi, [r12+rdi+56]
 mov rsi, [rsp+24]
 mov rdx, r14
 mov rcx, [rsp+32]
 mov r8, r15
 mov r9, [rsp+40]
 call r13
 mov [rsp+104], rax
 mov edi, 1
 lea rsi, [rsp+80]
 mov eax, 228
 syscall
 test rax, rax
 jne io_error
 mov rax, [rsp+80]
 sub rax, [rsp+64]
 imul rax, rax, 1000000000
 add rax, [rsp+88]
 sub rax, [rsp+72]
 mov [rsp+112], rax
 mov rax, 0x313052444c414948
 mov [rsp+96], rax
 lea rsi, [rsp+96]
 mov edx, 24
 call write_all
 mov rsi, [rsp+16]
 lea rsi, [r12+rsi+56]
 mov rdx, [rsp+24]
 call write_all
 mov rsi, r14
 mov rdx, [rsp+32]
 call write_all
 mov rsi, r15
 mov rdx, [rsp+40]
 call write_all
 xor edi, edi
 jmp exit
set_limit:
 # caller resource in edi, exact hard and soft bound in esi
 mov [rsp-16], rsi
 mov [rsp-8], rsi
 mov esi, edi
 xor edi, edi
 lea rdx, [rsp-16]
 xor r10d, r10d
 mov eax, 302
 syscall
 test rax, rax
 jne io_error
 ret
map_rw:
 xor edi, edi
 mov edx, 3
 mov r10d, 34
 mov r8, -1
 xor r9d, r9d
 mov eax, 9
 syscall
 cmp rax, -4095
 jae io_error
 ret
write_all:
 test rdx, rdx
 je write_done
 mov eax, 1
 mov edi, 1
 syscall
 cmp rax, -4
 je write_all
 test rax, rax
 jle io_error
 add rsi, rax
 sub rdx, rax
 jmp write_all
write_done:
 ret
invalid_frame:
 mov edi, 2
 jmp exit
capacity_error:
 mov edi, 3
 jmp exit
io_error:
 mov edi, 4
 jmp exit
loader_error:
 mov edi, 5
 jmp exit
bad_argument:
 mov edi, 64
exit:
 mov eax, 60
 syscall
 ud2

image_name:
 .asciz "hia-linked-successor"
proc_prefix:
 .ascii "/proc/self/fd/"
entry_name:
 .asciz "f0"
.extern dlopen_slot
.extern dlsym_slot
.section .note.GNU-stack,"",@progbits
