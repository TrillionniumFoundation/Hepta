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
 mov edx, 5242929
 sub rdx, rbx
 syscall
 cmp rax, -4
 je reading
 test rax, rax
 js io_error
 je read_done
 add rbx, rax
 cmp rbx, 5242928
 ja capacity_error
 jmp reading
read_done:
 cmp rbx, 48
 jb invalid_frame
 mov rax, 0x313053424f414948
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
 add rax, 48
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
 mov rsi, [rsp+16]
 call map_rw
 mov r13, rax
 mov rdi, rax
 lea rsi, [r12+48]
 mov rcx, [rsp+16]
 cld
 rep movsb
 mov rdi, r13
 mov rsi, [rsp+16]
 mov edx, 5
 mov eax, 10
 syscall
 test rax, rax
 jne io_error
 mov esi, 2097152
 call map_rw
 mov r14, rax
 lea r15, [rax+1048576]
 mov rdi, r14
 mov rcx, [rsp+32]
 mov al, 165
 rep stosb
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
 lea rdi, [r12+rdi+48]
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
 mov rax, 0x313052424f414948
 mov [rsp+96], rax
 lea rsi, [rsp+96]
 mov edx, 24
 call write_all
 mov rsi, [rsp+16]
 lea rsi, [r12+rsi+48]
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
bad_argument:
 mov edi, 64
exit:
 mov eax, 60
 syscall
 ud2
