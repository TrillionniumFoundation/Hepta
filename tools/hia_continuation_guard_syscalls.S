/* Fixed Linux x86-64 standard-stream ABI for a linked HIA continuation packer.
 * Input contains only the aggregate, its extent and the requested output capacity.
 * The packer and the guard checker are linked instructions in a read-only PT_LOAD.
 */
.intel_syntax noprefix
.text
.global _start, pack_call_hole, check_call_hole
.equ MAX_BYTES, 67108864
.equ WORK_BYTES, 1048576
.equ SOURCE, 80
.equ OUTPUT, 104
.equ WORK, 128
.equ ORIGINAL, 152
.equ USED, 160
.equ START_TIME, 168
.equ CHECK_MODE, 200

_start:
 cmp qword ptr [rsp], 1
 jne refused
 sub rsp, 256
 mov rbp, rsp
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
 xor edi, edi
 mov esi, 10
 call set_limit
 mov edi, 9
 mov esi, 536870912
 call set_limit
 mov edi, 1
 mov esi, 68157440
 call set_limit

 mov rsi, rbp
 mov edx, 32
 call read_exact
 movabs rax, 0x3155475443414948
 cmp [rbp], rax
 jne refused
 cmp qword ptr [rbp+24], 0
 jne refused
 mov rsi, [rbp+8]
 test rsi, rsi
 jz refused
 cmp rsi, MAX_BYTES
 ja refused
 lea rdi, [rbp+SOURCE]
 xor edx, edx
 call guarded_region
 mov rsi, [rbp+16]
 test rsi, rsi
 jz refused
 cmp rsi, MAX_BYTES
 ja refused
 lea rdi, [rbp+OUTPUT]
 mov edx, 165
 call guarded_region
 lea rdi, [rbp+WORK]
 mov esi, WORK_BYTES
 xor edx, edx
 call guarded_region

 mov rsi, [rbp+SOURCE]
 add rsi, 32
 mov rdx, [rbp+SOURCE+8]
 call read_exact
read_eof:
 xor eax, eax
 xor edi, edi
 lea rsi, [rbp+64]
 mov edx, 1
 syscall
 cmp rax, -4
 je read_eof
 test rax, rax
 jnz refused
 mov rdi, [rbp+SOURCE]
 mov rsi, [rbp+SOURCE+16]
 mov edx, 1
 mov eax, 10
 syscall
 test rax, rax
 jne io_error
 /* Keep an independent read-only preimage through the call. */
 mov rsi, [rbp+SOURCE+8]
 mov edx, 3
 call map_region
 mov [rbp+ORIGINAL], rax
 mov rdi, rax
 mov rsi, [rbp+SOURCE]
 add rsi, 32
 mov rcx, [rbp+SOURCE+8]
 rep movsb
 mov rdi, [rbp+ORIGINAL]
 mov rsi, [rbp+SOURCE+8]
 mov edx, 1
 mov eax, 10
 syscall
 test rax, rax
 jne io_error

 call clock_ns
 mov [rbp+START_TIME], rax
 mov rdi, [rbp+SOURCE]
 add rdi, 32
 mov rsi, [rbp+SOURCE+8]
 mov rdx, [rbp+OUTPUT]
 add rdx, 32
 mov rcx, [rbp+OUTPUT+8]
 mov r8, [rbp+WORK]
 add r8, 32
 mov r9d, WORK_BYTES
 .byte 0xe8
pack_call_hole: .long 0
 test rax, rax
 jz refused
 cmp rax, [rbp+OUTPUT+8]
 ja refused
 mov [rbp+USED], rax
 call clock_ns
 sub rax, [rbp+START_TIME]
 mov [rbp+16], rax

 mov qword ptr [rbp+CHECK_MODE], 2
 mov rdi, [rbp+SOURCE]
 add rdi, 32
 mov rsi, [rbp+SOURCE+8]
 mov rdx, [rbp+ORIGINAL]
 mov rcx, rsi
 call check_bytes
 lea rdi, [rbp+SOURCE]
 call check_region
 lea rdi, [rbp+OUTPUT]
 call check_region
 lea rdi, [rbp+WORK]
 call check_region
 mov rdi, [rbp+OUTPUT]
 add rdi, 32
 add rdi, [rbp+USED]
 mov rsi, [rbp+OUTPUT+8]
 sub rsi, [rbp+USED]
 mov eax, 165
 call check_fill

 movabs rax, 0x314b4f5443414948
 mov [rbp], rax
 mov rax, [rbp+USED]
 mov [rbp+8], rax
 mov rsi, rbp
 mov edx, 24
 call write_all
 mov rsi, [rbp+OUTPUT]
 add rsi, 32
 mov rdx, [rbp+OUTPUT+8]
 call write_all
 xor edi, edi
 jmp finish

/* Each descriptor holds accessible-page base, logical length, and rounded span. */
guarded_region:
 push rbx
 push r12
 push r13
 mov r12, rdi
 mov r13, rsi
 mov ebx, edx
 mov [r12+8], rsi
 add rsi, 4159
 and rsi, -4096
 mov [r12+16], rsi
 add rsi, 8192
 xor edx, edx
 call map_region
 lea rdi, [rax+4096]
 mov [r12], rdi
 mov rsi, [r12+16]
 mov edx, 3
 mov eax, 10
 syscall
 test rax, rax
 jne io_error
 mov rdi, [r12]
 mov rcx, [r12+16]
 mov al, 109
 rep stosb
 mov rdi, [r12]
 add rdi, 32
 mov rcx, r13
 mov eax, ebx
 rep stosb
 pop r13
 pop r12
 pop rbx
 ret

check_region:
 push r12
 mov r12, rdi
 mov rdi, [r12]
 mov esi, 32
 mov eax, 109
 call check_fill
 mov rdi, [r12]
 add rdi, 32
 add rdi, [r12+8]
 mov rsi, [r12+16]
 sub rsi, 32
 sub rsi, [r12+8]
 mov eax, 109
 call check_fill
 pop r12
 ret

check_fill:
 mov qword ptr [rbp+CHECK_MODE], 1
 mov [rbp+CHECK_MODE+8], rax
 xor edx, edx
 xor ecx, ecx
check_bytes:
 lea r8, [rbp+CHECK_MODE]
 mov r9d, 16
 /* Internal callers arrive with differing depths. Keep the HIA SysV call aligned. */
 push rbx
 mov rbx, rsp
 and rsp, -16
 .byte 0xe8
check_call_hole: .long 0
 mov rsp, rbx
 pop rbx
 test rax, rax
 jne refused
 ret

clock_ns:
 mov edi, 1
 lea rsi, [rbp+40]
 mov eax, 228
 syscall
 test rax, rax
 jnz io_error
 imul rax, qword ptr [rbp+40], 1000000000
 add rax, [rbp+48]
 ret
set_limit:
 mov [rbp+40], rsi
 mov [rbp+48], rsi
 lea rsi, [rbp+40]
 mov eax, 160
 syscall
 test rax, rax
 jne io_error
 ret
map_region:
 xor edi, edi
 mov r10d, 34
 mov r8, -1
 xor r9d, r9d
 mov eax, 9
 syscall
 cmp rax, -4095
 jae io_error
 ret
read_exact:
 test rdx, rdx
 jz transfer_done
 xor edi, edi
 xor eax, eax
 syscall
 cmp rax, -4
 je read_exact
 test rax, rax
 jle refused
 add rsi, rax
 sub rdx, rax
 jmp read_exact
write_all:
 test rdx, rdx
 jz transfer_done
 mov edi, 1
 mov eax, 1
 syscall
 cmp rax, -4
 je write_all
 test rax, rax
 jle io_error
 add rsi, rax
 sub rdx, rax
 jmp write_all
transfer_done:
 ret
refused:
 mov edi, 16
 jmp finish
io_error:
 mov edi, 15
finish:
 mov eax, 60
 syscall
 ud2
