/* Fixed Linux x86-64 OS / three-buffer ABI transport.
 *
 * HIA alone selects actions, source syntax, argument validity, digest operations,
 * compile sequencing, complete ELF profile, package bytes/modes and exit class.
 * This adapter transports one requested syscall or one admitted embedded HIA
 * call. It checks actual allocation bounds before forming any operand address.
 * No source parser, SHA implementation, package serializer, filesystem path,
 * child execution, loader, dynamic linker, retry policy or success receipt lives
 * here. Every ordinary return, including negative errno, reaches HIA unchanged.
 *
 * SysV process entry. Four rel32 holes are filled by the HIA ELF packer.
 */
.intel_syntax noprefix
.text
.global _start, policy_hole, frontend_hole, compiler_hole, sha_hole
.equ SOURCE_BYTES, 8392704
.equ OUTPUT_OFFSET, 8392704
.equ OUTPUT_BYTES, 16777216
.equ POLICY_OFFSET, 25169920
.equ FRONTEND_OFFSET, 25174016
.equ FRONTEND_BYTES, 67112960
.equ SHA_WORK_OFFSET, 92286976
.equ MAPPING_BYTES, 92295168
.equ ASSEMBLY, 4096
.equ CODE, 1052672
.equ SHA_INPUT, 2105344
.equ SHA_OUTPUT, 2174976
.equ PACKAGE, 2228224
.equ PACKAGE_CAPACITY, 9441280
.equ LIMIT, 1048576
.equ WIRE_LIMIT, 8388608
/* Private transport stack: state[4096], early diagnostic[4096], 64 ABI bytes.
 * Captured action/sequence never alias HIA-writable state or output.
 */
.equ CAPTURED_ACTION, 8192
.equ CAPTURED_SEQUENCE, 8200
.equ OUTPUT_CAPACITY, 8208
.equ ABI_REFUSALS, 8216
.equ MAP_LIVE, 8224

_start:
 cld
 mov r15,rsp
 sub rsp,8256
 mov rdi,rsp
 mov ecx,1032
 xor eax,eax
 rep stosq
 mov r13,rsp
 lea r14,[rsp+4096]
 mov r12,rsp
 xor ebp,ebp
 mov QWORD PTR [rsp+OUTPUT_CAPACITY],4096
 mov rax,[r15]
 mov [r13+16],rax
 /* Bounded argv byte capture only. All length/content decisions are HIA. */
 cmp rax,2
 jb args_complete
 mov rsi,[r15+16]
 xor ecx,ecx
capture_mode:
 cmp rcx,16
 jae mode_complete
 mov al,[rsi+rcx]
 test al,al
 jz mode_complete
 mov [r13+rcx+256],al
 inc rcx
 jmp capture_mode
mode_complete:
 mov [r13+24],rcx
 cmp QWORD PTR [r15],3
 jb args_complete
 mov rsi,[r15+24]
 xor ecx,ecx
capture_digest:
 cmp rcx,65
 jae digest_complete
 mov al,[rsi+rcx]
 test al,al
 jz digest_complete
 mov [r13+rcx+320],al
 inc rcx
 jmp capture_digest
digest_complete:
 mov [r13+32],rcx
args_complete:
 mov QWORD PTR [r13],0

policy_next:
 cmp QWORD PTR [r13+80],WIRE_LIMIT
 ja abi_refused
 mov rdi,r12
 mov rsi,[r13+80]
 mov rdx,r14
 mov rcx,[rsp+OUTPUT_CAPACITY]
 mov r8,r13
 mov r9d,4096
 .byte 0xe8
policy_hole: .long 0
 /* Bind the returned command to this invocation's issued state. */
 cmp rax,[r13+64]
 jne abi_refused
 test rax,rax
 jz abi_refused
 cmp rax,11
 ja abi_refused
 cmp QWORD PTR [r13+72],0
 je abi_refused
 mov [rsp+CAPTURED_ACTION],rax
 mov rcx,[r13+72]
 mov [rsp+CAPTURED_SEQUENCE],rcx
 cmp eax,1
 je read_one
 cmp eax,2
 je sha_one
 cmp eax,3
 je frontend_one
 cmp eax,4
 je compile_one
 cmp eax,5
 je write_package_one
 cmp eax,6
 je write_diagnostic_one
 cmp eax,7
 je exit_one
 cmp eax,8
 je protect_source_one
 cmp eax,9
 je signal_one
 cmp eax,10
 je map_one
 jmp protect_package_one

read_one:
 cmp QWORD PTR [rsp+MAP_LIVE],1
 jne abi_refused
 mov rsi,[r13+160]
 cmp rsi,[r13+80]
 jne abi_refused
 cmp rsi,WIRE_LIMIT
 ja abi_refused
 mov rdx,[r13+152]
 test rdx,rdx
 jz abi_refused
 mov eax,WIRE_LIMIT+1
 sub rax,rsi
 cmp rdx,rax
 ja abi_refused
 add rsi,r12
 xor edi,edi
 xor eax,eax
 syscall
 jmp effect_return

sha_one:
 cmp QWORD PTR [rsp+MAP_LIVE],1
 jne abi_refused
 cmp QWORD PTR [r13+160],SHA_INPUT
 jne abi_refused
 mov rsi,[r13+152]
 test rsi,rsi
 jz abi_refused
 cmp rsi,65537
 ja abi_refused
 lea rdi,[r14+SHA_INPUT]
 lea rdx,[r14+SHA_OUTPUT]
 mov ecx,32
 lea r8,[r12+SHA_WORK_OFFSET]
 mov r9d,8192
 .byte 0xe8
sha_hole: .long 0
 jmp effect_return

frontend_one:
 cmp QWORD PTR [rsp+MAP_LIVE],1
 jne abi_refused
 cmp QWORD PTR [r13+160],0
 jne abi_refused
 mov rsi,[r13+152]
 cmp rsi,[r13+80]
 jne abi_refused
 test rsi,rsi
 jz abi_refused
 cmp rsi,WIRE_LIMIT
 ja abi_refused
 /* The fixed three-field configuration is supplied by HIA, not selected here. */
 mov rax,[r13+768]
 mov [rbp+40],rax
 mov rax,[r13+776]
 mov [rbp+48],rax
 mov rax,[r13+784]
 mov [rbp+56],rax
 mov rdi,r12
 lea rdx,[r14+ASSEMBLY]
 mov ecx,LIMIT
 mov r8,rbp
 mov r9d,FRONTEND_BYTES
 .byte 0xe8
frontend_hole: .long 0
 jmp effect_return

compile_one:
 cmp QWORD PTR [rsp+MAP_LIVE],1
 jne abi_refused
 cmp QWORD PTR [r13+160],0
 jne abi_refused
 mov rsi,[r13+152]
 cmp rsi,[r13+88]
 jne abi_refused
 test rsi,rsi
 jz abi_refused
 cmp rsi,LIMIT
 ja abi_refused
 mov rax,[r13+168]
 cmp rax,1
 je compile_raw
 cmp rax,2
 jne abi_refused
 lea rbx,[r14+ASSEMBLY]
 jmp compile_prepared
compile_raw:
 cmp rsi,[r13+80]
 jne abi_refused
 mov rbx,r12
compile_prepared:
 /* The compiler ABI requires a fresh zero 1-MiB workspace. Frontend arena
  * bytes are not valid compiler initialization. This is fixed ABI preparation. */
 mov rdi,rbp
 mov ecx,LIMIT/8
 xor eax,eax
 rep stosq
 mov rdi,rbx
 mov rsi,[r13+152]
 lea rdx,[r14+CODE]
 mov ecx,LIMIT
 mov r8,rbp
 mov r9d,LIMIT
 .byte 0xe8
compiler_hole: .long 0
 jmp effect_return

write_package_one:
 cmp QWORD PTR [rsp+MAP_LIVE],1
 jne abi_refused
 mov rax,[r13+104]
 test rax,rax
 jz abi_refused
 cmp rax,PACKAGE_CAPACITY
 ja abi_refused
 mov rcx,[r13+192]
 cmp rcx,rax
 jae abi_refused
 sub rax,rcx
 cmp rax,[r13+152]
 jne abi_refused
 lea rsi,[rcx+PACKAGE]
 cmp rsi,[r13+160]
 jne abi_refused
 add rsi,r14
 mov rdx,rax
 mov edi,1
 mov eax,1
 syscall
 jmp effect_return

write_diagnostic_one:
 mov rax,[r13+184]
 test rax,rax
 jz abi_refused
 cmp rax,4096
 ja abi_refused
 mov rcx,[r13+224]
 cmp rcx,rax
 jae abi_refused
 sub rax,rcx
 cmp rax,[r13+152]
 jne abi_refused
 cmp rcx,[r13+160]
 jne abi_refused
 lea rsi,[r14+rcx]
 mov rdx,rax
 mov edi,2
 mov eax,1
 syscall
 jmp effect_return

exit_one:
 mov rdi,[r13+176]
 cmp rdi,255
 ja abi_refused
 mov eax,60
 syscall
 ud2

protect_source_one:
 cmp QWORD PTR [rsp+MAP_LIVE],1
 jne abi_refused
 mov rdi,r12
 mov esi,SOURCE_BYTES
 mov edx,1
 mov eax,10
 syscall
 jmp effect_return

signal_one:
 lea rsi,[r13+1024]
 mov edi,13
 xor edx,edx
 mov r10d,8
 mov eax,13
 syscall
 jmp effect_return

map_one:
 cmp QWORD PTR [rsp+MAP_LIVE],0
 jne abi_refused
 xor edi,edi
 mov esi,MAPPING_BYTES
 mov edx,3
 mov r10d,0x22
 mov r8,-1
 xor r9d,r9d
 mov eax,9
 syscall
 /* This branch only decides whether the returned value is an address that
  * may be dereferenced. HIA receives the unchanged syscall result either way. */
 cmp rax,-4095
 jae effect_return
 mov rbx,rax
 lea rdi,[rax+POLICY_OFFSET]
 mov rsi,r13
 mov ecx,512
 rep movsq
 mov r12,rbx
 lea r13,[rbx+POLICY_OFFSET]
 lea r14,[rbx+OUTPUT_OFFSET]
 lea rbp,[rbx+FRONTEND_OFFSET]
 mov QWORD PTR [rsp+OUTPUT_CAPACITY],OUTPUT_BYTES
 mov QWORD PTR [rsp+MAP_LIVE],1
 mov rax,rbx
 jmp effect_return

protect_package_one:
 cmp QWORD PTR [rsp+MAP_LIVE],1
 jne abi_refused
 lea rdi,[r14+PACKAGE]
 mov esi,PACKAGE_CAPACITY
 mov edx,1
 mov eax,10
 syscall

effect_return:
 mov [r13+8],rax
 mov rcx,[rsp+CAPTURED_ACTION]
 mov [r13+40],rcx
 mov rcx,[rsp+CAPTURED_SEQUENCE]
 mov [r13+48],rcx
 mov QWORD PTR [r13],1
 jmp policy_next

abi_refused:
 /* A malformed action is never executed. One HIA refusal request is allowed;
  * if that cannot produce a mechanically valid command, exit 70 without any
  * success output. This last path is transport corruption, not source policy. */
 cmp QWORD PTR [rsp+ABI_REFUSALS],0
 jne fatal_abi
 mov QWORD PTR [rsp+ABI_REFUSALS],1
 mov QWORD PTR [r13],2
 jmp policy_next
fatal_abi:
 mov edi,70
 mov eax,60
 syscall
 ud2
.section .note.GNU-stack,"",@progbits
