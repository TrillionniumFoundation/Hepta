.intel_syntax noprefix
.text
.global _start
.equ INPUT_N,8388608
.equ INPUT_EXTENT,1052672
.equ JSON_AT,1052672
.equ JSON_N,16777216
.equ CANON_AT,17829888
.equ CANON_N,16777216
.equ ARENA_AT,34607104
.equ ARENA_N,33554432
.equ SCRATCH_AT,68161536
.equ SCRATCH_N,16384
.equ CORE_AT,68177920
.equ CORE_N,67108864
.equ TOTAL_N,135286784
.equ O,4096
.equ S,8192
.equ MODE,S+32
_start:
 mov r15,rsp
 cmp QWORD PTR [r15],2
 ja usage
 xor edi,edi
 mov esi,TOTAL_N
 mov edx,3
 mov r10d,34
 mov r8,-1
 xor r9d,r9d
 mov eax,9
 syscall
 cmp rax,-4095
 jae io_failure
 mov r12,rax
 lea rbp,[r12+SCRATCH_AT]
 # The installed public dispatcher authenticates the same helper for both
 # actions. It chooses the existing checker alias only in exec argv[0].
 mov QWORD PTR [rbp+MODE],1
 cmp QWORD PTR [r15],2
 je select_compact
 mov rsi,[r15+8]
 lea rdi,[rip+check_alias]
 call option_equal
 test eax,eax
 jz presentation_ready
 mov QWORD PTR [rbp+MODE],0
 jmp presentation_ready
select_compact:
 mov rsi,[r15+16]
 lea rdi,[rip+compact_option]
 call option_equal
 test eax,eax
 jz usage
 mov QWORD PTR [rbp+MODE],2
 jmp presentation_ready
option_equal:
 mov al,[rdi]
 cmp al,[rsi]
 jne different_option
 inc rdi
 inc rsi
 test al,al
 jne option_equal
 mov eax,1
 ret
different_option:
 xor eax,eax
 ret
check_alias: .asciz "hia-check-assembly-accepted"
compact_option: .asciz "--agent-compact"
presentation_ready:
 .byte 0x48,0x8d,0x05
presentation_images_hole: .long 0
 mov r15,rax
read_input:
 xor edi,edi
 mov rax,[rbp+S]
 lea rsi,[r12+rax]
 mov edx,INPUT_N+1
 sub rdx,rax
 mov eax,0
 syscall
 cmp rax,-4
 je read_input
 test rax,rax
 js io_failure
 jz input_complete
 cmp rax,rdx
 ja io_failure
 add [rbp+S],rax
 cmp QWORD PTR [rbp+S],INPUT_N
 ja capacity
 jmp read_input
input_complete:
 mov rdi,r12
 mov rsi,[rbp+S]
 add rsi,4095
 and rsi,-4096
 test rsi,rsi
 jnz preflight_protect
 mov esi,4096
preflight_protect:
 mov edx,1
 mov eax,10
 syscall
 test rax,rax
 jnz io_failure
 mov QWORD PTR [rbp+88],1274
 mov rdi,r12
 mov rsi,[rbp+S]
 lea rdx,[r12+CORE_AT]
 mov ecx,512
 mov r8,rbp
 mov r9d,4096
 mov rax,[r15]
 add rax,r15
 call rax
 test rax,rax
 jz source_preflight_passed
 cmp rax,1
 jne io_failure
 mov r13,rax
 mov r14,[rbp+80]
 jmp report_ready
source_preflight_passed:
 cmp QWORD PTR [rbp+80],0
 jne io_failure
 mov QWORD PTR [rbp+88],0
 mov rdi,r12
 mov rsi,[rbp+S]
 lea rdx,[r12+JSON_AT]
 mov ecx,JSON_N
 lea r8,[r12+ARENA_AT]
 mov r9d,131072
 .byte 0xe8
syntax_call_hole: .long 0
 mov [rbp+104],rax
 mov [rbp+S+24],rax
 mov rdx,[r12+ARENA_AT+256]
 mov [rbp+144],rdx
 mov rdx,[r12+ARENA_AT+264]
 mov [rbp+152],rdx
 # This is only a CABI view-range check. HIA classifies every raw status.
 test rax,rax
 jz admission_skipped
 cmp rax,JSON_N
 ja admission_skipped
 lea rdi,[r12+JSON_AT]
 mov esi,JSON_N
 mov edx,1
 mov eax,10
 syscall
 test rax,rax
 jnz io_failure
 # Scratch reset between independent HIA owners; no parsed-object bridge.
 lea rdi,[r12+ARENA_AT]
 mov ecx,16384
 xor eax,eax
 rep stosq
 lea rdi,[r12+JSON_AT]
 mov rsi,[rbp+S+24]
 lea rdx,[r12+CORE_AT]
 mov ecx,CORE_N
 lea r8,[r12+ARENA_AT]
 mov r9d,ARENA_N
 .byte 0xe8
core_call_hole: .long 0
 # Preserve the full actual Core decision. HIA owns classification.
 mov [rbp+112],rax
 mov rdx,[r12+CORE_AT+120]
 mov [rbp+160],rdx
 mov rdx,[r12+CORE_AT+80]
 mov [rbp+168],rdx
 mov rdx,[r12+CORE_AT+56]
 mov [rbp+176],rdx
 mov rdx,[r12+CORE_AT+72]
 mov [rbp+184],rdx
 # Canonical output is not needed when Core returned a nonzero raw result.
 # No status/message classification here: only native HIA can authorize JSON.
 test rax,rax
 jnz admission_skipped
 mov QWORD PTR [r12+ARENA_AT+48],262144
 mov QWORD PTR [r12+ARENA_AT+56],64
 lea rdi,[r12+JSON_AT]
 mov rsi,[rbp+S+24]
 lea rdx,[r12+CANON_AT]
 mov ecx,CANON_N
 lea r8,[r12+ARENA_AT]
 mov r9d,ARENA_N
 .byte 0xe8
canonical_call_hole: .long 0
 # The HIA presenter, not the adapter, classifies the raw CABI result.
 mov [rbp+96],rax
admission_skipped:
 # All source ranges become immutable before either HIA hash is computed.
 mov rdi,r12
 mov esi,SCRATCH_AT
 mov edx,1
 mov eax,10
 syscall
 test rax,rax
 jnz io_failure
 mov rax,[rbp+S]
 mov [rbp+120],rax
 mov rdi,r12
 mov esi,SCRATCH_AT
 lea rdx,[r12+CORE_AT]
 mov ecx,8192
 mov r8,rbp
 mov r9d,4096
 mov rax,[r15]
 add rax,r15
 call rax
 mov r13,rax
 mov r14,[rbp+80]
 mov rax,[rbp+96]
 mov [rbp+S+48],rax
report_ready:
 cmp r13,255
 ja io_failure
 cmp QWORD PTR [rbp+MODE],0
 je release_inputs
 test r13,r13
 jz prepare_import
 cmp QWORD PTR [rbp+MODE],2
 je compact_refusal
 cmp r13,1
 jne HIA_status
 test r14,r14
 jz io_failure
 cmp r14,8192
 ja io_failure
 lea rdi,[r12+CORE_AT]
 mov rsi,r14
 lea rdx,[r12+CORE_AT+8192]
 mov ecx,8192
 mov r8,rbp
 mov r9d,4096
 mov rax,[r15+16]
 add rax,r15
 call rax
 test rax,rax
 jz io_failure
 cmp rax,8192
 ja io_failure
 mov r14,rax
 mov r13d,2
 mov QWORD PTR [rbp+S+40],8192
 jmp release_inputs
compact_refusal:
 cmp r13,1
 jne HIA_status
 mov r13d,2
 cmp QWORD PTR [rbp+S],1048576
 jbe HIA_status
 mov r13d,3
 jmp HIA_status
prepare_import:
 # Diagnostic and pretty presentations have separate private workspace state.
 mov rbx,[rbp+104]
 mov rdi,rbp
 mov ecx,512
 xor eax,eax
 cld
 rep stosq
 mov rax,[rbp+S+48]
 mov [rbp+96],rax
 mov [rbp+120],rbx
release_inputs:
 mov rdi,r12
 mov esi,INPUT_EXTENT
 mov eax,11
 syscall
 test rax,rax
 jnz io_failure
 lea rdi,[r12+JSON_AT]
 mov esi,JSON_N
 mov eax,11
 syscall
 test rax,rax
 jnz io_failure
 lea rdi,[r12+ARENA_AT]
 mov esi,ARENA_N
 mov eax,11
 syscall
 test rax,rax
 jnz io_failure
 cmp QWORD PTR [rbp+MODE],0
 je release_canonical
 test r13,r13
 jz import_output
release_canonical:
 lea rdi,[r12+CANON_AT]
 mov esi,CANON_N
 mov eax,11
 syscall
 test rax,rax
 jnz io_failure
 cmp r13,1
 je diagnostic_output
 cmp QWORD PTR [rbp+S+40],8192
 je diagnostic_output
 test r13,r13
 jnz HIA_status
diagnostic_output:
 test r14,r14
 jz io_failure
 cmp r14,8192
 ja io_failure
 lea rdi,[r12+CORE_AT]
 mov esi,CORE_N
 mov edx,1
 mov eax,10
 syscall
 test rax,rax
 jnz io_failure
 mov QWORD PTR [rbp+S+16],0
write_output:
 mov rax,[rbp+S+16]
 add rax,[rbp+S+40]
 lea rsi,[r12+CORE_AT+rax]
 mov rdx,r14
 sub rdx,[rbp+S+16]
 mov edi,1
 mov eax,1
 syscall
 cmp rax,-4
 je write_output
 test rax,rax
 jle io_failure
 add [rbp+S+16],rax
 mov rax,[rbp+S+16]
 cmp rax,r14
 ja io_failure
 jb write_output
 lea rdi,[r12+CORE_AT]
 mov esi,CORE_N
 mov eax,11
 syscall
 test rax,rax
 jnz io_failure
 mov rdi,rbp
 mov esi,SCRATCH_N
 mov eax,11
 syscall
 test rax,rax
 jnz io_failure
 mov rdi,r13
 jmp exit_process
import_output:
 lea rdi,[r12+CORE_AT]
 mov esi,CORE_N
 mov eax,11
 syscall
 test rax,rax
 jnz io_failure
 lea rdi,[r12+CANON_AT]
 mov esi,CANON_N
 mov edx,1
 mov eax,10
 syscall
 test rax,rax
 jnz io_failure
 cmp QWORD PTR [rbp+MODE],2
 je compact_output
pretty_loop:
 lea rdi,[r12+CANON_AT]
 mov esi,CANON_N
 lea rdx,[rbp+O]
 mov ecx,128
 mov r8,rbp
 mov r9d,4096
 mov rax,[r15+8]
 add rax,r15
 call rax
 test rax,rax
 jnz import_status
 mov rax,[rbp+80]
 cmp rax,128
 ja io_failure
 mov [rbp+S+8],rax
 mov QWORD PTR [rbp+S+16],0
 test rax,rax
 jnz write_import
 cmp QWORD PTR [rbp+8],5
 jne io_failure
 jmp import_complete
write_import:
 mov rax,[rbp+S+16]
 lea rsi,[rbp+O+rax]
 mov rdx,[rbp+S+8]
 sub rdx,rax
 mov edi,1
 mov eax,1
 syscall
 cmp rax,-4
 je write_import
 test rax,rax
 jle io_failure
 add [rbp+S+16],rax
 mov rax,[rbp+S+16]
 cmp rax,[rbp+S+8]
 ja io_failure
 jb write_import
 cmp QWORD PTR [rbp+8],5
 jne pretty_loop
 jmp import_complete
compact_output:
 mov rdx,[rbp+S+48]
 test rdx,rdx
 jz io_failure
 cmp rdx,8388608
 ja capacity
 lea rsi,[r12+CANON_AT]
compact_write:
 mov eax,1
 mov edi,1
 syscall
 cmp rax,-4
 je compact_write
 test rax,rax
 jle io_failure
 add rsi,rax
 sub rdx,rax
 jnz compact_write
import_complete:
 lea rdi,[r12+CANON_AT]
 mov esi,CANON_N
 mov eax,11
 syscall
 test rax,rax
 jnz io_failure
 mov rdi,rbp
 mov esi,SCRATCH_N
 mov eax,11
 syscall
 test rax,rax
 jnz io_failure
 xor edi,edi
 jmp exit_process
import_status:
 cmp rax,255
 ja io_failure
 mov r13,rax
HIA_status:
 mov rdi,r13
 jmp exit_process
capacity:
 mov edi,3
 jmp exit_process
usage:
 mov edi,64
 jmp exit_process
io_failure:
 mov edi,4
exit_process:
 mov eax,60
 syscall
 ud2
