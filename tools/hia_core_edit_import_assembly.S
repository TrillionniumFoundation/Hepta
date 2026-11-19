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
.equ PUBLISH_PATH,S+56
_start:
 mov r15,rsp
 cmp QWORD PTR [r15],3
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
 cmp QWORD PTR [r15],1
 je select_check
 cmp QWORD PTR [r15],3
 je select_publish_option
 mov rsi,[r15+8]
 lea rdi,[rip+publish_alias]
 call option_equal
 test eax,eax
 jnz select_publish
 mov rsi,[r15+16]
 lea rdi,[rip+compact_option]
 call option_equal
 test eax,eax
 jz usage
 mov QWORD PTR [rbp+MODE],2
 jmp presentation_ready
select_check:
 mov rsi,[r15+8]
 lea rdi,[rip+check_alias]
 call option_equal
 test eax,eax
 jz presentation_ready
 mov QWORD PTR [rbp+MODE],0
 jmp presentation_ready
select_publish_option:
 mov rsi,[r15+16]
 lea rdi,[rip+publish_option]
 call option_equal
 test eax,eax
 jz usage
 mov rax,[r15+24]
 jmp publish_mode
select_publish:
 mov rax,[r15+16]
publish_mode:
 mov [rbp+PUBLISH_PATH],rax
 mov QWORD PTR [rbp+MODE],3
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
publish_alias: .asciz "hia-publish-import"
publish_option: .asciz "--publish"
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
 cmp QWORD PTR [rbp+MODE],3
 je publish_write
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

publish_write:
 # Paths and filesystem effects are owned by the same HIA publisher as
 # before. It now receives this verified, read-only canonical image;
 # there is no second source capture, assembly parse or Core decision.
 mov rbx,[rbp+PUBLISH_PATH]
 mov r14,[rbp+S+48]
 mov r13,[rbp+S]
 lea r12,[r12+CANON_AT]
 mov rdi,rbp
 mov esi,SCRATCH_N
 mov eax,11
 syscall
 test rax,rax
 jnz io_failure
 mov esi,16384
 call pub_allocate
 mov rbp,rax
 mov [rbp+64],r12
 mov [rbp+72],r14
 mov [rbp+384],r13
 mov r12,rbx
 mov rax,[r15+16]
 add rax,r15
 mov [rbp+392],rax
 mov rax,[r15+24]
 add rax,r15
 mov [rbp+320],rax
 mov rax,[r15+32]
 add rax,r15
 mov [rbp+336],rax
 mov rax,[r15+40]
 add rax,r15
 mov [rbp+344],rax
 mov esi,270336
 call pub_allocate
 mov [rbp],rax
 mov rbx,rax
 mov rdi,r12
 call pub_c_length
 mov [rbp+360],rax
 mov [rbx+8],rax
 movabs rax,3544411325348268360
 mov [rbx],rax
 lea rdi,[rbx+48]
 mov rsi,r12
 mov rcx,[rbp+360]
 cld
 rep movsb
 mov rdi,rbx
 add rdi,[rbp+360]
 add rdi,48
 mov esi,4096
 mov eax,79
 syscall
 mov [rbx+24],rax
 xor ecx,ecx
 test rax,rax
 js pub_cwd_ready
 jz pub_io_failure
 cmp rax,4096
 ja pub_io_failure
 lea rcx,[rax-1]
pub_cwd_ready:
 mov [rbx+32],rcx
 add rcx,[rbp+360]
 add rcx,48
 mov [rbp+8],rcx
 mov rdi,rbx
 mov esi,270336
 call pub_readonly
 mov rdi,rbx
 mov rsi,[rbp+8]
 lea rdx,[rbp+768]
 mov ecx,8
 lea r8,[rbp+776]
 mov r9d,8
 call QWORD PTR [rbp+336]
 test rax,rax
 jnz pub_HIA_status
 mov esi,262144
 call pub_allocate
 mov [rbp+16],rax
 mov esi,1048576
 call pub_allocate
 mov [rbp+32],rax
 mov rdi,[rbp]
 mov rsi,[rbp+8]
 mov rdx,[rbp+16]
 mov ecx,262144
 mov r8,[rbp+32]
 mov r9d,1048576
 call QWORD PTR [rbp+320]
 test rax,rax
 jz pub_io_failure
 cmp rax,4095
 ja pub_io_failure
 mov [rbp+24],rax
 mov rdi,[rbp+16]
 mov esi,262144
 call pub_readonly
 mov rdi,[rbp]
 mov esi,270336
 call pub_release
 mov rdi,[rbp+32]
 mov esi,1048576
 call pub_release
 # Observe the exact new destination, without dereferencing its final
 # component or creating any staging file. HIA classifies the observation.
 mov edi,-100
 mov rsi,[rbp+16]
 lea rdx,[rbp+768]
 mov r10d,256
 mov eax,262
 syscall
 mov [rbp+456],rax
 mov rax,QWORD PTR [rip+pub_output_probe]
 mov [rbp+448],rax
 lea rdi,[rbp+448]
 mov esi,16
 lea rdx,[rbp+1024]
 mov ecx,512
 lea r8,[rbp+1536]
 xor r9d,r9d
 call QWORD PTR [rbp+392]
 cmp rax,512
 ja pub_io_failure
 test rax,rax
 jz pub_destination_ready
 lea rdx,[rbp+1024]
 mov [rbp+112],rdx
 mov [rbp+120],rax
 call pub_write_report
 mov edi,2
 jmp pub_exit
pub_destination_ready:
 # Retain the native publisher's post-admission byte limits.
 mov esi,4096
 call pub_allocate
 mov [rbp+80],rax
 movabs rdx,3544411312715024712
 mov [rax],rdx
 mov rdx,[rbp+72]
 mov [rax+16],rdx
 mov rdx,[rbp+384]
 mov [rax+24],rdx
 mov rdi,rax
 mov esi,4096
 call pub_readonly
 mov rdi,[rbp+80]
 mov esi,32
 lea rdx,[rbp+768]
 mov ecx,8
 lea r8,[rbp+776]
 mov r9d,8
 call QWORD PTR [rbp+336]
 test rax,rax
 jnz pub_HIA_status
 mov rdi,[rbp+80]
 mov esi,4096
 call pub_release
 mov esi,4096
 call pub_allocate
 mov [rbp+88],rax
 mov esi,4096
 call pub_allocate
 mov [rbp+96],rax
 lea rdi,[rip+pub_sha_initialize]
 mov esi,1
 call pub_hash_arguments
 call QWORD PTR [rbp+336]
 test rax,rax
 jnz pub_io_failure
 # Mechanical bounded copies retain the original SHA packet <=8MiB+1.
 mov esi,8392704
 call pub_allocate
 mov [rbp+136],rax
pub_hash_copy_next:
 mov rax,[rbp+72]
 sub rax,[rbp+144]
 mov edx,8388608
 cmp rax,rdx
 cmova rax,rdx
 mov [rbp+152],rax
 mov rdi,[rbp+136]
 mov BYTE PTR [rdi+4095],1
 add rdi,4096
 mov rsi,[rbp+64]
 add rsi,[rbp+144]
 mov rcx,rax
 cld
 rep movsb
 mov rdi,[rbp+136]
 mov esi,8392704
 call pub_readonly
 mov rdi,[rbp+136]
 add rdi,4095
 mov rsi,[rbp+152]
 inc rsi
 call pub_hash_arguments
 call QWORD PTR [rbp+336]
 test rax,rax
 jnz pub_io_failure
 mov rax,[rbp+152]
 add [rbp+144],rax
 mov rdi,[rbp+136]
 mov esi,8392704
 mov edx,3
 call pub_protect
 mov rax,[rbp+144]
 cmp rax,[rbp+72]
 jb pub_hash_copy_next
 mov rdi,[rbp+136]
 mov esi,8392704
 call pub_release
 lea rdi,[rip+pub_sha_finalize]
 mov esi,1
 call pub_hash_arguments
 call QWORD PTR [rbp+336]
 cmp rax,32
 jne pub_io_failure
 mov rdi,[rbp+96]
 mov esi,4096
 call pub_readonly
 mov esi,8192
 call pub_allocate
 mov [rbp+104],rax
 mov rbx,rax
 movabs rdx,3544423407342930248
 mov [rbx],rdx
 mov QWORD PTR [rbx+8],1
 mov rax,[rbp+72]
 mov [rbx+16],rax
 mov rax,[rbp+24]
 mov [rbx+24],rax
 lea rdi,[rbx+32]
 mov rsi,[rbp+96]
 mov ecx,32
 cld
 rep movsb
 lea rdi,[rbx+80]
 mov rsi,[rbp+16]
 mov rcx,[rbp+24]
 rep movsb
 mov rdi,rbx
 mov esi,8192
 call pub_readonly
 mov rdi,[rbp+88]
 mov esi,4096
 call pub_release
 mov rdi,[rbp+96]
 mov esi,4096
 call pub_release
 mov esi,262144
 call pub_allocate
 mov [rbp+112],rax
 mov esi,32768
 call pub_allocate
 mov [rbp+128],rax
 mov rdi,[rbp+104]
 mov rsi,[rbp+24]
 add rsi,80
 mov rdx,[rbp+112]
 mov ecx,262144
 mov r8,[rbp+128]
 mov r9d,32768
 call QWORD PTR [rbp+336]
 test rax,rax
 jz pub_io_failure
 cmp rax,262144
 ja pub_io_failure
 mov [rbp+120],rax
 mov rdi,[rbp+112]
 mov esi,262144
 call pub_readonly
 mov rdi,[rbp+104]
 mov esi,8192
 call pub_release
 mov rdi,[rbp+128]
 mov esi,32768
 call pub_release
 # Same opaque ABI for parent creation and then exact byte publication.
 mov rax,[rbp+16]
 mov [rbp+256],rax
 mov rax,[rbp+24]
 mov [rbp+264],rax
 mov rax,[rbp+336]
 mov [rbp+352],rax
 movabs r12,3544406867423873352
 call pub_effect_allocate
 call pub_effect_loop
 call pub_effect_release
 mov rax,[rbp+64]
 mov [rbp+256],rax
 mov rax,[rbp+72]
 mov [rbp+264],rax
 mov rax,[rbp+344]
 mov [rbp+352],rax
 movabs r12,3544406931680610632
 call pub_effect_allocate
 mov rbx,[rbp+288]
 mov rax,[rbp+24]
 mov [rbx+40],rax
 mov rax,[rbp+72]
 mov [rbx+48],rax
 mov rdi,[rbp+272]
 add rdi,4096
 mov rsi,[rbp+16]
 mov rcx,[rbp+24]
 inc rcx
 cld
 rep movsb
 call pub_effect_loop
 call pub_effect_release
 mov rdi,[rbp+16]
 mov esi,262144
 call pub_release
 mov rdi,[rbp+64]
 mov esi,CANON_N
 call pub_release
 call pub_write_report
 mov rdi,[rbp+112]
 mov esi,262144
 call pub_release
 mov rdi,rbp
 mov esi,16384
 call pub_release
 xor edi,edi
 jmp pub_exit
pub_hash_arguments:
 mov rdx,[rbp+96]
 mov ecx,32
 mov r8,[rbp+88]
 mov r9d,1184
 ret
pub_effect_allocate:
 # Subroutine contains no native CABI calls; pub_allocate/syscall only.
 mov esi,1048576
 call pub_allocate
 mov [rbp+272],rax
 mov QWORD PTR [rbp+280],1048576
 mov esi,98304
 call pub_allocate
 mov [rbp+288],rax
 mov QWORD PTR [rbp+296],98304
 mov [rax],r12
 ret
pub_effect_release:
 mov rdi,[rbp+272]
 mov esi,1048576
 call pub_release
 mov rdi,[rbp+288]
 mov esi,98304
 call pub_release
 ret
pub_effect_loop:
 sub rsp,8
pub_effect_next:
 mov rdi,[rbp+256]
 mov rsi,[rbp+264]
 mov rdx,[rbp+272]
 mov rcx,[rbp+280]
 mov r8,[rbp+288]
 mov r9,[rbp+296]
 call QWORD PTR [rbp+352]
 cmp rax,96
 jne pub_HIA_status
 mov rdi,[rbp+272]
 mov esi,1048576
 call pub_readonly
 mov r12,[rbp+272]
 movabs rax,3544409130703866184
 cmp [r12],rax
 jne pub_io_failure
 cmp QWORD PTR [r12+16],2
 je pub_effect_done
 cmp QWORD PTR [r12+16],1
 jne pub_io_failure
 mov rbx,[r12+32]
 cmp rbx,63
 ja pub_io_failure
 sub rsp,64
 mov rax,[r12+24]
 mov [rsp+48],rax
 lea rsi,[r12+40]
 mov rdi,rsp
 mov ecx,6
 cld
 rep movsq
 xor edx,edx
pub_effect_translate:
 test bl,1
 jz pub_effect_argument_ready
 mov rax,[rsp+rdx*8]
 mov rcx,rax
 shr rcx,48
 cmp rcx,1
 jb pub_io_failure
 cmp rcx,3
 ja pub_io_failure
 dec rcx
 shl rcx,4
 shl rax,16
 shr rax,16
 cmp rax,[rbp+rcx+264]
 jae pub_io_failure
 add rax,[rbp+rcx+256]
 mov [rsp+rdx*8],rax
pub_effect_argument_ready:
 shr rbx,1
 inc edx
 cmp edx,6
 jb pub_effect_translate
 mov rax,[rsp+48]
 mov rdi,[rsp]
 mov rsi,[rsp+8]
 mov rdx,[rsp+16]
 mov r10,[rsp+24]
 mov r8,[rsp+32]
 mov r9,[rsp+40]
 syscall
 add rsp,64
 mov r13,[rbp+288]
 mov [r13+32],rax
 mov rax,[r12+8]
 mov [r13+24],rax
 mov rdi,r12
 mov esi,1048576
 mov edx,3
 call pub_protect
 jmp pub_effect_next
pub_effect_done:
 mov rdi,[r12+24]
 cmp rdi,255
 ja pub_io_failure
 test rdi,rdi
 jnz pub_exit
 add rsp,8
 ret
pub_write_report:
 mov r12,[rbp+112]
 mov r13,[rbp+120]
pub_write_next:
 test r13,r13
 jz pub_write_done
 mov edx,4096
 cmp r13,rdx
 cmovb rdx,r13
 mov rsi,r12
 mov edi,1
 mov eax,1
 syscall
 cmp rax,-4
 je pub_write_next
 test rax,rax
 jle pub_io_failure
 cmp rax,rdx
 ja pub_io_failure
 add r12,rax
 sub r13,rax
 jmp pub_write_next
pub_write_done:
 ret
pub_c_length:
 xor eax,eax
pub_c_length_loop:
 cmp rax,131072
 jae pub_io_failure
 cmp BYTE PTR [rdi+rax],0
 je pub_c_length_done
 inc rax
 jmp pub_c_length_loop
pub_c_length_done:
 ret
pub_allocate:
 xor edi,edi
 mov edx,3
 mov r10d,34
 mov r8,-1
 xor r9d,r9d
 mov eax,9
 syscall
 cmp rax,-4095
 jae pub_io_failure
 ret
pub_readonly:
 mov edx,1
pub_protect:
 mov eax,10
 syscall
 test rax,rax
 jnz pub_io_failure
 ret
pub_release:
 mov eax,11
 syscall
 test rax,rax
 jnz pub_io_failure
 ret
pub_HIA_status:
 cmp rax,255
 ja pub_io_failure
 mov rdi,rax
 jmp pub_exit
pub_io_failure:
 mov edi,4
pub_exit:
 mov eax,60
 syscall
 ud2
pub_sha_initialize: .byte 0
pub_sha_finalize: .byte 2
pub_output_probe: .ascii "HIAPEX01"
.section .note.GNU-stack,"",@progbits
