.intel_syntax noprefix
.text
.global _start
.type _start,@function
.equ RAW_N,16777219
.equ RAW_EXTENT,16781312
.equ SOURCE_N,25169920
.equ TEMP_AT,25169920
.equ TEMP_N,16777216
.equ WORK_AT,41947136
.equ WORK_N,67108864
.equ OUT_AT,109056000
.equ OUT_N,33554432
.equ CORE_AT,142610432
.equ CORE_N,67108864
.equ SCR_AT,209719296
.equ SCR_N,16384
.equ TOTAL_N,209735680
.equ CTRL,25165824
.equ DRIVER_TEXT,OUT_N-504
.equ DRIVER_TEXT_LIMIT,504
.equ SLICE,8388608
.equ QUERY,16777216
.equ IO,12288
.equ S,8192
.equ NOMINAL_ORIGIN,S+112
.equ ORIGIN_DIGEST,S+64
.equ ORIGIN_TAG,CTRL+1536
.equ ORIGIN_BYTES,CTRL+1544
.equ ORIGIN_MAGIC,3544423407359707464

_start:
 add rsp,8
 cmp QWORD PTR [rsp],1
 jne usage
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
 lea rbp,[r12+SCR_AT]
read_input:
 xor edi,edi
 mov rax,[rbp+S]
 lea rsi,[r12+rax]
 mov edx,RAW_N+1
 sub rdx,rax
 xor eax,eax
 syscall
 cmp rax,-4
 je read_input
 test rax,rax
 js io_failure
 jz input_complete
 add [rbp+S],rax
 cmp QWORD PTR [rbp+S],RAW_N
 ja capacity
 jmp read_input
input_complete:
 mov rdi,r12
 mov esi,RAW_EXTENT
 mov edx,1
 mov eax,10
 syscall
 test rax,rax
 jnz io_failure
extract_base:
 mov rdi,r12
 mov rsi,[rbp+S]
 lea rdx,[r12+TEMP_AT]
 mov ecx,TEMP_N
 lea r8,[r12+WORK_AT]
 mov r9d,WORK_N
 call edit_base_extract_start
 call scalar_status
 cmp rax,32
 jbe invalid
 cmp rax,8388640
 ja invalid
 mov [rbp+S+16],rax
 sub rax,32
 mov [rbp+S+8],rax
 lea rsi,[r12+TEMP_AT+32]
 lea rdi,[r12+RAW_EXTENT]
 mov rcx,rax
 rep movsb
 lea rdi,[r12+RAW_EXTENT]
 mov esi,8388608
 mov edx,1
 mov eax,10
 syscall
 test rax,rax
 jnz io_failure
 lea rdi,[r12+WORK_AT]
 mov ecx,WORK_N/8
 xor eax,eax
 rep stosq
 lea rdi,[r12+RAW_EXTENT]
 mov rsi,[rbp+S+8]
 lea rdx,[r12+CORE_AT]
 mov ecx,CORE_N
 lea r8,[r12+WORK_AT]
 mov r9d,33554432
 call edit_base_admission_start
 mov [rbp+S+24],rax
 cmp eax,0xfffffffb
 jne base_checked
 cmp QWORD PTR [rbp+NOMINAL_ORIGIN],0
 je lower_nominal
base_checked:
 lea rdi,[r12+WORK_AT]
 mov ecx,WORK_N/8
 xor eax,eax
 rep stosq
 lea r13,[r12+OUT_AT]
 movabs rax,3544404724050643272
 mov [r13+CTRL],rax
 mov rax,[rbp+S]
 mov [r13+CTRL+8],rax
 mov rax,[rbp+S+8]
 mov [r13+CTRL+16],rax
 mov rax,[rbp+S+24]
 mov [r13+CTRL+24],rax
 mov rax,[rbp+S+16]
 mov [r13+CTRL+32],rax
 mov rdi,r12
 mov rsi,[rbp+S]
 mov rdx,r13
 mov ecx,OUT_N
 lea r8,[r12+WORK_AT]
 mov r9d,WORK_N
 call edit_apply_owner_start
 call scalar_status
 test rax,rax
 jz invalid
 cmp rax,WORK_N
 ja io_failure
 mov rdi,r12
 mov esi,SOURCE_N
 mov rdx,r13
 mov ecx,OUT_N
 lea r8,[r12+WORK_AT]
 mov r9d,WORK_N
 call edit_apply_owner_start
 call edit_status
 test rax,rax
 jz invalid
 cmp rax,8388608
 ja io_failure
 mov [rbp+S+32],rax
 mov rdi,r13
 mov esi,8388608
 mov edx,1
 mov eax,10
 syscall
 test rax,rax
 jnz io_failure
 lea rdi,[r12+TEMP_AT]
 mov ecx,TEMP_N/8
 xor eax,eax
 rep stosq
 mov rdi,r13
 mov rsi,[rbp+S+32]
 lea rdx,[r13+SLICE]
 mov ecx,8388608
 lea r8,[r12+TEMP_AT]
 mov r9d,TEMP_N
 call edit_slice_start
 mov [r13+CTRL+256],rax
 mov rdi,r13
 mov esi,8388608
 mov edx,3
 mov eax,10
 syscall
 test rax,rax
 jnz io_failure
 movabs rax,3544422316236687688
 mov [r13+CTRL],rax
 cmp QWORD PTR [rbp+NOMINAL_ORIGIN],0
 je render_query
 movabs rax,ORIGIN_MAGIC
 mov [r13+ORIGIN_TAG],rax
 lea rdi,[r13+ORIGIN_BYTES]
 lea rsi,[rbp+ORIGIN_DIGEST]
 mov ecx,4
 cld
 rep movsq
render_query:
 mov rdi,r12
 mov esi,SOURCE_N
 mov rdx,r13
 mov ecx,OUT_N
 lea r8,[r12+WORK_AT]
 mov r9d,WORK_N
 call edit_apply_owner_start
 mov [r13+CTRL+320],rax
 call query_status
 test rax,rax
 jz invalid
 cmp rax,1048576
 ja io_failure
 movabs rax,3544423415748315464
 mov [r13+CTRL],rax
 mov rdi,r12
 mov esi,SOURCE_N
 mov rdx,r13
 mov ecx,OUT_N
 lea r8,[r12+WORK_AT]
 mov r9d,WORK_N
 call edit_apply_owner_start
 mov [r13+CTRL+344],rax
 call edit_status
 test rax,rax
 jnz invalid
 movabs rax,3544423420043282760
 mov [r13+CTRL],rax
 mov rdi,r12
 mov esi,SOURCE_N
 mov rdx,r13
 mov ecx,OUT_N
 lea r8,[r12+WORK_AT]
 mov r9d,WORK_N
 call edit_apply_owner_start
 mov [r13+CTRL+384],rax
 call scalar_status
 test rax,rax
 jz invalid
 cmp rax,16384
 ja io_failure
 lea rdi,[r12+WORK_AT+58720256]
 mov esi,16384
 mov edx,1
 mov eax,10
 syscall
 test rax,rax
 jnz io_failure
 lea rdi,[r12+TEMP_AT]
 mov ecx,TEMP_N/8
 xor eax,eax
 rep stosq
 movabs rax,3544408026880493896
 mov [r12+TEMP_AT+120],rax
 lea rdi,[r12+WORK_AT+58720256]
 mov rsi,[r13+CTRL+384]
 lea rdx,[r12+WORK_AT+58736640]
 mov ecx,8372224
 lea r8,[r12+TEMP_AT]
 mov r9d,TEMP_N
 call edit_apply_owner_start
 mov [r13+CTRL+368],rax
 lea rdi,[r12+WORK_AT+58720256]
 mov esi,16384
 mov edx,3
 mov eax,10
 syscall
 test rax,rax
 jnz io_failure
 movabs rax,3544427818089793864
 mov [r13+CTRL],rax
 mov rdi,r12
 mov esi,SOURCE_N
 mov rdx,r13
 mov ecx,OUT_N
 lea r8,[r12+WORK_AT]
 mov r9d,WORK_N
 call edit_apply_owner_start
 mov [r13+CTRL+416],rax
 call edit_status
 test rax,rax
 jnz invalid
 movabs rax,3544405819267303752
 mov [r13+CTRL],rax
 mov rdi,r12
 mov esi,SOURCE_N
 mov rdx,r13
 mov ecx,OUT_N
 lea r8,[r12+WORK_AT]
 mov r9d,WORK_N
 call edit_apply_owner_start
 mov [r13+CTRL+472],rax
 call scalar_status
 test rax,rax
 jz invalid
 cmp rax,16777216
 ja io_failure
 mov rax,[r13+CTRL+440]
 cmp rax,2
 jb io_failure
 cmp rax,4096
 ja io_failure
 mov rdi,r13
 mov esi,16777216
 mov edx,1
 mov eax,10
 syscall
 test rax,rax
 jnz io_failure
 lea rdi,[r13+17825792]
 mov esi,4096
 mov edx,1
 mov eax,10
 syscall
 test rax,rax
 jnz io_failure
 lea rdi,[r12+CORE_AT]
 mov ecx,CORE_N/8
 xor eax,eax
 rep stosq
 mov QWORD PTR [r12+CORE_AT],2
 mov QWORD PTR [r12+CORE_AT+8],1
 cmp QWORD PTR [rbp+NOMINAL_ORIGIN],0
 je patch_request
 movabs rax,3544423407342930248
 mov [r12+CORE_AT+CORE_N-40],rax
 lea rdi,[r12+CORE_AT+CORE_N-32]
 lea rsi,[rbp+ORIGIN_DIGEST]
 mov ecx,4
 cld
 rep movsq
patch_request:
 mov rdi,r13
 mov rsi,[r13+CTRL+472]
 lea rdx,[r12+TEMP_AT]
 mov ecx,TEMP_N
 lea r8,[r12+CORE_AT]
 mov r9d,CORE_N
 call edit_base_extract_start
 mov [r13+CTRL+456],rax
 call scalar_status
 cmp rax,32
 jbe invalid
 cmp rax,8392704
 ja io_failure
 movabs r10,3544423347213388104
 cmp [r12+TEMP_AT],r10
 jne io_failure
 cmp QWORD PTR [r12+TEMP_AT+24],0
 jne io_failure
 mov r10,[r12+TEMP_AT+8]
 cmp r10,2
 jb io_failure
 cmp r10,8388608
 ja io_failure
 mov r11,[r12+TEMP_AT+16]
 cmp r11,4096
 ja io_failure
 add r11,r10
 add r11,32
 cmp r11,rax
 jne io_failure
 lea rsi,[r13+17825792]
 lea rdi,[r12+TEMP_AT+8392704]
 mov rcx,[r13+CTRL+440]
 mov [r13+CTRL+464],rcx
 rep movsb
 lea rdi,[r12+TEMP_AT]
 mov esi,TEMP_N
 mov edx,1
 mov eax,10
 syscall
 test rax,rax
 jnz io_failure
 lea rdi,[r12+CORE_AT]
 mov ecx,CORE_N/8
 xor eax,eax
 rep stosq
 lea rdi,[r12+WORK_AT]
 mov ecx,33554432/8
 rep stosq
 lea rdi,[r12+TEMP_AT+32]
 mov rsi,[r12+TEMP_AT+8]
 lea rdx,[r12+CORE_AT]
 mov ecx,CORE_N
 lea r8,[r12+WORK_AT]
 mov r9d,33554432
 call edit_base_admission_start
 mov [r13+CTRL+448],rax
 mov rdi,r13
 mov esi,16777216
 mov edx,3
 mov eax,10
 syscall
 test rax,rax
 jnz io_failure
 lea rdi,[r13+17825792]
 mov esi,4096
 mov edx,3
 mov eax,10
 syscall
 test rax,rax
 jnz io_failure
 mov rdi,r12
 mov esi,SOURCE_N
 mov eax,11
 syscall
 test rax,rax
 jnz io_failure
 lea rdi,[r12+CORE_AT]
 mov esi,CORE_N
 mov eax,11
 syscall
 test rax,rax
 jnz io_failure
 lea rdi,[r12+WORK_AT]
 mov esi,WORK_N
 mov eax,11
 syscall
 test rax,rax
 jnz io_failure
 mov rdi,r13
 mov ecx,25165824/8
 xor eax,eax
 rep stosq
 mov rdi,rbp
 mov ecx,4096/8
 rep stosq
 movabs rax,3544406918778931528
 mov [r13+CTRL],rax
 lea rdi,[r12+TEMP_AT]
 mov esi,TEMP_N
 mov rdx,r13
 mov ecx,OUT_N
 lea r8,[rbp]
 mov r9d,4096
 call edit_apply_owner_start
 mov [r13+CTRL+496],rax
 call scalar_status
 test rax,rax
 jz invalid
 cmp rax,16777216
 ja io_failure
 mov [rbp+96],rax
 movabs rax,3544421216725059912
 mov [rbp+120],rax
 lea rdi,[r12+TEMP_AT]
 mov esi,TEMP_N
 mov eax,11
 syscall
 test rax,rax
 jnz io_failure
 mov rdi,r13
 mov esi,OUT_N
 mov edx,1
 mov eax,10
 syscall
 test rax,rax
 jnz io_failure
 lea rdi,[r13+16777216]
 mov esi,16777216
 mov eax,11
 syscall
 test rax,rax
 jnz io_failure
pretty_loop:
 mov rdi,r13
 mov rsi,[rbp+96]
 lea rdx,[rbp+IO]
 mov ecx,4096
 mov r8,rbp
 mov r9d,4096
 call edit_apply_owner_start
 test rax,rax
 jnz HIA_status
 mov rax,[rbp+80]
 cmp rax,4096
 ja io_failure
 test rax,rax
 jz empty_chunk
 mov [rbp+S+48],rax
 mov QWORD PTR [rbp+S+40],0
 lea rdi,[rbp+IO]
 mov esi,4096
 mov edx,1
 mov eax,10
 syscall
 test rax,rax
 jnz io_failure
write_output:
 mov rax,[rbp+S+40]
 lea rsi,[rbp+IO+rax]
 mov rdx,[rbp+S+48]
 sub rdx,rax
 mov edi,1
 mov eax,1
 syscall
 cmp rax,-4
 je write_output
 test rax,rax
 jle io_failure
 add [rbp+S+40],rax
 mov rax,[rbp+S+40]
 cmp rax,[rbp+S+48]
 ja io_failure
 jb write_output
 lea rdi,[rbp+IO]
 mov esi,4096
 mov edx,3
 mov eax,10
 syscall
 test rax,rax
 jnz io_failure
empty_chunk:
 cmp QWORD PTR [rbp+8],5
 je completed
 cmp QWORD PTR [rbp+80],0
 je io_failure
 jmp pretty_loop
completed:
 mov rdi,r13
 mov esi,16777216
 mov eax,11
 syscall
 test rax,rax
 jnz io_failure
 mov rdi,rbp
 mov esi,SCR_N
 mov eax,11
 syscall
 test rax,rax
 jnz io_failure
 xor edi,edi
 jmp exit_process
query_status:
 mov r10d,0xfffffffa
 cmp rax,r10
 je capacity
 mov r10d,0xfffffffb
 cmp rax,r10
 je capacity
 mov r10d,0xfffffffc
 cmp rax,r10
 je invalid
scalar_status:
 mov r10,rax
 shr r10,32
 test r10,r10
 jnz io_failure
 mov r10d,0xfffffffd
 cmp rax,r10
 je io_failure
 mov r10d,0xfffffffe
 cmp rax,r10
 je capacity
 mov r10d,0xffffffff
 cmp rax,r10
 je invalid
 ret
HIA_status:
 cmp rax,255
 ja io_failure
 mov rdi,rax
 jmp exit_process
# Only these stages can publish a refusal packet at the end of OUT_N.
edit_status:
 mov r10d,0xffffffff
 cmp rax,r10
 je driver_refusal
 jmp scalar_status
driver_refusal:
 lea rdi,[r13+DRIVER_TEXT-8]
 cmp QWORD PTR [rdi],0
 je invalid
 mov esi,8
 lea rdx,[r13+DRIVER_TEXT]
 mov ecx,DRIVER_TEXT_LIMIT
 xor r8d,r8d
 xor r9d,r9d
 call edit_base_extract_start
 test rax,rax
 jz invalid
 cmp rax,DRIVER_TEXT_LIMIT
 ja io_failure
 mov rdx,rax
 lea rsi,[r13+DRIVER_TEXT]
write_refusal:
 mov edi,1
 mov eax,1
 syscall
 cmp rax,-4
 je write_refusal
 test rax,rax
 jle io_failure
 cmp rax,rdx
 ja io_failure
 add rsi,rax
 sub rdx,rax
 jnz write_refusal
 jmp invalid

invalid:
 mov edi,2
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

lower_nominal:
 mov rdi,r12
 mov rsi,[rbp+S]
 lea rdx,[r12+RAW_EXTENT]
 mov rcx,[rbp+S+8]
 lea r8,[rbp+ORIGIN_DIGEST]
 call nominal_edit_envelope
 test rax,rax
 jz envelope_refused
 mov [rbp+S],rax
 mov QWORD PTR [rbp+NOMINAL_ORIGIN],1
 lea rdi,[r12+WORK_AT]
 mov ecx,WORK_N/8
 xor eax,eax
 rep stosq
 jmp extract_base
envelope_refused:
 mov rdi,rdx
 jmp exit_process

.section .note.GNU-stack,"",@progbits
