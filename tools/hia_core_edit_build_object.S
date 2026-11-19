.intel_syntax noprefix
.text
.global _start
.type _start,@function
.equ CORE_N,67108864
.equ SOURCE_N,41943040
.equ RAW_N,8388608
.equ EVT_N,34880
.equ EVT_MAP,36864
.equ CODE_N,16777280
.equ ART_N,67108864
.equ WRITE_W,33554432
.equ C,67092480
.equ NOMINAL_HASH,1800
.equ NOMINAL_PRESENT,1832
.equ LOWERED_CORE,1840
.equ LOWERED_EXTENT,1848
.equ IMAGE_LIMIT,13<<19
_start:
 # The static linker calls this entry. The adapter itself never returns.
 add rsp,8
 mov rax,[rsp]
 sub rax,2
 cmp rax,1
 ja usage
 mov r15,[rsp+16]
 cmp QWORD PTR [rsp],2
 je output_arg_ready
 mov r15,[rsp+24]
output_arg_ready:
 lea r14,[rip+build_backend_start]
 mov esi,4096
 call allocate
 mov rbp,rax
 cmp QWORD PTR [rsp],3
 jne input_arg_saved
 mov rax,[rsp+16]
 mov [rbp+120],rax
input_arg_saved:
 mov esi,270336
 call allocate
 mov [rbp+360],rax
 mov rdi,r15
 mov ecx,131072
 call c_length
 mov [rbp+376],rax
 mov rbx,[rbp+360]
 mov [rbx+8],rax
 xor eax,eax
 cmp QWORD PTR [rbp+120],0
 je input_length_captured
 mov rdi,[rbp+120]
 call c_length
 inc QWORD PTR [rbx+40]
input_length_captured:
 mov [rbx+16],rax
 movabs rax,3544411325348268360
 mov [rbx],rax
 mov rcx,[rbx+8]
 mov rsi,r15
 lea rdi,[rbx+48]
 cld
 rep movsb
 mov rsi,[rbp+120]
 mov rcx,[rbx+16]
 rep movsb
 mov esi,4096
 push 79
 pop rax
 syscall
 mov [rbx+24],rax
 xor ecx,ecx
 test rax,rax
 js cwd_count_captured
 jz io_failure
 lea rcx,[rax-1]
cwd_count_captured:
 mov [rbx+32],rcx
 add rcx,[rbx+8]
 add rcx,[rbx+16]
 add rcx,48
 mov [rbp+376],rcx
 lea r15,[rbp+256]
 mov rdi,rbx
 mov esi,270336
 call protect_readonly
 mov esi,262144
 call allocate
 mov [r15+40],rax
 mov esi,1048576
 call allocate
 mov [r15+112],rax
 mov rdi,[r15+104]
 mov rsi,[r15+120]
 mov rdx,[r15+40]
 mov ecx,262144
 mov r8,rax
 mov r9d,1048576
 call build_frontend_start
 test rax,rax
 jz io_failure
 cmp rax,4095
 ja native_status
 mov [r15+48],rax
 mov rdi,[r15+40]
 mov esi,262144
 call protect_readonly
 cmp QWORD PTR [rbp+120],0
 je source_admitted
 mov rdi,[r15+104]
 mov esi,270336
 call protect_writable
open_source:
 push -100
 pop rdi
 mov rsi,[r15+40]
 add rsi,4096
 mov edx,657408
 xor r10d,r10d
 mov eax,257
 syscall
 cmp rax,-4
 je open_source
 test rax,rax
 js io_failure
 mov [rbp+112],rax
 mov rbx,[r15+104]
 mov [rbx+8],rax
 xor eax,eax
 mov [rbx+24],rax
 movabs rax,3544406927603747144
 mov [rbx],rax
stat_source:
 mov rdi,[rbp+112]
 lea rsi,[rbx+32]
 push 5
 pop rax
 syscall
 cmp rax,-4
 je stat_source
 mov [rbx+16],rax
 mov rdi,rbx
 mov esi,270336
 call protect_readonly
 mov esi,176
 mov rdx,[r15+112]
 push 8
 pop rcx
 lea r8,[rdx+8]
 push 8
 pop r9
 call build_frontend_start
 mov rdi,rax
 test rax,rax
 jnz exit
source_admitted:
 mov rdi,[r15+104]
 mov esi,270336
 call release
 mov rdi,[r15+112]
 mov esi,1048576
 call release
 lea rdi,[rbp+1360]
 push 63
 pop rax
 syscall
 test rax,rax
 jnz io_failure
 lea rdi,[rbp+1360]
 push 65
 pop rcx
 call c_length
 mov [r15+56],rax
 lea rdi,[rbp+1620]
 push 65
 pop rcx
 call c_length
 mov [r15+64],rax
 mov esi,SOURCE_N
 call allocate
 mov r12,rax
 mov [rbp],rax
 mov esi,CORE_N
 call allocate
 mov r13,rax
 mov [rbp+8],rax
 mov esi,EVT_MAP
 call allocate
 mov [rbp+16],rax
read_input:
 mov rdi,[rbp+112]
 mov rax,[rbp+88]
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
 add [rbp+88],rax
 cmp QWORD PTR [rbp+88],RAW_N
 ja capacity
 jmp read_input
input_complete:
 cmp QWORD PTR [rbp+120],0
 je source_closed
 mov rdi,[rbp+112]
 push 3
 pop rax
 syscall
 test rax,rax
 jnz io_failure
source_closed:
 mov rdi,r12
 mov esi,RAW_N
 call protect_readonly
check_core:
 mov rdi,r12
 mov rsi,[rbp+88]
 mov rdx,r13
 mov ecx,CORE_N
 lea r8,[r12+RAW_N]
 mov r9d,33554432
 call build_core_start
 mov [rbp+1112],rax
 cmp eax,0xfffffffb
 jne core_verified
 cmp QWORD PTR [rbp+NOMINAL_PRESENT],0
 je lower_nominal
core_verified:
 call require_native_zero
 mov rdi,r12
 mov esi,SOURCE_N
 call protect_readonly
 call frontend_arguments
 call build_frontend_start
 mov [rbp+1120],rax
 call require_native_zero
 call frontend_arguments
 call build_frontend_start
 mov [rbp+1128],rax
 call require_native_zero
 movabs rax,3616483217365879112
 mov [rbp+768],rax
 mov QWORD PTR [rbp+776],1
codegen_loop:
 call frontend_arguments
 call build_codegen_start
 mov [rbp+1136],rax
 call require_native_zero
 mov rdi,[rbp+16]
 mov esi,EVT_MAP
 call protect_readonly
 mov rbx,[rbp+16]
 movabs rax,3544425636246407496
 cmp [rbx],rax
 jne io_failure
 mov rax,[rbx+8]
 cmp rax,128
 ja io_failure
 mov [rbp+112],rax
 mov [rbp+104],rax
 imul rax,272
 add rax,64
 cmp [rbx+16],rax
 jne io_failure
 mov rax,[rbx+40]
 mov [rbp+120],rax
 cmp QWORD PTR [rbx+48],1
 je codegen_complete
 cmp QWORD PTR [rbx+48],0
 jne io_failure
 lea rax,[rbx+64]
 mov [rbp+96],rax
next_event:
 cmp QWORD PTR [rbp+104],0
 je capture_batch
 mov rbx,[rbp+96]
 cmp QWORD PTR [rbx],1
 je numeric_event
 cmp QWORD PTR [rbx],2
 jne event_io_failure
 lea rdi,[rbx+8]
 push 64
 pop rsi
 mov rax,[rbx+16]
 test rax,rax
 jz initialize_code
 cmp QWORD PTR [rbp+24],0
 je event_io_failure
 cmp rax,4
 je named_event
 cmp rax,5
 je named_event
 jmp invoke_state
named_event:
 mov rax,[rbx+24]
 test rax,rax
 jz event_io_failure
 cmp rax,192
 ja event_io_failure
 add rsi,rax
 jmp invoke_state
event_io_failure:
 jmp io_failure
initialize_code:
 cmp QWORD PTR [rbp+24],0
 jne io_failure
 lea rdi,[rbx+8]
 push 64
 pop rsi
 lea rdx,[rbp+512]
 push 8
 pop rcx
 lea r8,[rbp+600]
 push 8
 pop r9
 call r14
 mov edx,0xffffff00
 cmp rax,rdx
 jae native_status
 test rax,rax
 jz io_failure
 mov [rbp+32],rax
 mov rsi,rax
 call allocate
 mov [rbp+40],rax
 mov esi,CODE_N
 call allocate
 mov [rbp+24],rax
 lea rdi,[rbx+8]
 push 64
 pop rsi
invoke_state:
 call byte_state
 jmp event_complete
numeric_event:
 cmp QWORD PTR [rbp+24],0
 je io_failure
 lea rdi,[rbx+8]
 push 64
 pop rsi
 lea rdx,[rbp+512]
 push 80
 pop rcx
 lea r8,[rbp+600]
 push 8
 pop r9
 call r14
 call require_native_zero
 mov rcx,[rbp+512]
 cmp rcx,63
 ja io_failure
 lea rax,[rcx+8]
 cmp [rbp+600],rax
 jne io_failure
 mov [rbp+784],rcx
 lea rsi,[rbp+520]
 lea rdi,[rbp+832]
 rep movsb
 lea rdi,[rbp+768]
 mov rsi,[rbp+784]
 add rsi,64
 call byte_state
 event_complete:
 add QWORD PTR [rbp+96],272
 dec QWORD PTR [rbp+104]
 jmp next_event
capture_batch:
 mov rbx,[rbp+24]
 test rbx,rbx
 jz io_failure
 movabs rax,3616465607999965512
 cmp [rbx],rax
 jne io_failure
 mov rax,[rbx+8]
 cmp rax,16777216
 ja io_failure
 mov [r13+C+48],rax
 mov rax,[rbp+120]
 mov [r13+C+184],rax
 mov rax,[rbp+112]
 mov [r13+C+200],rax
 mov QWORD PTR [r13+C+208],0
 mov rax,[rbx+40]
 mov [r13+C+216],rax
 mov rdi,[rbp+16]
 mov esi,EVT_MAP
 call protect_writable
 jmp codegen_loop
codegen_complete:
 cmp QWORD PTR [rbp+112],0
 jne io_failure
 mov rbx,[rbp+24]
 test rbx,rbx
 jz io_failure
 cmp QWORD PTR [rbx+40],1
 jne io_failure
 mov rdi,rbx
 mov esi,CODE_N
 call protect_readonly
 mov rdi,[rbp+40]
 mov rsi,[rbp+32]
 call protect_readonly
 mov rdi,r13
 mov esi,CORE_N
 call protect_readonly
 mov esi,20480
 call allocate
 mov [r15-120],rax
 mov rdi,r12
 mov esi,SOURCE_N
 mov rdx,rax
 mov ecx,20480
 mov r8,r13
 mov r9d,CORE_N
 call build_frontend_start
 test rax,rax
 jz io_failure
 cmp rax,18496
 ja native_status
 cmp rax,64
 jb io_failure
 mov [r15-112],rax
 mov rdi,[r15-120]
 cmp [rdi+24],rax
 jne io_failure
 cmp QWORD PTR [rdi+32],0
 jne io_failure
 mov esi,20480
 call protect_readonly
 mov rbx,[rbp+24]
 mov rax,[rbx+8]
 mov [r15+72],rax
 mov rax,[rbx+40]
 mov [r15+88],rax
 mov esi,262144
 call allocate
 mov [r15-72],rax
 mov rdi,r12
 mov esi,SOURCE_N
 mov rdx,rax
 mov ecx,262144
 mov r8,r13
 mov r9d,CORE_N
 call build_frontend_start
 test rax,rax
 jz io_failure
 cmp rax,200703
 ja native_status
 mov [r15-64],rax
 mov rdi,[r15-72]
 mov esi,262144
 call protect_readonly
 mov esi,8388608
 call allocate
 mov [r15-56],rax
 mov esi,33554432
 call allocate
 mov [r15-40],rax
 mov QWORD PTR [rax+48],262144
 mov QWORD PTR [rax+56],64
 mov rdi,r12
 mov rsi,[rbp+88]
 mov rdx,[r15-56]
 mov ecx,8388608
 mov r8,rax
 mov r9d,33554432
 call build_frontend_start
 test rax,rax
 jz io_failure
 cmp rax,8388608
 ja native_status
 mov [r15-48],rax
 mov rdi,[r15-56]
 mov esi,8388608
 call protect_readonly
 mov rdi,[r15-40]
 mov esi,33554432
 call release
 mov rdi,r12
 mov esi,SOURCE_N
 call release
 mov rdi,r13
 mov esi,CORE_N
 call release
 mov rdi,[rbp+16]
 mov esi,EVT_MAP
 call release
 mov esi,ART_N
 call allocate
 mov [rbp+64],rax
 mov rdi,[rbp+24]
 mov esi,CODE_N
 mov rdx,rax
 mov ecx,ART_N
 mov r8,[rbp+40]
 mov r9,[rbp+32]
 call r14
 test rax,rax
 jz io_failure
 cmp rax,ART_N
 ja native_status
 mov [rbp+72],rax
 mov rdi,[rbp+64]
 mov esi,ART_N
 call protect_readonly
 mov rdi,[rbp+40]
 mov rsi,[rbp+32]
 call release
 mov esi,ART_N
 call allocate
 mov [rbp+48],rax
 mov esi,WRITE_W
 call allocate
 mov [rbp+80],rax
 mov rdi,[rbp+64]
 mov rsi,[rbp+72]
 mov rdx,[rbp+48]
 mov ecx,ART_N
 mov r8,rax
 mov r9d,WRITE_W
 call r14
 test rax,rax
 jz io_failure
 cmp rax,ART_N
 ja native_status
 mov [rbp+56],rax
 mov rdi,[rbp+48]
 movabs rax,282584257676671
 cmp [rdi],rax
 jne io_failure
 mov esi,ART_N
 call protect_readonly
 mov rdi,[rbp+64]
 mov esi,ART_N
 call release
 mov rdi,[rbp+80]
 mov esi,WRITE_W
 call release
 mov rax,[r15-112]
 add rax,[rbp+56]
 jc io_failure
 cmp rax,67127360
 ja io_failure
 mov [r15-96],rax
 mov esi,67129344
 call allocate
 mov [r15-104],rax
 mov rdi,rax
 mov rsi,[r15-120]
 mov rcx,[r15-112]
 cld
 rep movsb
 mov rax,[rbp+56]
 mov rbx,[r15-104]
 mov [rbx+32],rax
 mov rsi,[rbp+48]
 mov rcx,rax
 rep movsb
 mov rdi,[r15-104]
 mov esi,67129344
 call protect_readonly
 mov esi,32768
 call allocate
 mov [r15-88],rax
 mov esi,4096
 call allocate
 mov [r15-80],rax
 mov rdi,[r15-104]
 mov rsi,[r15-96]
 mov rdx,[r15-88]
 mov ecx,32768
 mov r8,rax
 mov r9d,4096
 call r14
 test rax,rax
 jz io_failure
 cmp rax,32768
 ja native_status
 mov [rbp+1152],rax
 mov rdi,[r15-88]
 mov esi,32768
 call protect_readonly
 mov rdi,[r15-120]
 mov esi,20480
 call release
 mov rdi,[r15-104]
 mov esi,67129344
 call release
 mov rdi,[r15-88]
 mov esi,32768
 call release
 mov rax,[r15-80]
 mov rax,[rax+8]
 mov [rbp+1104],rax
 mov rdi,[r15-80]
 mov esi,4096
 call release
 # HIA owns the entire four-role hash operation.
 mov esi,4096
 call allocate
 mov [r15-32],rax
 mov esi,4096
 call allocate
 mov [r15-24],rax
 # The linker materializes its writable segment as zero-filled bytes.
 # Use the full ELF file extent without hashing mutated constructor state.
 mov rax,QWORD PTR ds:0x400080
 add rax,QWORD PTR ds:0x400098
 cmp rax,IMAGE_LIMIT
 ja io_failure
 mov [r15+80],rax
 lea r12,[rbp+1152]
 movabs rax,3544416750009403720
 mov [r12-128],rax
 mov QWORD PTR [r12-120],1
 mov rax,[r15-48]
 mov [r12-112],rax
 mov rax,[r15+72]
 mov [r12-104],rax
 mov rax,[rbp+56]
 mov [r12-96],rax
 mov rax,[r15+80]
 mov [r12-88],rax
 mov rax,[r15-64]
 mov [r12-80],rax
 mov [r12+16],rax
 mov rax,[r15+48]
 mov [r12-72],rax
 mov rax,[r15+56]
 mov [r12-64],rax
 mov rax,[r15+64]
 mov [r12-56],rax
 # Actual results already captured in the hash header; no synthetic statuses.
 mov rax,[rbp+56]
 mov [r12-8],rax
 mov rax,[r15+88]
 mov [r12+8],rax
 mov rsi,[r15-48]
 add rsi,[r15+72]
 add rsi,[rbp+56]
 add rsi,[r15+80]
 add rsi,192
 jc io_failure
 cmp rsi,RAW_N+ART_N+(16<<20)+IMAGE_LIMIT+192
 ja io_failure
 mov [r15+112],rsi
 call allocate
 mov [r15+104],rax
 mov rdi,rax
 lea rsi,[r12-128]
 push 24
 pop rcx
 cld
 rep movsq
 mov rsi,[r15-56]
 mov rcx,[r15-48]
 rep movsb
 mov rsi,[rbp+24]
 add rsi,64
 mov rcx,[r15+72]
 rep movsb
 mov rsi,[rbp+48]
 mov rcx,[rbp+56]
 rep movsb
 mov esi,0x400000
 mov rcx,QWORD PTR ds:0x400080
 rep movsb
 xor eax,eax
 mov rcx,QWORD PTR ds:0x400098
 rep stosb
 mov rdi,[r15+104]
 mov rsi,[r15+112]
 call protect_readonly
 mov rdx,[r15-24]
 mov ecx,320
 mov r8,[r15-32]
 mov r9d,1184
 call build_frontend_start
 cmp rax,320
 jne native_status
 cmp QWORD PTR [rbp+NOMINAL_PRESENT],0
 je freeze_hashes
 mov rdi,[r15-24]
 mov QWORD PTR [rdi+152],1
 add rdi,288
 lea rsi,[rbp+NOMINAL_HASH]
 push 4
 pop rcx
 cld
 rep movsq
freeze_hashes:
 mov rdi,[r15-24]
 mov esi,4096
 call protect_readonly
 mov rdi,[r15+104]
 mov rsi,[r15+112]
 call release
hashes_complete:
 mov esi,262144
 call allocate
 mov [r15+8],rax
 mov rdi,rax
 mov rsi,[r15-24]
 push 40
 pop rcx
 cld
 rep movsq
 mov rsi,[r15-72]
 mov rcx,[r15-64]
 rep movsb
 mov rsi,[r15+40]
 mov rcx,[r15+48]
 rep movsb
 lea rsi,[rbp+1360]
 mov rcx,[r15+56]
 rep movsb
 lea rsi,[rbp+1620]
 mov rcx,[r15+64]
 rep movsb
 sub rdi,[r15+8]
 cmp rdi,262144
 ja io_failure
 mov [r15+16],rdi
 mov rdi,[r15+8]
 mov esi,262144
 call protect_readonly
 mov rdi,[r15-72]
 mov esi,262144
 call release
 mov rdi,[r15-56]
 mov esi,8388608
 call release
 mov rdi,[rbp+24]
 mov esi,16777280
 call release
 mov rdi,[r15-32]
 mov esi,4096
 call release
 mov rdi,[r15-24]
 mov esi,4096
 call release
 mov esi,262144
 call allocate
 mov [r15+24],rax
 mov esi,32768
 call allocate
 mov [r15+96],rax
 mov rdi,[r15+8]
 mov rsi,[r15+16]
 mov rdx,[r15+24]
 mov ecx,262144
 mov r8,rax
 mov r9d,32768
 call build_codegen_start
 test rax,rax
 jz io_failure
 cmp rax,262144
 ja native_status
 mov [r15+32],rax
 mov rdi,[r15+24]
 mov esi,262144
 call protect_readonly
 mov rdi,[r15+8]
 mov esi,262144
 call release
 mov rdi,[r15+96]
 mov esi,32768
 call release
 # Native HIA owns filesystem state and all exact-byte/identity decisions.
 mov esi,1048576
 call allocate
 mov r12,rax
 mov esi,98304
 call allocate
 mov r13,rax
 movabs rax,3544406931680610632
 mov [r13],rax
 mov rax,[r15+48]
 mov [r13+40],rax
 mov rcx,rax
 inc rcx
 mov rax,[rbp+56]
 mov [r13+48],rax
 mov rax,[rbp+48]
 mov [rbp+96],rax
 mov rax,[rbp+56]
 mov [rbp+128],rax
 mov [rbp+104],r12
 mov QWORD PTR [rbp+136],1048576
 mov [rbp+112],r13
 mov QWORD PTR [rbp+144],98304
 mov rsi,[r15+40]
 lea rdi,[r12+4096]
 cld
 rep movsb
 mov rdi,[r15+40]
 mov esi,262144
 call release
publication_loop:
 mov rdi,[rbp+48]
 mov rsi,[rbp+56]
 mov rdx,r12
 mov ecx,1048576
 mov r8,r13
 mov r9d,98304
 call r14
 cmp rax,96
 jne native_status
 mov rdi,r12
 mov esi,1048576
 call protect_readonly
 movabs rax,3544409130703866184
 cmp [r12],rax
 jne io_failure
 cmp QWORD PTR [r12+16],2
 je publication_complete
 cmp QWORD PTR [r12+16],1
 jne io_failure
 mov rbx,[r12+32]
 cmp rbx,63
 ja io_failure
 sub rsp,64
 mov rax,[r12+24]
 mov [rsp+48],rax
 lea rsi,[r12+40]
 mov rdi,rsp
 push 6
 pop rcx
 cld
 rep movsq
 xor edx,edx
translate_argument:
 test bl,1
 jz argument_ready
 mov rax,[rsp+rdx*8]
 mov rcx,rax
 shr rcx,48
 cmp rcx,1
 jb io_failure
 cmp rcx,3
 ja io_failure
 shl rax,16
 shr rax,16
 cmp rax,[rbp+rcx*8+120]
 jae io_failure
 add rax,[rbp+rcx*8+88]
 mov [rsp+rdx*8],rax
argument_ready:
 shr rbx,1
 inc edx
 cmp edx,6
 jb translate_argument
 mov rax,[rsp+48]
 mov rdi,[rsp]
 mov rsi,[rsp+8]
 mov rdx,[rsp+16]
 mov r10,[rsp+24]
 mov r8,[rsp+32]
 mov r9,[rsp+40]
 syscall
 add rsp,64
 mov [r13+32],rax
 mov rax,[r12+8]
 mov [r13+24],rax
 mov rdi,r12
 mov esi,1048576
 call protect_writable
 jmp publication_loop
publication_complete:
 mov rdi,[r12+24]
 test rdi,rdi
 jnz exit
 mov rdi,r12
 mov esi,1048576
 call release
 mov rdi,r13
 mov esi,98304
 call release
 mov rsi,[r15+24]
 mov rdx,[r15+32]
 call write_owned
 mov rdi,[rbp+48]
 mov esi,ART_N
 call release
 mov rdi,[r15+24]
 mov esi,262144
 call release
 mov rdi,rbp
 mov esi,4096
 call release
 xor edi,edi
 jmp exit
write_owned:
 mov r12,rsi
 mov r13,rdx
write_owned_loop:
 test r13,r13
 jz write_owned_done
 mov edx,4096
 cmp r13,rdx
 cmovb rdx,r13
 mov rsi,r12
 push 1
 pop rdi
 push 1
 pop rax
 syscall
 cmp rax,-4
 je write_owned_loop
 test rax,rax
 jle io_failure
 cmp rax,rdx
 ja io_failure
 add r12,rax
 sub r13,rax
 jmp write_owned_loop
write_owned_done:
 ret
lower_nominal:
 mov rdi,r12
 mov rsi,[rbp+88]
 call nominal_lower_for_build
 test rdx,rdx
 jz io_failure
 cmp rdx,RAW_N
 ja capacity
 mov [rbp+LOWERED_CORE],rax
 mov [rbp+LOWERED_EXTENT],rdx
 mov rsi,rcx
 lea rdi,[rbp+NOMINAL_HASH]
 lea rbx,[rsi+64]
 cld
copy_digest:
 # The HIA report owner returns eight SHA-256 words in 64-bit slots.
 lodsq
 mov rdx,rax
 shr rdx,32
 jnz io_failure
 bswap eax
 stosd
 cmp rsi,rbx
 jb copy_digest
 mov QWORD PTR [rbp+NOMINAL_PRESENT],1
 # Retry independent Core admission in fresh, disjoint memory.
 mov rdi,r12
 mov esi,SOURCE_N
 call release
 mov rdi,r13
 mov esi,CORE_N
 call release
 mov esi,SOURCE_N
 call allocate
 mov r12,rax
 mov [rbp],rax
 mov rdi,rax
 mov rsi,[rbp+LOWERED_CORE]
 mov rcx,[rbp+LOWERED_EXTENT]
 mov [rbp+88],rcx
 cld
 rep movsb
 mov esi,CORE_N
 call allocate
 mov r13,rax
 mov [rbp+8],rax
 mov rdi,r12
 mov esi,RAW_N
 call protect_readonly
 jmp check_core

frontend_arguments:
 mov rdi,r12
 mov esi,SOURCE_N
 mov rdx,[rbp+16]
 mov ecx,EVT_N
 mov r8,r13
 mov r9d,CORE_N
 ret
c_length:
 xor eax,eax
c_length_loop:
 cmp rax,rcx
 jae usage
 cmp BYTE PTR [rdi+rax],0
 je c_length_done
 inc rax
 jmp c_length_loop
c_length_done:
 ret
allocate:
 xor edi,edi
 push 3
 pop rdx
 push 34
 pop r10
 push -1
 pop r8
 xor r9d,r9d
 push 9
 pop rax
 syscall
 cmp rax,-4095
 jae io_failure
 ret
protect_readonly:
 push 1
 pop rdx
 jmp protect
protect_writable:
 push 3
 pop rdx
protect:
 push 10
 pop rax
 syscall
 test rax,rax
 jnz io_failure
 ret
release:
 push 11
 pop rax
 syscall
 test rax,rax
 jnz io_failure
 ret
byte_state:
 mov rdx,[rbp+24]
 mov ecx,CODE_N
 mov r8,[rbp+40]
 mov r9,[rbp+32]
 sub rsp,8
 call r14
 add rsp,8
 test rax,rax
 jnz native_status
 ret
require_native_zero:
 test rax,rax
 jnz native_status
 ret
native_status:
 mov rdx,rax
 shr rdx,32
 jnz io_failure
 mov edx,0xfffffffe
 cmp rax,rdx
 je capacity
 mov edx,0xfffffffd
 cmp rax,rdx
 je io_failure
invalid:
 push 2
 pop rdi
 jmp exit
capacity:
 push 3
 pop rdi
 jmp exit
io_failure:
 push 4
 pop rdi
 jmp exit
usage:
 push 64
 pop rdi
exit:
 push 60
 pop rax
 syscall
 ud2
