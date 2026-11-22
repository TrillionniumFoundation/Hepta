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
.equ SHARED_MODE,1856
.equ SHARED_ARTIFACT,1864
.equ SHARED_EXTENT,1872
.equ SHARED_FRAME,1880
.equ SHARED_FRAME_EXTENT,1888
.equ SHARED_EXPORT_WORK,1896
.equ SHARED_SYMBOLS,1904
.equ SHARED_SYMBOL_EXTENT,1912
.equ SHARED_HASH_INPUT,1920
.equ SHARED_HASH_CHUNK,1928
.equ SHARED_DIGEST,1936
.equ REPORT_CAPACITY,1968
.equ SHARED_LINK_WORK_BYTES,1048576
.equ SHARED_FRAME_BYTES,266240
.equ SHARED_EXPORT_WORK_BYTES,1639448
.equ SHARED_SYMBOL_BYTES,1574976
.equ SHARED_SYMBOL_HEAD,2112
.equ SHARED_REPORT_BYTES,1048576
.equ HASH_CHUNK_BYTES,8388608
.equ HASH_INPUT_BYTES,HASH_CHUNK_BYTES+1
.equ HASH_STATE_BYTES,1184
.equ HASH_STATE,2048
.equ REPORT_SCRATCH,3328
.equ IMAGE_LIMIT,7<<20
.equ PROVER_FD,3440
.equ PROOF_INPUT,3448
.equ PROOF_OUTPUT,3456
.equ PROOF_STATUS,3464
.equ PROOF_PARENT,3472
.equ PROOF_REPORT,3480
.equ PROOF_SIZE,3488
.equ SHARED_LINK_ID,3496
.equ PROOF_REQUEST,3504
.equ PROOF_LIMIT,2097152
.equ VERIFIED_LINK_LIMIT,90112
.equ VERIFIED_OBJECT_LIMIT,73728
.equ PLAN_FD,3520
.equ SOURCE_EXTENT,3528
.equ PLAN_PREFIX,3536
.equ PLAN_STAT,3616
.equ PLAN_EXTENT,3760
.equ PLAN_REPORT_CAPACITY,3768
.equ PLAN_BYTES,8388608
.equ PLAN_HEADER,80
_start:
 # The static linker calls this entry. The adapter itself never returns.
 add rsp,8
 lea r14,[rip+build_backend_start]
 mov esi,4096
 call allocate
 mov rbp,rax
 mov QWORD PTR [rbp+REPORT_CAPACITY],262144
 cmp QWORD PTR [rsp],2
 jb usage
 mov rsi,[rsp+8]
 lea rdi,[rip+verified_build_mode]
 mov ecx,19
 cld
 repe cmpsb
 jne ordinary_build_mode
 mov rax,[rsp]
 sub rax,3
 cmp rax,1
 ja usage
 mov rsi,[rsp+rax*8+24]
 call read_pinned_descriptor
 mov [rbp+PROVER_FD],rax
 dec QWORD PTR [rsp]
 mov QWORD PTR [rbp+SHARED_MODE],2
 jmp build_args
ordinary_build_mode:
 mov rsi,[rsp+8]
 lea rdi,[rip+shared_build_mode]
 mov ecx,17
 cld
 repe cmpsb
 jne build_args
 mov QWORD PTR [rbp+SHARED_MODE],1
build_args:
 cmp QWORD PTR [rsp],4
 jne build_paths
 cmp QWORD PTR [rbp+SHARED_MODE],2
 je usage
 mov rsi,[rsp+16]
 lea rdi,[rip+plan_build_mode]
 mov ecx,17
 cld
 repe cmpsb
 jne usage
 mov rsi,[rsp+24]
 call read_pinned_descriptor
 mov [rbp+PLAN_FD],rax
 mov rax,[rsp+32]
 mov [rsp+16],rax
 mov QWORD PTR [rsp],2
build_paths:
 mov rax,[rsp]
 sub rax,2
 cmp rax,1
 ja usage
 mov r15,[rsp+16]
 test rax,rax
 jz output_arg_ready
 mov r15,[rsp+24]
output_arg_ready:
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
 cmp QWORD PTR [rbp+PLAN_FD],0
 je allocate_source
 add esi,PLAN_BYTES
allocate_source:
 mov [rbp+SOURCE_EXTENT],rsi
 call allocate
 mov r12,rax
 mov [rbp],rax
 cmp QWORD PTR [rbp+PLAN_FD],0
 je allocate_core
 call capture_build_plan
allocate_core:
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
 mov rsi,[rbp+SOURCE_EXTENT]
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
 cmp QWORD PTR [rbp+SHARED_MODE],2
 je release_core_work
 mov rdi,r12
 mov rsi,[rbp+SOURCE_EXTENT]
 call release
release_core_work:
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
 cmp QWORD PTR [rbp+SHARED_MODE],0
 je attach_plan_identity
 call link_shared_artifact
attach_plan_identity:
 cmp QWORD PTR [rbp+PLAN_FD],0
 je publish_artifact
 call bind_plan_report
publish_artifact:
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
 mov rsi,[rbp+REPORT_CAPACITY]
 call release
 mov rdi,rbp
 mov esi,4096
 call release
 xor edi,edi
 jmp exit

link_shared_artifact:
 # Keep the direct object immutable; do not publish until the independent
 # inventory confirms that the linked ELF exposes exactly its admitted exports.
 sub rsp,8
 mov esi,ART_N
 call allocate
 mov [rbp+SHARED_ARTIFACT],rax
 mov esi,SHARED_LINK_WORK_BYTES
 call allocate
 mov rdi,[rbp+48]
 mov rsi,[rbp+56]
 mov rdx,[rbp+SHARED_ARTIFACT]
 mov ecx,ART_N
 mov r8,rax
 mov r9d,SHARED_LINK_WORK_BYTES
 mov [rbp+SHARED_EXPORT_WORK],rax
 lea rax,[rip+build_shared_linker_identity_start]
 mov [rbp+SHARED_LINK_ID],rax
 cmp QWORD PTR [rbp+SHARED_MODE],2
 jne ordinary_link
 cmp rsi,VERIFIED_OBJECT_LIMIT
 ja invalid
 mov ecx,VERIFIED_LINK_LIMIT
 mov r9d,512
 call build_verified_linker_start
 mov edx,0xffffffff
 cmp rax,rdx
 je try_ordinary_link
 cmp rax,VERIFIED_LINK_LIMIT
 ja native_status
 lea rdx,[rip+build_verified_linker_identity_start]
 mov [rbp+SHARED_LINK_ID],rdx
 jmp shared_linked
try_ordinary_link:
 # The ordinary emitter receives the same zeroed buffers as the direct path.
 mov rdi,[rbp+SHARED_ARTIFACT]
 mov esi,ART_N
 call release
 mov rdi,[rbp+SHARED_EXPORT_WORK]
 mov esi,SHARED_LINK_WORK_BYTES
 call release
 mov esi,ART_N
 call allocate
 mov [rbp+SHARED_ARTIFACT],rax
 mov esi,SHARED_LINK_WORK_BYTES
 call allocate
 mov [rbp+SHARED_EXPORT_WORK],rax
 mov rdi,[rbp+48]
 mov rsi,[rbp+56]
 mov rdx,[rbp+SHARED_ARTIFACT]
 mov ecx,ART_N
 mov r8,[rbp+SHARED_EXPORT_WORK]
 mov r9d,SHARED_LINK_WORK_BYTES
ordinary_link:
 call build_shared_linker_start
shared_linked:
 cmp rax,64
 jb io_failure
 cmp rax,ART_N
 ja native_status
 mov [rbp+SHARED_EXTENT],rax
 mov rdi,[rbp+SHARED_ARTIFACT]
 mov esi,ART_N
 call protect_readonly
 mov rdi,[rbp+SHARED_EXPORT_WORK]
 mov esi,SHARED_LINK_WORK_BYTES
 call release
 mov esi,SHARED_FRAME_BYTES
 call allocate
 mov [rbp+SHARED_FRAME],rax
 movabs rdx,0x3130584553414948  # HIASEX01
 mov [rax],rdx
 mov rcx,[r15+32]
 lea rdx,[rcx+88]
 mov [rbp+SHARED_FRAME_EXTENT],rdx
 lea rdi,[rax+88]
 mov rsi,[r15+24]
 cld
 rep movsb
 mov rdi,[rbp+SHARED_FRAME]
 mov esi,SHARED_FRAME_BYTES
 call protect_readonly
 mov esi,SHARED_EXPORT_WORK_BYTES
 call allocate
 mov [rbp+SHARED_EXPORT_WORK],rax
 mov rdi,[rbp+SHARED_FRAME]
 mov rsi,[rbp+SHARED_FRAME_EXTENT]
 mov rdx,rax
 mov ecx,SHARED_EXPORT_WORK_BYTES
 lea r8,[rbp+REPORT_SCRATCH]
 mov r9d,96
 call build_shared_report_start
 cmp rax,SHARED_EXPORT_WORK_BYTES
 jne native_status
 mov esi,SHARED_SYMBOL_BYTES
 call allocate
 mov [rbp+SHARED_SYMBOLS],rax
 mov rdi,[rbp+SHARED_ARTIFACT]
 mov rsi,[rbp+SHARED_EXTENT]
 mov rdx,rax
 mov ecx,SHARED_SYMBOL_BYTES
 mov r8,[rbp+SHARED_EXPORT_WORK]
 mov r9d,SHARED_EXPORT_WORK_BYTES
 call build_shared_inventory_start
 cmp rax,SHARED_SYMBOL_HEAD
 jb io_failure
 cmp rax,SHARED_SYMBOL_BYTES
 ja native_status
 mov [rbp+SHARED_SYMBOL_EXTENT],rax
 mov rdi,[rbp+SHARED_EXPORT_WORK]
 mov esi,SHARED_EXPORT_WORK_BYTES
 call release
 mov rdi,[rbp+SHARED_SYMBOLS]
 mov esi,SHARED_SYMBOL_BYTES
 call protect_readonly
 mov rdi,[rbp+SHARED_ARTIFACT]
 mov rsi,[rbp+SHARED_EXTENT]
 lea rdx,[rbp+REPORT_SCRATCH]
 xor ecx,ecx
 mov r8,[rbp+SHARED_SYMBOLS]
 mov r9,[rbp+SHARED_SYMBOL_EXTENT]
 call build_shared_report_start
 dec rax
 cmp rax,2047
 ja invalid
 mov r12,rax
 mov rdi,[rbp+SHARED_SYMBOLS]
 mov esi,SHARED_SYMBOL_BYTES
 call release
 mov rdi,[rbp+SHARED_FRAME]
 mov esi,SHARED_FRAME_BYTES
 call protect_writable
 mov rbx,[rbp+SHARED_FRAME]
 movabs rax,0x3130524253414948  # HIASBR01
 mov [rbx],rax
 mov rax,[rbp+SHARED_EXTENT]
 mov [rbx+8],rax
 mov [rbx+16],r12
 mov r12,[rbp+SHARED_ARTIFACT]
 mov r13,[rbp+SHARED_EXTENT]
 call hash_bytes
 lea rsi,[rbp+SHARED_DIGEST]
 lea rdi,[rbx+24]
 mov ecx,4
 cld
 rep movsq
 mov rsi,[rbp+SHARED_LINK_ID]
 mov ecx,4
 rep movsq
 cmp QWORD PTR [rbp+SHARED_MODE],2
 jne shared_report_ready
 call prove_shared_artifact
shared_report_ready:
 mov rdi,[rbp+SHARED_FRAME]
 mov esi,SHARED_FRAME_BYTES
 call protect_readonly
 mov rdi,[r15+24]
 mov esi,262144
 call release
 mov esi,SHARED_REPORT_BYTES
 call allocate
 mov [r15+24],rax
 mov QWORD PTR [rbp+REPORT_CAPACITY],SHARED_REPORT_BYTES
 mov rdi,[rbp+SHARED_FRAME]
 mov rsi,[rbp+SHARED_FRAME_EXTENT]
 mov rdx,rax
 mov ecx,SHARED_REPORT_BYTES
 lea r8,[rbp+REPORT_SCRATCH]
 mov r9d,96
 call build_shared_report_start
 test rax,rax
 jz io_failure
 cmp rax,SHARED_REPORT_BYTES
 ja native_status
 mov [r15+32],rax
 mov rdi,[r15+24]
 mov esi,SHARED_REPORT_BYTES
 call protect_readonly
 mov rdi,[rbp+SHARED_FRAME]
 mov esi,SHARED_FRAME_BYTES
 call release
 mov rdi,[rbp+48]
 mov esi,ART_N
 call release
 mov rax,[rbp+SHARED_ARTIFACT]
 mov [rbp+48],rax
 mov rax,[rbp+SHARED_EXTENT]
 mov [rbp+56],rax
 add rsp,8
 ret

hash_bytes:
 # This adapter moves bounded chunks only. The HIA stream image owns SHA-256.
 sub rsp,8
 mov esi,HASH_INPUT_BYTES
 call allocate
 mov [rbp+SHARED_HASH_INPUT],rax
 mov esi,1
 call shared_hash_transition
 call require_native_zero
shared_hash_chunk:
 mov rdi,[rbp+SHARED_HASH_INPUT]
 mov BYTE PTR [rdi],1
 inc rdi
 mov ecx,HASH_CHUNK_BYTES
 cmp r13,rcx
 cmovb rcx,r13
 mov [rbp+SHARED_HASH_CHUNK],rcx
 mov rsi,r12
 cld
 rep movsb
 mov rsi,[rbp+SHARED_HASH_CHUNK]
 inc rsi
 call shared_hash_transition
 call require_native_zero
 mov rax,[rbp+SHARED_HASH_CHUNK]
 add r12,rax
 sub r13,rax
 jnz shared_hash_chunk
 mov rdi,[rbp+SHARED_HASH_INPUT]
 mov BYTE PTR [rdi],2
 mov esi,1
 call shared_hash_transition
 cmp rax,32
 jne io_failure
 mov rdi,[rbp+SHARED_HASH_INPUT]
 mov esi,HASH_INPUT_BYTES
 call release
 add rsp,8
 ret

shared_hash_transition:
 mov rdi,[rbp+SHARED_HASH_INPUT]
 lea rdx,[rbp+SHARED_DIGEST]
 mov ecx,32
 lea r8,[rbp+HASH_STATE]
 mov r9d,HASH_STATE_BYTES
 jmp build_shared_hash_start

# Move only the bounded sealed plan authorization and layout. HIA validates
# layout ordinals in the emitter and binds the authorization to its report.
capture_build_plan:
 mov rdi,[rbp+PLAN_FD]
 mov esi,1034
 mov eax,72
 syscall
 cmp rax,15
 jne invalid
 mov rdi,[rbp+PLAN_FD]
 lea rsi,[rbp+PLAN_STAT]
 mov eax,5
 syscall
 test rax,rax
 jne io_failure
 mov rax,[rbp+PLAN_STAT+48]
 cmp rax,PLAN_HEADER+40
 jb invalid
 sub rax,PLAN_HEADER
 cmp rax,PLAN_BYTES
 ja capacity
 mov [rbp+PLAN_EXTENT],rax
 lea rdi,[rbp+PLAN_PREFIX]
 mov esi,PLAN_HEADER
 xor edx,edx
 call read_build_plan_bytes
 movabs rax,0x3130515645414948    # HIAEVQ01
 cmp rax,[rbp+PLAN_PREFIX]
 jne invalid
 cmp QWORD PTR [rbp+PLAN_PREFIX+8],0
 jne invalid
 lea rdi,[r12+SOURCE_N]
 mov rsi,[rbp+PLAN_EXTENT]
 mov edx,PLAN_HEADER
 call read_build_plan_bytes
 lea rdi,[r12+SOURCE_N]
 mov rax,[rbp+PLAN_EXTENT]
 cmp [rdi+16],rax
 jne invalid
 mov esi,PLAN_BYTES
 jmp protect_readonly

read_build_plan_bytes:
 mov r10,rdx
 mov rdx,rsi
 mov rsi,rdi
 mov rdi,[rbp+PLAN_FD]
read_build_plan_part:
 mov eax,17
 syscall
 cmp rax,-4
 je read_build_plan_part
 test rax,rax
 jle io_failure
 add rsi,rax
 add r10,rax
 sub rdx,rax
 jnz read_build_plan_part
 ret

bind_plan_report:
 sub rsp,8
 mov rsi,[r15+32]
 add rsi,PLAN_HEADER
 mov [rbp+PLAN_EXTENT],rsi
 call allocate
 mov rbx,rax
 mov rdi,rax
 lea rsi,[rbp+PLAN_PREFIX]
 mov ecx,PLAN_HEADER/8
 cld
 rep movsq
 mov rsi,[r15+24]
 mov rcx,[r15+32]
 rep movsb
 mov rdi,rbx
 mov rsi,[rbp+PLAN_EXTENT]
 call protect_readonly
 mov rsi,[rbp+REPORT_CAPACITY]
 add rsi,4096
 mov [rbp+PLAN_REPORT_CAPACITY],rsi
 call allocate
 mov rdx,rax
 mov [rbp+PLAN_PREFIX],rax
 mov rdi,rbx
 mov rsi,[rbp+PLAN_EXTENT]
 mov rcx,[rbp+PLAN_REPORT_CAPACITY]
 lea r8,[rbp+REPORT_SCRATCH]
 mov r9d,96
 call build_shared_report_start
 test rax,rax
 jz io_failure
 cmp rax,[rbp+PLAN_REPORT_CAPACITY]
 ja native_status
 mov [r15+32],rax
 mov rdi,[rbp+PLAN_PREFIX]
 mov rsi,[rbp+PLAN_REPORT_CAPACITY]
 call protect_readonly
 mov rdi,[r15+24]
 mov rsi,[rbp+REPORT_CAPACITY]
 call release
 mov rdi,rbx
 mov rsi,[rbp+PLAN_EXTENT]
 call release
 mov rax,[rbp+PLAN_PREFIX]
 mov [r15+24],rax
 mov rax,[rbp+PLAN_REPORT_CAPACITY]
 mov [rbp+REPORT_CAPACITY],rax
 add rsp,8
 ret

read_pinned_descriptor:
 # The launcher passes the descriptor as eight lowercase hexadecimal digits.
 xor eax,eax
 push 8
 pop rcx
proof_fd_digit:
 movzx edx,BYTE PTR [rsi]
 inc rsi
 sub edx,48
 cmp edx,9
 jbe proof_fd_append
 sub edx,39
 cmp edx,10
 jb usage
 cmp edx,15
 ja usage
proof_fd_append:
 shl eax,4
 or eax,edx
 loop proof_fd_digit
 cmp BYTE PTR [rsi],0
 jne usage
 cmp eax,3
 jl usage
 ret

prove_shared_artifact:
 # No caller-supplied executable may authorize publication. HIA hashes the
 # exact, sealed descriptor and compares it with this build's attached image.
 sub rsp,8
 mov edi,[rbp+PROVER_FD]
 call require_sealed
 mov eax,8
 xor esi,esi
 mov edx,2
 syscall
 cmp rax,[rip+build_prover_identity_start]
 jne io_failure
 mov rsi,rax
 xor edi,edi
 mov edx,1
 mov r10d,2
 mov r8d,[rbp+PROVER_FD]
 xor r9d,r9d
 mov eax,9
 syscall
 cmp rax,-4095
 jae io_failure
 mov rbx,rax
 mov r12,rax
 mov r13,rsi
 call hash_bytes
 mov rdi,rbx
 mov rsi,[rip+build_prover_identity_start]
 call release
 lea rsi,[rbp+SHARED_DIGEST]
 lea rdi,[rip+build_prover_identity_start+8]
 mov ecx,4
 cld
 repe cmpsq
 jne io_failure

 call new_proof_file
 mov [rbp+PROOF_INPUT],rax
 lea rsi,[rbp+PROOF_REQUEST]
 movabs rax,0x3130465250414948    # HIAPRF01
 mov [rsi],rax
 mov QWORD PTR [rsi+16],10000
 mov rax,[rbp+88]
 mov [rsi+24],rax
 mov rax,[rbp+56]
 mov [rsi+32],rax
 mov rax,[rbp+SHARED_EXTENT]
 mov [rsi+40],rax
 mov edi,[rbp+PROOF_INPUT]
 mov edx,48
 call write_proof_bytes
 mov rsi,[rbp]
 mov rdx,[rbp+88]
 call write_proof_bytes
 mov rsi,[rbp+48]
 mov rdx,[rbp+56]
 call write_proof_bytes
 mov rsi,[rbp+SHARED_ARTIFACT]
 mov rdx,[rbp+SHARED_EXTENT]
 call write_proof_bytes
 call seal_proof_file
 mov eax,8
 xor esi,esi
 xor edx,edx
 syscall
 test rax,rax
 jnz io_failure

 call new_proof_file
 mov [rbp+PROOF_OUTPUT],rax
 mov eax,39
 syscall
 mov [rbp+PROOF_PARENT],rax
 mov eax,57
 syscall
 test rax,rax
 js io_failure
 jz proof_child
 mov ebx,eax
wait_proof:
 mov edi,ebx
 lea rsi,[rbp+PROOF_STATUS]
 xor edx,edx
 xor r10d,r10d
 mov eax,61
 syscall
 cmp rax,-4
 je wait_proof
 cmp eax,ebx
 jne io_failure
 cmp DWORD PTR [rbp+PROOF_STATUS],0
 jne invalid
 mov edi,[rbp+PROVER_FD]
 call close_proof_file
 mov edi,[rbp+PROOF_INPUT]
 call close_proof_file
 mov edi,[rbp+PROOF_OUTPUT]
 call seal_proof_file
 mov eax,8
 xor esi,esi
 mov edx,2
 syscall
 cmp rax,464
 jb invalid
 cmp rax,PROOF_LIMIT
 ja capacity
 mov [rbp+PROOF_SIZE],rax
 mov rsi,rax
 xor edi,edi
 mov edx,1
 mov r10d,2
 mov r8d,[rbp+PROOF_OUTPUT]
 xor r9d,r9d
 mov eax,9
 syscall
 cmp rax,-4095
 jae io_failure
 mov [rbp+PROOF_REPORT],rax
 mov edi,[rbp+PROOF_OUTPUT]
 call close_proof_file

 # HIA admits only a positive receipt for these exact immutable final bytes.
 mov rdi,[rbp+PROOF_REPORT]
 mov rsi,[rbp+PROOF_SIZE]
 mov rbx,[rbp+SHARED_FRAME]
 lea r8,[rbx+24]
 mov r9d,32
 lea rdx,[rbp+REPORT_SCRATCH]
 xor ecx,ecx
 call build_shared_report_start
 cmp rax,1
 jb invalid
 cmp rax,6
 ja invalid
 mov rbx,[rbp+SHARED_FRAME]
 add rbx,[rbp+SHARED_FRAME_EXTENT]
 mov [rbx+32],rax
 mov r12,[rbp+PROOF_REPORT]
 mov r13,[rbp+PROOF_SIZE]
 call hash_bytes
 lea rsi,[rbp+SHARED_DIGEST]
 mov rdi,rbx
 mov ecx,4
 cld
 rep movsq
 mov rax,[rbp+SHARED_FRAME]
 movabs rdx,0x3230524253414948    # HIASBR02
 mov [rax],rdx
 add QWORD PTR [rbp+SHARED_FRAME_EXTENT],40
 mov rdi,[rbp+PROOF_REPORT]
 mov rsi,[rbp+PROOF_SIZE]
 call release
 mov rdi,[rbp]
 mov esi,SOURCE_N
 call release
 add rsp,8
 ret

proof_child:
 mov eax,157
 mov edi,1                       # PR_SET_PDEATHSIG
 mov esi,9
 xor edx,edx
 xor r10d,r10d
 xor r8d,r8d
 syscall
 test rax,rax
 js io_failure
 mov eax,110
 syscall
 cmp rax,[rbp+PROOF_PARENT]
 jne io_failure
 mov edi,[rbp+PROOF_INPUT]
 xor esi,esi
 call dup_proof_file
 mov edi,[rbp+PROOF_OUTPUT]
 mov esi,1
 call dup_proof_file
 mov eax,436
 mov edi,3
 mov esi,-1
 mov edx,4                       # CLOSE_RANGE_CLOEXEC
 syscall
 test rax,rax
 js io_failure
 sub rsp,32
 lea rax,[rip+prover_name]
 mov [rsp],rax
 mov QWORD PTR [rsp+8],0
 mov QWORD PTR [rsp+16],0
 mov edi,[rbp+PROVER_FD]
 lea rsi,[rip+proof_empty]
 mov rdx,rsp
 lea r10,[rsp+16]
 mov r8d,4096
 mov eax,322
 syscall
 jmp io_failure

new_proof_file:
 lea rdi,[rip+prover_name]
 mov esi,3
 mov eax,319
 syscall
 test rax,rax
 js io_failure
 cmp eax,2
 ja proof_file_ready
 mov edi,eax
 mov esi,1030
 mov edx,3
 mov eax,72
 syscall
 test rax,rax
 js io_failure
 push rax
 call close_proof_file
 pop rax
proof_file_ready:
 ret

seal_proof_file:
 mov eax,72
 mov esi,1033
 mov edx,15
 syscall
 test rax,rax
 js io_failure
require_sealed:
 mov eax,72
 mov esi,1034
 syscall
 cmp eax,15
 jne io_failure
 ret

dup_proof_file:
 xor edx,edx
 mov eax,292
 syscall
 test rax,rax
 js io_failure
 ret

close_proof_file:
 mov eax,3
 syscall
 test rax,rax
 js io_failure
 ret

write_proof_bytes:
 test rdx,rdx
 jz proof_bytes_ready
 mov eax,1
 syscall
 cmp rax,-4
 je write_proof_bytes
 test rax,rax
 jle io_failure
 cmp rax,rdx
 ja io_failure
 sub rdx,rax
 add rsi,rax
 jmp write_proof_bytes
proof_bytes_ready:
 ret
prover_name: .asciz "hia-safe-core-prove"
proof_empty: .byte 0
verified_build_mode: .asciz "hia-build-verified"
plan_build_mode: .asciz "--planned-layout"

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
shared_build_mode:
 .asciz "hia-build-shared"
lower_nominal:
 mov rdi,r12
 mov rsi,[rbp+88]
 call nominal_lower_for_core
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
