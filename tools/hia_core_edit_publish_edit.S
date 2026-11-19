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
.equ OUTPUT_N,33554432
.equ FRAME_N,16777216
.equ NOMINAL_ORIGIN,S+112
.equ ORIGIN_DIGEST,S+64
.equ ORIGIN_TAG,CTRL+1536
.equ ORIGIN_BYTES,CTRL+1544
.equ ORIGIN_MAGIC,3544423407359707464

_start:
 add rsp,8
 cmp QWORD PTR [rsp],2
 jne usage
 mov r12,[rsp+16]
 mov esi,16384
 call allocate
 mov rbp,rax
 lea rax,[rip+edit_base_admission_start]
 mov [rbp+328],rax
 lea rax,[rip+edit_base_extract_start]
 mov [rbp+320],rax
 lea rax,[rip+edit_apply_owner_start]
 mov [rbp+336],rax
 lea rax,[rip+edit_publication_start]
 mov [rbp+344],rax
 mov esi,270336
 call allocate
 mov [rbp],rax
 mov rbx,rax
 mov rdi,r12
 call c_length
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
 js cwd_ready
 jz io_failure
 cmp rax,4096
 ja io_failure
 lea rcx,[rax-1]
cwd_ready:
 mov [rbx+32],rcx
 add rcx,[rbp+360]
 add rcx,48
 mov [rbp+8],rcx
 mov rdi,rbx
 mov esi,270336
 call readonly
 mov rdi,rbx
 mov rsi,[rbp+8]
 lea rdx,[rbp+768]
 mov ecx,8
 lea r8,[rbp+776]
 mov r9d,8
 call QWORD PTR [rbp+344]
 test rax,rax
 jnz HIA_status
 mov esi,262144
 call allocate
 mov [rbp+16],rax
 mov esi,1048576
 call allocate
 mov [rbp+32],rax
 mov rdi,[rbp]
 mov rsi,[rbp+8]
 mov rdx,[rbp+16]
 mov ecx,262144
 mov r8,[rbp+32]
 mov r9d,1048576
 call QWORD PTR [rbp+344]
 test rax,rax
 jz io_failure
 cmp rax,4095
 ja io_failure
 mov [rbp+24],rax
 mov rdi,[rbp+16]
 mov esi,262144
 call readonly
 mov rdi,[rbp]
 mov esi,270336
 call release
 mov rdi,[rbp+32]
 mov esi,1048576
 call release
 mov r15,rbp
 mov esi,TOTAL_N
 call allocate
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
 cmp rax,rdx
 ja io_failure
 add [rbp+S],rax
 cmp QWORD PTR [rbp+S],RAW_N
 ja capacity
 jmp read_input
input_complete:
 mov rdi,r12
 mov esi,RAW_EXTENT
 call readonly
extract_base:
 mov rdi,r12
 mov rsi,[rbp+S]
 lea rdx,[r12+TEMP_AT]
 mov ecx,TEMP_N
 lea r8,[r12+WORK_AT]
 mov r9d,WORK_N
 call QWORD PTR [r15+320]
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
 call readonly
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
 call QWORD PTR [r15+328]
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
 call QWORD PTR [r15+336]
 call scalar_status
 test rax,rax
 jz invalid
 cmp rax,WORK_N
 ja io_failure
 call run_edit_owner
 call edit_status
 test rax,rax
 jz invalid
 cmp rax,8388608
 ja io_failure
 mov [rbp+S+32],rax
 mov rdi,r13
 mov esi,8388608
 call readonly
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
 call QWORD PTR [r15+344]
 mov [r13+CTRL+256],rax
 mov rdi,r13
 mov esi,8388608
 mov edx,3
 call protect
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
 call run_edit_owner
 mov [r13+CTRL+320],rax
 call query_status
 test rax,rax
 jz invalid
 cmp rax,1048576
 ja io_failure
 movabs rax,3544423415748315464
 mov [r13+CTRL],rax
 call run_edit_owner
 mov [r13+CTRL+344],rax
 call edit_status
 test rax,rax
 jnz invalid
 movabs rax,3544423420043282760
 mov [r13+CTRL],rax
 call run_edit_owner
 mov [r13+CTRL+384],rax
 call scalar_status
 cmp rax,16384
 ja io_failure
 lea rdi,[r12+WORK_AT+58720256]
 mov esi,16384
 call readonly
 lea rdi,[r12+WORK_AT+58720256]
 mov rsi,[r13+CTRL+384]
 lea rdx,[r12+TEMP_AT]
 call edit_response_syntax
 test eax,eax
 jz response_admitted
 cmp eax,DRIVER_TEXT_LIMIT
 ja io_failure
 lea rsi,[r12+TEMP_AT]
 mov edx,eax
 jmp write_refusal
response_admitted:
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
 call QWORD PTR [r15+336]
 mov [r13+CTRL+368],rax
 lea rdi,[r12+WORK_AT+58720256]
 mov esi,16384
 mov edx,3
 call protect
 movabs rax,3544427818089793864
 mov [r13+CTRL],rax
 call run_edit_owner
 mov [r13+CTRL+416],rax
 call edit_status
 test rax,rax
 jnz invalid
 movabs rax,3544405819267303752
 mov [r13+CTRL],rax
 call run_edit_owner
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
 call readonly
 lea rdi,[r13+17825792]
 mov esi,4096
 call readonly
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
 call QWORD PTR [r15+320]
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
 call readonly
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
 call QWORD PTR [r15+328]
 mov [r13+CTRL+448],rax
 mov [r15+40],rax
 mov rdi,r13
 mov esi,16777216
 mov edx,3
 call protect
 lea rdi,[r13+17825792]
 mov esi,4096
 mov edx,3
 call protect
 mov rdi,r12
 mov esi,SOURCE_N
 call release
 lea rdi,[r12+CORE_AT]
 mov esi,CORE_N
 call release
 lea rdi,[r12+WORK_AT]
 mov esi,WORK_N
 call release
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
 call QWORD PTR [r15+336]
 mov [r13+CTRL+496],rax
 call scalar_status
 test rax,rax
 jz invalid
 cmp rax,16777216
 ja io_failure
 mov [rbp+96],rax
 mov [r15+80],rax
 mov [r15+8],r13
 mov [r15+32],rbp
 lea rax,[r12+TEMP_AT]
 mov [r15],rax
 mov rbp,r15
 mov rax,[rbp]
 lea rdx,[rax+32]
 mov [rbp+64],rdx
 mov rax,[rax+8]
 mov [rbp+72],rax
 mov rdi,[rbp+8]
 mov esi,OUTPUT_N
 call readonly
 mov esi,4096
 call allocate
 mov [rbp+88],rax
 mov esi,4096
 call allocate
 mov [rbp+96],rax
 mov rdi,[rbp+64]
 mov rsi,[rbp+72]
 mov rdx,[rbp+96]
 mov ecx,32
 mov r8,[rbp+88]
 mov r9d,1184
 call QWORD PTR [rbp+344]
 cmp rax,32
 jne io_failure
 mov rdi,[rbp+96]
 mov esi,4096
 call readonly
 mov esi,8192
 call allocate
 mov [rbp+104],rax
 mov rbx,rax
 movabs rdx,3544423355803322696
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
 call readonly
 mov rdi,[rbp+88]
 mov esi,4096
 call release
 mov rdi,[rbp+96]
 mov esi,4096
 call release
 mov esi,262144
 call allocate
 mov [rbp+48],rax
 mov esi,32768
 call allocate
 mov [rbp+88],rax
 mov rdi,[rbp+104]
 mov rsi,[rbp+24]
 add rsi,80
 mov rdx,[rbp+48]
 mov ecx,262144
 mov r8,[rbp+88]
 mov r9d,32768
 call QWORD PTR [rbp+344]
 test rax,rax
 jz io_failure
 cmp rax,262144
 ja io_failure
 mov [rbp+56],rax
 mov rdi,[rbp+48]
 mov esi,262144
 call readonly
 mov rdi,[rbp+104]
 mov esi,8192
 call release
 mov rdi,[rbp+88]
 mov esi,32768
 call release
 mov esi,OUTPUT_N
 call allocate
 mov [rbp+112],rax
 lea rdi,[rax+16777216]
 mov rsi,[rbp+48]
 mov rcx,[rbp+56]
 cld
 rep movsb
 mov rbx,[rbp+32]
 movabs rax,3544406867239323976
 mov [rbx],rax
 mov rax,[rbp+40]
 mov [rbx+8],rax
 mov rax,[rbp+56]
 mov [rbx+16],rax
 mov QWORD PTR [rbx+24],0
 mov rdi,[rbp+8]
 mov rsi,[rbp+80]
 mov rdx,[rbp+112]
 mov ecx,OUTPUT_N
 mov r8,rbx
 mov r9d,4096
 call QWORD PTR [rbp+344]
 call scalar_status
 cmp rax,2
 jb io_failure
 cmp rax,OUTPUT_N
 ja invalid
 mov [rbp+120],rax
 mov rdi,[rbp+112]
 mov esi,OUTPUT_N
 call readonly
 mov rdi,[rbp+48]
 mov esi,262144
 call release
 mov rdi,[rbp+8]
 mov esi,OUTPUT_N
 call release
 # Same opaque ABI for parent creation and then exact byte publication.
 mov rax,[rbp+16]
 mov [rbp+256],rax
 mov rax,[rbp+24]
 mov [rbp+264],rax
 mov rax,[rbp+344]
 mov [rbp+352],rax
 movabs r12,3544406867423873352
 call effect_allocate
 call effect_loop
 call effect_release
 mov rax,[rbp+64]
 mov [rbp+256],rax
 mov rax,[rbp+72]
 mov [rbp+264],rax
 mov rax,[rbp+344]
 mov [rbp+352],rax
 movabs r12,3544406931680610632
 call effect_allocate
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
 call effect_loop
 call effect_release
 mov rdi,[rbp+16]
 mov esi,262144
 call release
 mov rdi,[rbp]
 mov esi,FRAME_N
 call release
 mov r14,rbp
 mov r13,[r14+112]
 mov rbp,[r14+32]
 mov rdi,rbp
 mov ecx,512
 xor eax,eax
 cld
 rep stosq
 mov rax,[r14+120]
 mov [rbp+96],rax
 movabs rax,3544421216725059912
 mov [rbp+120],rax
pretty_loop:
 mov rdi,r13
 mov rsi,[rbp+96]
 lea rdx,[rbp+IO]
 mov ecx,4096
 mov r8,rbp
 mov r9d,4096
 call QWORD PTR [r14+336]
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
 call readonly
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
 call protect
empty_chunk:
 cmp QWORD PTR [rbp+8],5
 je completed
 cmp QWORD PTR [rbp+80],0
 je io_failure
 jmp pretty_loop
completed:
 mov rdi,[r14+112]
 mov esi,OUTPUT_N
 call release
 mov rdi,rbp
 mov esi,SCR_N
 call release
 mov rdi,r14
 mov esi,16384
 call release
 xor edi,edi
 jmp exit
run_edit_owner:
 mov rdi,r12
 mov esi,SOURCE_N
 mov rdx,r13
 mov ecx,OUT_N
 lea r8,[r12+WORK_AT]
 mov r9d,WORK_N
 jmp QWORD PTR [r15+336]
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
 call QWORD PTR [r15+320]
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
 jmp exit
effect_allocate:
 # Subroutine contains no native CABI calls; allocate/syscall only.
 mov esi,1048576
 call allocate
 mov [rbp+272],rax
 mov QWORD PTR [rbp+280],1048576
 mov esi,98304
 call allocate
 mov [rbp+288],rax
 mov QWORD PTR [rbp+296],98304
 mov [rax],r12
 ret
effect_release:
 mov rdi,[rbp+272]
 mov esi,1048576
 call release
 mov rdi,[rbp+288]
 mov esi,98304
 call release
 ret
effect_loop:
 sub rsp,8
effect_next:
 mov rdi,[rbp+256]
 mov rsi,[rbp+264]
 mov rdx,[rbp+272]
 mov rcx,[rbp+280]
 mov r8,[rbp+288]
 mov r9,[rbp+296]
 call QWORD PTR [rbp+352]
 cmp rax,96
 jne HIA_status
 mov rdi,[rbp+272]
 mov esi,1048576
 call readonly
 mov r12,[rbp+272]
 movabs rax,3544409130703866184
 cmp [r12],rax
 jne io_failure
 cmp QWORD PTR [r12+16],2
 je effect_done
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
 mov ecx,6
 cld
 rep movsq
 xor edx,edx
effect_translate:
 test bl,1
 jz effect_argument_ready
 mov rax,[rsp+rdx*8]
 mov rcx,rax
 shr rcx,48
 cmp rcx,1
 jb io_failure
 cmp rcx,3
 ja io_failure
 dec rcx
 shl rcx,4
 shl rax,16
 shr rax,16
 cmp rax,[rbp+rcx+264]
 jae io_failure
 add rax,[rbp+rcx+256]
 mov [rsp+rdx*8],rax
effect_argument_ready:
 shr rbx,1
 inc edx
 cmp edx,6
 jb effect_translate
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
 call protect
 jmp effect_next
effect_done:
 mov rdi,[r12+24]
 cmp rdi,255
 ja io_failure
 test rdi,rdi
 jnz exit
 add rsp,8
 ret
c_length:
 xor eax,eax
c_length_loop:
 cmp rax,131072
 jae io_failure
 cmp BYTE PTR [rdi+rax],0
 je c_length_done
 inc rax
 jmp c_length_loop
c_length_done:
 ret
allocate:
 xor edi,edi
 mov edx,3
 mov r10d,34
 mov r8,-1
 xor r9d,r9d
 mov eax,9
 syscall
 cmp rax,-4095
 jae io_failure
 ret
readonly:
 mov edx,1
protect:
 mov eax,10
 syscall
 test rax,rax
 jnz io_failure
 ret
release:
 mov eax,11
 syscall
 test rax,rax
 jnz io_failure
 ret
HIA_status:
 cmp rax,255
 ja io_failure
 mov rdi,rax
 jmp exit
usage:
 mov edi,64
 jmp exit
capacity:
 mov edi,3
 jmp exit
io_failure:
 mov edi,4
exit:
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
 cld
 rep stosq
 jmp extract_base
envelope_refused:
 mov rax,rdx
 jmp HIA_status

.section .note.GNU-stack,"",@progbits
