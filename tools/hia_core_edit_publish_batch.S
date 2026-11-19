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
.equ SLICE,8388608
.equ QUERY,0
.equ IO,12288
.equ S,8192
.equ BS,0
.equ OUTPUT_N,33554432
.equ FRAME_N,16777216
.equ NOMINAL_ORIGIN,S+112
.equ ORIGIN_DIGEST,S+64
.equ ORIGIN_TAG,CTRL+1536
.equ ORIGIN_BYTES,CTRL+1544
.equ ORIGIN_MAGIC,3544423407359707464

_start:
 add rsp,8
 cld
 cmp QWORD PTR [rsp],2
 jne usage
 mov r12,[rsp+16]
 mov esi,16384
 call allocate
 mov rbp,rax
 lea r15,[rbp+256]
 lea rax,[rip+edit_base_admission_start]
 mov [r15+72],rax
 lea rax,[rip+edit_batch_front_start]
 mov [r15+64],rax
 lea rax,[rip+edit_batch_apply_start]
 mov [r15+80],rax
 lea rax,[rip+edit_publication_start]
 mov [r15+88],rax
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
 rep movsb
 mov rdi,rbx
 add rdi,[rbp+360]
 add rdi,48
 mov esi,4096
 push 79
 pop rax
 syscall
 mov [rbx+24],rax
 xor ecx,ecx
 test rax,rax
 js cwd_ready
 jz mechanical_error_hub_7
 cmp rax,4096
 ja mechanical_error_hub_7
 jmp mechanical_error_hub_7_skip
mechanical_error_hub_7:
 jmp io_failure
mechanical_error_hub_7_skip:
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
 push 8
 pop rcx
 lea r8,[rbp+776]
 push 8
 pop r9
 call QWORD PTR [r15+88]
 test rax,rax
 jnz HIA_status
 mov esi,262144
 call allocate
 mov [rbp+16],rax
 mov esi,1048576
 call allocate
 mov [rbp+32],rax
 call mechanical_compact_4
 mov ecx,262144
 mov r8,[rbp+32]
 mov r9d,1048576
 call QWORD PTR [r15+88]
 test rax,rax
 jz mechanical_error_hub_2
 cmp rax,4095
 ja mechanical_error_hub_2
 mov [rbp+24],rax
 call mechanical_compact_5
 call readonly
 mov rdi,[rbp]
 mov esi,270336
 call release
 mov rdi,[rbp+32]
 mov esi,1048576
 call release
 mov esi,TOTAL_N
 call allocate
 mov r12,rax
 lea r14,[r12+WORK_AT]
 lea rbx,[r12+CORE_AT]
 lea rbp,[r12+SCR_AT]
read_input:
 xor edi,edi
 mov rax,[rbp+BS]
 lea rsi,[r12+rax]
 mov edx,RAW_N+1
 sub rdx,rax
 xor eax,eax
 syscall
 cmp rax,-4
 je read_input
 test rax,rax
 js mechanical_error_hub_2
 jmp mechanical_error_hub_2_skip
mechanical_error_hub_2:
 jmp io_failure
mechanical_error_hub_2_skip:
 jz input_complete
 cmp rax,rdx
 ja mechanical_error_hub_2
 add [rbp+BS],rax
 cmp QWORD PTR [rbp+BS],RAW_N
 ja capacity
 jmp read_input
input_complete:
 call mechanical_outline_13
extract_base:
 mov rdi,r12
 mov rsi,[rbp+BS]
 call mechanical_compact_6
 mov r8,r14
 mov r9d,WORK_N
 call QWORD PTR [r15+64]
 call scalar_status
 cmp rax,32
 jbe mechanical_error_hub_8
 cmp rax,8388640
 ja mechanical_error_hub_8
 jmp mechanical_error_hub_8_skip
mechanical_error_hub_8:
 jmp invalid
mechanical_error_hub_8_skip:
 mov [rbp+BS+16],rax
 sub rax,32
 mov [rbp+BS+8],rax
 lea rsi,[r12+TEMP_AT+32]
 lea rdi,[r12+RAW_EXTENT]
 mov rcx,rax
 rep movsb
 lea rdi,[r12+RAW_EXTENT]
 mov esi,8388608
 call readonly
 call mechanical_outline_3
 lea rdi,[r12+RAW_EXTENT]
 mov rsi,[rbp+BS+8]
 call mechanical_outline_5
 mov [rbp+BS+24],rax
 cmp eax,0xfffffffb
 jne base_checked
 cmp QWORD PTR [rbp+NOMINAL_ORIGIN],0
 je lower_nominal
base_checked:
 call mechanical_outline_3
 lea r13,[r12+OUT_AT]
 call mechanical_outline_0
 call mechanical_outline_11
 movabs rax,3544418953277294920
 call mechanical_compact_1
 call batch_stage_status
 test rax,rax
 jz normalized_input_ready
 cmp rax,1048576
 ja io_failure
 mov [rbp+BS+48],rax
 lea rdi,[r13+19922944]
 mov esi,1048576
 call mechanical_outline_2
 call mechanical_compact_9
 rep stosq
 movabs rax,3544418987637033288
 mov [r12+TEMP_AT+120],rax
 lea rdi,[r13+19922944]
 mov rsi,[rbp+BS+48]
 mov rdx,rbx
 mov ecx,CORE_N
 call mechanical_outline_16
 mov [r13+CTRL+8192+696],rax
 call mechanical_outline_12
 lea rdi,[r13+19922944]
 call mechanical_outline_10
 movabs rax,3616476547315222856
 mov [r13+CTRL],rax
 call mechanical_outline_4
 call mechanical_outline_14
 call batch_stage_status
 test rax,rax
 jz invalid
 cmp rax,16777216
 ja io_failure
 mov [rbp+BS],rax
 mov rdi,r12
 mov esi,RAW_EXTENT
 call mechanical_compact_0
 mov rsi,r13
 mov rdi,r12
 mov rcx,[rbp+BS]
 rep movsb
 mov ecx,RAW_EXTENT
 sub rcx,[rbp+BS]
 xor eax,eax
 rep stosb
 call mechanical_outline_13
 call mechanical_outline_3
 mov rdi,r13
 mov ecx,OUT_N/8
 rep stosq
 call mechanical_outline_0
 call mechanical_outline_11
normalized_input_ready:
 movabs rax,3544413455719156040
 call mechanical_compact_2
 call batch_stage_status
 test rax,rax
 jz invalid
 cmp rax,16
 ja mechanical_error_hub_10
selection_loop:
 call run_batch_owner
 call mechanical_outline_1
 cmp rax,8388608
 ja mechanical_error_hub_10
 jmp mechanical_error_hub_10_skip
mechanical_error_hub_10:
 jmp io_failure
mechanical_error_hub_10_skip:
 mov [rbp+BS+32],rax
 mov rdi,r13
 mov esi,8388608
 call mechanical_outline_6
 mov rdi,r13
 mov rsi,[rbp+BS+32]
 lea rdx,[r13+SLICE]
 mov ecx,8388608
 call mechanical_compact_10
 call QWORD PTR [r15+88]
 mov [r13+CTRL+256],rax
 mov rdi,r13
 mov esi,8388608
 call mechanical_compact_0
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
 movabs rax,3544422316236687688
 call mechanical_compact_2
 mov [r13+CTRL+320],rax
 mov r10,[r13+CTRL]
 mov [r13+CTRL+328],r10
 call query_status
 test rax,rax
 jz invalid
 cmp rax,1048576
 ja mechanical_error_hub_4
 movabs rax,3544404659626133832
 call mechanical_compact_2
 call mechanical_compact_3
 jz selection_loop
 cmp rax,1048576
 ja mechanical_error_hub_4
 jmp mechanical_error_hub_4_skip
mechanical_error_hub_4:
 jmp io_failure
mechanical_error_hub_4_skip:
 mov [r13+CTRL+336],rax
 mov r10,[r13+CTRL]
 mov [r13+CTRL+344],r10
 movabs rax,3544423351323806024
 call mechanical_compact_1
 mov [r13+CTRL+352],rax
 call batch_stage_status
 test rax,rax
 jnz invalid
 movabs rax,3544428848881944904
 call mechanical_compact_1
 mov [r13+CTRL+360],rax
 call mechanical_outline_1
 cmp rax,65536
 ja mechanical_error_hub_4
 movabs rax,3544412356207528264
 call mechanical_compact_2
 mov [r13+CTRL+8584],rax
 call mechanical_outline_7
 call mechanical_compact_7
 call mechanical_outline_6
 movabs rax,3544407958161017160
 mov [r12+TEMP_AT+120],rax
 lea rdi,[r13+20971520]
 mov rsi,[r13+CTRL+360]
 lea rdx,[r12+WORK_AT+58785792]
 mov ecx,8323072
 call mechanical_outline_16
 mov [r13+CTRL+8192+400],rax
 call mechanical_compact_7
 call mechanical_compact_0
 movabs rax,3544427749370317128
 call mechanical_compact_1
 mov [r13+CTRL+8616],rax
 call batch_stage_status
 test rax,rax
 jnz invalid
 movabs rax,3544421152300550472
 call mechanical_compact_1
 mov [r13+CTRL+8648],rax
 call mechanical_outline_8
 mov rax,[r13+CTRL+8192+448]
 cmp rax,2
 jb mechanical_error_hub_6
 cmp rax,4096
 ja mechanical_error_hub_6
 jmp mechanical_error_hub_6_skip
mechanical_error_hub_6:
 jmp io_failure
mechanical_error_hub_6_skip:
 mov rdi,r13
 mov esi,16777216
 call readonly
 lea rdi,[r13+22020096]
 mov esi,4096
 call mechanical_outline_2
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
 mov rsi,[r13+CTRL+8192+456]
 call mechanical_compact_6
 call mechanical_outline_14
 mov [r13+CTRL+8192+464],rax
 call mechanical_outline_12
 cmp rax,32
 jbe invalid
 cmp rax,8392704
 ja mechanical_error_hub_0
 movabs r10,3544423347213388104
 cmp [r12+TEMP_AT],r10
 jne mechanical_error_hub_0
 cmp QWORD PTR [r12+TEMP_AT+24],0
 jne mechanical_error_hub_0
 mov r10,[r12+TEMP_AT+8]
 cmp r10,2
 jb mechanical_error_hub_0
 jmp mechanical_error_hub_0_skip
mechanical_error_hub_0:
 jmp io_failure
mechanical_error_hub_0_skip:
 cmp r10,8388608
 ja mechanical_error_hub_0
 mov r11,[r12+TEMP_AT+16]
 cmp r11,4096
 ja mechanical_error_hub_0
 add r11,r10
 add r11,32
 cmp r11,rax
 jne mechanical_error_hub_0
 lea rsi,[r13+22020096]
 lea rdi,[r12+TEMP_AT+8392704]
 mov rcx,[r13+CTRL+8192+448]
 mov [r13+CTRL+8192+472],rcx
 rep movsb
 call mechanical_compact_8
 call mechanical_outline_2
 mov rdi,r14
 mov ecx,33554432/8
 rep stosq
 lea rdi,[r12+TEMP_AT+32]
 mov rsi,[r12+TEMP_AT+8]
 call mechanical_outline_5
 mov [r13+CTRL+8192+480],rax
 mov [r15-16],rax
 mov rdi,r13
 mov esi,16777216
 call mechanical_compact_0
 lea rdi,[r13+22020096]
 call mechanical_outline_9
 mov rdi,r12
 mov esi,SOURCE_N
 call release
 mov rdi,rbx
 mov esi,CORE_N
 call release
 mov rdi,r14
 mov esi,WORK_N
 call release
 mov rdi,r13
 mov ecx,25165824/8
 xor eax,eax
 rep stosq
 mov rdi,rbp
 mov ecx,4096/8
 rep stosq
 movabs rax,3544406858649389384
 mov [r13+CTRL],rax
 call mechanical_compact_8
 mov rdx,r13
 mov ecx,OUT_N
 mov r8,rbp
 mov r9d,4096
 call QWORD PTR [r15+64]
 call mechanical_outline_8
 mov [rbp+96],rax
 mov [r15-8],rax
 mov [r15-32],r13
 mov [r15-24],rbp
 lea rax,[r12+TEMP_AT]
 mov [r15-40],rax
 lea rbp,[r15-256]
 mov rax,[r15-40]
 lea rdx,[rax+32]
 mov [rbp+64],rdx
 mov rax,[rax+8]
 mov [rbp+72],rax
 mov rdi,[r15-32]
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
 push 32
 pop rcx
 mov r8,[rbp+88]
 mov r9d,1184
 call QWORD PTR [r15+88]
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
 push 32
 pop rcx
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
 call QWORD PTR [r15+88]
 test rax,rax
 jz mechanical_error_hub_5
 cmp rax,262144
 ja mechanical_error_hub_5
 jmp mechanical_error_hub_5_skip
mechanical_error_hub_5:
 jmp io_failure
mechanical_error_hub_5_skip:
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
 rep movsb
 mov rbx,[r15-24]
 movabs rax,3544406867239323976
 mov [rbx],rax
 mov rax,[r15-16]
 mov [rbx+8],rax
 mov rax,[rbp+56]
 mov [rbx+16],rax
 mov QWORD PTR [rbx+24],0
 mov rdi,[r15-32]
 mov rsi,[r15-8]
 mov rdx,[rbp+112]
 mov ecx,OUTPUT_N
 mov r8,rbx
 mov r9d,4096
 call QWORD PTR [r15+88]
 call scalar_status
 cmp rax,2
 jb mechanical_error_hub_5
 cmp rax,OUTPUT_N
 ja invalid
 mov [rbp+120],rax
 mov rdi,[rbp+112]
 mov esi,OUTPUT_N
 call readonly
 mov rdi,[rbp+48]
 mov esi,262144
 call release
 mov rdi,[r15-32]
 mov esi,OUTPUT_N
 call release
 # Same opaque ABI for parent creation and then exact byte publication.
 mov rax,[rbp+16]
 mov [rbp+256],rax
 mov rax,[rbp+24]
 call mechanical_outline_15
 movabs r12,3544406867423873352
 call effect_allocate
 call effect_loop
 call effect_release
 mov rax,[rbp+64]
 mov [rbp+256],rax
 mov rax,[rbp+72]
 call mechanical_outline_15
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
 rep movsb
 call effect_loop
 call effect_release
 call mechanical_compact_5
 call release
 mov rdi,[r15-40]
 mov esi,FRAME_N
 call release
 mov r14,rbp
 mov r13,[r14+112]
 mov rbp,[r15-24]
 mov rdi,rbp
 mov ecx,512
 xor eax,eax
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
 ja mechanical_error_hub_3
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
 push 1
 pop rdi
 push 1
 pop rax
 syscall
 cmp rax,-4
 je write_output
 test rax,rax
 jle mechanical_error_hub_3
 add [rbp+S+40],rax
 mov rax,[rbp+S+40]
 cmp rax,[rbp+S+48]
 ja mechanical_error_hub_3
 jmp mechanical_error_hub_3_skip
mechanical_error_hub_3:
 jmp io_failure
mechanical_error_hub_3_skip:
 jb write_output
 lea rdi,[rbp+IO]
 call mechanical_outline_9
empty_chunk:
 cmp QWORD PTR [rbp+8],5
 je completed
 cmp QWORD PTR [rbp+80],0
 je mechanical_error_hub_3
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
run_batch_front:
 call mechanical_outline_17
 jmp QWORD PTR [r15+64]
run_batch_owner:
 call mechanical_outline_17
 jmp QWORD PTR [r15+80]
query_status:
 mov r10d,0xfffffffa
 cmp rax,r10
 je mechanical_error_hub_9
 mov r10d,0xfffffffb
 cmp rax,r10
 je mechanical_error_hub_9
 jmp mechanical_error_hub_9_skip
mechanical_error_hub_9:
 jmp capacity
mechanical_error_hub_9_skip:
 mov r10d,0xfffffffc
 cmp rax,r10
 je invalid
# A native stage returns a reserved refusal code, never a length.
batch_stage_status:
 mov r10d,0xffffffd1
 cmp rax,r10
 jb scalar_status
 mov r10d,0xffffffda
 cmp rax,r10
 ja scalar_status
 push rax
 mov rdi,rsp
 mov esi,8
 lea rdx,[r13+OUT_N-256]
 mov ecx,256
 xor r8d,r8d
 xor r9d,r9d
 call QWORD PTR [r15+80]
 add rsp,8
 test rax,rax
 jz invalid
 cmp rax,256
 ja io_failure
 mov rdx,rax
 lea rsi,[r13+OUT_N-256]
batch_write_refusal:
 mov edi,1
 mov eax,1
 syscall
 cmp rax,-4
 je batch_write_refusal
 test rax,rax
 jle io_failure
 cmp rax,rdx
 ja io_failure
 add rsi,rax
 sub rdx,rax
 jnz batch_write_refusal
 jmp invalid
scalar_status:
 mov r10,rax
 shr r10,32
 jnz io_failure
 cmp eax,0xfffffffd
 jb scalar_return
 mov edi,eax
 neg edi
 inc edi
 jmp exit
scalar_return:
 ret
invalid:
 push 2
 pop rdi
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
 lea rbp,[rbp+256]
effect_next:
 call mechanical_compact_4
 mov rcx,[rbp+24]
 mov r8,[rbp+32]
 mov r9,[rbp+40]
 call QWORD PTR [rbp+96]
 cmp rax,96
 jne HIA_status
 mov rdi,[rbp+16]
 mov esi,1048576
 call readonly
 mov r12,[rbp+16]
 movabs rax,3544409130703866184
 cmp [r12],rax
 jne mechanical_error_hub_1
 cmp QWORD PTR [r12+16],2
 je effect_done
 cmp QWORD PTR [r12+16],1
 jne mechanical_error_hub_1
 mov rbx,[r12+32]
 cmp rbx,63
 ja mechanical_error_hub_1
 sub rsp,64
 mov rax,[r12+24]
 mov [rsp+48],rax
 lea rsi,[r12+40]
 mov rdi,rsp
 push 6
 pop rcx
 rep movsq
 xor edx,edx
effect_translate:
 test bl,1
 jz effect_argument_ready
 mov rax,[rsp+rdx*8]
 mov rcx,rax
 shr rcx,48
 dec rcx
 cmp rcx,2
 ja mechanical_error_hub_1
 jmp mechanical_error_hub_1_skip
mechanical_error_hub_1:
 jmp io_failure
mechanical_error_hub_1_skip:
 shl rcx,4
 shl rax,16
 shr rax,16
 cmp rax,[rbp+rcx+8]
 jae mechanical_error_hub_1
 add rax,[rbp+rcx]
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
 mov r13,[rbp+32]
 mov [r13+32],rax
 mov rax,[r12+8]
 mov [r13+24],rax
 mov rdi,r12
 call mechanical_outline_10
 jmp effect_next
effect_done:
 mov rdi,[r12+24]
 cmp rdi,255
 ja io_failure
 test rdi,rdi
 jnz exit
 lea rbp,[rbp-256]
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
 push 3
 pop rdx
 push 34
 pop r10
 mov r8,-1
 xor r9d,r9d
 push 9
 pop rax
 syscall
 cmp rax,-4095
 jae io_failure
 ret
readonly:
 push 1
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
HIA_status:
 cmp rax,255
 ja io_failure
 mov rdi,rax
 jmp exit
usage:
 push 64
 pop rdi
 jmp exit
capacity:
 push 3
 pop rdi
 jmp exit
io_failure:
 push 4
 pop rdi
exit:
 push 60
 pop rax
 syscall
 ud2
lower_nominal:
 mov rdi,r12
 mov rsi,[rbp+BS]
 lea rdx,[r12+RAW_EXTENT]
 mov rcx,[rbp+BS+8]
 lea r8,[rbp+ORIGIN_DIGEST]
 call nominal_edit_envelope
 test rax,rax
 jz envelope_refused
 mov [rbp+BS],rax
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
.text
mechanical_outline_0:
 movabs rax,3544408022585526600
 mov [r13+CTRL],rax
 mov rax,[rbp+BS]
 mov [r13+CTRL+8],rax
 mov rax,[rbp+BS+8]
 mov [r13+CTRL+16],rax
 mov rax,[rbp+BS+24]
 mov [r13+CTRL+24],rax
 mov rax,[rbp+BS+16]
 mov [r13+CTRL+32],rax
 mov rdi,r12
 mov rsi,[rbp+BS]
 mov rdx,r13
 mov ecx,OUT_N
 mov r8,r14
 mov r9d,WORK_N
 jmp QWORD PTR [r15+80]
mechanical_outline_1:
 call mechanical_compact_3
 jz invalid
 ret
mechanical_outline_2:
 call readonly
 mov rdi,rbx
 mov ecx,CORE_N/8
 xor eax,eax
 rep stosq
 ret
mechanical_outline_3:
 mov rdi,r14
 mov ecx,WORK_N/8
 xor eax,eax
 rep stosq
 ret
mechanical_outline_4:
 mov rdi,r12
 mov esi,SOURCE_N
 mov rdx,r13
 mov ecx,OUT_N
 ret
mechanical_outline_5:
 mov rdx,rbx
 mov ecx,CORE_N
 mov r8,r14
 mov r9d,33554432
 jmp QWORD PTR [r15+72]
mechanical_outline_6:
 call readonly
 call mechanical_compact_9
 xor eax,eax
 rep stosq
 ret
mechanical_outline_7:
 call mechanical_compact_3
 jnz mechanical_error_hub_12
 ret
mechanical_outline_8:
 call mechanical_outline_1
 cmp rax,16777216
 ja mechanical_error_hub_11
 ret
mechanical_outline_9:
 mov esi,4096
 call mechanical_compact_0
 ret
mechanical_outline_10:
 mov esi,1048576
 call mechanical_compact_0
 ret
mechanical_outline_11:
 mov [r13+CTRL+504],rax
 call mechanical_outline_1
 cmp rax,WORK_N
 ja mechanical_error_hub_11
 jmp mechanical_error_hub_11_skip
mechanical_error_hub_11:
 jmp io_failure
mechanical_error_hub_11_skip:
 ret
mechanical_outline_12:
 call scalar_status
 mov r10d,0xffffffe0
 cmp rax,r10
 jae mechanical_error_hub_12
 jmp mechanical_error_hub_12_skip
mechanical_error_hub_12:
 jmp invalid
mechanical_error_hub_12_skip:
 ret
mechanical_outline_13:
 mov rdi,r12
 mov esi,RAW_EXTENT
 call readonly
 ret
mechanical_outline_14:
 mov r8,rbx
 mov r9d,CORE_N
 jmp QWORD PTR [r15+64]
mechanical_outline_15:
 mov [rbp+264],rax
 mov rax,[r15+88]
 mov [rbp+352],rax
 ret
mechanical_outline_16:
 call mechanical_compact_10
 jmp QWORD PTR [r15+80]
mechanical_outline_17:
 call mechanical_outline_4
 lea r8,[r12+WORK_AT]
 mov r9d,WORK_N
 ret
.text
mechanical_compact_0:
 push 3
 pop rdx
 call protect
 ret
mechanical_compact_1:
 mov [r13+CTRL],rax
 jmp run_batch_front
mechanical_compact_2:
 mov [r13+CTRL],rax
 jmp run_batch_owner
mechanical_compact_3:
 call scalar_status
 test rax,rax
 ret
mechanical_compact_4:
 mov rdi,[rbp]
 mov rsi,[rbp+8]
 mov rdx,[rbp+16]
 ret
mechanical_compact_5:
 mov rdi,[rbp+16]
 mov esi,262144
 ret
mechanical_compact_6:
 lea rdx,[r12+TEMP_AT]
 mov ecx,TEMP_N
 ret
mechanical_compact_7:
 lea rdi,[r13+20971520]
 mov esi,65536
 ret
mechanical_compact_8:
 lea rdi,[r12+TEMP_AT]
 mov esi,TEMP_N
 ret
mechanical_compact_9:
 lea rdi,[r12+TEMP_AT]
 mov ecx,TEMP_N/8
 ret
mechanical_compact_10:
 lea r8,[r12+TEMP_AT]
 mov r9d,TEMP_N
 ret
