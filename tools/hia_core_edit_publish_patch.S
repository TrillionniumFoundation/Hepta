.intel_syntax noprefix
.text
.global _start
.equ RAW_N,8388608
.equ SOURCE_N,41943040
.equ CORE_N,67108864
.equ CANON_N,16777216
.equ CANON_MAP,16781312
.equ WIRE_N,16777219
.equ INPUT_N,16781312
.equ FRAME_AT,16781312
.equ FRAME_N,67108864
.equ SCRATCH_AT,83890176
.equ PATCH_WORK_N,67108864
.equ CORE_STATE_N,67108864
.equ CORE_ARENA_N,33554432
.equ SCRATCH_N,100663296
.equ TOTAL_N,184553472
.equ OUTPUT_AT,SCRATCH_AT
.equ OUTPUT_N,33554432
.equ WORK_AT,117444608
.equ WORK_N,16384
.equ UNUSED_AT,117460992
.equ UNUSED_N,67092480
.equ O,4096
.equ S,8192
_start:
 cmp QWORD PTR [rsp],3
 jne usage
 mov rax,[rsp+16]
 cmp BYTE PTR [rax],118
 jne usage
 movzx r15d,BYTE PTR [rax+1]
 cmp r15d,49
 jb usage
 cmp r15d,50
 ja usage
 cmp BYTE PTR [rax+2],0
 jne usage
 sub r15d,48
 mov r12,[rsp+24]
 mov esi,16384
 call allocate
 mov rbp,rax
 .byte 0x48,0x8d,0x05
core_address_hole: .long 0
 mov [rbp+328],rax
 .byte 0x48,0x8d,0x05
front_address_hole: .long 0
 mov [rbp+320],rax
 .byte 0x48,0x8d,0x05
owner_address_hole: .long 0
 mov [rbp+336],rax
 .byte 0x48,0x8d,0x05
publication_address_hole: .long 0
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
 call QWORD PTR [rbp+336]
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
 call QWORD PTR [rbp+336]
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
 mov rbx,rbp
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
 xor r13d,r13d
read_input:
 xor edi,edi
 lea rsi,[r12+r13]
 mov edx,WIRE_N+1
 sub rdx,r13
 xor eax,eax
 syscall
 cmp rax,-4
 je read_input
 test rax,rax
 js io_failure
 jz captured
 cmp rax,rdx
 ja io_failure
 add r13,rax
 cmp r13,WIRE_N
 ja capacity
 jmp read_input
captured:
 mov rdi,r12
 mov esi,INPUT_N
 mov edx,1
 mov eax,10
 syscall
 test rax,rax
 jnz io_failure
 # Original mode0, full base admission, mode2, full candidate admission.
 lea rdi,[r12+FRAME_AT]
 xor eax,eax
 mov ecx,FRAME_N+PATCH_WORK_N
 cld
 rep stosb
 mov rdi,r12
 mov rsi,r13
 lea rdx,[r12+FRAME_AT]
 mov ecx,FRAME_N
 lea r8,[r12+SCRATCH_AT]
 mov r9d,PATCH_WORK_N
 call QWORD PTR [rbx+320]
 call patch_status
 cmp rax,32
 jbe invalid
 cmp rax,8388640
 ja invalid
 mov r14,rax
 sub r14,32
 mov r10,0x3130544150414948
 cmp [r12+FRAME_AT],r10
 jne invalid
 cmp QWORD PTR [r12+FRAME_AT+8],0
 jne invalid
 cmp QWORD PTR [r12+FRAME_AT+16],0
 jne invalid
 cmp QWORD PTR [r12+FRAME_AT+24],0
 jne invalid
 lea rdi,[r12+SCRATCH_AT]
 xor eax,eax
 mov ecx,SCRATCH_N
 rep stosb
 lea rdi,[r12+FRAME_AT+32]
 mov rsi,r14
 lea rdx,[r12+SCRATCH_AT]
 mov ecx,CORE_STATE_N
 lea r8,[r12+SCRATCH_AT+CORE_STATE_N]
 mov r9d,CORE_ARENA_N
 call QWORD PTR [rbx+328]
 call core_status
 lea rdi,[r12+FRAME_AT]
 xor eax,eax
 mov ecx,FRAME_N+PATCH_WORK_N
 rep stosb
 mov QWORD PTR [r12+SCRATCH_AT],2
 mov [r12+SCRATCH_AT+8],r15
 mov rdi,r12
 mov rsi,r13
 lea rdx,[r12+FRAME_AT]
 mov ecx,FRAME_N
 lea r8,[r12+SCRATCH_AT]
 mov r9d,PATCH_WORK_N
 call QWORD PTR [rbx+320]
 call patch_status
 # A policy refusal cannot reach candidate or publication handling.
 cmp eax,0xffffffe0
 jae patch_diagnostic
 cmp rax,32
 jbe invalid
 cmp rax,16777248
 ja invalid
 mov r13,rax
 mov r10,0x3130524150414948
 cmp [r12+FRAME_AT],r10
 jne invalid
 cmp QWORD PTR [r12+FRAME_AT+24],0
 jne invalid
 mov r14,[r12+FRAME_AT+8]
 cmp r14,2
 jb invalid
 cmp r14,8388608
 ja invalid
 mov r10,[r12+FRAME_AT+16]
 cmp r10,2
 jb invalid
 cmp r10,8388608
 ja invalid
 add r10,r14
 add r10,32
 cmp r10,r13
 jne invalid
 # Result frame is immutable and disjoint from both Core output views.
 lea rdi,[r12+FRAME_AT]
 mov esi,FRAME_N
 mov edx,1
 mov eax,10
 syscall
 test rax,rax
 jnz io_failure
 lea rdi,[r12+SCRATCH_AT]
 xor eax,eax
 mov ecx,SCRATCH_N
 rep stosb
 lea rdi,[r12+FRAME_AT+32]
 mov rsi,r14
 lea rdx,[r12+SCRATCH_AT]
 mov ecx,CORE_STATE_N
 lea r8,[r12+SCRATCH_AT+CORE_STATE_N]
 mov r9d,CORE_ARENA_N
 call QWORD PTR [rbx+328]
 mov r14,rax
 call core_status
 # Reuse released Core state for private composed output and presenter scratch.
 lea rdi,[r12+SCRATCH_AT]
 xor eax,eax
 mov ecx,OUTPUT_N+WORK_N
 rep stosb
 lea rbp,[r12+WORK_AT]
 mov [rbp+96],r13
 mov [rbp+104],r14
 lea rax,[r12+FRAME_AT]
 mov [rbx+384],rax
 mov [rbx+392],r13
 lea rax,[r12+OUTPUT_AT]
 mov [rbx+400],rax
 mov [rbx+408],rbp
 mov [rbx+416],r14
 lea rdi,[r12+UNUSED_AT]
 mov esi,UNUSED_N
 mov eax,11
 syscall
 test rax,rax
 jnz io_failure
 mov rdi,r12
 mov esi,INPUT_N
 mov eax,11
 syscall
 test rax,rax
 jnz io_failure
 mov rbp,rbx
 mov rax,[rbp+384]
 lea rdx,[rax+32]
 mov [rbp+64],rdx
 mov rax,[rax+8]
 mov [rbp+72],rax
 mov esi,4096
 call allocate
 mov [rbp+88],rax
 mov esi,4096
 call allocate
 mov [rbp+96],rax
 call hash_payload
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
 mov [rbp+448],rax
 mov esi,32768
 call allocate
 mov [rbp+128],rax
 mov rdi,[rbp+104]
 mov rsi,[rbp+24]
 add rsi,80
 mov rdx,[rbp+448]
 mov ecx,262144
 mov r8,[rbp+128]
 mov r9d,32768
 call QWORD PTR [rbp+336]
 test rax,rax
 jz io_failure
 cmp rax,262144
 ja io_failure
 mov [rbp+456],rax
 mov rdi,[rbp+448]
 mov esi,262144
 call readonly
 mov rdi,[rbp+104]
 mov esi,8192
 call release
 mov rdi,[rbp+128]
 mov esi,32768
 call release
 mov rax,[rbp+392]
 add rax,[rbp+456]
 add rax,64
 cmp rax,33554432
 ja io_failure
 mov [rbp+440],rax
 mov esi,33554432
 call allocate
 mov [rbp+432],rax
 mov rbx,rax
 movabs rax,3544420057268439368
 mov [rbx],rax
 mov rax,[rbp+416]
 mov [rbx+8],rax
 mov rax,[rbp+392]
 mov [rbx+16],rax
 mov rax,[rbp+456]
 mov [rbx+24],rax
 lea rdi,[rbx+64]
 mov rsi,[rbp+384]
 mov rcx,[rbp+392]
 cld
 rep movsb
 mov rsi,[rbp+448]
 mov rcx,[rbp+456]
 rep movsb
 mov rdi,rbx
 mov esi,33554432
 call readonly
 mov rdi,[rbp+448]
 mov esi,262144
 call release
 mov rdi,[rbp+432]
 mov rsi,[rbp+440]
 mov rdx,[rbp+400]
 mov ecx,OUTPUT_N
 mov r8,[rbp+408]
 mov r9d,4096
 call QWORD PTR [rbp+336]
 call patch_status
 cmp rax,2
 jb io_failure
 cmp rax,OUTPUT_N
 ja invalid
 mov [rbp+120],rax
 mov rax,[rbp+400]
 mov [rbp+112],rax
 mov rdi,rax
 mov esi,OUTPUT_N
 call readonly
 mov rdi,[rbp+432]
 mov esi,33554432
 call release
 # Same opaque ABI for parent creation and then exact byte publication.
 mov rax,[rbp+16]
 mov [rbp+256],rax
 mov rax,[rbp+24]
 mov [rbp+264],rax
 mov rax,[rbp+336]
 mov [rbp+352],rax
 movabs r12,3544406867423873352
 call effect_allocate
 call effect_loop
 call effect_release
 mov rax,[rbp+64]
 mov [rbp+256],rax
 mov rax,[rbp+72]
 mov [rbp+264],rax
 mov rax,[rbp+320]
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
 mov rdi,[rbp+384]
 mov esi,FRAME_N
 call release
 mov r14,rbp
 mov rbp,[r14+408]
 mov rdi,rbp
 mov ecx,512
 xor eax,eax
 cld
 rep stosq
 mov rax,[r14+120]
 mov [rbp+96],rax
pretty_loop:
 mov rdi,[r14+112]
 mov esi,OUTPUT_N
 lea rdx,[rbp+O]
 mov ecx,128
 mov r8,rbp
 mov r9d,4096
 call QWORD PTR [r14+344]
 test rax,rax
 jnz HIA_status
 mov rax,[rbp+80]
 cmp rax,128
 ja io_failure
 mov [rbp+S],rax
 mov QWORD PTR [rbp+S+8],0
 test rax,rax
 jnz write_output
 cmp QWORD PTR [rbp+8],5
 jne io_failure
 jmp completed
write_output:
 mov rax,[rbp+S+8]
 lea rsi,[rbp+O+rax]
 mov rdx,[rbp+S]
 sub rdx,rax
 mov edi,1
 mov eax,1
 syscall
 cmp rax,-4
 je write_output
 test rax,rax
 jle io_failure
 add [rbp+S+8],rax
 mov rax,[rbp+S+8]
 cmp rax,[rbp+S]
 ja io_failure
 jb write_output
 cmp QWORD PTR [rbp+8],5
 jne pretty_loop
completed:
 mov rdi,[r14+112]
 mov esi,OUTPUT_N
 call release
 mov rdi,rbp
 mov esi,WORK_N
 call release
 mov rdi,r14
 mov esi,16384
 call release
 xor edi,edi
 jmp exit
hash_payload:
 sub rsp,8
 mov QWORD PTR [rbp+144],0
 lea rdi,[rip+sha_initialize]
 mov esi,1
 call hash_arguments
 call QWORD PTR [rbp+336]
 test rax,rax
 jnz io_failure
 # Mechanical bounded copies retain the original SHA packet <=8MiB+1.
 mov esi,8392704
 call allocate
 mov [rbp+136],rax
hash_copy_next:
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
 call readonly
 mov rdi,[rbp+136]
 add rdi,4095
 mov rsi,[rbp+152]
 inc rsi
 call hash_arguments
 call QWORD PTR [rbp+336]
 test rax,rax
 jnz io_failure
 mov rax,[rbp+152]
 add [rbp+144],rax
 mov rdi,[rbp+136]
 mov esi,8392704
 mov edx,3
 call protect
 mov rax,[rbp+144]
 cmp rax,[rbp+72]
 jb hash_copy_next
 mov rdi,[rbp+136]
 mov esi,8392704
 call release
 lea rdi,[rip+sha_finalize]
 mov esi,1
 call hash_arguments
 call QWORD PTR [rbp+336]
 cmp rax,32
 jne io_failure
 mov rdi,[rbp+96]
 mov esi,4096
 call readonly
 add rsp,8
 ret
core_status:
 call patch_status
 test rax,rax
 jnz invalid
 ret
patch_status:
 mov r10,rax
 shr r10,32
 test r10,r10
 jnz io_failure
 mov r10d,0xfffffffe
 cmp rax,r10
 je capacity
 mov r10d,0xfffffffd
 cmp rax,r10
 je io_failure
 ret
patch_diagnostic:
 lea rdi,[r12+FRAME_AT]
 mov [rdi],rax
 mov esi,8
 lea rdx,[rdi+16]
 mov ecx,512
 xor r8d,r8d
 xor r9d,r9d
 .byte 0xe8
patch_diagnostic_hole: .long 0
 test eax,eax
 jz invalid
 cmp eax,512
 ja io_failure
 mov edx,eax
 lea rsi,[r12+FRAME_AT+16]
patch_diagnostic_write:
 mov edi,1
 mov eax,1
 syscall
 cmp rax,-4
 je patch_diagnostic_write
 test rax,rax
 jle io_failure
 add rsi,rax
 sub rdx,rax
 jnz patch_diagnostic_write
 jmp invalid
invalid:
 mov edi,2
 jmp exit
hash_arguments:
 mov rdx,[rbp+96]
 mov ecx,32
 mov r8,[rbp+88]
 mov r9d,1184
 ret
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
sha_initialize: .byte 0
sha_finalize: .byte 2
.section .note.GNU-stack,"",@progbits
