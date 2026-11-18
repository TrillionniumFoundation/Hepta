.intel_syntax noprefix
.text
.global _start
.equ RAW_N,8388608
.equ SOURCE_N,41943040
.equ CORE_N,67108864
.equ CANON_N,16777216
.equ CANON_MAP,8388608
.equ INPUT_N,8388608
.equ INPUT_EXTENT,8392704
.equ C1_AT,8392704
.equ C2_AT,25169920
.equ ASM_AT,41947136
.equ ASM_N,8388608
.equ JSON_AT,50335744
.equ JSON_N,16777216
.equ ARENA_AT,67112960
.equ ARENA_N,33554432
.equ SCRATCH_AT,100667392
.equ SCRATCH_N,16384
.equ CORE_AT,100683776
.equ TOTAL_N,167792640
.equ S,8192
_start:
 cmp QWORD PTR [rsp],2
 jne usage
 mov r12,[rsp+16]
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
 call QWORD PTR [rbp+320]
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
 mov r14,rbp
 mov esi,TOTAL_N
 call allocate
 mov r12,rax
 lea rbp,[r12+SCRATCH_AT]
read_input:
 xor edi,edi
 mov rax,[rbp+S]
 lea rsi,[r12+rax]
 mov edx,INPUT_N+1
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
 cmp QWORD PTR [rbp+S],INPUT_N
 ja capacity
 jmp read_input
input_complete:
 mov rdi,r12
 mov esi,INPUT_EXTENT
 mov edx,1
 mov eax,10
 syscall
 test rax,rax
 jnz io_failure
 mov rdi,r12
 mov rsi,[rbp+S]
 lea rdx,[r12+CORE_AT]
 mov ecx,CORE_N
 lea r8,[r12+ARENA_AT]
 mov r9d,ARENA_N
 call QWORD PTR [r14+328]
 mov [rbp+176],rax
 test rax,rax
 jnz finish
 lea rdi,[r12+ARENA_AT]
 mov ecx,ARENA_N/8
 xor eax,eax
 rep stosq
 mov QWORD PTR [r12+ARENA_AT+48],262144
 mov QWORD PTR [r12+ARENA_AT+56],64
 mov rdi,r12
 mov rsi,[rbp+S]
 lea rdx,[r12+C1_AT]
 mov ecx,CANON_N
 lea r8,[r12+ARENA_AT]
 mov r9d,ARENA_N
 call QWORD PTR [r14+320]
 mov [rbp+160],rax
 test rax,rax
 jz finish
 cmp rax,CANON_N
 ja finish
 lea rdi,[r12+C1_AT]
 mov esi,CANON_N
 mov edx,1
 mov eax,10
 syscall
 test rax,rax
 jnz io_failure
 lea rdi,[r12+ARENA_AT]
 mov ecx,ARENA_N/8
 xor eax,eax
 rep stosq
 mov QWORD PTR [r12+ARENA_AT+48],262144
 mov QWORD PTR [r12+ARENA_AT+56],64
 mov rax,[rbp+176]
 mov [r12+ARENA_AT+112],rax
 lea rdi,[r12+C1_AT]
 mov rsi,[rbp+160]
 lea rdx,[r12+ASM_AT]
 mov ecx,ASM_N
 lea r8,[r12+ARENA_AT]
 mov r9d,ARENA_N
 call QWORD PTR [r14+344]
 mov [rbp+192],rax
 test rax,rax
 jz finish
 cmp rax,1048576
 ja finish
 lea rdi,[r12+ASM_AT]
 mov esi,ASM_N
 mov edx,1
 mov eax,10
 syscall
 test rax,rax
 jnz io_failure
 lea rdi,[r12+ARENA_AT]
 mov ecx,ARENA_N/8
 xor eax,eax
 rep stosq
 lea rdi,[r12+ASM_AT]
 mov rsi,[rbp+192]
 lea rdx,[r12+JSON_AT]
 mov ecx,JSON_N
 lea r8,[r12+ARENA_AT]
 mov r9d,131072
 call QWORD PTR [r14+336]
 mov [rbp+200],rax
 test rax,rax
 jz finish
 cmp rax,JSON_N
 ja finish
 lea rdi,[r12+JSON_AT]
 mov esi,JSON_N
 mov edx,1
 mov eax,10
 syscall
 test rax,rax
 jnz io_failure
 lea rdi,[r12+ARENA_AT]
 mov ecx,ARENA_N/8
 xor eax,eax
 rep stosq
 lea rdi,[r12+CORE_AT]
 mov ecx,CORE_N/8
 xor eax,eax
 rep stosq
 lea rdi,[r12+JSON_AT]
 mov rsi,[rbp+200]
 lea rdx,[r12+CORE_AT]
 mov ecx,CORE_N
 lea r8,[r12+ARENA_AT]
 mov r9d,ARENA_N
 call QWORD PTR [r14+328]
 mov [rbp+184],rax
 test rax,rax
 jnz finish
 lea rdi,[r12+ARENA_AT]
 mov ecx,ARENA_N/8
 xor eax,eax
 rep stosq
 mov QWORD PTR [r12+ARENA_AT+48],262144
 mov QWORD PTR [r12+ARENA_AT+56],64
 lea rdi,[r12+JSON_AT]
 mov rsi,[rbp+200]
 lea rdx,[r12+C2_AT]
 mov ecx,CANON_N
 lea r8,[r12+ARENA_AT]
 mov r9d,ARENA_N
 call QWORD PTR [r14+320]
 mov [rbp+168],rax
 test rax,rax
 jz finish
 cmp rax,CANON_N
 ja finish
 lea rdi,[r12+C2_AT]
 mov esi,CANON_N
 mov edx,1
 mov eax,10
 syscall
 test rax,rax
 jnz io_failure
finish:
 movabs rax,5208772604367785568
 mov [rbp],rax
 lea rdi,[r12+C1_AT]
 mov esi,CANON_N*2
 lea rdx,[r12+CORE_AT]
 mov ecx,CORE_N
 mov r8,rbp
 mov r9d,4096
 call QWORD PTR [r14+344]
 mov r13,rax
 cmp r13,255
 ja io_failure
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
 lea rdi,[r12+CORE_AT]
 mov esi,CORE_N
 mov eax,11
 syscall
 test rax,rax
 jnz io_failure
 test r13,r13
 jnz render_status
 lea rax,[r12+C1_AT]
 mov [r14+64],rax
 mov rax,[rbp+160]
 mov [r14+72],rax
 lea rax,[r12+ASM_AT]
 mov [r14+384],rax
 mov rax,[rbp+192]
 mov [r14+392],rax
 lea rdi,[r12+C2_AT]
 mov esi,CANON_N
 call release
 mov rdi,rbp
 mov esi,SCRATCH_N
 call release
 mov rbp,r14
 mov esi,4096
 call allocate
 mov [rbp+88],rax
 mov esi,4096
 call allocate
 mov [rbp+96],rax
 call hash_payload
 lea rdi,[rbp+512]
 mov rsi,[rbp+96]
 mov ecx,32
 cld
 rep movsb
 mov rdi,[rbp+64]
 mov esi,CANON_N
 call release
 mov rax,[rbp+384]
 mov [rbp+64],rax
 mov rax,[rbp+392]
 mov [rbp+72],rax
 mov rdi,[rbp+96]
 mov esi,4096
 mov edx,3
 call protect
 call hash_payload
 mov esi,8192
 call allocate
 mov [rbp+104],rax
 mov rbx,rax
 movabs rdx,3544423407393261896
 mov [rbx],rdx
 mov QWORD PTR [rbx+8],1
 mov rax,[rbp+72]
 mov [rbx+16],rax
 mov rax,[rbp+24]
 mov [rbx+24],rax
 lea rdi,[rbx+32]
 lea rsi,[rbp+512]
 mov ecx,32
 cld
 rep movsb
 lea rdi,[rbx+64]
 mov rsi,[rbp+96]
 mov ecx,32
 rep movsb
 lea rdi,[rbx+112]
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
 mov [rbp+112],rax
 mov esi,32768
 call allocate
 mov [rbp+128],rax
 mov rdi,[rbp+104]
 mov rsi,[rbp+24]
 add rsi,112
 mov rdx,[rbp+112]
 mov ecx,262144
 mov r8,[rbp+128]
 mov r9d,32768
 call QWORD PTR [rbp+336]
 test rax,rax
 jz io_failure
 cmp rax,262144
 ja io_failure
 mov [rbp+120],rax
 mov rdi,[rbp+112]
 mov esi,262144
 call readonly
 mov rdi,[rbp+104]
 mov esi,8192
 call release
 mov rdi,[rbp+128]
 mov esi,32768
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
 mov rdi,[rbp+64]
 mov esi,CANON_MAP
 call release
 call write_report
 mov rdi,[rbp+112]
 mov esi,262144
 call release
 mov rdi,rbp
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
render_status:
 mov rax,r13
 jmp HIA_status
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
write_report:
 mov r12,[rbp+112]
 mov r13,[rbp+120]
write_next:
 test r13,r13
 jz write_done
 mov edx,4096
 cmp r13,rdx
 cmovb rdx,r13
 mov rsi,r12
 mov edi,1
 mov eax,1
 syscall
 cmp rax,-4
 je write_next
 test rax,rax
 jle io_failure
 cmp rax,rdx
 ja io_failure
 add r12,rax
 sub r13,rax
 jmp write_next
write_done:
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
