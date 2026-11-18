.intel_syntax noprefix
.text
.global _start
.equ CORE_N,67108864
.equ SOURCE_N,41943040
.equ RAW_N,8388608
.equ EVT_N,34880
.equ EVT_MAP,36864
.equ CODE_N,16777280
.equ ART_N,67108864
.equ WRITE_W,33554432
.equ C,67092480
_start:
 cmp QWORD PTR [rsp],1
 jne usage
 .byte 0x4c,0x8d,0x35
byte_address_hole: .long 0
 mov esi,4096
 call allocate
 mov rbp,rax
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
 xor edi,edi
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
 mov rdi,r12
 mov esi,RAW_N
 mov edx,1
 call protect
 mov rdi,r12
 mov rsi,[rbp+88]
 mov rdx,r13
 mov ecx,CORE_N
 lea r8,[r12+RAW_N]
 mov r9d,33554432
 .byte 0xe8
core_hole: .long 0
 test rax,rax
 jnz native_status
 mov rdi,r12
 mov esi,SOURCE_N
 mov edx,1
 call protect
 mov rdi,r12
 mov esi,SOURCE_N
 mov rdx,[rbp+16]
 mov ecx,EVT_N
 mov r8,r13
 mov r9d,CORE_N
 .byte 0xe8
frame_hole: .long 0
 test rax,rax
 jnz native_status
 mov rdi,r12
 mov esi,SOURCE_N
 mov rdx,[rbp+16]
 mov ecx,EVT_N
 mov r8,r13
 mov r9d,CORE_N
 .byte 0xe8
exports_hole: .long 0
 test rax,rax
 jnz native_status
 movabs rax,3616483217365879112
 mov [rbp+768],rax
 mov QWORD PTR [rbp+776],1
codegen_loop:
 mov rdi,r12
 mov esi,SOURCE_N
 mov rdx,[rbp+16]
 mov ecx,EVT_N
 mov r8,r13
 mov r9d,CORE_N
 .byte 0xe8
codegen_hole: .long 0
 test rax,rax
 jnz native_status
 mov rdi,[rbp+16]
 mov esi,EVT_MAP
 mov edx,1
 call protect
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
 jne io_failure
 lea rdi,[rbx+8]
 mov esi,64
 mov rax,[rbx+16]
 test rax,rax
 jz initialize_code
 cmp QWORD PTR [rbp+24],0
 je io_failure
 cmp rax,4
 je named_event
 cmp rax,5
 je named_event
 cmp rax,2
 je invoke_state
 cmp rax,3
 je invoke_state
 cmp rax,6
 je invoke_state
 cmp rax,7
 jne io_failure
 jmp invoke_state
named_event:
 mov rax,[rbx+24]
 test rax,rax
 jz io_failure
 cmp rax,192
 ja io_failure
 add rsi,rax
 jmp invoke_state
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
 mov esi,64
invoke_state:
 call byte_state
 jmp event_complete
numeric_event:
 cmp QWORD PTR [rbp+24],0
 je io_failure
 lea rdi,[rbx+8]
 mov esi,64
 lea rdx,[rbp+512]
 mov ecx,80
 lea r8,[rbp+600]
 mov r9d,8
 call r14
 test rax,rax
 jnz native_status
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
 mov edx,3
 call protect
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
 mov edx,1
 call protect
 mov rdi,[rbp+40]
 mov rsi,[rbp+32]
 mov edx,1
 call protect
 mov rdi,r13
 mov esi,CORE_N
 mov edx,1
 call protect
 mov esi,20480
 call allocate
 mov [rbp+136],rax
 mov rdi,r12
 mov esi,SOURCE_N
 mov rdx,rax
 mov ecx,20480
 mov r8,r13
 mov r9d,CORE_N
 .byte 0xe8
expectations_hole: .long 0
 test rax,rax
 jz io_failure
 cmp rax,18496
 ja native_status
 cmp rax,64
 jb io_failure
 mov [rbp+144],rax
 mov rdi,[rbp+136]
 cmp [rdi+24],rax
 jne io_failure
 cmp QWORD PTR [rdi+32],0
 jne io_failure
 mov esi,20480
 mov edx,1
 call protect
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
 mov edx,1
 call protect
 mov rdi,[rbp+24]
 mov esi,CODE_N
 call release
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
 mov edx,1
 call protect
 mov rdi,[rbp+64]
 mov esi,ART_N
 call release
 mov rdi,[rbp+80]
 mov esi,WRITE_W
 call release
 mov rax,[rbp+144]
 add rax,[rbp+56]
 jc io_failure
 cmp rax,67127360
 ja io_failure
 mov [rbp+160],rax
 mov esi,67129344
 call allocate
 mov [rbp+152],rax
 mov rdi,rax
 mov rsi,[rbp+136]
 mov rcx,[rbp+144]
 cld
 rep movsb
 mov rax,[rbp+56]
 mov rbx,[rbp+152]
 mov [rbx+32],rax
 mov rsi,[rbp+48]
 mov rcx,rax
 rep movsb
 mov rdi,[rbp+152]
 mov esi,67129344
 mov edx,1
 call protect
 mov esi,32768
 call allocate
 mov [rbp+168],rax
 mov esi,4096
 call allocate
 mov [rbp+176],rax
 mov rdi,[rbp+152]
 mov rsi,[rbp+160]
 mov rdx,[rbp+168]
 mov ecx,32768
 mov r8,rax
 mov r9d,4096
 call r14
 test rax,rax
 jz io_failure
 cmp rax,32768
 ja native_status
 mov rdi,[rbp+168]
 mov esi,32768
 mov edx,1
 call protect
 mov rdi,[rbp+136]
 mov esi,20480
 call release
 mov rdi,[rbp+152]
 mov esi,67129344
 call release
 mov rdi,[rbp+168]
 mov esi,32768
 call release
 mov rdi,[rbp+176]
 mov esi,4096
 call release
write_output:
 mov rax,[rbp+56]
 sub rax,[rbp+128]
 jz output_complete
 mov edx,4096
 cmp rax,rdx
 cmovb rdx,rax
 mov rsi,[rbp+48]
 add rsi,[rbp+128]
 mov edi,1
 mov eax,1
 syscall
 cmp rax,-4
 je write_output
 test rax,rax
 jle io_failure
 add [rbp+128],rax
 cmp rax,rdx
 ja io_failure
 jmp write_output
output_complete:
 mov rdi,[rbp+48]
 mov esi,ART_N
 call release
 mov rdi,rbp
 mov esi,4096
 call release
 xor edi,edi
 jmp exit
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
 mov edi,2
 jmp exit
capacity:
 mov edi,3
 jmp exit
io_failure:
 mov edi,4
 jmp exit
usage:
 mov edi,64
exit:
 mov eax,60
 syscall
 ud2
