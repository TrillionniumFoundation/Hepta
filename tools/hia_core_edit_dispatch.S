.intel_syntax noprefix
.text
.global _start
_start:
 mov rbp,rsp
 cmp QWORD PTR [rbp],0
 je usage
 jmp argument_diagnostic
execute_command:
 mov esi,1048576
 call allocate
 mov r13,rax
 mov esi,8388608
 call allocate
 mov r14,rax
 mov rdi,r12
 mov esi,8388608
 call readonly
 sub rsp,128
 mov [rsp],r12
 mov [rsp+8],r13
 mov [rsp+16],r14
 mov [rsp+24],r15
 mov QWORD PTR [rsp+32],1048576
 mov QWORD PTR [rsp+40],8388608
 # Only the validated initial dispatch may hand off to the selfhost role.
 mov QWORD PTR [rsp+120],0
dispatch_loop:
 mov rdi,r12
 mov rsi,r15
 mov rdx,r13
 mov ecx,1048576
 mov r8,r14
 mov r9d,8388608
 cmp QWORD PTR [rsp+120],0
 jne selfhost_dispatch
 .byte 0xe8
dispatch_call_hole: .long 0
 jmp dispatch_result
selfhost_dispatch:
 .byte 0xe8
selfhost_call_hole: .long 0
dispatch_result:
 cmp rax,96
 jne failure
 mov rdi,r13
 mov esi,1048576
 call readonly
 movabs rax,3544409130703866184
 cmp [r13],rax
 jne failure
 cmp QWORD PTR [r13+16],2
 je terminal
 cmp QWORD PTR [r13+16],3
 je execute_fd
 cmp QWORD PTR [r13+16],4
 je select_selfhost
 cmp QWORD PTR [r13+16],1
 jne failure
 mov rbx,[r13+32]
 cmp rbx,63
 ja failure
 lea rsi,[r13+40]
 lea rdi,[rsp+48]
 push 6
 pop rcx
 cld
 rep movsq
 xor edx,edx
translate_argument:
 test bl,1
 jz argument_ready
 mov rax,[rsp+rdx*8+48]
 mov rcx,rax
 shr rcx,48
 cmp rcx,1
 jb failure
 cmp rcx,3
 ja failure
 shl rax,16
 shr rax,16
 cmp rax,[rsp+rcx*8+16]
 jae failure
 add rax,[rsp+rcx*8-8]
 mov [rsp+rdx*8+48],rax
argument_ready:
 shr rbx,1
 inc edx
 cmp edx,6
 jb translate_argument
 mov rax,[r13+24]
 mov rdi,[rsp+48]
 mov rsi,[rsp+56]
 mov rdx,[rsp+64]
 mov r10,[rsp+72]
 mov r8,[rsp+80]
 mov r9,[rsp+88]
 syscall
 jmp capture_result
select_selfhost:
 cmp QWORD PTR [rsp+120],0
 jne failure
 cmp QWORD PTR [r13+8],1
 jne failure
 mov QWORD PTR [rsp+120],1
 mov rdi,r13
 mov esi,1048576
 push 3
 pop rdx
 call protect
 # Reuse the immutable original argv packet, not the dispatcher's scratch.
 cld
 xor eax,eax
 mov rdi,r13
 mov ecx,1048576/8
 rep stosq
 mov rdi,r14
 mov ecx,8388608/8
 rep stosq
 jmp dispatch_loop
execute_fd:
 mov rbx,[r13+32]
 test rbx,rbx
 jz failure
 cmp rbx,6
 ja failure
 xor edx,edx
translate_exec:
 mov rax,[r13+rdx*8+40]
 mov rcx,rax
 shr rcx,48
 cmp rcx,2
 jne failure
 shl rax,16
 shr rax,16
 cmp rax,1048576
 jae failure
 add rax,r13
 mov [rsp+rdx*8+48],rax
 inc edx
 cmp rdx,rbx
 jb translate_exec
 mov QWORD PTR [rsp+rbx*8+48],0
 mov QWORD PTR [rsp+112],0
 mov rdi,[r13+24]
 lea rsi,[rip+empty_path]
 lea rdx,[rsp+48]
 lea r10,[rsp+112]
 mov r8d,4096
 mov eax,322
 syscall
capture_result:
 mov [r14+65560],rax
 mov rax,[r13+8]
 mov [r14+65552],rax
 mov rdi,r13
 mov esi,1048576
 push 3
 pop rdx
 call protect
 jmp dispatch_loop
terminal:
 mov rdi,[r13+24]
 cmp rdi,255
 ja failure
 jmp exit

# Import kernel argv/environment byte spans and raw terminal facts. The
# framing, option decisions, help/error text and character encoding are HIA.
argument_diagnostic:
 sub rsp,192
 mov esi,8388608
 call allocate
 mov r12,rax
 mov rax,[rbp]
 lea rbx,[rbp+rax*8+16]
 dec rax
 mov [r12+8],rax
 xor ecx,ecx
argument_count_env:
 cmp rcx,524285
 ja failure
 cmp QWORD PTR [rbx+rcx*8],0
 je argument_count_ready
 inc rcx
 jmp argument_count_env
argument_count_ready:
 mov [r12+16],rcx
 add rcx,rax
 cmp rcx,524285
 ja failure
 mov [rsp+64],rcx
 # HCLILNX4, little-endian.
 movabs rax,0x34584e4c494c4348
 mov [r12],rax
 mov r15,rcx
 shl r15,4
 add r15,48
 lea r14,[r12+48]
 lea rbx,[rbp+16]
 xor r13d,r13d
argument_collect:
 cmp r13,[rsp+64]
 jae argument_observe
 mov rdi,[rbx]
 add rbx,8
 test rdi,rdi
 jne argument_string
 mov rdi,[rbx]
 add rbx,8
argument_string:
 xor eax,eax
argument_strlen:
 cmp eax,131072
 jae failure
 cmp BYTE PTR [rdi+rax],0
 je argument_string_ready
 inc eax
 jmp argument_strlen
argument_string_ready:
 mov edx,8388608
 sub rdx,r15
 cmp rax,rdx
 ja failure
 mov [r14],r15
 mov [r14+8],rax
 mov rcx,rax
 mov rsi,rdi
 lea rdi,[r12+r15]
 add r15,rax
 cld
 rep movsb
 add r14,16
 inc r13
 jmp argument_collect
argument_observe:
 mov [rsp+64],r15
 mov edi,1
 mov esi,0x5413
 mov rdx,rsp
 mov eax,16
 syscall
 test rax,rax
 jne argument_tty
 movzx eax,WORD PTR [rsp+2]
 mov [r12+24],rax
argument_tty:
 mov edi,1
 mov esi,0x5401
 mov rdx,rsp
 mov eax,16
 syscall
 test rax,rax
 sete al
 movzx eax,al
 mov [r12+32],rax
 mov QWORD PTR [r12+40],4300
 # Allocate only the observed UTF-32 frame extent (one point per raw byte).
 mov rsi,[r12+8]
 shl rsi,4
 lea rsi,[rsi+r15*4+232]
 mov [rsp+72],rsi
 call allocate
 mov r13,rax
 mov rdi,r12
 mov rsi,[rsp+64]
 mov rdx,r13
 mov rcx,[rsp+72]
 mov BYTE PTR [rsp],1
 mov r8,rsp
 mov r9d,1
 .byte 0xe8
argument_frame_hole: .long 0
 cmp rax,192
 jb failure
 cmp rax,[rsp+72]
 ja failure
 mov [rsp+80],rax
 mov rbx,[r12+8]
 mov rdi,r12
 mov esi,8388608
 call release
 mov rdi,r13
 mov rsi,[rsp+72]
 call readonly

 .byte 0x48,0x8d,0x05
argument_images_hole: .long 0
 mov r12,rax
 mov rsi,[r12+8]
 mov rax,[r12]
 test rax,rax
 jz failure
 cmp rax,1048552
 ja failure
 cmp rsi,1048576
 ja failure
 mov rax,[r12+16]
 test rax,rax
 jz failure
 cmp rax,rsi
 jae failure
 call allocate
 mov r15,rax
 mov esi,4096
 call allocate
 mov r14,rax
 lea rdi,[r12+24]
 mov rsi,[r12]
 mov rdx,r15
 mov rcx,[r12+8]
 mov r8,r14
 mov r9d,4096
 .byte 0xe8
argument_unpack_hole: .long 0
 cmp rax,[r12+8]
 jne failure
 mov rdi,r14
 mov esi,4096
 call release
 mov rdi,r15
 mov rsi,[r12+8]
 mov edx,5
 call protect

 imul rsi,rbx,80
 add rsi,[rsp+80]
 add rsi,65536
 mov [rsp+88],rsi
 call allocate
 mov r14,rax
 mov rdi,r13
 mov rsi,[rsp+80]
 # The control output is 128 bytes; reserve separate ABI scratch.
 sub rsp,160
 mov rdx,rsp
 mov ecx,128
 mov r8,r14
 mov r9,[rsp+248]
 call r15
 add rsp,160
 test eax,eax
 jne failure
 movabs rax,3770433532758606664
 cmp [r14],rax
 jne failure
 mov rax,[r14+8]
 test rax,rax
 jz argument_command
 cmp rax,3
 ja failure
 mov QWORD PTR [rsp+96],0
 mov QWORD PTR [rsp+104],1
 cmp rax,3
 jne argument_formatter
 mov QWORD PTR [rsp+96],2
 mov QWORD PTR [rsp+104],2
argument_formatter:
 mov rax,[rsp+96]
 cmp [r14+112],rax
 jne failure
 imul rsi,rbx,24
 add rsi,131072
 mov [rsp+112],rsi
 call allocate
 mov [rsp+120],rax
 mov rdi,rax
 mov rsi,r14
 mov ecx,128
 cld
 rep movsq
 mov rcx,[r14+80]
 cmp rcx,rbx
 ja failure
 imul rsi,rbx,48
 lea rsi,[r14+rsi+32768]
 lea rdi,[rax+131072]
 imul rcx,rcx,3
 rep movsq
 mov rdi,r14
 mov rsi,[rsp+88]
 call release

 imul rsi,[rsp+80],12
 add rsi,131072
 mov [rsp+128],rsi
 call allocate
 mov r14,rax
 add r15,[r12+16]
 mov rdi,r13
 mov rsi,[rsp+80]
 mov rdx,r14
 mov rcx,[rsp+128]
 mov r8,[rsp+120]
 mov r9,[rsp+112]
 call r15
 test eax,eax
 jne failure
 mov rax,[rsp+120]
 mov r15,[rax+1024]
 mov rdx,[rsp+128]
 shr rdx,2
 cmp r15,rdx
 ja failure
 cmp [rax+1032],r15
 ja failure
 test r15,r15
 jz argument_exit

 imul rsi,r15,6
 mov [rsp+136],rsi
 call allocate
 mov r13,rax
 mov rdi,r14
 lea rsi,[r15*4]
 mov rdx,r13
 mov rcx,[rsp+136]
 mov rax,[rsp+104]
 inc eax
 mov [rsp],al
 mov r8,rsp
 mov r9d,1
 .byte 0xe8
argument_encode_hole: .long 0
 cmp rax,[rsp+136]
 ja failure
 mov rdx,rax
 mov rsi,r13
 mov rdi,[rsp+104]
argument_write:
 test rdx,rdx
 jz argument_exit
 mov eax,1
 syscall
 cmp rax,-4
 je argument_write
 test rax,rax
 jle argument_exit
 add rsi,rax
 sub rdx,rax
 jmp argument_write
argument_exit:
 mov rdi,[rsp+96]
 jmp exit
argument_command:
 # Release staging buffers after HIA emits canonical arguments for effects.
 mov esi,8388608
 call allocate
 mov [rsp+144],rax
 mov rdi,r13
 mov rsi,[rsp+80]
 mov rdx,rax
 mov ecx,8388608
 mov r8,r14
 mov r9,[rsp+88]
 .byte 0xe8
argument_command_hole: .long 0
 cmp rax,32
 jb failure
 cmp rax,8388608
 ja failure
 mov [rsp+152],rax
 mov rdi,r14
 mov rsi,[rsp+88]
 call release
 mov rdi,r13
 mov rsi,[rsp+72]
 call release
 mov rdi,r15
 mov rsi,[r12+8]
 call release
 mov r12,[rsp+144]
 mov r15,[rsp+152]
 mov rsp,rbp
 jmp execute_command
readonly:
 push 1
 pop rdx
protect:
 push 10
 pop rax
 syscall
 test rax,rax
 jnz failure
 ret
empty_path: .byte 0
allocate:
 xor edi,edi
 push 3
 pop rdx
 mov r10d,34
 push -1
 pop r8
 xor r9d,r9d
 push 9
 pop rax
 syscall
 cmp rax,-4095
 jae failure
 ret
release:
 push 11
 pop rax
 syscall
 test rax,rax
 jnz failure
 ret
usage:
 push 64
 pop rdi
 jmp exit
failure:
 push 4
 pop rdi
exit:
 push 60
 pop rax
 syscall
 ud2
