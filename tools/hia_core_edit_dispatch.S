.intel_syntax noprefix
.text
.global _start
_start:
 mov rbp,rsp
 mov rbx,[rbp]
 test rbx,rbx
 jz usage
 dec rbx
 cmp rbx,524286
 ja failure
 mov esi,8388608
 call allocate
 mov r12,rax
 movabs rax,3555107374463273288
 mov [r12],rax
 mov QWORD PTR [r12+8],1
 mov [r12+16],rbx
 mov r15,rbx
 shl r15,4
 add r15,32
 mov [r12+24],r15
 xor r13d,r13d
 lea r14,[r12+32]
capture:
 cmp r13,rbx
 jae captured
 mov rdi,[rbp+r13*8+16]
 xor eax,eax
scan:
 cmp rax,131072
 jae failure
 cmp BYTE PTR [rdi+rax],0
 je scanned
 inc rax
 jmp scan
scanned:
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
 jmp capture
captured:
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
