.intel_syntax noprefix
.text
.global _start
.equ CORE_STATE_BYTES,67108864
.equ CORE_ARENA_BYTES,33554432
.equ ADMITTED_V9,0x314b4f3956414948
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
 sub rsp,160
 mov [rsp],r12
 mov [rsp+8],r13
 mov [rsp+16],r14
 mov [rsp+24],r15
 mov QWORD PTR [rsp+32],1048576
 mov QWORD PTR [rsp+40],8388608
 mov QWORD PTR [rsp+96],0
 mov QWORD PTR [rsp+104],0
 mov QWORD PTR [rsp+112],0
 mov QWORD PTR [rsp+120],0
 mov [rsp+144],r12
 mov esi,67108864
 call allocate
 mov [rsp+128],rax
 mov esi,33554432
 call allocate
 mov [rsp+136],rax
 mov QWORD PTR [rsp+152],0
dispatch_loop:
 mov rdi,r12
 mov rsi,r15
 mov rdx,r13
 mov rcx,[rsp+32]
 mov r8,r14
 mov r9,[rsp+40]
 cmp QWORD PTR [rsp+104],0
 jne emergency_dispatch
 .byte 0xe8
dispatch_call_hole: .long 0
 jmp dispatch_return
emergency_dispatch:
 .byte 0xe8
emergency_call_hole: .long 0
dispatch_return:
 cmp rax,96
 jne failure
 cmp QWORD PTR [rsp+104],0
 jne event_ready
 mov rdi,r13
 mov rsi,[rsp+32]
 call readonly
event_ready:
 movabs rax,3544409130703866184
 cmp [r13],rax
 jne failure
 cmp QWORD PTR [r13+16],2
 je terminal
 cmp QWORD PTR [rsp+104],0
 jne syscall_kind_only
 cmp QWORD PTR [r13+16],3
 je execute_fd
 cmp QWORD PTR [r13+16],4
 je capsule_call
 cmp QWORD PTR [r13+16],5
 je bind_known_source
 cmp QWORD PTR [r13+16],6
 je fixed_Core_call
 cmp QWORD PTR [r13+16],7
 je fixed_policy_call
syscall_kind_only:
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
 cmp rax,57
 jne issue_syscall
 cmp QWORD PTR [rsp+96],0
 jne failure
issue_syscall:
 syscall
 cmp QWORD PTR [rsp+104],0
 jne capture_result
 cmp QWORD PTR [r13+24],57
 jne observe_reap_result
 test rax,rax
 jle capture_result
 mov [rsp+96],rax
 jmp capture_result
observe_reap_result:
 cmp QWORD PTR [r13+24],61
 jne observe_waitid_result
 cmp rax,[rsp+96]
 jne capture_result
 mov QWORD PTR [rsp+96],0
 jmp capture_result
observe_waitid_result:
 cmp QWORD PTR [r13+24],247
 jne capture_result
 test rax,rax
 jne capture_result
 test QWORD PTR [rsp+72],16777216
 jnz capture_result
 test QWORD PTR [rsp+72],4
 jz capture_result
 cmp QWORD PTR [rsp+48],1
 jne capture_result
 mov rcx,[rsp+96]
 cmp [rsp+56],rcx
 jne capture_result
 lea rcx,[r14+90200]
 cmp [rsp+64],rcx
 jne capture_result
 mov ecx,[r14+90216]
 cmp rcx,[rsp+96]
 jne capture_result
 mov QWORD PTR [rsp+96],0
 jmp capture_result
bind_known_source:
 cmp QWORD PTR [rsp+96],0
 jne failure
 mov r15,[r13+32]
 cmp r15,8388608
 ja failure
 mov rax,[r13+24]
 test rax,rax
 jz bind_original_source
 cmp rax,1
 je bind_canonical_source
 cmp rax,2
 jne failure
 cmp r15,32
 jne failure
 mov r12,[rsp+128]
 add r12,16777280
 jmp source_bound
bind_canonical_source:
 mov r12,[rsp+128]
 jmp source_bound
bind_original_source:
 mov r12,[rsp+144]
source_bound:
 mov [rsp],r12
 mov [rsp+24],r15
 xor eax,eax
 jmp capture_result
fixed_Core_call:
 cmp QWORD PTR [rsp+96],0
 jne failure
 cmp QWORD PTR [r13+24],2
 je call_full_Core
 cmp QWORD PTR [r13+24],3
 jne failure
 mov rax,[rsp+136]
 movabs rdx,3544428857538988360
 mov [rax+8],rdx
 mov QWORD PTR [rax+48],262144
 mov QWORD PTR [rax+56],64
 call Core_arguments
 .byte 0xe8
canonical_wire_call_hole: .long 0
 mov [rsp+152],rax
 mov rdi,[rsp+128]
 mov esi,67108864
 call readonly
 mov rdi,[rsp+136]
 mov esi,33554432
 call readonly
 mov rax,[rsp+152]
 mov eax,eax
 jmp capture_result
call_full_Core:
 # Validate current v9 Core with the shared HIA owner before applying the
 # selected compiler's existing scalar export policy to that same input.
 call Core_arguments
 .byte 0x4c,0x8d,0x1d
current_Core_archive_hole: .long 0
 mov rax,[r11]
 add rax,r11
 call rax
 mov rbx,[rsp+128]
 xor r11d,r11d
 test eax,eax
 jne reset_Core_scratch
 cmp QWORD PTR [rbx+24],9
 jne reset_Core_scratch
 mov r11d,1
reset_Core_scratch:
 mov rdi,rbx
 mov esi,CORE_STATE_BYTES
 push r11
 call discard_Core_scratch
 mov rdi,[rsp+144]
 mov esi,CORE_ARENA_BYTES
 call discard_Core_scratch
 pop r11
 test r11d,r11d
 jz call_selected_policy
 movabs rax,ADMITTED_V9
 mov [rbx+CORE_STATE_BYTES-8],rax
call_selected_policy:
 call Core_arguments
 .byte 0x4c,0x8d,0x1d
selected_Core_archive_hole: .long 0
 mov rax,[r11+8]
 add rax,r11
 call rax
 mov eax,eax
 jmp capture_result
Core_arguments:
 mov rdi,r12
 mov rsi,r15
 mov rdx,[rsp+136]
 mov ecx,CORE_STATE_BYTES
 mov r8,[rsp+144]
 mov r9d,CORE_ARENA_BYTES
 ret
discard_Core_scratch:
 mov edx,4
 mov eax,28
 syscall
 test rax,rax
 jnz failure
 ret
fixed_policy_call:
 cmp QWORD PTR [rsp+96],0
 jne failure
 cmp QWORD PTR [r13+24],3
 jne failure
 jmp known_policy_views
capsule_call:
 cmp QWORD PTR [r13+24],1
 jne failure
known_policy_views:
 cmp QWORD PTR [r13+32],21
 jne failure
 lea rsi,[r13+40]
 lea rdi,[rsp+48]
 mov ecx,6
 cld
 rep movsq
 xor ebx,ebx
capsule_view:
 mov rax,[rsp+rbx+48]
 mov rcx,rax
 shr rcx,48
 cmp rcx,3
 jne failure
 shl rax,16
 shr rax,16
 cmp rax,8388608
 jae failure
 mov edx,8388608
 sub rdx,rax
 cmp [rsp+rbx+56],rdx
 ja failure
 add rax,r14
 mov [rsp+rbx+48],rax
 add ebx,16
 cmp ebx,48
 jb capsule_view
 mov rdi,[rsp+48]
 mov rsi,[rsp+56]
 mov rdx,[rsp+64]
 mov rcx,[rsp+72]
 call disjoint_views
 mov rdi,[rsp+48]
 mov rsi,[rsp+56]
 mov rdx,[rsp+80]
 mov rcx,[rsp+88]
 call disjoint_views
 mov rdi,[rsp+64]
 mov rsi,[rsp+72]
 mov rdx,[rsp+80]
 mov rcx,[rsp+88]
 call disjoint_views
 mov rdi,[rsp+48]
 mov rsi,[rsp+56]
 mov rdx,[rsp+64]
 mov rcx,[rsp+72]
 mov r8,[rsp+80]
 mov r9,[rsp+88]
 cmp QWORD PTR [r13+16],7
 je invoke_fixed_policy
 .byte 0xe8
capsule_call_hole: .long 0
 jmp known_unit_result
invoke_fixed_policy:
 .byte 0xe8
policy_call_hole: .long 0
known_unit_result:
 mov eax,eax
 jmp capture_result
disjoint_views:
 lea rax,[rdi+rsi]
 cmp rax,rdx
 jbe separate_views
 lea rax,[rdx+rcx]
 cmp rax,rdi
 jbe separate_views
 jmp failure
separate_views:
 ret
execute_fd:
 cmp QWORD PTR [rsp+96],0
 jne failure
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
 cmp QWORD PTR [rsp+104],0
 jne emergency_result
 mov [r14+65560],rax
 mov rax,[r13+8]
 mov [r14+65552],rax
 mov rdi,r13
 mov esi,1048576
 push 3
 pop rdx
 call protect
 jmp dispatch_loop
emergency_result:
 mov [r14+24],rax
 mov rax,[r13+8]
 mov [r14+16],rax
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
 lea rax,[rbp-160]
 cmp rsp,rax
 ja raw_exit
 cmp QWORD PTR [rbp-56],0
 jne raw_exit
 cmp QWORD PTR [rbp-64],0
 je raw_exit
 mov rsp,rax
 mov [rsp+112],rdi
 mov QWORD PTR [rsp+104],1
 mov QWORD PTR [rsp+120],0
 lea r12,[rsp+96]
 lea r13,[r14+94208]
 lea r14,[r14+98304]
 mov r15d,32
 mov [rsp],r12
 mov [rsp+8],r13
 mov [rsp+16],r14
 mov QWORD PTR [rsp+24],32
 mov QWORD PTR [rsp+32],4096
 mov QWORD PTR [rsp+40],4096
 mov rdi,r14
 xor eax,eax
 mov ecx,512
 cld
 rep stosq
 jmp dispatch_loop
raw_exit:
 push 60
 pop rax
 syscall
 ud2
