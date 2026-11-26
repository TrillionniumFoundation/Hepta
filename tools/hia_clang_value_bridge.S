/* Mechanical native bindings, fixed HIA calls, views, atomics and syscalls.
 * HIAMVCB1 is generated only by the fixed parent native prefix. Ordinary BC1
 * requests carry actual Value capabilities and never native function pointers.
 */
.intel_syntax noprefix
.text
.global hia_clang_value_compile
.global hia_clang_value_bind
.global hia_clang_value_exception
.global hia_clang_value_bridge_end
.type hia_clang_value_compile,@function
hia_clang_value_compile:
.Av_compile:
 mov r10d,1
 jmp .Av_entry
hia_clang_value_bind:
.Av_bind_entry:
 xor r10d,r10d
 jmp .Av_entry
hia_clang_value_exception:
 mov r10d,3
.Av_entry:
 push rbp
 push rbx
 push r12
 push r13
 push r14
 push r15
 sub rsp,104
 mov [rsp+88],r10
 mov QWORD PTR [rsp+96],0
 mov r12,rdi
 mov r13,rsi
 mov r14,rdx
 mov r15,rcx
 mov rbx,r8
 mov rbp,r9
 test r12,r12
 jz .Av_bad
 test r14,r14
 jz .Av_bad
 test rbx,rbx
 jz .Av_bad
 test rbx,7
 jnz .Av_bad
 cmp r15,128
 jb .Av_bad
 cmp rbp,538968064
 jne .Av_bad
 mov rax,r12
 add rax,r13
 jc .Av_bad
 mov [rsp+80],rax
 mov rax,r14
 add rax,r15
 jc .Av_bad
 mov [rsp+64],rax
 mov rax,rbx
 add rax,rbp
 jc .Av_bad
 mov [rsp+72],rax
 cmp r12,[rsp+64]
 jae .Av_so
 cmp r14,[rsp+80]
 jb .Av_bad
.Av_so:
 cmp r12,[rsp+72]
 jae .Av_sw
 cmp rbx,[rsp+80]
 jb .Av_bad
.Av_sw:
 cmp r14,[rsp+72]
 jae .Av_ow
 cmp rbx,[rsp+64]
 jb .Av_bad
.Av_ow:
 cmp QWORD PTR [rsp+88],0
 je .Av_bind_validate
 cmp QWORD PTR [rsp+88],3
 je .Av_exception_validate
 cmp r13,256
 jb .Av_bad
 mov rax,0x314342564d414948
 cmp [r12],rax
 je .Av_compile_profile
 mov rax,0x3143505643414948
 cmp [r12],rax
 jne .Av_bad
.Av_compile_profile:
 cmp QWORD PTR [r12+8],1
 ja .Av_bad
 cmp r15,512
 jb .Av_bad
 cmp QWORD PTR [r12+8],0
 jne .Av_retire_validate
 cmp r15,1049088
 jb .Av_bad
 mov rax,0x3143505643414948
 cmp [r12],rax
 jne .Av_runtime_profile
 cmp QWORD PTR [r12+16],2
 ja .Av_bad
 cmp QWORD PTR [r12+24],1
 ja .Av_bad
 cmp QWORD PTR [r12+32],1
 ja .Av_bad
 jmp .Av_profile_valid
.Av_runtime_profile:
 cmp QWORD PTR [r12+16],0
 jne .Av_bad
.Av_profile_valid:
 cmp QWORD PTR [r12+64],0
 je .Av_bad
 cmp QWORD PTR [r12+88],0
 jne .Av_bad
 mov rax,[r12+40]
 test rax,rax
 jz .Av_bad
 cmp rax,8388608
 ja .Av_bad
 mov rcx,r13
 sub rcx,256
 cmp rax,rcx
 ja .Av_bad
 sub rcx,rax
 mov rax,[r12+48]
 cmp rax,5136
 ja .Av_bad
 cmp rax,rcx
 ja .Av_bad
 sub rcx,rax
 cmp rcx,0
 je .Av_bad
 cmp [r12+56],rcx
 jne .Av_bad
 mov ecx,96
.Av_compile_reserved:
 cmp QWORD PTR [r12+rcx],0
 jne .Av_bad
 add ecx,8
 cmp ecx,256
 jb .Av_compile_reserved
 jmp .Av_lock
.Av_retire_validate:
 cmp r13,256
 jne .Av_bad
 mov QWORD PTR [rsp+88],2
 mov ecx,16
.Av_retire_words:
 cmp QWORD PTR [r12+rcx],0
 jne .Av_bad
 add ecx,8
 cmp ecx,256
 jb .Av_retire_words
 jmp .Av_lock
.Av_exception_validate:
 cmp r13,128
 jne .Av_bad
 mov rax,0x314543564d414948
 cmp [r12],rax
 jne .Av_bad
 cmp QWORD PTR [r12+8],1
 ja .Av_bad
 mov rax,[r12+8]
 add [rsp+88],rax
 mov ecx,16
.Av_exception_reserved:
 cmp QWORD PTR [r12+rcx],0
 jne .Av_bad
 add ecx,8
 cmp ecx,128
 jb .Av_exception_reserved
 jmp .Av_lock
.Av_bind_validate:
 cmp r13,128
 jne .Av_bad
 mov rax,0x314243564d414948
 cmp [r12],rax
 je .Av_bind_fields
 mov rax,0x324243564d414948
 cmp [r12],rax
 jne .Av_bad
 cmp QWORD PTR [r12+40],2147483647
 ja .Av_bad
.Av_bind_fields:
 cmp QWORD PTR [r12+8],0
 je .Av_bad
 cmp QWORD PTR [r12+16],0
 je .Av_bad
 cmp QWORD PTR [r12+24],256
 jne .Av_bad
 cmp QWORD PTR [r12+32],0
 je .Av_bad
 mov rax,[r12+16]
 add rax,256
 jc .Av_bad
 mov ecx,40
 mov rax,0x324243564d414948
 cmp [r12],rax
 jne .Av_bind_reserved
 mov ecx,48
.Av_bind_reserved:
 cmp QWORD PTR [r12+rcx],0
 jne .Av_bad
 add ecx,8
 cmp ecx,128
 jb .Av_bind_reserved
.Av_lock:
 xor eax,eax
 mov edx,1
 lock cmpxchg [rbx+120],rdx
 jne .Av_busy
 mov QWORD PTR [rsp+96],1
 cmp QWORD PTR [rsp+88],0
 jne .Av_existing
 cmp QWORD PTR [rbx],0
 jne .Av_bad
 mov ecx,8
.Av_blank:
 cmp ecx,120
 je .Av_blank_next
 cmp QWORD PTR [rbx+rcx],0
 jne .Av_bad
.Av_blank_next:
 add ecx,8
 cmp ecx,4096
 jb .Av_blank
 mov eax,39
 syscall
 test rax,rax
 jle .Av_bad
 mov [rbx+16],rax
 mov rax,0x3157425643414948
 mov [rbx],rax
 mov [rbx+8],rbx
 mov [rbx+24],rbp
 lea rax,[rip+.Av_compile]
 mov [rbx+32],rax
 mov rax,[r12+8]
 mov [rbx+40],rax
 mov rax,[r12+16]
 mov [rbx+48],rax
 mov rax,[r12+24]
 mov [rbx+56],rax
 mov rax,[r12+32]
 mov [rbx+64],rax
 jmp .Av_views
.Av_existing:
 mov rax,0x3157425643414948
 cmp [rbx],rax
 jne .Av_bad
 cmp [rbx+8],rbx
 jne .Av_bad
 cmp [rbx+24],rbp
 jne .Av_bad
 lea rax,[rip+.Av_compile]
 cmp [rbx+32],rax
 jne .Av_bad
 mov eax,39
 syscall
 cmp rax,[rbx+16]
 jne .Av_bad
.Av_views:
 mov rax,[rsp+88]
 mov [rbx+128],rax
 mov [rbx+144],rbx
 mov [rbx+152],r12
 mov [rbx+160],r13
 mov [rbx+168],r14
 mov [rbx+176],r15
 mov QWORD PTR [rbx+256],0
.Av_owner:
 mov rdi,r12
 mov rsi,r13
 mov rdx,r14
 mov rcx,r15
 mov r8,rbx
 mov r9,rbp
 .byte 0xe8
.global clang_value_owner_hole
clang_value_owner_hole:.long 0
.Av_dispatch:
 test eax,eax
 jz .Av_return
 cmp eax,10
 je .Av_owner
 cmp eax,1
 je .Av_syscall
 cmp eax,2
 je .Av_child
 cmp eax,100
 je .Av_coercion
 cmp eax,101
 je .Av_transport
 cmp eax,102
 je .Av_cleanup
 cmp eax,103
 je .Av_exceptions
 cmp eax,104
 je .Av_path_policy
 jmp .Av_return
.Av_coercion:
 mov rdi,r12
 mov rsi,r13
 mov rdx,r14
 mov rcx,r15
 mov r8,rbx
 mov r9,rbp
 .byte 0xe8
.global clang_value_coercion_hole
clang_value_coercion_hole:.long 0
 jmp .Av_dispatch
.Av_transport:
 mov rdi,r12
 mov rsi,r13
 mov rdx,r14
 mov rcx,r15
 mov r8,rbx
 mov r9,rbp
 .byte 0xe8
.global clang_value_transport_hole
clang_value_transport_hole:.long 0
 jmp .Av_dispatch
.Av_cleanup:
 mov rdi,r12
 mov rsi,r13
 mov rdx,r14
 mov rcx,r15
 mov r8,rbx
 mov r9,rbp
 .byte 0xe8
.global clang_value_cleanup_hole
clang_value_cleanup_hole:.long 0
 jmp .Av_dispatch
.Av_exceptions:
 mov rdi,r12
 mov rsi,r13
 mov rdx,r14
 mov rcx,r15
 mov r8,rbx
 mov r9,rbp
 .byte 0xe8
.global clang_value_exceptions_hole
clang_value_exceptions_hole:.long 0
 jmp .Av_dispatch
.Av_path_policy:
 mov rdi,r12
 mov rsi,r13
 mov rdx,r14
 mov rcx,r15
 mov r8,rbx
 mov r9,rbp
 .byte 0xe8
.global clang_value_path_hole
clang_value_path_hole:.long 0
 jmp .Av_dispatch
.Av_child:
 mov eax,[rbx+320]
 test eax,eax
 jz .Av_copy
 mov rdi,[rbx+328]
 mov rsi,[rbx+336]
 mov rdx,[rbx+344]
 mov rcx,[rbx+352]
 mov r8,[rbx+360]
 mov r9,[rbx+368]
 cmp eax,1
 je .Av_value
 cmp eax,2
 je .Av_clang
 cmp eax,3
 je .Av_codec
 cmp eax,4
 je .Av_buffers
 cmp eax,5
 je .Av_which
 cmp eax,6
 je .Av_origin
 jmp .Av_bad
.Av_value:
 mov r8,[rbx+48]
 mov r9,[rbx+56]
 call QWORD PTR [rbx+40]
 jmp .Av_child_return
.Av_clang:
 call .Av_legacy
 jmp .Av_child_return
.Av_origin:
 call .Av_origin_producer
 jmp .Av_child_return
.Av_codec:
 .byte 0xe8
.global clang_value_codec_hole
clang_value_codec_hole:.long 0
 jmp .Av_child_return
.Av_buffers:
 .byte 0xe8
.global clang_value_buffers_hole
clang_value_buffers_hole:.long 0
 jmp .Av_child_return
.Av_which:
 .byte 0xe8
.global clang_value_which_hole
clang_value_which_hole:.long 0
.Av_child_return:
 mov eax,eax
 mov [rbx+264],rax
 jmp .Av_owner
.Av_copy:
 mov rcx,[rbx+336]
 cmp rcx,[rbx+352]
 ja .Av_bad
 test rcx,rcx
 jz .Av_copied
 mov rsi,[rbx+328]
 mov rdi,[rbx+344]
 test rsi,rsi
 jz .Av_bad
 test rdi,rdi
 jz .Av_bad
 mov rax,rsi
 add rax,rcx
 jc .Av_bad
 mov rax,rdi
 add rax,rcx
 jc .Av_bad
 cld
 rep movsb
.Av_copied:
 mov QWORD PTR [rbx+264],0
 jmp .Av_owner
.Av_syscall:
 xor ecx,ecx
 mov r10,[r14+56]
.Av_argument:
 mov rax,[r14+8+rcx*8]
 mov rdx,r10
 and edx,3
 shr r10,2
 test edx,edx
 jz .Av_ready
 cmp edx,1
 jne .Av_output
 cmp rax,r13
 jae .Av_bad
 add rax,r12
 jmp .Av_ready
.Av_output:
 cmp edx,2
 jne .Av_work
 cmp rax,r15
 jae .Av_bad
 add rax,r14
 jmp .Av_ready
.Av_work:
 cmp rax,rbp
 jae .Av_bad
 add rax,rbx
.Av_ready:
 mov [rsp+rcx*8],rax
 inc ecx
 cmp ecx,6
 jb .Av_argument
 test r10,r10
 jnz .Av_bad
 mov rax,[r14]
 mov rdi,[rsp]
 mov rsi,[rsp+8]
 mov rdx,[rsp+16]
 mov r10,[rsp+24]
 mov r8,[rsp+32]
 mov r9,[rsp+40]
 syscall
 mov [rbx+264],rax
 jmp .Av_owner
.Av_busy:
 mov eax,0xfffffffc
 jmp .Av_return
.Av_bad:
 mov eax,0xfffffffd
.Av_return:
 cmp QWORD PTR [rsp+96],0
 je .Av_unlocked
 mov QWORD PTR [rbx+120],0
.Av_unlocked:
 add rsp,104
 pop r15
 pop r14
 pop r13
 pop r12
 pop rbx
 pop rbp
 ret
/* Private capture from the sole native owner; its caller holds an active
 * owner borrow for this entire call. No request carries an entry address. */
.global hia_clang_value_bind_owner
hia_clang_value_bind_owner:
 push rbx
 push r12
 push r13
 push r14
 sub rsp,264
 mov r12,rdx
 mov r13,rcx
 mov r14,r8
 test rdi,rdi
 jz .Av_owner_bind_bad
 cmp rsi,32
 jne .Av_owner_bind_bad
 mov rbx,[rdi]
 mov rax,0x31424f5643414948
 cmp rbx,rax
 je .Av_owner_bind_old
 mov rax,0x32424f5643414948
 cmp rbx,rax
 jne .Av_owner_bind_bad
 cmp QWORD PTR [rdi+8],2147483647
 ja .Av_owner_bind_bad
 mov rax,[rdi+8]
 mov [rsp+256],rax
 jmp .Av_owner_bind_common
.Av_owner_bind_old:
 cmp QWORD PTR [rdi+8],0
 jne .Av_owner_bind_bad
 mov QWORD PTR [rsp+256],0
.Av_owner_bind_common:
 cmp QWORD PTR [rdi+16],0
 jne .Av_owner_bind_bad
 cmp QWORD PTR [rdi+24],0
 jne .Av_owner_bind_bad
 test r12,r12
 jz .Av_owner_bind_bad
 test r12,7
 jnz .Av_owner_bind_bad
 cmp r13,538968064
 jne .Av_owner_bind_bad
 test r14,r14
 jz .Av_owner_bind_bad
 cmp r9,2048
 jne .Av_owner_bind_bad
 mov rax,0x31574f4c47414948
 cmp [r14],rax
 jne .Av_owner_bind_bad
 cmp [r14+16],r14
 jne .Av_owner_bind_bad
 /* owner+24 is its fixed entry, not an extent; r9 is the 2048-byte extent. */
 cmp QWORD PTR [r14+24],0
 je .Av_owner_bind_bad
 cmp QWORD PTR [r14+80],1
 jne .Av_owner_bind_bad
 mov eax,39
 syscall
 cmp rax,[r14+8]
 jne .Av_owner_bind_bad
 lea rax,[r14+512]
 cmp [r14+48],rax
 jne .Av_owner_bind_bad
 cmp QWORD PTR [r14+56],256
 jne .Av_owner_bind_bad
 mov rdi,rsp
 mov ecx,256
 xor eax,eax
 cld
 rep stosb
 mov rax,0x314243564d414948
 mov [rsp],rax
 mov rax,0x32424f5643414948
 cmp rbx,rax
 jne .Av_owner_bind_frame
 mov rax,0x324243564d414948
 mov [rsp],rax
 mov rax,[rsp+256]
 mov [rsp+40],rax
.Av_owner_bind_frame:
 mov rax,[r14+40]
 mov [rsp+8],rax
 mov rax,[r14+48]
 mov [rsp+16],rax
 mov rax,[r14+56]
 mov [rsp+24],rax
 mov rax,[r14+664]
 mov [rsp+32],rax
 mov rdi,rsp
 mov esi,128
 lea rdx,[rsp+128]
 mov ecx,128
 mov r8,r12
 mov r9,r13
 call .Av_bind_entry
 test eax,eax
 jne .Av_owner_bind_return
 cmp QWORD PTR [rsp+136],0
 jne .Av_owner_bind_error
 cmp QWORD PTR [rsp+216],1
 jne .Av_owner_bind_error
 cmp QWORD PTR [rsp+224],1
 jne .Av_owner_bind_error
 xor eax,eax
 jmp .Av_owner_bind_return
.Av_owner_bind_error:
 mov eax,0xfffffffb
 jmp .Av_owner_bind_return
.Av_owner_bind_bad:
 mov eax,0xfffffffd
.Av_owner_bind_return:
 add rsp,264
 pop r14
 pop r13
 pop r12
 pop rbx
 ret

.balign 16
.Av_legacy:
.include "tools/hia_clang_compile_bridge.S"
.text
.balign 16
.Av_origin_producer:
.include "tools/hia_clang_origin_bridge.S"
.text
hia_clang_value_bridge_end:
.size hia_clang_value_compile,.-hia_clang_value_compile
.section .note.GNU-stack,"",@progbits
