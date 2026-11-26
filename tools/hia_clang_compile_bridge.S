/* Mechanical fixed native HIA calls, raw views, atomics and Linux syscalls.
 * All Clang admission, process, publication and custody policy is HIA.
 * The source catalog is a fixed native image role; requests cannot replace it.
 */
.intel_syntax noprefix
.text
.global hia_clang_compile
.global hia_clang_compile_bridge_end
.extern dlsym
.type hia_clang_compile,@function
hia_clang_compile:
.Lentry:
 push rbp
 push rbx
 push r12
 push r13
 push r14
 push r15
 sub rsp,104
 mov QWORD PTR [rsp+96],0
 mov r12,rdi
 mov r13,rsi
 mov r14,rdx
 mov r15,rcx
 mov rbx,r8
 mov rbp,r9
 test r12,r12
 jz .Lbad
 test r14,r14
 jz .Lbad
 test rbx,rbx
 jz .Lbad
 test rbx,7
 jnz .Lbad
 cmp r13,256
 jb .Lbad
 cmp r15,512
 jb .Lbad
 cmp rbp,536870912
 jb .Lbad
 mov rax,r12
 add rax,r13
 jc .Lbad
 mov [rsp+80],rax
 mov rax,r14
 add rax,r15
 jc .Lbad
 mov [rsp+64],rax
 mov rax,rbx
 add rax,rbp
 jc .Lbad
 mov [rsp+72],rax
 cmp r12,[rsp+64]
 jae .Lso_ok
 cmp r14,[rsp+80]
 jb .Lbad
.Lso_ok:
 cmp r12,[rsp+72]
 jae .Lsw_ok
 cmp rbx,[rsp+80]
 jb .Lbad
.Lsw_ok:
 cmp r14,[rsp+72]
 jae .Low_ok
 cmp rbx,[rsp+64]
 jb .Lbad
.Low_ok:
 mov rax,0x3130424c43414948
 cmp [r12],rax
 jne .Lbad
 cmp QWORD PTR [r12+8],1
 ja .Lbad
 xor eax,eax
 mov edx,1
 lock cmpxchg [rbx+16368],rdx
 jne .Lbusy
 mov QWORD PTR [rsp+96],1
 cmp QWORD PTR [r12+8],1
 je .Lretire
 cmp r15,1049088
 jb .Lbad
 cmp QWORD PTR [rbx+48],0
 jne .Lbad
 mov eax,39
 syscall
 test rax,rax
 jle .Lbad
 mov [rsp+88],rax
 mov rdi,rbx
 mov ecx,4096
 xor eax,eax
 cld
 rep stosb
 mov rax,[rsp+88]
 mov [rbx+40],rax
 lea rax,[rip+.Lentry]
 mov [rbx+208],rax
 jmp .Lviews
.Lretire:
 cmp r13,256
 jne .Lbad
 mov ecx,16
.Lreserved:
 cmp QWORD PTR [r12+rcx],0
 jne .Lbad
 add ecx,8
 cmp ecx,256
 jb .Lreserved
 mov rax,0x3130574c43414948
 cmp [rbx+48],rax
 jne .Lbad
 cmp [rbx+32],rbx
 jne .Lbad
 cmp [rbx+56],rbp
 jne .Lbad
 lea rax,[rip+.Lentry]
 cmp [rbx+208],rax
 jne .Lbad
 mov eax,39
 syscall
 cmp rax,[rbx+40]
 jne .Lbad
 mov QWORD PTR [rbx],900
 mov QWORD PTR [rbx+680],1
 mov QWORD PTR [rbx+824],0
 mov QWORD PTR [rbx+832],0
.Lviews:
 mov [rbx+56],rbp
 mov [rbx+64],rbx
 mov [rbx+72],r12
 mov [rbx+80],r13
 mov [rbx+88],r14
 mov [rbx+96],r15
 .byte 0x48,0x8d,0x05
.global clang_compile_catalog_hole
clang_compile_catalog_hole: .long 0
 mov [rbx+192],rax
 .byte 0x48,0xb8
.global clang_compile_catalog_length_hole
clang_compile_catalog_length_hole: .quad 0
 mov [rbx+200],rax
.Lowner:
 mov rdi,r12
 mov rsi,r13
 mov rdx,r14
 mov rcx,r15
 mov r8,rbx
 mov r9,rbp
 .byte 0xe8
.global clang_compile_owner_hole
clang_compile_owner_hole: .long 0
.Ldispatch:
 test eax,eax
 jz .Lreturn
 cmp eax,10
 je .Lowner
 cmp eax,1
 je .Lsyscall
 cmp eax,2
 je .Lchild
 cmp eax,3
 je .Lorigin
 cmp eax,4
 je .Lpeek
 cmp eax,100
 je .Lpolicy_prepare
 cmp eax,101
 je .Lpolicy_tools
 cmp eax,102
 je .Lpolicy_execute
 cmp eax,103
 je .Lpolicy_publish
 cmp eax,104
 je .Lpolicy_transport
 cmp eax,105
 je .Lpolicy_diagnostics
 cmp eax,106
 je .Lpolicy_cleanup
 cmp eax,107
 je .Lpolicy_location
 jmp .Lreturn
.Lpolicy_prepare:
 mov rdi,r12
 mov rsi,r13
 mov rdx,r14
 mov rcx,r15
 mov r8,rbx
 mov r9,rbp
 .byte 0xe8
.global clang_compile_prepare_hole
clang_compile_prepare_hole: .long 0
 jmp .Ldispatch
.Lpolicy_tools:
 mov rdi,r12
 mov rsi,r13
 mov rdx,r14
 mov rcx,r15
 mov r8,rbx
 mov r9,rbp
 .byte 0xe8
.global clang_compile_tools_hole
clang_compile_tools_hole: .long 0
 jmp .Ldispatch
.Lpolicy_execute:
 mov rdi,r12
 mov rsi,r13
 mov rdx,r14
 mov rcx,r15
 mov r8,rbx
 mov r9,rbp
 .byte 0xe8
.global clang_compile_execute_hole
clang_compile_execute_hole: .long 0
 jmp .Ldispatch
.Lpolicy_publish:
 mov rdi,r12
 mov rsi,r13
 mov rdx,r14
 mov rcx,r15
 mov r8,rbx
 mov r9,rbp
 .byte 0xe8
.global clang_compile_publish_hole
clang_compile_publish_hole: .long 0
 jmp .Ldispatch
.Lpolicy_transport:
 mov rdi,r12
 mov rsi,r13
 mov rdx,r14
 mov rcx,r15
 mov r8,rbx
 mov r9,rbp
 .byte 0xe8
.global clang_compile_transport_hole
clang_compile_transport_hole: .long 0
 jmp .Ldispatch
.Lpolicy_diagnostics:
 mov rdi,r12
 mov rsi,r13
 mov rdx,r14
 mov rcx,r15
 mov r8,rbx
 mov r9,rbp
 .byte 0xe8
.global clang_compile_diagnostics_hole
clang_compile_diagnostics_hole: .long 0
 jmp .Ldispatch
.Lpolicy_cleanup:
 mov rdi,r12
 mov rsi,r13
 mov rdx,r14
 mov rcx,r15
 mov r8,rbx
 mov r9,rbp
 .byte 0xe8
.global clang_compile_cleanup_hole
clang_compile_cleanup_hole: .long 0
 jmp .Ldispatch
.Lpolicy_location:
 mov rdi,r12
 mov rsi,r13
 mov rdx,r14
 mov rcx,r15
 mov r8,rbx
 mov r9,rbp
 .byte 0xe8
.global clang_compile_location_hole
clang_compile_location_hole: .long 0
 jmp .Ldispatch
.Lchild:
 mov eax,[rbx+128]
 test eax,eax
 jz .Lcopy
 mov rdi,[rbx+136]
 mov rsi,[rbx+144]
 mov rdx,[rbx+152]
 mov rcx,[rbx+160]
 mov r8,[rbx+168]
 mov r9,[rbx+176]
 cmp eax,1
 je .Lrole_hash
 cmp eax,2
 je .Lrole_admission
 cmp eax,3
 je .Lrole_canonical
 cmp eax,4
 je .Lrole_llvm
 cmp eax,5
 je .Lrole_llvm_meta
 cmp eax,6
 je .Lrole_which
 cmp eax,7
 je .Lrole_path
 cmp eax,8
 je .Lrole_file
 cmp eax,9
 je .Lrole_capture
 cmp eax,10
 je .Lrole_object
 cmp eax,11
 je .Lrole_shared
 cmp eax,12
 je .Lrole_identity
 cmp eax,13
 je .Lrole_rmtree
 cmp eax,14
 je .Lrole_receipt
 cmp eax,15
 je .Lrole_buffers
 jmp .Lbad
.Lrole_hash:
 .byte 0xe8
.global clang_compile_hash_hole
clang_compile_hash_hole: .long 0
 jmp .Lchild_return
.Lrole_admission:
 .byte 0xe8
.global clang_compile_admission_hole
clang_compile_admission_hole: .long 0
 jmp .Lchild_return
.Lrole_canonical:
 .byte 0xe8
.global clang_compile_canonical_hole
clang_compile_canonical_hole: .long 0
 jmp .Lchild_return
.Lrole_llvm:
 .byte 0xe8
.global clang_compile_llvm_hole
clang_compile_llvm_hole: .long 0
 jmp .Lchild_return
.Lrole_llvm_meta:
 .byte 0xe8
.global clang_compile_llvm_meta_hole
clang_compile_llvm_meta_hole: .long 0
 jmp .Lchild_return
.Lrole_which:
 .byte 0xe8
.global clang_compile_which_hole
clang_compile_which_hole: .long 0
 jmp .Lchild_return
.Lrole_path:
 .byte 0xe8
.global clang_compile_path_hole
clang_compile_path_hole: .long 0
 jmp .Lchild_return
.Lrole_file:
 .byte 0xe8
.global clang_compile_file_hole
clang_compile_file_hole: .long 0
 jmp .Lchild_return
.Lrole_capture:
 .byte 0xe8
.global clang_compile_capture_hole
clang_compile_capture_hole: .long 0
 jmp .Lchild_return
.Lrole_object:
 .byte 0xe8
.global clang_compile_object_hole
clang_compile_object_hole: .long 0
 jmp .Lchild_return
.Lrole_shared:
 .byte 0xe8
.global clang_compile_shared_hole
clang_compile_shared_hole: .long 0
 jmp .Lchild_return
.Lrole_identity:
 .byte 0xe8
.global clang_compile_identity_hole
clang_compile_identity_hole: .long 0
 jmp .Lchild_return
.Lrole_rmtree:
 .byte 0xe8
.global clang_compile_rmtree_hole
clang_compile_rmtree_hole: .long 0
 jmp .Lchild_return
.Lrole_receipt:
 .byte 0xe8
.global clang_compile_receipt_hole
clang_compile_receipt_hole: .long 0
 jmp .Lchild_return
.Lrole_buffers:
 .byte 0xe8
.global clang_compile_buffers_hole
clang_compile_buffers_hole: .long 0
 jmp .Lchild_return
.Lchild_return:
 mov eax,eax
 mov [rbx+8],rax
 jmp .Lowner
.Lcopy:
 mov rcx,[rbx+144]
 cmp rcx,[rbx+160]
 ja .Lbad
 test rcx,rcx
 jz .Lcopied
 mov rsi,[rbx+136]
 mov rdi,[rbx+152]
 test rsi,rsi
 jz .Lbad
 test rdi,rdi
 jz .Lbad
 mov rax,rsi
 add rax,rcx
 jc .Lbad
 mov rax,rdi
 add rax,rcx
 jc .Lbad
 cld
 rep movsb
.Lcopied:
 mov QWORD PTR [rbx+8],0
 jmp .Lowner
.Lorigin:
 xor edi,edi
 lea rsi,[rip+.Ldladdr_name]
 .byte 0xe8
.global clang_compile_dladdr_hole
clang_compile_dladdr_hole: .long 0
 test rax,rax
 jz .Lorigin_missing
 mov r11,rax
 lea rdi,[rip+.Lentry]
 lea rsi,[rbx+2048]
 call r11
 mov eax,eax
.Lorigin_missing:
 mov [rbx+8],rax
 jmp .Lowner
.Lpeek:
 mov rax,[rbx+2080]
 test rax,rax
 jz .Lbad
 movzx eax,BYTE PTR [rax]
 mov [rbx+8],rax
 jmp .Lowner
.Lsyscall:
 xor ecx,ecx
 mov r10,[r14+56]
.Largument:
 mov rax,[r14+8+rcx*8]
 mov rdx,r10
 and edx,3
 shr r10,2
 test edx,edx
 jz .Largument_ready
 cmp edx,1
 jne .Largument_output
 cmp rax,r13
 jae .Lbad
 add rax,r12
 jmp .Largument_ready
.Largument_output:
 cmp edx,2
 jne .Largument_work
 cmp rax,r15
 jae .Lbad
 add rax,r14
 jmp .Largument_ready
.Largument_work:
 cmp rax,rbp
 jae .Lbad
 add rax,rbx
.Largument_ready:
 mov [rsp+rcx*8],rax
 inc ecx
 cmp ecx,6
 jb .Largument
 test r10,r10
 jnz .Lbad
 mov rax,[r14]
 mov rdi,[rsp]
 mov rsi,[rsp+8]
 mov rdx,[rsp+16]
 mov r10,[rsp+24]
 mov r8,[rsp+32]
 mov r9,[rsp+40]
 syscall
 mov [rbx+8],rax
 jmp .Lowner
.Lbusy:
 mov eax,0xfffffffc
 jmp .Lreturn
.Lbad:
 mov eax,0xfffffffd
.Lreturn:
 cmp QWORD PTR [rsp+96],0
 je .Lunlocked
 mov QWORD PTR [rbx+16368],0
.Lunlocked:
 add rsp,104
 pop r15
 pop r14
 pop r13
 pop r12
 pop rbx
 pop rbp
 ret
.Ldladdr_name: .asciz "dladdr"
hia_clang_compile_bridge_end:
.size hia_clang_compile,.-hia_clang_compile
.section .note.GNU-stack,"",@progbits
