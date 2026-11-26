/* Mechanical fixed native HIA calls, raw views, atomics and Linux syscalls.
 * All Clang admission, process, publication and custody policy is HIA.
 * The source catalog is a fixed native image role; requests cannot replace it.
 */
.intel_syntax noprefix
.text
.global hia_clang_origin
.global hia_clang_origin_bridge_end
.extern dlsym
.type hia_clang_origin,@function
hia_clang_origin:
.Loentry:
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
 jz .Lobad
 test r14,r14
 jz .Lobad
 test rbx,rbx
 jz .Lobad
 test rbx,7
 jnz .Lobad
 cmp r13,256
 jb .Lobad
 cmp r15,512
 jb .Lobad
 cmp rbp,536870912
 jb .Lobad
 mov rax,r12
 add rax,r13
 jc .Lobad
 mov [rsp+80],rax
 mov rax,r14
 add rax,r15
 jc .Lobad
 mov [rsp+64],rax
 mov rax,rbx
 add rax,rbp
 jc .Lobad
 mov [rsp+72],rax
 cmp r12,[rsp+64]
 jae .Loso_ok
 cmp r14,[rsp+80]
 jb .Lobad
.Loso_ok:
 cmp r12,[rsp+72]
 jae .Losw_ok
 cmp rbx,[rsp+80]
 jb .Lobad
.Losw_ok:
 cmp r14,[rsp+72]
 jae .Loow_ok
 cmp rbx,[rsp+64]
 jb .Lobad
.Loow_ok:
 mov rax,0x3230424c43414948
 cmp [r12],rax
 jne .Lobad
 cmp QWORD PTR [r12+8],1
 ja .Lobad
 xor eax,eax
 mov edx,1
 lock cmpxchg [rbx+16368],rdx
 jne .Lobusy
 mov QWORD PTR [rsp+96],1
 cmp QWORD PTR [r12+8],1
 je .Loretire
 cmp r15,1049088
 jb .Lobad
 cmp QWORD PTR [rbx+48],0
 jne .Lobad
 mov eax,39
 syscall
 test rax,rax
 jle .Lobad
 mov [rsp+88],rax
 mov rdi,rbx
 mov ecx,4096
 xor eax,eax
 cld
 rep stosb
 mov rax,[rsp+88]
 mov [rbx+40],rax
 lea rax,[rip+.Loentry]
 mov [rbx+208],rax
 jmp .Loviews
.Loretire:
 cmp r13,256
 jne .Lobad
 mov ecx,16
.Loreserved:
 cmp QWORD PTR [r12+rcx],0
 jne .Lobad
 add ecx,8
 cmp ecx,256
 jb .Loreserved
 mov rax,0x3130574c43414948
 cmp [rbx+48],rax
 jne .Lobad
 cmp [rbx+32],rbx
 jne .Lobad
 cmp [rbx+56],rbp
 jne .Lobad
 lea rax,[rip+.Loentry]
 cmp [rbx+208],rax
 jne .Lobad
 mov eax,39
 syscall
 cmp rax,[rbx+40]
 jne .Lobad
 mov QWORD PTR [rbx],900
 mov QWORD PTR [rbx+680],1
 mov QWORD PTR [rbx+824],0
 mov QWORD PTR [rbx+832],0
.Loviews:
 mov [rbx+56],rbp
 mov [rbx+64],rbx
 mov [rbx+72],r12
 mov [rbx+80],r13
 mov [rbx+88],r14
 mov [rbx+96],r15
 .byte 0x48,0x8d,0x05
.global clang_origin_catalog_hole
clang_origin_catalog_hole: .long 0
 mov [rbx+192],rax
 .byte 0x48,0xb8
.global clang_origin_catalog_length_hole
clang_origin_catalog_length_hole: .quad 0
 mov [rbx+200],rax
.Loowner:
 mov rdi,r12
 mov rsi,r13
 mov rdx,r14
 mov rcx,r15
 mov r8,rbx
 mov r9,rbp
 .byte 0xe8
.global clang_origin_owner_hole
clang_origin_owner_hole: .long 0
.Lodispatch:
 test eax,eax
 jz .Loreturn
 cmp eax,10
 je .Loowner
 cmp eax,1
 je .Losyscall
 cmp eax,2
 je .Lochild
 cmp eax,3
 je .Loorigin
 cmp eax,4
 je .Lopeek
 cmp eax,100
 je .Lopolicy_prepare
 cmp eax,101
 je .Lopolicy_tools
 cmp eax,102
 je .Lopolicy_execute
 cmp eax,103
 je .Lopolicy_publish
 cmp eax,104
 je .Lopolicy_transport
 cmp eax,105
 je .Lopolicy_diagnostics
 cmp eax,106
 je .Lopolicy_cleanup
 cmp eax,107
 je .Lopolicy_location
 jmp .Loreturn
.Lopolicy_prepare:
 mov rdi,r12
 mov rsi,r13
 mov rdx,r14
 mov rcx,r15
 mov r8,rbx
 mov r9,rbp
 .byte 0xe8
.global clang_origin_prepare_hole
clang_origin_prepare_hole: .long 0
 jmp .Lodispatch
.Lopolicy_tools:
 mov rdi,r12
 mov rsi,r13
 mov rdx,r14
 mov rcx,r15
 mov r8,rbx
 mov r9,rbp
 .byte 0xe8
.global clang_origin_tools_hole
clang_origin_tools_hole: .long 0
 jmp .Lodispatch
.Lopolicy_execute:
 mov rdi,r12
 mov rsi,r13
 mov rdx,r14
 mov rcx,r15
 mov r8,rbx
 mov r9,rbp
 .byte 0xe8
.global clang_origin_execute_hole
clang_origin_execute_hole: .long 0
 jmp .Lodispatch
.Lopolicy_publish:
 mov rdi,r12
 mov rsi,r13
 mov rdx,r14
 mov rcx,r15
 mov r8,rbx
 mov r9,rbp
 .byte 0xe8
.global clang_origin_publish_hole
clang_origin_publish_hole: .long 0
 jmp .Lodispatch
.Lopolicy_transport:
 mov rdi,r12
 mov rsi,r13
 mov rdx,r14
 mov rcx,r15
 mov r8,rbx
 mov r9,rbp
 .byte 0xe8
.global clang_origin_transport_hole
clang_origin_transport_hole: .long 0
 jmp .Lodispatch
.Lopolicy_diagnostics:
 mov rdi,r12
 mov rsi,r13
 mov rdx,r14
 mov rcx,r15
 mov r8,rbx
 mov r9,rbp
 .byte 0xe8
.global clang_origin_diagnostics_hole
clang_origin_diagnostics_hole: .long 0
 jmp .Lodispatch
.Lopolicy_cleanup:
 mov rdi,r12
 mov rsi,r13
 mov rdx,r14
 mov rcx,r15
 mov r8,rbx
 mov r9,rbp
 .byte 0xe8
.global clang_origin_cleanup_hole
clang_origin_cleanup_hole: .long 0
 jmp .Lodispatch
.Lopolicy_location:
 mov rdi,r12
 mov rsi,r13
 mov rdx,r14
 mov rcx,r15
 mov r8,rbx
 mov r9,rbp
 .byte 0xe8
.global clang_origin_location_hole
clang_origin_location_hole: .long 0
 jmp .Lodispatch
.Lochild:
 mov eax,[rbx+128]
 test eax,eax
 jz .Locopy
 mov rdi,[rbx+136]
 mov rsi,[rbx+144]
 mov rdx,[rbx+152]
 mov rcx,[rbx+160]
 mov r8,[rbx+168]
 mov r9,[rbx+176]
 cmp eax,1
 je .Lorole_hash
 cmp eax,2
 je .Lorole_admission
 cmp eax,3
 je .Lorole_canonical
 cmp eax,4
 je .Lorole_llvm
 cmp eax,5
 je .Lorole_llvm_meta
 cmp eax,6
 je .Lorole_which
 cmp eax,7
 je .Lorole_path
 cmp eax,8
 je .Lorole_file
 cmp eax,9
 je .Lorole_capture
 cmp eax,10
 je .Lorole_object
 cmp eax,11
 je .Lorole_shared
 cmp eax,12
 je .Lorole_identity
 cmp eax,13
 je .Lorole_rmtree
 cmp eax,14
 je .Lorole_receipt
 cmp eax,15
 je .Lorole_buffers
 jmp .Lobad
.Lorole_hash:
 .byte 0xe8
.global clang_origin_hash_hole
clang_origin_hash_hole: .long 0
 jmp .Lochild_return
.Lorole_admission:
 .byte 0xe8
.global clang_origin_admission_hole
clang_origin_admission_hole: .long 0
 jmp .Lochild_return
.Lorole_canonical:
 .byte 0xe8
.global clang_origin_canonical_hole
clang_origin_canonical_hole: .long 0
 jmp .Lochild_return
.Lorole_llvm:
 .byte 0xe8
.global clang_origin_llvm_hole
clang_origin_llvm_hole: .long 0
 jmp .Lochild_return
.Lorole_llvm_meta:
 .byte 0xe8
.global clang_origin_llvm_meta_hole
clang_origin_llvm_meta_hole: .long 0
 jmp .Lochild_return
.Lorole_which:
 .byte 0xe8
.global clang_origin_which_hole
clang_origin_which_hole: .long 0
 jmp .Lochild_return
.Lorole_path:
 .byte 0xe8
.global clang_origin_path_hole
clang_origin_path_hole: .long 0
 jmp .Lochild_return
.Lorole_file:
 .byte 0xe8
.global clang_origin_file_hole
clang_origin_file_hole: .long 0
 jmp .Lochild_return
.Lorole_capture:
 .byte 0xe8
.global clang_origin_capture_hole
clang_origin_capture_hole: .long 0
 jmp .Lochild_return
.Lorole_object:
 .byte 0xe8
.global clang_origin_object_hole
clang_origin_object_hole: .long 0
 jmp .Lochild_return
.Lorole_shared:
 .byte 0xe8
.global clang_origin_shared_hole
clang_origin_shared_hole: .long 0
 jmp .Lochild_return
.Lorole_identity:
 .byte 0xe8
.global clang_origin_identity_hole
clang_origin_identity_hole: .long 0
 jmp .Lochild_return
.Lorole_rmtree:
 .byte 0xe8
.global clang_origin_rmtree_hole
clang_origin_rmtree_hole: .long 0
 jmp .Lochild_return
.Lorole_receipt:
 .byte 0xe8
.global clang_origin_receipt_hole
clang_origin_receipt_hole: .long 0
 jmp .Lochild_return
.Lorole_buffers:
 .byte 0xe8
.global clang_origin_buffers_hole
clang_origin_buffers_hole: .long 0
 jmp .Lochild_return
.Lochild_return:
 mov eax,eax
 mov [rbx+8],rax
 jmp .Loowner
.Locopy:
 mov rcx,[rbx+144]
 cmp rcx,[rbx+160]
 ja .Lobad
 test rcx,rcx
 jz .Locopied
 mov rsi,[rbx+136]
 mov rdi,[rbx+152]
 test rsi,rsi
 jz .Lobad
 test rdi,rdi
 jz .Lobad
 mov rax,rsi
 add rax,rcx
 jc .Lobad
 mov rax,rdi
 add rax,rcx
 jc .Lobad
 cld
 rep movsb
.Locopied:
 mov QWORD PTR [rbx+8],0
 jmp .Loowner
.Loorigin:
 mov QWORD PTR [rbx+8],0
 jmp .Loowner
.Lopeek:
 mov rax,[rbx+2080]
 test rax,rax
 jz .Lobad
 movzx eax,BYTE PTR [rax]
 mov [rbx+8],rax
 jmp .Loowner
.Losyscall:
 xor ecx,ecx
 mov r10,[r14+56]
.Loargument:
 mov rax,[r14+8+rcx*8]
 mov rdx,r10
 and edx,3
 shr r10,2
 test edx,edx
 jz .Loargument_ready
 cmp edx,1
 jne .Loargument_output
 cmp rax,r13
 jae .Lobad
 add rax,r12
 jmp .Loargument_ready
.Loargument_output:
 cmp edx,2
 jne .Loargument_work
 cmp rax,r15
 jae .Lobad
 add rax,r14
 jmp .Loargument_ready
.Loargument_work:
 cmp rax,rbp
 jae .Lobad
 add rax,rbx
.Loargument_ready:
 mov [rsp+rcx*8],rax
 inc ecx
 cmp ecx,6
 jb .Loargument
 test r10,r10
 jnz .Lobad
 mov rax,[r14]
 mov rdi,[rsp]
 mov rsi,[rsp+8]
 mov rdx,[rsp+16]
 mov r10,[rsp+24]
 mov r8,[rsp+32]
 mov r9,[rsp+40]
 syscall
 mov [rbx+8],rax
 jmp .Loowner
.Lobusy:
 mov eax,0xfffffffc
 jmp .Loreturn
.Lobad:
 mov eax,0xfffffffd
.Loreturn:
 cmp QWORD PTR [rsp+96],0
 je .Lounlocked
 mov QWORD PTR [rbx+16368],0
.Lounlocked:
 add rsp,104
 pop r15
 pop r14
 pop r13
 pop r12
 pop rbx
 pop rbp
 ret
hia_clang_origin_bridge_end:
.size hia_clang_origin,.-hia_clang_origin
.section .note.GNU-stack,"",@progbits
