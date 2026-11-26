/* Fixed native LLVM phases. This file contains only ABI/view checks and direct
 * call routing. Source interpretation and rendering live in HIA roles. */
.text
.global hia_program_llvm
.type hia_program_llvm,@function
hia_program_llvm:
 push %rbx
 push %rbp
 push %r12
 push %r13
 push %r14
 push %r15
 sub $40,%rsp
 mov %rdi,%r12
 mov %rsi,%r13
 mov %rdx,%r14
 mov %rcx,%r15
 mov %r8,%rbx
 mov %r9,%rbp
 test %r12,%r12
 jz .Linvalid
 test %r14,%r14
 jz .Linvalid
 test %rbx,%rbx
 jz .Linvalid
 cmp $64,%r13
 jb .Linvalid
 cmp $134217728,%rbp
 jb .Linvalid
 mov %r12,%rax
 add %r13,%rax
 jc .Linvalid
 mov %rax,0(%rsp)
 mov %r14,%rax
 add %r15,%rax
 jc .Linvalid
 mov %rax,8(%rsp)
 mov %rbx,%rax
 add %rbp,%rax
 jc .Linvalid
 mov %rax,16(%rsp)
 cmp 8(%rsp),%r12
 jae .Linput_output_ok
 cmp 0(%rsp),%r14
 jb .Linvalid
.Linput_output_ok:
 cmp 16(%rsp),%r12
 jae .Linput_work_ok
 cmp 0(%rsp),%rbx
 jb .Linvalid
.Linput_work_ok:
 cmp 16(%rsp),%r14
 jae .Loutput_work_ok
 cmp 8(%rsp),%rbx
 jb .Linvalid
.Loutput_work_ok:
 movq $0,25165824(%rbx)
.Lowner:
 mov %r12,%rdi
 mov %r13,%rsi
 mov %r14,%rdx
 mov %r15,%rcx
 mov %rbx,%r8
 mov %rbp,%r9
 .byte 0xe8
.global hia_llvm_owner_hole
hia_llvm_owner_hole: .long 0
 test %eax,%eax
 jz .Lsuccess
 cmp $2,%eax
 je .Lowner
 cmp $11,%eax
 je .Ldecode
 cmp $20,%eax
 je .Lscalar
 cmp $21,%eax
 je .Lmemory
 cmp $22,%eax
 je .Lbulk
 cmp $23,%eax
 je .Lflow
 cmp $24,%eax
 je .Lanalysis
 cmp $27,%eax
 je .Loutline
 cmp $26,%eax
 je .Lvector
 cmp $25,%eax
 je .Lmodule
 jmp .Lreturn
.Ldecode:
 lea 64(%r12),%rdi
 lea -64(%r13),%rsi
 mov %rbx,%rdx
 mov $25165824,%ecx
 lea 109051904(%rbx),%r8
 mov $25165824,%r9d
 .byte 0xe8
.global hia_llvm_decode_hole
hia_llvm_decode_hole: .long 0
 mov %eax,%eax
 mov %rax,25166032(%rbx)
 jmp .Lowner
.Lscalar:
 lea .Lscalar_call(%rip),%r11
 jmp .Lrestore
.Lmemory:
 lea .Lmemory_call(%rip),%r11
 jmp .Lrestore
.Lbulk:
 lea .Lbulk_call(%rip),%r11
 jmp .Lrestore
.Lflow:
 lea .Lflow_call(%rip),%r11
 jmp .Lrestore
.Lanalysis:
 lea .Lanalysis_call(%rip),%r11
 jmp .Lrestore
.Lvector:
 lea .Lvector_call(%rip),%r11
 jmp .Lrestore
.Loutline:
 lea .Loutline_call(%rip),%r11
 jmp .Lrestore
.Lmodule:
 lea .Lmodule_call(%rip),%r11
.Lrestore:
 mov %r12,%rdi
 mov %r13,%rsi
 mov %r14,%rdx
 mov %r15,%rcx
 mov %rbx,%r8
 mov %rbp,%r9
 jmp *%r11
.Lscalar_call:
 .byte 0xe8
.global hia_llvm_scalar_hole
hia_llvm_scalar_hole: .long 0
 jmp .Lsubresult
.Lmemory_call:
 .byte 0xe8
.global hia_llvm_memory_hole
hia_llvm_memory_hole: .long 0
 jmp .Lsubresult
.Lbulk_call:
 .byte 0xe8
.global hia_llvm_bulk_hole
hia_llvm_bulk_hole: .long 0
 jmp .Lsubresult
.Lflow_call:
 .byte 0xe8
.global hia_llvm_flow_hole
hia_llvm_flow_hole: .long 0
 jmp .Lsubresult
.Lanalysis_call:
 .byte 0xe8
.global hia_llvm_analysis_hole
hia_llvm_analysis_hole: .long 0
 jmp .Lsubresult
.Lvector_call:
 .byte 0xe8
.global hia_llvm_vector_hole
hia_llvm_vector_hole: .long 0
 jmp .Lsubresult
.Loutline_call:
 .byte 0xe8
.global hia_llvm_outline_hole
hia_llvm_outline_hole: .long 0
 jmp .Lsubresult
.Lmodule_call:
 .byte 0xe8
.global hia_llvm_module_hole
hia_llvm_module_hole: .long 0
.Lsubresult:
 cmp $2,%eax
 je .Lowner
 jmp .Lreturn
.Lsuccess:
 mov 25165976(%rbx),%eax
 jmp .Lreturn
.Linvalid:
 mov $-3,%eax
.Lreturn:
 add $40,%rsp
 pop %r15
 pop %r14
 pop %r13
 pop %r12
 pop %rbp
 pop %rbx
 ret
.global hia_llvm_bridge_end
hia_llvm_bridge_end:
.size hia_program_llvm,.-hia_program_llvm
.section .note.GNU-stack,"",@progbits
