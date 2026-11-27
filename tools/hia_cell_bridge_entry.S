/* Independent oracle for the original three-range borrowed-byte guards.
 * Production emits these bytes with HIA; no assembler is used by the builder.
 * Keep per-range extent/null/address ordering and empty-range semantics.
 */
.text
.globl cell_bridge_step
.type cell_bridge_step,@function
cell_bridge_step:
    cmpq $65792, %rsi
    ja .Lextent
    testq %rsi, %rsi
    je .Lsource_done
    testq %rdi, %rdi
    je .Lnull
    movq %rdi, %r10
    addq %rsi, %r10
    jc .Laddress
.Lsource_done:
    cmpq $65792, %rcx
    ja .Lextent
    testq %rcx, %rcx
    je .Loutput_done
    testq %rdx, %rdx
    je .Lnull
    movq %rdx, %r11
    addq %rcx, %r11
    jc .Laddress
.Loutput_done:
    cmpq $65792, %r9
    ja .Lextent
    testq %r9, %r9
    je .Lworkspace_done
    testq %r8, %r8
    je .Lnull
    movq %r8, %rax
    addq %r9, %rax
    jc .Laddress
.Lworkspace_done:
    testq %rsi, %rsi
    je .Lsource_output_done
    testq %rcx, %rcx
    je .Lsource_output_done
    cmpq %rdx, %r10
    jbe .Lsource_output_done
    cmpq %rdi, %r11
    jbe .Lsource_output_done
    jmp .Lalias
.Lsource_output_done:
    testq %rsi, %rsi
    je .Lsource_workspace_done
    testq %r9, %r9
    je .Lsource_workspace_done
    cmpq %r8, %r10
    jbe .Lsource_workspace_done
    cmpq %rdi, %rax
    jbe .Lsource_workspace_done
    jmp .Lalias
.Lsource_workspace_done:
    testq %rcx, %rcx
    je .Loutput_workspace_done
    testq %r9, %r9
    je .Loutput_workspace_done
    cmpq %r8, %r11
    jbe .Loutput_workspace_done
    cmpq %rdx, %rax
    jbe .Loutput_workspace_done
    jmp .Lalias
.Loutput_workspace_done:
    jmp cell_bridge_flat
.Lextent:
    movl $1, %eax
    shlq $32, %rax
    ret
.Lnull:
    movl $2, %eax
    shlq $32, %rax
    ret
.Laddress:
    movl $3, %eax
    shlq $32, %rax
    ret
.Lalias:
    movl $4, %eax
    shlq $32, %rax
    ret
cell_bridge_flat:
.size cell_bridge_step, .-cell_bridge_step
.section .note.GNU-stack,"",@progbits
