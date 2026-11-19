.intel_syntax noprefix
.text
.global edit_response_syntax
.type edit_response_syntax,@function
.equ RESPONSE_CHECK_OUTPUT, 128<<10
.equ RESPONSE_CHECK_WORK, 12288
.equ EDIT_SYNTAX, 0x313053514f414948

/* rdi/rsi: the original, read-only response bytes and extent.
   rdx: caller-owned temporary output and syntax workspace.
   The HIA image returns zero or the exact refusal report extent. */
edit_response_syntax:
 mov ecx,RESPONSE_CHECK_OUTPUT
 lea r8,[rdx+RESPONSE_CHECK_OUTPUT]
 mov r9d,RESPONSE_CHECK_WORK
 movabs rax,EDIT_SYNTAX
 mov [r8+RESPONSE_CHECK_WORK-8],rax
 jmp public_presentation_start
.size edit_response_syntax,.-edit_response_syntax

.section .note.GNU-stack,"",@progbits
