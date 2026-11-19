/* Fixed ABI transport; capture decoding and syntax policy are HIA images. */
.intel_syntax noprefix
.text
.equ BATCH_CHECK_OUTPUT, 8<<20
.equ BATCH_CHECK_WORK, 12288
.equ EDIT_SYNTAX, 0x313053514f414948

.global decode_batch_capture
.type decode_batch_capture,@function
decode_batch_capture:
 xor r8d,r8d
 xor r9d,r9d
 jmp edit_batch_capture_start
.size decode_batch_capture,.-decode_batch_capture

.global edit_batch_input_syntax
.type edit_batch_input_syntax,@function
edit_batch_input_syntax:
 /* The caller may reuse this region after the syntax decision. */
 mov r10,rdi
 mov rdi,rdx
 mov ecx,(BATCH_CHECK_OUTPUT+BATCH_CHECK_WORK)/8
 xor eax,eax
 cld
 rep stosq
 mov rdi,r10
 mov ecx,BATCH_CHECK_OUTPUT
 lea r8,[rdx+rcx]
 mov r9d,BATCH_CHECK_WORK
 movabs rax,EDIT_SYNTAX
 mov [r8+BATCH_CHECK_WORK-8],rax
 jmp public_presentation_start
.size edit_batch_input_syntax,.-edit_batch_input_syntax

.section .note.GNU-stack,"",@progbits
