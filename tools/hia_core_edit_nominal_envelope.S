/* Linux custody bridge for HIA's already-admitted two-object edit envelope.
   HIA finds the base boundary and elaborates the base. The suffix is opaque. */
.intel_syntax noprefix
.text
.global nominal_edit_envelope
.type nominal_edit_envelope,@function
.equ RAW_LIMIT,8388608
.equ ENVELOPE_LIMIT,16777219
.equ ENVELOPE_MAP,16781312

/* Input: edit mapping/extent, canonical base/extent, output digest.
   The mapping has a page-rounded envelope followed by the 8-MiB base.
   Return the replacement extent, or zero and the refusal status. */
nominal_edit_envelope:
 push rbp
 push rbx
 push r12
 push r13
 push r14
 push r15
 sub rsp,40
 mov r12,rdi
 mov r13,rsi
 mov r14,rdx
 mov r15,rcx
 mov [rsp],r8
 mov [rsp+24],rdi
 xor edx,edx
 xor ecx,ecx
 xor r8d,r8d
 xor r9d,r9d
 call edit_base_span_start
 test eax,eax
 jz refused
 cmp rax,r13
 jae refused
 add r12,rax
 sub r13,rax
 mov rdi,r14
 mov rsi,r15
 call nominal_lower_for_core
 test rax,rax
 jz failed
 test rdx,rdx
 jz failed
 cmp rdx,RAW_LIMIT
 ja exhausted
 mov r14,rax
 mov r15,rdx
 lea rsi,[r13+r15+1]
 cmp rsi,ENVELOPE_LIMIT
 ja exhausted
 mov [rsp+8],rsi
 mov [rsp+16],rcx
 xor edi,edi
 mov edx,3
 mov r10d,34
 mov r8,-1
 xor r9d,r9d
 mov eax,9
 syscall
 cmp rax,-4095
 jae failed
 mov rbx,rax
 cld
 mov BYTE PTR [rbx],91
 lea rdi,[rbx+1]
 mov rsi,r14
 mov rcx,r15
 rep movsb
 mov rsi,r12
 mov rcx,r13
 rep movsb
 mov rdi,[rsp+24]
 mov esi,ENVELOPE_MAP+RAW_LIMIT
 mov edx,3
 mov eax,10
 syscall
 test rax,rax
 jnz failed
 mov rdi,[rsp+24]
 mov rsi,rbx
 mov rcx,[rsp+8]
 rep movsb
 mov rdi,[rsp+24]
 mov esi,ENVELOPE_MAP
 mov edx,1
 mov eax,10
 syscall
 test rax,rax
 jnz failed
 mov rdi,rbx
 mov rsi,[rsp+8]
 mov eax,11
 syscall
 test rax,rax
 jnz failed

 /* The constructor returns eight big-endian SHA-256 words, each widened
    into a native machine word. Store their 32 original digest bytes. */
 mov rdi,[rsp]
 mov rsi,[rsp+16]
 mov ecx,8
digest_word:
 lodsq
 bswap eax
 stosd
 dec ecx
 jnz digest_word
 mov rax,[rsp+8]
 jmp finish
refused:
 mov edx,2
 jmp failure
exhausted:
 mov edx,3
 jmp failure
failed:
 mov edx,4
failure:
 xor eax,eax
finish:
 add rsp,40
 pop r15
 pop r14
 pop r13
 pop r12
 pop rbx
 pop rbp
 ret
.size nominal_edit_envelope,.-nominal_edit_envelope
