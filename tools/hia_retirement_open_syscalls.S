/* Linux x86-64 SysV foreign transport only; no retirement policy.
 * Args: pathname pointer, flags, retained two-word result slot.
 * Slot: stage (0 not entered, 1 started, 2 returned), signed kernel result.
 * Recording the result before returning to Python closes CALL/STORE and line
 * interruption windows. There is no retry, close, creation or policy fallback.
 */
.intel_syntax noprefix
.text
.global hia_retirement_open
.type hia_retirement_open,@function
hia_retirement_open:
 mov r8,rdx
 mov QWORD PTR [r8],1
 mov rdx,rsi
 mov rsi,rdi
 mov rdi,-100
 xor r10d,r10d
 mov eax,257
 syscall
 mov QWORD PTR [r8+8],rax
 mov QWORD PTR [r8],2
 ret
.size hia_retirement_open,.-hia_retirement_open
.section .note.GNU-stack,"",@progbits
