/* Experimental CPython transaction primitive, SysV x86-64, GIL held.
 * Frame: fn,args[6],reserved,pending,SetRaised,GetRaised,result,error,marker.
 * No object policy, loop, cardinality, or cleanup plan is implemented here.
 * The host supplies only an admitted fixed primitive address selected by HIA.
 */
.text
.global hia_unpack_transaction
.type hia_unpack_transaction,@function
hia_unpack_transaction:
    push %rbx
    mov %rdi,%rbx
    movq $1,104(%rbx)
    mov 64(%rbx),%rdi
    call *72(%rbx)
    movq $2,104(%rbx)
    mov 8(%rbx),%rdi
    mov 16(%rbx),%rsi
    mov 24(%rbx),%rdx
    mov 32(%rbx),%rcx
    mov 40(%rbx),%r8
    mov 48(%rbx),%r9
    xor %eax,%eax
    call *(%rbx)
    mov %rax,88(%rbx)
    movq $3,104(%rbx)
    call *80(%rbx)
    mov %rax,96(%rbx)
    movq $4,104(%rbx)
    xor %eax,%eax
    pop %rbx
    ret
.size hia_unpack_transaction,.-hia_unpack_transaction
.global hia_unpack_load_word
.type hia_unpack_load_word,@function
hia_unpack_load_word:
    mov (%rdi),%rax
    ret
.size hia_unpack_load_word,.-hia_unpack_load_word
.section .note.GNU-stack,"",@progbits
