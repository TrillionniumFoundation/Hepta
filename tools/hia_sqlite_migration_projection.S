/* Sealed component-call and single-frame stdin/stdout transport. The HIA
 * controller owns every transition, page selection and output byte.
 */
.intel_syntax noprefix
.section .text,"ax",@progbits
.global _start
.type _start,@function
.equ INPUT_LIMIT,(256<<20)+56
.equ OUTPUT_LIMIT,64<<20
.equ WORKSPACE_FIXED,198<<20

.macro span pointer, extent, slot
 mov \pointer,[r14+\slot]
 mov \extent,[r14+\slot+8]
 mov rax,[rsp+8]
 cmp \pointer,rax
 ja malformed
 sub rax,\pointer
 cmp \extent,rax
 ja malformed
 add \pointer,r14
.endm

_start:
 /* The HIA ELF linker calls the selected symbol from its Linux stub. */
 cmp QWORD PTR [rsp+8],1
 jne malformed
 sub rsp,40
 /* Report a disconnected consumer as an I/O failure, not a signal exit. */
 mov QWORD PTR [rsp],1
 mov QWORD PTR [rsp+8],0
 mov QWORD PTR [rsp+16],0
 mov QWORD PTR [rsp+24],0
 mov edi,13
 mov rsi,rsp
 xor edx,edx
 mov r10d,8
 mov eax,13
 syscall
 test rax,rax
 js io_error
 mov edx,8
 mov rsi,rsp
 call read_exact
 mov r15,[rsp]
 cmp r15,568
 jb malformed
 cmp r15,INPUT_LIMIT
 ja malformed
 mov rsi,r15
 call allocate
 mov r12,rax
 mov rsi,r12
 mov rdx,r15
 call read_exact
check_eof:
 xor eax,eax
 xor edi,edi
 lea rsi,[rsp+16]
 mov edx,1
 syscall
 cmp rax,-4
 je check_eof
 test rax,rax
 js io_error
 jnz malformed
 mov rdi,r12
 mov rsi,r15
 mov edx,1
 mov eax,10
 syscall
 test rax,rax
 jnz io_error
 mov esi,OUTPUT_LIMIT
 call allocate
 mov r13,rax
 lea rsi,[r15+WORKSPACE_FIXED]
 mov [rsp+8],rsi
 call allocate
 mov r14,rax
next:
 mov rdi,r12
 mov rsi,r15
 mov rdx,r13
 mov ecx,OUTPUT_LIMIT
 mov r8,r14
 mov r9,[rsp+8]
 call projection
 test eax,eax
 jz publish
 cmp eax,64
 jae rejected
 mov ebx,eax
 span rdi,rsi,16
 span rdx,rcx,32
 span r8,r9,48
 cmp ebx,1
 je catalog_call
 cmp ebx,2
 je walk_call
 cmp ebx,3
 je lookup_call
 cmp ebx,4
 je layout_call
 cmp ebx,5
 je importer_call
 cmp ebx,6
 jne malformed
 call planner
 jmp resume
catalog_call:
 call catalog
 jmp resume
walk_call:
 call walker
 jmp resume
lookup_call:
 call lookup
 jmp resume
layout_call:
 call layout
 jmp resume
importer_call:
 call importer
resume:
 mov eax,eax
 mov [r14],rax
 jmp next
publish:
 mov rdx,[r14+24]
 cmp rdx,64
 jb malformed
 cmp rdx,OUTPUT_LIMIT
 ja malformed
 mov rsi,r13
write_loop:
 mov edi,1
 mov eax,1
 syscall
 cmp rax,-4
 je write_loop
 test rax,rax
 jle io_error
 add rsi,rax
 sub rdx,rax
 jnz write_loop
 xor edi,edi
 jmp exit
rejected:
 cmp eax,66
 ja malformed
 mov edi,eax
 jmp exit
read_exact:
 xor edi,edi
 xor eax,eax
 syscall
 cmp rax,-4
 je read_exact
 test rax,rax
 js io_error
 jz malformed
 add rsi,rax
 sub rdx,rax
 jnz read_exact
 ret
allocate:
 xor edi,edi
 mov edx,3
 mov r10d,34
 mov r8,-1
 xor r9d,r9d
 mov eax,9
 syscall
 cmp rax,-4095
 jae io_error
 ret
malformed:
 mov edi,64
 jmp exit
io_error:
 mov edi,74
exit:
 mov eax,60
 syscall
 ud2
.size _start,.-_start

.balign 16
projection: .incbin "sqlite-migration-projection.image.bin"
.balign 16
catalog: .incbin "sqlite-agent-catalog.image.bin"
.balign 16
walker: .incbin "sqlite-table-walk.image.bin"
.balign 16
lookup: .incbin "sqlite-rowid-lookup.image.bin"
.balign 16
layout: .incbin "sqlite-record-layout.image.bin"
.balign 16
importer: .incbin "sqlite-agent-row-import.image.bin"
.balign 16
planner: .incbin "sqlite-migration-plan.image.bin"
.section .note.GNU-stack,"",@progbits
