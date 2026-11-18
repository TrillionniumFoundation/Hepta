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
.equ STAGE_LIMIT,128<<20
.equ STAGE_STATE,8192

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
 xor ebx,ebx
 cmp QWORD PTR [rsp+8],1
 je startup
 cmp QWORD PTR [rsp+8],2
 jne malformed
 mov rdi,[rsp+24]
 lea rsi,[rip+stage_option]
 mov ecx,8
stage_option_byte:
 lodsb
 scasb
 jne malformed
 dec ecx
 jnz stage_option_byte
 mov ebx,1
startup:
 sub rsp,40
 mov [rsp+32],rbx
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
 cmp QWORD PTR [rsp+32],0
 jne start_stage
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
start_stage:
 mov r15,rdx
 mov r12,r13
 mov rdi,r12
 mov rsi,r15
 mov edx,1
 mov eax,10
 syscall
 test rax,rax
 jnz io_error
 mov esi,STAGE_LIMIT
 call allocate
 mov r13,rax
 mov esi,STAGE_STATE
 call allocate
 mov r14,rax
stage_next:
 mov rdi,r12
 mov rsi,r15
 mov rdx,r13
 mov ecx,STAGE_LIMIT
 mov r8,r14
 mov r9d,STAGE_STATE
 call stager
 test eax,eax
 jz stage_done
 cmp eax,64
 jae rejected
 mov ebx,eax
 mov rdi,r12
 mov r11,r15
 cmp ebx,1
 je stage_spans
 mov rdi,r13
 mov r11d,STAGE_LIMIT
 cmp ebx,2
 je stage_spans
 cmp ebx,3
 jne malformed
 mov rdi,r14
 mov r11d,4096
stage_spans:
 mov rax,[r14+16]
 cmp rax,r11
 ja malformed
 sub r11,rax
 mov rsi,[r14+24]
 cmp rsi,r11
 ja malformed
 add rdi,rax
 mov rax,[r14+32]
 cmp rax,STAGE_LIMIT
 ja malformed
 mov ecx,STAGE_LIMIT
 sub rcx,rax
 cmp [r14+40],rcx
 ja malformed
 mov rcx,[r14+40]
 lea rdx,[r13+rax]
 lea r8,[r14+4096]
 xor r9d,r9d
 cmp ebx,1
 je stage_batch
 cmp ebx,2
 je stage_inventory
 mov r9d,4096
 call cost_sequence
 jmp stage_resume
stage_batch:
 call batch_importer
 jmp stage_resume
stage_inventory:
 call artifact_catalog
stage_resume:
 mov eax,eax
 mov [r14],rax
 jmp stage_next
stage_done:
 mov rdx,[r14+24]
 cmp rdx,56
 jb malformed
 cmp rdx,STAGE_LIMIT
 ja malformed
 mov rsi,r13
 jmp write_loop
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

stage_option: .asciz "--stage"
.balign 16
projection: .incbin "sqlite-migration-projection.image.bin"
.balign 16
stager: .incbin "sqlite-migration-stage.image.bin"
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
.balign 16
batch_importer: .incbin "sqlite-agent-import-batch.image.bin"
.balign 16
artifact_catalog: .incbin "sqlite-agent-artifact-catalog.image.bin"
.balign 16
cost_sequence: .incbin "sqlite-agent-cost-sequence.image.bin"
.section .note.GNU-stack,"",@progbits
