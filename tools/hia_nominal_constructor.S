/* Ordinary Linux transport for the HIA constructor and its type session.
 * A phase/action frame owns all continuation selection and semantic status;
 * this adapter only moves bounded spans between four static HIA images.
 */
.intel_syntax noprefix
.text
.global _start
.type _start,@function

.equ RAW_LIMIT, 8<<20
.equ PACKET_CAPACITY, 32<<20
.equ JSON_LIMIT, (8<<20)+128
.equ TYPES_ARENA, 128<<20
.equ CONSTRUCTOR_ARENA, 192<<20
.equ TYPES_OUTPUT, 64<<20
.equ FRAME_CAPACITY, 64<<10

.equ INPUT_MAGIC, 0x3130585343414948
.equ HANDOFF_INPUT, 0x3130584243414948
.equ HANDOFF_REQUEST, 0x3130514943414948
.equ HANDOFF_REPLY, 0x3130504943414948
.equ COMPLETE_MAGIC, 0x3130465343414948
.equ DECODE_REQUEST, 0x3130514a4e414948
.equ DECODE_REPLY, 0x3130504a4e414948
.equ RENDER_REQUEST, 0x313051544a414948
.equ RENDER_REPLY, 0x313050544a414948
.equ PACK_REQUEST, 0x3130514343414948
.equ PACK_REPLY, 0x3130504343414948
.equ TYPE_REQUEST, 0x3130515443414948
.equ TYPE_CUSTODY, 0x3130595443414948
.equ TYPE_REPLY, 0x3130505443414948
.equ CONSTRUCTOR_FRAME, 0x3130525443414948
.equ STREAM_MAGIC, 0x31304b5443414948
.equ CODEC_ERROR, 0x3130454a4e414948
.equ FUNCTION_FRAME, 0x3130444146414948
.equ FUNCTION_REQUEST, 0x3130514146414948
.equ FUNCTION_PACKET, 0x3130504146414948
.equ FUNCTION_FINAL, 0x3130464146414948

/* All regions supplied to a component as disjoint slices stay disjoint. */
.macro region bytes, slot
 mov esi, \bytes
 call map_private
 mov [rip+\slot],rax
.endm

_start:
 cmp QWORD PTR [rsp+8],1
 jne malformed
 xor ebp,ebp
 lea rsi,[rip+sigpipe]
 mov edi,13
 xor edx,edx
 mov r10d,8
 mov eax,13
 syscall
 test rax,rax
 jne io_failure
 lea rsi,[rip+request]
 mov edx,64
 call read_exact
 mov rax,INPUT_MAGIC
 cmp QWORD PTR [rip+request],rax
 je normal_header
 mov rax,HANDOFF_INPUT
 cmp QWORD PTR [rip+request],rax
 jne malformed
 mov rax,[rip+request+32]
 test rax,rax
 je malformed
 cmp rax,3
 ja malformed
 mov [rip+handoff_role],rax
 jmp reserved_header
normal_header:
 cmp QWORD PTR [rip+request+32],0
 jne malformed
reserved_header:
 mov rax,[rip+request+40]
 or rax,[rip+request+48]
 or rax,[rip+request+56]
 jne malformed
 cmp QWORD PTR [rip+request+16],1
 ja malformed
 mov r15,[rip+request+24]
 cmp r15,RAW_LIMIT
 ja too_large
 mov esi,1
 test r15,r15
 cmovnz rsi,r15
 call map_private
 mov r12,rax
 test r15,r15
 je confirm_eof
 mov rsi,r12
 mov rdx,r15
 call read_exact
confirm_eof:
 xor edi,edi
 lea rsi,[rip+spare]
 mov edx,1
 xor eax,eax
 syscall
 cmp rax,-4
 je confirm_eof
 test rax,rax
 js io_failure
 jne malformed

 region PACKET_CAPACITY, json
 region PACKET_CAPACITY, codec_work
 mov r8,[rip+codec_work]
 mov rax,DECODE_REQUEST
 mov [r8],rax
 mov rax,[rip+request+8]
 mov [r8+8],rax
 mov QWORD PTR [r8+16],1
 mov rax,[rip+request+16]
 mov [r8+24],rax
 mov rdi,r12
 mov rsi,r15
 mov rdx,[rip+json]
 mov ecx,PACKET_CAPACITY
 mov r9d,PACKET_CAPACITY
 call codec
 cmp eax,0xfffffff9
 jae codec_refusal
 cmp eax,41
 jb io_failure
 cmp eax,PACKET_CAPACITY
 ja io_failure
 mov r13d,eax
 mov r8,[rip+codec_work]
 mov rax,DECODE_REPLY
 cmp [r8],rax
 jne io_failure
 cmp [r8+8],r13
 jne io_failure
 cmp [r8+40],r15
 jne io_failure

 region CONSTRUCTOR_ARENA, constructor_work
 region TYPES_ARENA, type_work
 region TYPES_OUTPUT, type_output
 region FRAME_CAPACITY, frame
 mov rdi,[rip+json]
 mov rsi,r13
 call owner_frame
dispatch:
 cmp eax,64
 jne io_failure
 mov r12,[rip+frame]
 cmp QWORD PTR [rip+function_mode],0
 jne dispatch_function
 mov rax,CONSTRUCTOR_FRAME
 cmp [r12],rax
 jne io_failure
 cmp QWORD PTR [r12+24],2000
 je finished
 cmp QWORD PTR [r12+16],0
 jne io_failure
 cmp QWORD PTR [r12+8],0
 je resume
 cmp QWORD PTR [r12+8],2
 jne io_failure
 mov r13,[r12+48]
 mov r14,[r12+56]
 mov rax,[rip+last_request]
 inc rax
 cmp r13,rax
 jne io_failure
 cmp r14,1
 jb io_failure
 cmp r14,5
 ja io_failure
 jmp pack_request

dispatch_function:
 mov rax,FUNCTION_FRAME
 cmp [r12],rax
 jne io_failure
 cmp QWORD PTR [r12+8],10
 je finish_function
 cmp QWORD PTR [r12+8],1
 je finish_function
 cmp QWORD PTR [r12+16],0
 jne io_failure
 cmp QWORD PTR [r12+8],0
 je resume_function
 cmp QWORD PTR [r12+8],2
 jne io_failure
 mov r13,[r12+48]
 mov rax,[rip+last_request]
 inc rax
 cmp r13,rax
 jne io_failure
 mov r14d,2

pack_request:
 mov [rip+last_request],r13
 cmp QWORD PTR [rip+function_mode],0
 jne pack_function_request
 lea rdi,[rip+pack_command]
 mov rax,PACK_REQUEST
 mov [rdi],rax
 mov [rdi+8],r13
 mov [rdi+16],r14
 mov esi,24
 mov rdx,[rip+type_output]
 mov ecx,PACKET_CAPACITY+64
 mov r8,[rip+constructor_work]
 mov r9d,CONSTRUCTOR_ARENA
 call owner
 mov r10,PACK_REPLY
 jmp validate_pack

pack_function_request:
 lea rdi,[rip+pack_command]
 mov rax,FUNCTION_REQUEST
 mov [rdi],rax
 mov [rdi+8],r13
 mov esi,16
 mov rdx,[rip+type_output]
 mov ecx,PACKET_CAPACITY+64
 mov r8,[rip+function_work]
 mov r9d,CONSTRUCTOR_ARENA
 call function_admit_start
 mov r10,FUNCTION_PACKET

validate_pack:
 cmp eax,88
 jb io_failure
 cmp eax,PACKET_CAPACITY+64
 ja io_failure
 mov r15d,eax
 sub r15,64
 mov rdi,[rip+type_output]
 cmp [rdi],r10
 jne io_failure
 cmp [rdi+8],r13
 jne io_failure
 cmp [rdi+16],r14
 jne io_failure
 cmp [rdi+24],r15
 jne io_failure

 mov rdi,[rip+codec_work]
 call clear_header
 mov rax,RENDER_REQUEST
 mov [rdi],rax
 mov r8,rdi
 mov rdi,[rip+type_output]
 add rdi,64
 mov rsi,r15
 mov rdx,[rip+json]
 mov ecx,PACKET_CAPACITY
 mov r9d,PACKET_CAPACITY
 call codec
 cmp eax,0xfffffff9
 jae codec_refusal
 test eax,eax
 je io_failure
 cmp eax,JSON_LIMIT
 ja io_failure
 mov r12d,eax
 mov r8,[rip+codec_work]
 mov rax,RENDER_REPLY
 cmp [r8],rax
 jne io_failure
 cmp [r8+8],r12
 jne io_failure
 cmp [r8+16],r15
 jne io_failure

 mov rdi,[rip+type_work]
 add rdi,TYPES_ARENA-64
 call clear_header
 mov rax,TYPE_REQUEST
 mov [rdi],rax
 mov [rdi+8],r13
 mov [rdi+16],r14
 mov rdi,[rip+json]
 mov rsi,r12
 mov rdx,[rip+type_output]
 mov ecx,TYPES_OUTPUT
 mov r8,[rip+type_work]
 mov r9d,TYPES_ARENA
 call types_image_start
 cmp eax,64
 jb io_failure
 cmp eax,TYPES_OUTPUT
 ja io_failure
 mov r15d,eax
 mov r8,[rip+type_work]
 add r8,TYPES_ARENA-64
 mov rax,TYPE_CUSTODY
 cmp [r8],rax
 jne io_failure
 cmp [r8+8],r13
 jne io_failure
 cmp [r8+16],r14
 jne io_failure
 cmp [r8+32],r15
 jne io_failure
 mov rax,[r8+24]
 cmp rax,50
 ja io_failure
 mov [rip+delegate_status],rax
 mov rdi,[rip+type_output]
 mov rax,TYPE_REPLY
 cmp [rdi],rax
 jne io_failure
 cmp [rdi+8],r13
 jne io_failure
 cmp [rdi+16],r14
 jne io_failure
 mov rsi,r15
 call owner_frame
 jmp dispatch

resume:
 mov rax,[rip+last_request]
 cmp [r12+48],rax
 jne io_failure
 cmp QWORD PTR [r12+56],0
 jne io_failure
 jmp resume_stage

resume_function:
 mov rax,[rip+last_request]
 cmp [r12+48],rax
 jne io_failure
resume_stage:
 mov rdi,[rip+type_work]
 mov esi,TYPES_ARENA
 call owner_frame
 jmp dispatch

finished:
 cmp QWORD PTR [r12+8],2
 jne io_failure
 cmp QWORD PTR [r12+56],0
 jne io_failure
 mov rax,[rip+last_request]
 cmp [r12+48],rax
 jne io_failure
 mov r15,[r12+16]
 mov rax,[rip+delegate_status]
 cmp r15,999
 je delegated
 test rax,rax
 jne io_failure
 cmp r15,14
 ja io_failure
 test r15,r15
 jne complete
 cmp QWORD PTR [rip+handoff_role],0
 jne handoff
 jmp complete
delegated:
 test rax,rax
 je io_failure
complete:
 lea rsi,[rip+complete_header]
 mov [rsi+8],r15
 mov [rsi+16],rax
 mov rax,[r12+32]
 mov [rsi+24],rax
 mov rax,[r12+40]
 mov [rsi+32],rax
 mov rax,[r12+48]
 mov [rsi+40],rax
 mov rax,[rip+request+24]
 mov [rsi+48],rax
 mov rax,COMPLETE_MAGIC
 mov [rsi],rax
 mov QWORD PTR [rsi+56],1
 mov edi,1
 mov edx,64
 call write_exact
 xor r13d,r13d
stream_result:
 lea rdi,[rip+spare]
 xor esi,esi
 mov rdx,[rip+frame]
 mov ecx,FRAME_CAPACITY
 mov r8,[rip+constructor_work]
 mov r9d,CONSTRUCTOR_ARENA
 call renderer
 cmp eax,64
 jb io_failure
 cmp eax,FRAME_CAPACITY
 ja io_failure
 mov edx,eax
 mov rsi,[rip+frame]
 mov rax,STREAM_MAGIC
 cmp [rsi],rax
 jne io_failure
 mov rax,[rsi+8]
 or rax,[rsi+32]
 or rax,[rsi+40]
 jne io_failure
 cmp [rsi+16],r13
 jne io_failure
 mov r14,[rsi+24]
 cmp r14,1
 ja io_failure
 mov rax,[rip+last_request]
 cmp [rsi+48],rax
 jne io_failure
 lea rax,[rdx-64]
 cmp [rsi+56],rax
 jne io_failure
 mov edi,1
 call write_exact
 inc r13
 test r14,r14
 je stream_result
 xor edi,edi
 test r15,r15
 je exit
 mov edi,65
 jmp exit

handoff:
 lea rdi,[rip+pack_command]
 mov rax,HANDOFF_REQUEST
 mov [rdi],rax
 mov r13,[rip+handoff_role]
 cmp r13,3
 jne handoff_command
 mov r13d,1
handoff_command:
 mov [rdi+8],r13
 mov esi,16
 mov rdx,[rip+type_output]
 mov ecx,PACKET_CAPACITY+64
 mov r8,[rip+constructor_work]
 mov r9d,CONSTRUCTOR_ARENA
 call owner
 cmp eax,88
 jb io_failure
 cmp eax,PACKET_CAPACITY+64
 ja io_failure
 mov edx,eax
 mov rsi,[rip+type_output]
 mov rax,HANDOFF_REPLY
 cmp [rsi],rax
 jne io_failure
 cmp [rsi+8],r13
 jne io_failure
 lea rax,[rdx-64]
 cmp [rsi+16],rax
 jne io_failure
 mov rax,[rip+last_request]
 cmp [rsi+32],rax
 jne io_failure
 cmp QWORD PTR [rip+handoff_role],3
 je initialize_function
 mov edi,1
 call write_exact
 xor edi,edi
 jmp exit

initialize_function:
 /* The seed is disjoint in type_output. Only the retained resolver remains. */
 mov rdi,[rip+constructor_work]
 mov esi,CONSTRUCTOR_ARENA
 mov edx,4
 mov eax,28
 syscall
 test rax,rax
 jne io_failure
 mov rax,[rip+constructor_work]
 mov [rip+function_work],rax
 mov QWORD PTR [rip+function_mode],1
 mov QWORD PTR [rip+last_request],0
 mov QWORD PTR [rip+delegate_status],0
 mov rdi,[rip+type_output]
 mov rsi,[rdi+16]
 add rdi,64
 call owner_frame
 jmp dispatch

finish_function:
 mov rax,[rip+last_request]
 cmp [r12+48],rax
 jne io_failure
 mov r15,[r12+16]
 mov rax,[rip+delegate_status]
 cmp r15,999
 je function_delegate
 test rax,rax
 jne io_failure
 jmp function_complete
function_delegate:
 test rax,rax
 je io_failure
function_complete:
 mov rsi,r12
 mov [rsi+56],rax
 mov rax,FUNCTION_FINAL
 mov [rsi],rax
 mov edi,1
 mov edx,64
 call write_exact
 xor edi,edi
 test r15,r15
 je exit
 mov edi,65
 jmp exit

owner_frame:
 sub rsp,8
 mov rdx,[rip+frame]
 mov ecx,FRAME_CAPACITY
 mov r9d,CONSTRUCTOR_ARENA
 cmp QWORD PTR [rip+function_mode],0
 jne function_frame
 mov r8,[rip+constructor_work]
 call owner
 add rsp,8
 ret
function_frame:
 mov r8,[rip+function_work]
 call function_admit_start
 add rsp,8
 ret

clear_header:
 xor eax,eax
 mov ecx,8
 rep stosq
 sub rdi,64
 ret

map_private:
 xor edi,edi
 mov edx,3
 mov r10d,34
 mov r8,-1
 xor r9d,r9d
 mov eax,9
 syscall
 cmp rax,-4095
 jae io_failure
 ret

read_exact:
 xor edi,edi
 xor eax,eax
 syscall
 cmp rax,-4
 je read_exact
 test rax,rax
 js io_failure
 jz malformed
 add rsi,rax
 sub rdx,rax
 jne read_exact
 ret

write_exact:
 mov eax,1
 syscall
 cmp rax,-4
 je write_exact
 test rax,rax
 jle io_failure
 add rsi,rax
 sub rdx,rax
 jne write_exact
 ret

too_large:
 mov eax,0xfffffffb
codec_refusal:
 mov eax,eax
 lea rsi,[rip+codec_error]
 mov [rsi+8],rax
 mov rax,CODEC_ERROR
 mov [rsi],rax
 mov edi,1
 mov edx,16
 call write_exact
 mov edi,65
 jmp exit
malformed:
 mov edi,64
 jmp exit
io_failure:
 mov edi,74
exit:
 mov eax,60
 syscall
 ud2
.size _start,.-_start

.balign 8
sigpipe: .quad 1,0,0,0
.balign 16
owner: .incbin "owner.image.bin"
.balign 16
renderer: .incbin "render.image.bin"
.balign 16
codec: .incbin "nominal-json.image.bin"
.bss
.balign 8
request: .skip 64
complete_header: .skip 64
codec_error: .skip 16
pack_command: .skip 24
frame: .skip 8
json: .skip 8
codec_work: .skip 8
constructor_work: .skip 8
type_work: .skip 8
type_output: .skip 8
last_request: .skip 8
delegate_status: .skip 8
handoff_role: .skip 8
function_mode: .skip 8
function_work: .skip 8
spare: .skip 1
.section .note.GNU-stack,"",@progbits
