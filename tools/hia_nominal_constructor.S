/* Linux transport for HIA construction, type resolution and function lowering.
 * HIA's continuation frames select the next image; this adapter only moves
 * bounded spans and retains the successful helper stream until commit.
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
.equ BODY_FINAL, 0x31304c4246414948
.equ BODY_COMMAND, 0x3130514346414948
.equ BODY_PACKET, 0x3130505046414948
.equ BODY_RESULT, 0x3130515046414948
.equ HELPER_REQUEST, 0x3130514846414948
.equ HELPER_CONTROL, 0x3130434846414948
.equ HELPER_REPLY, 0x3130524846414948
.equ HELPER_WORKSPACE, 2<<20
.equ HELPER_OUTPUT, 4<<20
.equ FUNCTION_STATE_ACTION, 4096+64

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
 cmp rax,4
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
 mov rax,[r12+8]
 cmp rax,1
 je finish_function
 cmp QWORD PTR [rip+handoff_role],3
 jne dispatch_body
 cmp rax,10
 je finish_function
 jmp dispatch_function_request

dispatch_body:
 cmp rax,10
 je next_records
 cmp rax,21
 je next_records
 cmp rax,20
 je next_terms
 cmp rax,30
 je next_advanced
 cmp QWORD PTR [r12+24],2000
 je finish_body
 jmp dispatch_function_request
next_records:
 lea rax,[rip+function_records_start]
 jmp next_kernel
next_terms:
 lea rax,[rip+function_terms_start]
 jmp next_kernel
next_advanced:
 lea rax,[rip+function_advanced_start]
next_kernel:
 mov [rip+function_kernel],rax
 jmp resume_function

dispatch_function_request:
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
 mov rax,[rip+function_kernel]
 lea rcx,[rip+function_admit_start]
 cmp rax,rcx
 je pack_request
 mov rax,[rip+function_work]
 mov r14,[rax+FUNCTION_STATE_ACTION]
 cmp r14,2
 jb io_failure
 cmp r14,6
 ja io_failure
 cmp r14,6
 je pack_helper_request

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
 mov rax,[rip+function_kernel]
 lea rcx,[rip+function_admit_start]
 cmp rax,rcx
 jne pack_body_request
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
 jmp validate_pack

pack_body_request:
 lea rdi,[rip+pack_command]
 mov rax,BODY_COMMAND
 mov [rdi],rax
 mov [rdi+8],r13
 mov [rdi+16],r14
 mov esi,24
 call body_packet
 cmp QWORD PTR [rdi+8],r14
 jne io_failure
 cmp QWORD PTR [rdi+16],r13
 jne io_failure
 jmp encode_command

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

encode_command:
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
 cmp QWORD PTR [rip+function_mode],0
 je type_call
 cmp r14,4
 jne type_call
 mov QWORD PTR [rdi+24],1
type_call:
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

pack_helper_request:
 mov [rip+last_request],r13
 mov rdi,[rip+type_work]
 add rdi,TYPES_ARENA-64
 call clear_header
 mov rax,HELPER_REQUEST
 mov [rdi],rax
 mov [rdi+8],r13
 mov rdi,[rip+type_work]
 mov esi,TYPES_ARENA
 call body_packet
 cmp QWORD PTR [rdi+8],6
 jne io_failure
 cmp [rdi+16],r13
 jne io_failure
 cmp r15,128<<10
 ja io_failure
 mov rdi,[rip+helper_work]
 add rdi,HELPER_WORKSPACE-64
 call clear_header
 mov rax,HELPER_CONTROL
 mov [rdi],rax
 mov [rdi+8],r13
 mov rdi,[rip+type_output]
 add rdi,64
 mov rsi,r15
 mov rdx,[rip+helper_output]
 mov ecx,HELPER_OUTPUT
 mov r8,[rip+helper_work]
 mov r9d,HELPER_WORKSPACE
 call function_helper_start
 cmp eax,64
 jb io_failure
 cmp eax,HELPER_OUTPUT
 ja io_failure
 mov r15d,eax
 mov rsi,[rip+helper_output]
 mov rax,HELPER_REPLY
 cmp [rsi],rax
 jne io_failure
 cmp [rsi+40],r13
 jne io_failure
 lea rax,[r15-64]
 cmp [rsi+32],rax
 jne io_failure
 mov rax,[rsi+8]
 cmp rax,3
 ja io_failure
 /* Helper errors occupy a disjoint code range in BODY_FINAL. */
 test rax,rax
 je retain_helper
 add rax,64
 mov [rip+delegate_status],rax
 jmp deliver_helper
retain_helper:
 mov QWORD PTR [rip+delegate_status],0
 mov edi,[rip+helper_fd]
 mov rdx,r15
 call write_exact
deliver_helper:
 mov rdi,[rip+helper_output]
 mov rsi,r15
 call owner_frame
 jmp dispatch

/* The sender controls the extent and cursor; each caller checks correlation. */
body_packet:
 sub rsp,8
 mov rdx,[rip+type_output]
 mov ecx,TYPES_OUTPUT
 mov r8,[rip+function_work]
 mov r9d,CONSTRUCTOR_ARENA
 call function_render_start
 add rsp,8
 cmp eax,88
 jb io_failure
 cmp eax,TYPES_OUTPUT
 ja io_failure
 mov r15d,eax
 sub r15,64
 mov rdi,[rip+type_output]
 mov rax,BODY_PACKET
 cmp [rdi],rax
 jne io_failure
 cmp [rdi+24],r15
 jne io_failure
 ret

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
 jb handoff_command
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
 jae initialize_function
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
 lea rax,[rip+function_admit_start]
 mov [rip+function_kernel],rax
 cmp QWORD PTR [rip+handoff_role],4
 jne function_begin
 region HELPER_WORKSPACE, helper_work
 region HELPER_OUTPUT, helper_output
 lea rdi,[rip+helper_stream_name]
 mov esi,1
 mov eax,319
 syscall
 test eax,eax
 js io_failure
 mov [rip+helper_fd],eax
function_begin:
 mov QWORD PTR [rip+function_mode],1
 mov QWORD PTR [rip+last_request],0
 mov QWORD PTR [rip+delegate_status],0
 mov rdi,[rip+type_output]
 mov rsi,[rdi+16]
 add rdi,64
 call owner_frame
 jmp dispatch

finish_body:
 cmp QWORD PTR [r12+8],2
 jne io_failure
 cmp QWORD PTR [r12+16],0
 jne io_failure
 mov r13,[rip+last_request]
 cmp [r12+48],r13
 jne io_failure
 lea rdi,[rip+pack_command]
 mov rax,BODY_RESULT
 mov [rdi],rax
 mov [rdi+8],r13
 mov QWORD PTR [rdi+16],0
 mov esi,24
 call body_packet
 cmp QWORD PTR [rdi+8],0
 jne io_failure
 cmp [rdi+16],r13
 jne io_failure
 mov rax,[r12+32]
 cmp [rdi+32],rax
 jne io_failure
 mov rax,[r12+40]
 cmp [rdi+40],rax
 jne io_failure
 mov rax,BODY_FINAL
 mov [r12],rax
 mov rsi,r12
 mov edi,1
 mov edx,64
 call write_exact
 mov rsi,[rip+type_output]
 lea rdx,[r15+64]
 mov edi,1
 call write_exact
 mov edi,[rip+helper_fd]
 xor esi,esi
 xor edx,edx
 mov eax,8
 syscall
 test rax,rax
 jne io_failure
drain_helpers:
 mov edi,[rip+helper_fd]
 mov rsi,[rip+json]
 mov edx,FRAME_CAPACITY
 xor eax,eax
 syscall
 cmp rax,-4
 je drain_helpers
 test rax,rax
 js io_failure
 jz body_complete
 mov rdx,rax
 mov edi,1
 call write_exact
 jmp drain_helpers
body_complete:
 xor edi,edi
 jmp exit

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
 cmp QWORD PTR [rip+handoff_role],4
 jne write_function_status
 mov rax,BODY_FINAL
write_function_status:
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
 call [rip+function_kernel]
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
helper_stream_name: .asciz "hia-function-helpers"
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
function_kernel: .skip 8
helper_work: .skip 8
helper_output: .skip 8
helper_fd: .skip 4
spare: .skip 1
.section .note.GNU-stack,"",@progbits
