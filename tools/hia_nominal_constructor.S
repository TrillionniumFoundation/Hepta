/* Linux transport for HIA construction, type resolution and function lowering.
 * HIA's continuation frames select the next image; this adapter only moves
 * bounded spans and retains the successful helper stream until commit.
 */
.intel_syntax noprefix
.text

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
.equ METADATA_REQUEST, 0x3130514d46414948
.equ METADATA_REPLY, 0x3130444d46414948
.equ OUTER_FRAME, 0x313052544f414948
.equ OUTER_ACK, 0x313041544f414948
.equ OUTER_FAIL, 0x313046544f414948
.equ OUTER_HEADER, 0x313048544f414948
.equ OUTER_NAME_REQUEST, 0x3130514e4f414948
.equ OUTER_NAME_REPLY, 0x3130504e4f414948
.equ OUTER_PACKET_REQUEST, 0x313051544f414948
.equ OUTER_PACKET_REPLY, 0x313050544f414948
.equ OUTER_FINAL, 0x3130464d4f414948
.equ FUNCTION_NEXT, 0x3130584e46414948
.equ OUTER_ARENA, 80<<20
.equ OBJECT_ROWS, 1744
.equ OBJECT_DATA, 64+OBJECT_ROWS*16
.equ OBJECT_CAPACITY, 64<<20
.equ PUBLIC_CANONICAL, 16<<20
.equ PUBLIC_CORE_ARENA, 32<<20
.equ PUBLIC_CORE_STATE, 64<<20
.equ CORE_REFUSAL_DETAIL, 120
.equ VERIFIED_FINAL, 0x3130464356414948
.equ PRESENTATION_BYTES, 96<<20
.equ PRESENTATION_CONTEXT, 0x3130434e4f414948
.equ PRESENTATION_TAIL, 9472
.equ PRESENTATION_HASH, 0x3130484e4f414948
.equ PRESENTATION_NORMALIZED, 0x31304a4e4f414948
.equ PRESENTATION_VERIFY, 0x3154505243414948
.equ PRESENTATION_SCHEMA, 0x313043534f414948
.equ PRESENTATION_ASSEMBLY_SCHEMA, 0x323043534f414948
.equ PRESENTATION_DRIVER_ERROR, 0x313052444f414948
.equ PRESENTATION_EDIT_QUERY_SYNTAX, 0x313053514f414948
.equ PRESENTATION_CONSTRUCTOR_DETAIL, 65568
.equ PRESENTATION_TYPE_DETAIL, 65600
.equ PRESENTATION_FUNCTION_DETAIL, 65700
.equ RENDER_ASSEMBLY, 11

/* All regions supplied to a component as disjoint slices stay disjoint. */
.macro region bytes, slot
 mov esi, \bytes
 call map_private
 mov [rip+\slot],rax
.endm

.ifdef HIA_NOMINAL_BUILD
.global nominal_lower_for_core
.type nominal_lower_for_core,@function
/* The embedded callers pass their already captured bytes. Return the
   compact Core span and the original canonical SHA-256 words. */
nominal_lower_for_core:
 push rbp
 push rbx
 push r12
 push r13
 push r14
 push r15
 sub rsp,8
 mov r12,rdi
 mov r15,rsi
 mov [rip+request+24],rsi
 mov QWORD PTR [rip+request+8],4300
 mov QWORD PTR [rip+handoff_role],6
 mov QWORD PTR [rip+stdio_mode],1
 call canonical_original
 jmp input_ready
.else
.global _start
.type _start,@function
_start:
 cmp QWORD PTR [rsp+8],2
 ja malformed
 cmp QWORD PTR [rsp+8],0
 je malformed
 xor ebp,ebp
 mov rbx,[rsp+16]
 lea rsi,[rip+sigpipe]
 mov edi,13
 xor edx,edx
 mov r10d,8
 mov eax,13
 syscall
 test rax,rax
 jne io_failure
 lea rsi,[rip+stdio_publish]
 call argument_equal
 test eax,eax
 jnz stdin_publish
 lea rsi,[rip+stdio_render]
 call argument_equal
 test eax,eax
 jnz stdin_render
 lea rsi,[rip+stdio_input_refusal]
 call argument_equal
 test eax,eax
 jnz stdin_input_refusal
 cmp QWORD PTR [rsp+8],1
 jne malformed
 lea rsi,[rip+stdio_verify]
 call argument_equal
 test eax,eax
 jnz stdin_verify
 lea rsi,[rip+stdio_inspect]
 call argument_equal
 test eax,eax
 jnz stdin_inspect
 lea rsi,[rip+stdio_normalize]
 call argument_equal
 test eax,eax
 jnz stdin_normalize
 lea rsi,[rip+stdio_agent_admit]
 call argument_equal
 test eax,eax
 jnz stdin_agent_admit
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
 cmp rax,9
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
.endif

input_ready:
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

 cmp QWORD PTR [rip+handoff_role],6
 jb initialize_constructor
 cmp QWORD PTR [rip+stdio_mode],0
 jne initialize_constructor
 call canonical_original
initialize_constructor:
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
 cmp QWORD PTR [rip+handoff_role],5
 jb helper_projection
 mov rdi,[rip+function_work]
 mov esi,CONSTRUCTOR_ARENA
 call outer_entry
 mov edi,3
 mov esi,20
 call check_outer
helper_projection:
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
 jmp retain_outer_helper
retain_helper:
 mov QWORD PTR [rip+delegate_status],0
 cmp QWORD PTR [rip+handoff_role],5
 jae retain_outer_helper
 mov edi,[rip+helper_fd]
 mov rdx,r15
 call write_exact
deliver_helper:
 mov rdi,[rip+helper_output]
 mov rsi,r15
 call owner_frame
 jmp dispatch

retain_outer_helper:
 cmp QWORD PTR [rip+handoff_role],5
 jb deliver_helper
 /* The helper entry has already returned. Its retained workspace and actual
    result remain disjoint from both clients' output buffers. */
 mov [rip+helper_extent],r15
 mov rdi,[rip+helper_work]
 mov esi,HELPER_WORKSPACE
 call outer_entry
 mov edi,7
 mov esi,22
 call check_outer
 lea rdi,[rip+outer_control]
 mov rax,OUTER_HEADER
 mov [rdi],rax
 mov rax,[rip+outer_request]
 mov [rdi+8],rax
 mov [rdi+16],r15
 mov QWORD PTR [rdi+24],HELPER_OUTPUT
 add rdi,32
 mov rsi,[rip+helper_output]
 mov ecx,8
 rep movsq
 lea rdi,[rip+outer_control]
 mov esi,96
 call outer_entry
 cmp QWORD PTR [rip+delegate_status],0
 jne outer_helper_refused
 mov edi,5
 mov esi,21
 call check_outer
 mov rax,[r12+40]
 mov [rip+outer_handle],rax
 call pack_outer_helper
 mov edx,2
 call ack_outer
 mov edi,0
 mov esi,10
 call check_outer
 mov r15,[rip+helper_extent]
 jmp deliver_helper
outer_helper_refused:
 mov edi,6
 mov esi,10
 call check_outer
 jmp deliver_helper

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
 mov rcx,[r12+40]
 mov [rip+input_profile],rcx
 cmp QWORD PTR [rip+handoff_role],0
 jne handoff
 jmp complete
delegated:
 test rax,rax
 je io_failure
complete:
 cmp QWORD PTR [rip+stdio_mode],0
 jne public_constructor_refusal
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

public_constructor_refusal:
.ifndef HIA_NOMINAL_BUILD
 cmp QWORD PTR [rip+handoff_role],6
 jbe stdio_rejected
.endif
 cmp r15,999
 je public_nominal_type_refusal
 test r15,r15
 jz stdio_rejected
 lea eax,[r15+PRESENTATION_CONSTRUCTOR_DETAIL]
 jmp public_driver_refusal
public_nominal_type_refusal:
 cmp rax,4
 je render_type_refusal
 cmp rax,7
 jne stdio_rejected
render_type_refusal:
 add eax,PRESENTATION_TYPE_DETAIL
 jmp public_driver_refusal

handoff:
 lea rdi,[rip+pack_command]
 mov rax,HANDOFF_REQUEST
 mov [rdi],rax
 mov r13,[rip+handoff_role]
 cmp r13,5
 jb normalize_handoff
 cmp QWORD PTR [rip+outer_work],0
 jne normalize_handoff
 mov r13d,2
 jmp handoff_command
normalize_handoff:
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
 cmp QWORD PTR [rip+handoff_role],5
 jb handoff_delivery
 cmp r13,2
 je initialize_outer
handoff_delivery:
 cmp QWORD PTR [rip+handoff_role],3
 jae initialize_function
 mov edi,1
 call write_exact
 xor edi,edi
 jmp exit

initialize_outer:
 region OUTER_ARENA, outer_work
 region FRAME_CAPACITY, outer_frame
 region OBJECT_CAPACITY, objects
 mov QWORD PTR [rip+object_cursor],OBJECT_DATA
 mov rdi,[rip+type_output]
 mov rsi,[rdi+16]
 add rdi,64
 call outer_entry
 mov edi,0
 mov esi,0
 call check_outer
 jmp handoff

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
 jb function_begin
 region HELPER_WORKSPACE, helper_work
 region HELPER_OUTPUT, helper_output
 cmp QWORD PTR [rip+handoff_role],5
 jae function_begin
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
 cmp QWORD PTR [rip+handoff_role],5
 jb dispatch
 cmp eax,64
 jne io_failure
 jmp next_outer

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
 cmp QWORD PTR [rip+handoff_role],5
 jae bind_outer_function
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
 cmp QWORD PTR [rip+handoff_role],5
 jae reject_outer_function
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

next_outer:
 mov rdi,[rip+type_work]
 mov esi,TYPES_ARENA
 call outer_entry
 cmp eax,64
 jne io_failure
 mov r12,[rip+outer_frame]
 mov rcx,OUTER_FRAME
 cmp [r12],rcx
 jne io_failure
 cmp QWORD PTR [r12+24],2000
 je finish_outer
 mov edi,2
 mov esi,10
 call check_outer
 mov rax,[rip+outer_request]
 inc rax
 cmp [r12+32],rax
 jne io_failure
 mov [rip+outer_request],rax
 lea rdi,[rip+outer_control]
 mov rcx,OUTER_NAME_REQUEST
 mov [rdi],rcx
 mov [rdi+8],rax
 mov esi,16
 call outer_entry
 cmp eax,65
 jb io_failure
 cmp eax,192
 ja io_failure
 mov r12,[rip+outer_frame]
 mov rcx,OUTER_NAME_REPLY
 cmp [r12],rcx
 jne io_failure
 mov rcx,[rip+outer_request]
 cmp [r12+8],rcx
 jne io_failure
 sub eax,64
 cmp [r12+16],rax
 jne io_failure
 mov rdx,[r12+24]
 inc rdx
 cmp [rip+outer_request],rdx
 jne io_failure
 lea rdi,[rip+outer_control]
 mov rcx,FUNCTION_NEXT
 mov [rdi],rcx
 mov [rdi+8],rax
 add rdi,16
 lea rsi,[r12+64]
 mov ecx,eax
 rep movsb
 lea rdi,[rip+outer_control]
 lea rsi,[rax+16]
 lea rax,[rip+function_admit_start]
 mov [rip+function_kernel],rax
 call owner_frame
 jmp dispatch

bind_outer_function:
 /* Reflect the function owner's final accounting before borrowing its arena. */
 mov [rip+pending_extent],r15
 lea rdi,[rip+outer_control]
 mov rax,METADATA_REQUEST
 mov [rdi],rax
 mov QWORD PTR [rdi+8],0
 mov esi,16
 mov rdx,[rip+frame]
 mov ecx,FRAME_CAPACITY
 mov r8,[rip+function_work]
 mov r9d,CONSTRUCTOR_ARENA
 call function_records_start
 cmp eax,64
 jb io_failure
 cmp eax,FRAME_CAPACITY
 ja io_failure
 mov rdi,[rip+frame]
 mov rax,METADATA_REPLY
 cmp [rdi],rax
 jne io_failure
 mov rdi,[rip+function_work]
 mov esi,CONSTRUCTOR_ARENA
 call outer_entry
 mov edi,4
 mov esi,11
 call check_outer
 mov rax,[r12+40]
 mov [rip+outer_handle],rax
 mov rsi,[rip+type_output]
 add rsi,64
 mov rdx,[rip+pending_extent]
 call store_object
 mov edx,1
 call ack_outer
 mov edi,0
 xor esi,esi
 call check_outer
 jmp next_outer

reject_outer_function:
 /* Preserve the component's exact refusal while the outer owner closes. */
 cmp r15,15
 jne pack_outer_function_refusal
 test rax,rax
 jne pack_outer_function_refusal
 mov QWORD PTR [rip+public_function_refusal],PRESENTATION_FUNCTION_DETAIL+15
pack_outer_function_refusal:
 mov [r12+56],rax
 mov rax,BODY_FINAL
 mov [r12],rax
 lea rdi,[rip+outer_control]
 mov rax,OUTER_FAIL
 mov [rdi],rax
 mov rax,[rip+outer_request]
 mov [rdi+8],rax
 mov QWORD PTR [rdi+16],0
 mov QWORD PTR [rdi+24],0
 mov esi,32
 call outer_entry
 cmp eax,64
 jne io_failure
 mov r12,[rip+outer_frame]
 mov rax,OUTER_FRAME
 cmp [r12],rax
 jne io_failure
 cmp QWORD PTR [r12+16],999
 jne io_failure
 jmp finish_outer

finish_outer:
 mov rax,[r12+16]
 test rax,rax
 jne outer_refusal
 cmp QWORD PTR [r12+8],2
 jne io_failure
 mov rdi,[rip+objects]
 call clear_header
 mov rax,OUTER_PACKET_REQUEST
 mov [rdi],rax
 mov rsi,[rip+object_cursor]
 mov [rdi+8],rsi
 mov rax,[r12+32]
 mov [rdi+16],rax
 mov rax,[r12+48]
 mov [rdi+24],rax
 mov rax,[r12+56]
 mov [rdi+32],rax
 mov rdx,[rip+type_output]
 mov ecx,TYPES_OUTPUT
 mov r8,[rip+outer_work]
 mov r9d,OUTER_ARENA
 call outer_render_start
 cmp eax,88
 jb io_failure
 cmp eax,TYPES_OUTPUT
 ja io_failure
 mov r15d,eax
 mov rsi,[rip+type_output]
 mov rax,OUTER_PACKET_REPLY
 cmp [rsi],rax
 jne io_failure
 lea rax,[r15-64]
 cmp [rsi+16],rax
 jne io_failure
 mov rax,[r12+32]
 cmp [rsi+8],rax
 jne io_failure
 mov rax,[r12+48]
 cmp [rsi+24],rax
 jne io_failure
 mov rax,[r12+56]
 cmp [rsi+32],rax
 jne io_failure
 cmp QWORD PTR [rip+handoff_role],6
 jae verify_assembled_core
 call write_outer_status
 mov rsi,[rip+type_output]
 mov rdx,r15
 mov edi,1
 call write_exact
 xor edi,edi
 jmp exit
outer_refusal:
 cmp QWORD PTR [rip+stdio_mode],0
 jne public_outer_refusal
 cmp QWORD PTR [r12+8],1
 jne io_failure
 mov r15,rax
 call write_outer_status
 cmp r15,999
 jne outer_failed
 mov rsi,[rip+frame]
 mov edx,64
 mov edi,1
 call write_exact
outer_failed:
 mov edi,65
 jmp exit

public_outer_refusal:
.ifndef HIA_NOMINAL_BUILD
 cmp QWORD PTR [rip+handoff_role],6
 jbe stdio_rejected
.endif
 cmp rax,999
 jne stdio_rejected
 mov eax,[rip+public_function_refusal]
 test eax,eax
 jz stdio_rejected
 jmp public_driver_refusal

.ifndef HIA_NOMINAL_BUILD
stdin_agent_admit:
 mov edi,6
 jmp stdin_begin
stdin_verify:
 mov edi,7
 jmp stdin_begin
stdin_inspect:
 mov edi,8
 jmp stdin_begin
stdin_normalize:
 mov edi,9
 jmp stdin_begin
stdin_publish:
 cmp QWORD PTR [rsp+8],2
 jne malformed
 mov rax,[rsp+24]
 mov [rip+publication_path],rax
 mov edi,10
 jmp stdin_begin
stdin_render:
 cmp QWORD PTR [rsp+8],2
 jne render_from_stdin
 mov rax,[rsp+24]
 mov [rip+publication_path],rax
render_from_stdin:
 mov edi,RENDER_ASSEMBLY
 jmp stdin_begin
stdin_input_refusal:
 cmp QWORD PTR [rsp+8],2
 jne malformed
 mov rax,[rsp+24]
 cmp BYTE PTR [rax],64
 jne measure_input_refusal_start
 /* The dispatcher retains [ + base + the ten-byte query prefix + query.
    The marker is followed by eight hexadecimal digits giving base length. */
 lea rsi,[rax+1]
 xor r8d,r8d
 xor ecx,ecx
read_refusal_boundary:
 movzx edx,BYTE PTR [rsi+rcx]
 sub edx,48
 cmp edx,9
 jbe retain_refusal_digit
 sub edx,39
 cmp edx,10
 jb malformed
 cmp edx,15
 ja malformed
retain_refusal_digit:
 shl r8d,4
 or r8d,edx
 inc ecx
 cmp ecx,8
 jne read_refusal_boundary
 cmp r8d,RAW_LIMIT
 ja malformed
 mov [rip+input_refusal_base_bytes],r8
 mov QWORD PTR [rip+input_refusal_query],1
 add rax,9
measure_input_refusal_start:
 xor ecx,ecx
measure_input_refusal:
 cmp ecx,256
 jae malformed
 cmp BYTE PTR [rax+rcx],0
 je retain_input_refusal
 inc ecx
 jmp measure_input_refusal
retain_input_refusal:
 test ecx,ecx
 jz malformed
 mov [rip+input_refusal_arg],rax
 mov [rip+input_refusal_bytes],rcx
 mov edi,7
stdin_begin:
 mov [rip+handoff_role],rdi
 mov QWORD PTR [rip+request+8],4300
 mov QWORD PTR [rip+stdio_mode],1
 mov esi,RAW_LIMIT+1
 call map_private
 mov r12,rax
 mov ebx,RAW_LIMIT+1
 cmp QWORD PTR [rip+input_refusal_query],0
 cmovne rbx,[rip+input_refusal_base_bytes]
 call read_raw_stdin
 cmp QWORD PTR [rip+input_refusal_query],0
 je classify_stdin
 cmp r15,rbx
 jne io_failure
 jmp classify_stdin

read_raw_stdin:
 xor r15d,r15d
read_stdin:
 cmp r15,rbx
 je read_stdin_done
 xor edi,edi
 lea rsi,[r12+r15]
 mov rdx,rbx
 sub rdx,r15
 xor eax,eax
 syscall
 cmp rax,-4
 je read_stdin
 test rax,rax
 js io_failure
 jz read_stdin_done
 add r15,rax
 cmp r15,RAW_LIMIT
 ja stdio_limit
 jmp read_stdin
read_stdin_done:
 ret

classify_stdin:
 mov [rip+request+24],r15
 call canonical_original
 region PRESENTATION_BYTES, presentation_output
 mov rdi,[rip+public_core_arena]
 mov esi,PUBLIC_CORE_ARENA
 call discard
 mov rdi,r12
 mov rsi,r15
 mov rdx,[rip+presentation_output]
 mov ecx,PRESENTATION_BYTES
 mov r8,[rip+public_core_arena]
 mov r9d,PUBLIC_CORE_ARENA
 mov rax,PRESENTATION_SCHEMA
 mov r10,PRESENTATION_ASSEMBLY_SCHEMA
 cmp QWORD PTR [rip+handoff_role],RENDER_ASSEMBLY
 cmove rax,r10
 mov [r8+PUBLIC_CORE_ARENA-8],rax
 call public_presentation_start
 mov edi,1
 cmp eax,0xfffffffc
 jae verified_refusal
 cmp eax,5
 jne classify_nominal
 cmp QWORD PTR [rip+handoff_role],RENDER_ASSEMBLY
 jne io_failure
 mov QWORD PTR [rip+legacy_assembly_profile],1
 jmp verify_primitive_stdin
classify_nominal:
 cmp eax,4
 ja io_failure
 test eax,eax
 jne input_ready

verify_primitive_stdin:
 mov rdi,[rip+public_core_arena]
 mov esi,PUBLIC_CORE_ARENA
 call discard
 region PUBLIC_CORE_STATE, public_core_state
 mov rdi,r12
 mov rsi,r15
 mov rdx,[rip+public_core_state]
 mov ecx,PUBLIC_CORE_STATE
 mov r8,[rip+public_core_arena]
 mov r9d,PUBLIC_CORE_ARENA
 call public_core_start
 mov edi,3
 test eax,eax
 jne primitive_stdin_refusal
 cmp QWORD PTR [rip+handoff_role],RENDER_ASSEMBLY
 je render_primitive_assembly
 mov r15,[rip+original_extent]
 mov rax,[rip+original_canonical]
 mov [rip+type_output],rax
 cmp QWORD PTR [rip+handoff_role],6
 je write_admitted_bytes
 jmp present_public

primitive_stdin_refusal:
 cmp QWORD PTR [rip+handoff_role],6
 jbe verified_refusal
 mov rdx,[rip+public_core_state]
 mov edx,DWORD PTR [rdx+CORE_REFUSAL_DETAIL]
 test edx,edx
 jz verified_refusal
 mov eax,edx
 jmp public_driver_refusal

render_primitive_assembly:
 cmp QWORD PTR [rip+legacy_assembly_profile],0
 jne assembly_profile_refused
 mov rdi,r12
 mov rsi,r15
 mov rdx,[rip+publication_path]
 sub rsp,8
 jmp nominal_render_assembly
.endif

canonical_original:
 sub rsp,8
 region PUBLIC_CANONICAL, original_canonical
 region PUBLIC_CORE_ARENA, public_core_arena
 mov rdi,r12
 mov rsi,r15
 mov rdx,[rip+original_canonical]
 mov ecx,PUBLIC_CANONICAL
 mov r8,[rip+public_core_arena]
 mov r9d,PUBLIC_CORE_ARENA
 mov QWORD PTR [r8+48],262144
 mov QWORD PTR [r8+56],64
 call public_canonical_start
 mov edi,1
 cmp eax,0xfffffffc
 jae verified_refusal
 test eax,eax
 je io_failure
 cmp eax,RAW_LIMIT
 ja verified_budget
 mov [rip+original_extent],rax
 add rsp,8
 ret

verify_assembled_core:
 /* Typed output never confers authority. Convert it to a bounded raw Core
    input, then invoke the independent primitive checker, not a receipt. */
 mov rdi,[rip+codec_work]
 call clear_header
 mov rax,RENDER_REQUEST
 mov [rdi],rax
 mov r8,rdi
 mov rdi,[rip+type_output]
 add rdi,64
 lea rsi,[r15-64]
 mov rdx,[rip+json]
 mov ecx,PACKET_CAPACITY
 mov r9d,PACKET_CAPACITY
 call codec
 mov edi,2
 cmp eax,0xfffffff9
 jae verified_refusal
 test eax,eax
 je io_failure
 cmp eax,RAW_LIMIT
 ja verified_budget
 mov [rip+compact_core_extent],rax

.ifdef HIA_NOMINAL_BUILD
 /* The caller independently checks these Core bytes on return. */
 region PRESENTATION_BYTES, presentation_output
 mov rdi,[rip+public_core_arena]
 mov esi,PUBLIC_CORE_ARENA
 call discard
 mov rdi,[rip+original_canonical]
 mov rsi,[rip+original_extent]
 mov rdx,[rip+presentation_output]
 mov ecx,PRESENTATION_BYTES
 mov r8,[rip+public_core_arena]
 mov r9d,PUBLIC_CORE_ARENA
 mov rax,PRESENTATION_HASH
 mov [r8+PUBLIC_CORE_ARENA-8],rax
 call public_presentation_start
 cmp eax,64
 jne io_failure
 mov rax,[rip+json]
 mov rdx,[rip+compact_core_extent]
 mov rcx,[rip+presentation_output]
 add rsp,8
 pop r15
 pop r14
 pop r13
 pop r12
 pop rbx
 pop rbp
 ret
.else
 region PUBLIC_CORE_STATE, public_core_state
 mov rdi,[rip+public_core_arena]
 mov esi,PUBLIC_CORE_ARENA
 call discard
 mov rdi,[rip+json]
 mov rsi,[rip+compact_core_extent]
 mov rdx,[rip+public_core_state]
 mov ecx,PUBLIC_CORE_STATE
 mov r8,[rip+public_core_arena]
 mov r9d,PUBLIC_CORE_ARENA
 call public_core_start
 mov edi,3
 test eax,eax
 jne verified_refusal

 mov rdi,[rip+public_core_arena]
 mov esi,PUBLIC_CORE_ARENA
 call discard
 mov rdi,[rip+json]
 mov rsi,[rip+compact_core_extent]
 mov rdx,[rip+type_output]
 mov ecx,PUBLIC_CANONICAL
 mov r8,[rip+public_core_arena]
 mov r9d,PUBLIC_CORE_ARENA
 mov QWORD PTR [r8+48],262144
 mov QWORD PTR [r8+56],64
 call public_canonical_start
 mov edi,4
 cmp eax,0xfffffffc
 jae verified_refusal
 test eax,eax
 je io_failure
 cmp eax,RAW_LIMIT
 ja verified_budget
 mov r15d,eax
 cmp QWORD PTR [rip+handoff_role],6
 ja present_public
write_admitted_bytes:
 lea rdi,[rip+verified_header]
 call clear_header
 mov rax,[rip+input_profile]
 mov [rdi+24],rax
 mov rax,[rip+original_extent]
 mov [rdi+32],rax
 mov [rdi+40],r15
 call write_verified
 mov rsi,[rip+original_canonical]
 mov rdx,[rip+original_extent]
 mov edi,1
 call write_exact
 mov rsi,[rip+type_output]
 mov rdx,r15
 mov edi,1
 call write_exact
 xor edi,edi
 jmp exit

present_public:
 cmp QWORD PTR [rip+input_refusal_arg],0
 jne write_input_refusal
 cmp QWORD PTR [rip+handoff_role],RENDER_ASSEMBLY
 je assembly_profile_refused
 mov [rip+verified_core_extent],r15
 mov rdi,[rip+public_core_arena]
 mov esi,PUBLIC_CORE_ARENA
 call discard
 cmp QWORD PTR [rip+presentation_output],0
 jne select_presentation
 region PRESENTATION_BYTES, presentation_output
select_presentation:
 cmp QWORD PTR [rip+handoff_role],9
 je present_normalized
 cmp QWORD PTR [rip+input_profile],0
 je select_report
 mov rdi,[rip+original_canonical]
 mov rsi,[rip+original_extent]
 mov rdx,[rip+presentation_output]
 mov ecx,PRESENTATION_BYTES
 mov r8,[rip+public_core_arena]
 mov r9d,PUBLIC_CORE_ARENA
 mov rax,PRESENTATION_HASH
 mov [r8+PUBLIC_CORE_ARENA-8],rax
 call public_presentation_start
 cmp eax,64
 jne io_failure
 mov r8,[rip+public_core_arena]
 lea rdi,[r8+PUBLIC_CORE_ARENA-PRESENTATION_TAIL]
 mov rax,PRESENTATION_CONTEXT
 mov [rdi],rax
 mov rax,[rip+input_profile]
 mov [rdi+8],rax
 add rdi,16
 mov rsi,[rip+presentation_output]
 mov ecx,8
 rep movsq
select_report:
 cmp QWORD PTR [rip+handoff_role],10
 je publish_canonical
 xor eax,eax
 cmp QWORD PTR [rip+handoff_role],7
 jne present_core
 mov rax,PRESENTATION_VERIFY
 jmp present_core
present_normalized:
 mov rax,PRESENTATION_NORMALIZED
present_core:
 mov rdi,[rip+type_output]
 mov rsi,[rip+verified_core_extent]
 mov rdx,[rip+presentation_output]
 mov ecx,PRESENTATION_BYTES
 mov r8,[rip+public_core_arena]
 mov r9d,PUBLIC_CORE_ARENA
 mov [r8+PUBLIC_CORE_ARENA-8],rax
 call public_presentation_start
 mov edi,5
 cmp eax,0xfffffffc
 jae verified_refusal
 test eax,eax
 je io_failure
 cmp eax,PRESENTATION_BYTES
 ja io_failure
 mov edx,eax
 mov rsi,[rip+presentation_output]
 mov edi,1
 call write_exact
 xor edi,edi
 jmp exit

write_input_refusal:
 cmp QWORD PTR [rip+input_refusal_query],0
 jne check_captured_query
emit_input_refusal:
 # stdin was admitted. Forward the bounded diagnostic prepared by HIA's
 # dispatcher, not a public report or the incomplete edit envelope.
 mov rsi,[rip+input_refusal_arg]
 mov rdx,[rip+input_refusal_bytes]
 mov edi,1
 call write_exact
 mov edi,2
 jmp exit

check_captured_query:
 /* Skip the framing bytes; the exact query ends at the sealed file extent. */
 xor edi,edi
 mov rsi,[rip+input_refusal_base_bytes]
 add rsi,11
 xor edx,edx
 mov eax,8
 syscall
 cmp rax,rsi
 jne io_failure
 mov esi,RAW_LIMIT+1
 call map_private
 mov r12,rax
 mov ebx,RAW_LIMIT+1
 call read_raw_stdin
 cmp QWORD PTR [rip+presentation_output],0
 jne check_query_syntax
 region PRESENTATION_BYTES, presentation_output
check_query_syntax:
 mov rdi,r12
 mov rsi,r15
 mov rdx,[rip+presentation_output]
 mov ecx,PRESENTATION_BYTES
 mov r8,[rip+public_core_arena]
 mov r9d,PUBLIC_CORE_ARENA
 mov rax,PRESENTATION_EDIT_QUERY_SYNTAX
 mov [r8+PUBLIC_CORE_ARENA-8],rax
 call public_presentation_start
 test eax,eax
 jz emit_input_refusal
 cmp eax,PRESENTATION_BYTES
 ja io_failure
 mov edx,eax
 mov rsi,[rip+presentation_output]
 mov edi,1
 call write_exact
 mov edi,2
 jmp exit

assembly_profile_refused:
 xor eax,eax
 jmp public_driver_refusal
.endif

public_driver_refusal:
 mov [rip+driver_status],eax
 cmp QWORD PTR [rip+presentation_output],0
 jne driver_work
 region PRESENTATION_BYTES, presentation_output
driver_work:
 lea rdi,[rip+verified_header]
 xor esi,esi
 mov rdx,[rip+presentation_output]
 mov ecx,PRESENTATION_BYTES
 mov r8,[rip+public_core_arena]
 mov r9d,PUBLIC_CORE_ARENA
 mov rax,[rip+driver_status]
 mov [r8+PUBLIC_CORE_ARENA-16],rax
 mov rax,PRESENTATION_DRIVER_ERROR
 mov [r8+PUBLIC_CORE_ARENA-8],rax
 and rsp,-16
 call public_presentation_start
 test eax,eax
 je io_failure
 cmp eax,PRESENTATION_BYTES
 ja io_failure
 mov edx,eax
 mov rsi,[rip+presentation_output]
 mov edi,1
 call write_exact
 mov edi,2
 jmp exit

.ifndef HIA_NOMINAL_BUILD
publish_canonical:
 mov rdi,[rip+publication_path]
 mov rsi,[rip+type_output]
 mov rdx,[rip+verified_core_extent]
 xor ecx,ecx
 cmp QWORD PTR [rip+input_profile],0
 cmovne rcx,[rip+presentation_output]
 add rsp,8
 jmp nominal_publish
.endif

verified_budget:
 mov eax,0xfffffffb
verified_refusal:
 cmp QWORD PTR [rip+stdio_mode],0
 jne stdio_refusal
 mov r15d,eax
 mov r14d,edi
 lea rdi,[rip+verified_header]
 call clear_header
 mov [rdi+8],r14
 mov [rdi+16],r15
 mov rax,[rip+input_profile]
 mov [rdi+24],rax
 call write_verified
 mov edi,65
 jmp exit

write_verified:
 lea rsi,[rip+verified_header]
 mov rax,VERIFIED_FINAL
 mov [rsi],rax
 mov edi,1
 mov edx,64
 jmp write_exact

discard:
 mov edx,4
 mov eax,28
 syscall
 test rax,rax
 jne io_failure
 ret

write_outer_status:
 mov rax,OUTER_FINAL
 mov [r12],rax
 mov rsi,r12
 mov edi,1
 mov edx,64
 jmp write_exact

ack_outer:
 lea rdi,[rip+outer_control]
 mov rax,OUTER_ACK
 mov [rdi],rax
 mov rax,[rip+outer_request]
 mov [rdi+8],rax
 mov [rdi+16],rdx
 mov rax,[rip+outer_handle]
 mov [rdi+24],rax
 mov esi,32
 jmp outer_entry

outer_entry:
 sub rsp,8
 mov rdx,[rip+outer_frame]
 mov ecx,FRAME_CAPACITY
 mov r8,[rip+outer_work]
 mov r9d,OUTER_ARENA
 call outer_owner_start
 add rsp,8
 ret

check_outer:
 cmp eax,64
 jne io_failure
 mov r12,[rip+outer_frame]
 mov rax,OUTER_FRAME
 cmp [r12],rax
 jne io_failure
 cmp [r12+8],rdi
 jne io_failure
 cmp [r12+24],rsi
 jne io_failure
 cmp QWORD PTR [r12+16],0
 jne io_failure
 ret

pack_outer_helper:
 sub rsp,8
 mov rdi,[rip+codec_work]
 call clear_header
 mov rax,DECODE_REQUEST
 mov [rdi],rax
 mov rax,[rip+request+8]
 mov [rdi+8],rax
 mov r8,rdi
 mov rdi,[rip+helper_output]
 mov rsi,[rdi+32]
 add rdi,64
 mov rdx,[rip+type_output]
 mov ecx,PACKET_CAPACITY
 mov r9d,PACKET_CAPACITY
 call codec
 cmp eax,70
 jb io_failure
 cmp eax,PACKET_CAPACITY
 ja io_failure
 mov rdx,rax
 mov rsi,[rip+type_output]
 cmp QWORD PTR [rsi],6
 jne io_failure
 cmp QWORD PTR [rsi+16],1
 jne io_failure
 cmp QWORD PTR [rsi+24],4
 jne io_failure
 cmp QWORD PTR [rsi+32],6
 jne io_failure
 mov rax,0x7265706c6568
 mov rcx,[rsi+40]
 shl rcx,16
 shr rcx,16
 cmp rcx,rax
 jne io_failure
 add rsi,46
 sub rdx,46
 call store_object
 add rsp,8
 ret

/* Only an outer-issued handle can select its bounded, write-once row. */
store_object:
 cmp rdx,24
 jb io_failure
 cmp QWORD PTR [rsi],6
 jne io_failure
 lea rax,[rdx-16]
 cmp [rsi+8],rax
 jne io_failure
 mov rcx,[rip+outer_handle]
 btr rcx,63
 jnc io_failure
 cmp rcx,OBJECT_ROWS
 jae io_failure
 shl rcx,4
 mov r8,[rip+objects]
 lea r9,[r8+rcx+64]
 cmp QWORD PTR [r9],0
 jne io_failure
 mov rax,[rip+object_cursor]
 mov rcx,OBJECT_CAPACITY
 sub rcx,rax
 cmp rdx,rcx
 ja io_failure
 mov [r9],rax
 mov [r9+8],rdx
 lea rdi,[r8+rax]
 add [rip+object_cursor],rdx
 mov rcx,rdx
 rep movsb
 ret

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
 cmp QWORD PTR [rip+stdio_mode],0
 jne stdio_refusal
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
 cmp QWORD PTR [rip+stdio_mode],0
 jne stdio_io
 mov edi,74
 jmp exit
stdio_refusal:
.ifndef HIA_NOMINAL_BUILD
 cmp QWORD PTR [rip+handoff_role],6
 jbe private_stdio_refusal
.endif
 cmp edi,1
 jne private_stdio_refusal
 cmp eax,0xffffffff
 je public_driver_refusal
 cmp eax,0xfffffffe
 je public_driver_refusal
 cmp eax,0xfffffffc
 je public_driver_refusal
private_stdio_refusal:
 cmp eax,0xfffffffe
 je stdio_limit
 /* Raw byte limit is handled while reading. In post-elaboration stages
    0xfffffffb is the bounded-output failure except Core FORMAT. */
 cmp edi,3
 je stdio_rejected
 cmp eax,0xfffffffb
 je stdio_limit
stdio_rejected:
 mov edi,2
 jmp exit
stdio_limit:
 mov edi,3
 jmp exit
stdio_io:
 mov edi,4
 jmp exit
argument_equal:
 mov rdi,rbx
check_arg_byte:
 mov al,[rdi]
 cmp al,[rsi]
 jne different_argument
 inc rdi
 inc rsi
 test al,al
 jne check_arg_byte
 mov eax,1
 ret
different_argument:
 xor eax,eax
 ret
exit:
 mov eax,60
 syscall
 ud2
.ifndef HIA_NOMINAL_BUILD
.size _start,.-_start
.endif

.balign 8
sigpipe: .quad 1,0,0,0
helper_stream_name: .asciz "hia-function-helpers"
stdio_verify: .asciz "hia-verify-core-json"
stdio_inspect: .asciz "hia-inspect-core-json"
stdio_normalize: .asciz "hia-normalize-core"
stdio_agent_admit: .asciz "hia-admit-agent-json"
stdio_publish: .asciz "hia-publish-program"
stdio_render: .asciz "hia-render-assembly"
.ifndef HIA_NOMINAL_BUILD
stdio_input_refusal: .asciz "hia-report-input-refusal"
.endif
.ifdef HIA_NOMINAL_BUILD
/* The HIA object writer supplies these independent read-only image spans. */
.set owner, core_nominal_owner_start
.set renderer, core_nominal_render_start
.set codec, core_nominal_codec_start
.else
.balign 16
owner: .incbin "owner.image.bin"
.balign 16
renderer: .incbin "render.image.bin"
.balign 16
codec: .incbin "nominal-json.image.bin"
.endif
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
.balign 8
outer_work: .skip 8
outer_frame: .skip 8
outer_request: .skip 8
outer_handle: .skip 8
pending_extent: .skip 8
helper_extent: .skip 8
objects: .skip 8
object_cursor: .skip 8
outer_control: .skip 144
input_profile: .skip 8
legacy_assembly_profile: .skip 8
driver_status: .skip 8
public_function_refusal: .skip 8
original_canonical: .skip 8
original_extent: .skip 8
compact_core_extent: .skip 8
public_core_arena: .skip 8
public_core_state: .skip 8
verified_header: .skip 64
verified_core_extent: .skip 8
presentation_output: .skip 8
publication_path: .skip 8
.ifndef HIA_NOMINAL_BUILD
input_refusal_arg: .skip 8
input_refusal_bytes: .skip 8
input_refusal_query: .skip 8
input_refusal_base_bytes: .skip 8
.endif
stdio_mode: .skip 8
spare: .skip 1
.section .note.GNU-stack,"",@progbits
