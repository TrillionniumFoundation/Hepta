/* Fixed Linux x86-64 mechanics for the native HIA clean build controller.
 * No JSON, manifest, digest, source language, recipe or package parser.
 * Every image call uses a fresh child and zero output/workspace. */
.intel_syntax noprefix
.text
.global _start, driver_call_hole, decoder_offset_value, self_size_value
.equ INPUT,0
.equ INPUTLEN,8
.equ WORK,16
.equ WORKLEN,24
.equ REPLY,32
.equ REPLYLEN,40
.equ RAW,48
.equ RAWLEN,56
.equ RAWCAP,64
.equ CODE,72
.equ CODELEN,80
.equ CODEOWN,88
.equ SRC,96
.equ SRCLEN,104
.equ OUT,112
.equ OUTLEN,120
.equ SCRATCH,128
.equ SCRATCHLEN,136
.equ RESULT,144
.equ PEER,152
.equ SEQUENCE,160
.equ CHILD,168
.equ ARGPTR,176
.equ ARGC,184
.equ PARENT,192
.equ STATUS,200
.equ EVENT,1024
_start:
 mov r15,rsp
 mov edi,4096
 mov esi,0x22
 call map_rw
 mov rbp,rax
 mov rax,[r15]
 mov [rbp+ARGC],rax
 cmp rax,2
 jb no_arg
 mov rax,[r15+16]
 mov [rbp+ARGPTR],rax
no_arg:
 mov eax,39
 syscall
 mov [rbp+PARENT],rax
 mov edi,8192
 mov esi,0x22
 call map_rw
 mov [rbp+WORK],rax
 mov QWORD PTR [rbp+WORKLEN],8192
 mov edi,1048576
 mov esi,0x22
 call map_rw
 mov [rbp+RAW],rax
 mov QWORD PTR [rbp+RAWCAP],1048576
read_next:
 mov rax,[rbp+RAWLEN]
 cmp rax,[rbp+RAWCAP]
 jb read_room
 mov rdi,[rbp+RAW]
 mov rsi,[rbp+RAWCAP]
 mov rdx,rsi
 add rdx,rdx
 jc io_fail
 mov [rbp+RAWCAP],rdx
 mov r10d,1
 mov eax,25
 syscall
 cmp rax,-4095
 jae io_fail
 mov [rbp+RAW],rax
read_room:
 xor edi,edi
 mov rsi,[rbp+RAW]
 add rsi,[rbp+RAWLEN]
 mov rdx,[rbp+RAWCAP]
 sub rdx,[rbp+RAWLEN]
 mov eax,0
 syscall
 cmp rax,-4
 je read_next
 test rax,rax
 js io_fail
 jz input_captured
 add [rbp+RAWLEN],rax
 jc io_fail
 jmp read_next
input_captured:
 /* Generic bounded argument capture; HIA validates its exact length and hex. */
 lea rbx,[rbp+256]
 mov rax,0x3130524142414948 /* HIABAR01 */
 mov [rbx],rax
 mov rax,[rbp+ARGC]
 mov [rbx+8],rax
 mov rax,[rbp+RAWLEN]
 mov [rbx+24],rax
 xor ecx,ecx
 mov rsi,[rbp+ARGPTR]
 test rsi,rsi
 jz arg_done
arg_next:
 cmp rcx,65
 jae arg_done
 mov al,[rsi+rcx]
 test al,al
 jz arg_done
 mov [rbx+rcx+32],al
 inc rcx
 jmp arg_next
arg_done:
 mov [rbx+16],rcx
 lea rax,[rcx+32]
 mov [rbp+INPUTLEN],rax
 mov [rbp+INPUT],rbx
call_controller:
 mov rdi,[rbp+INPUT]
 mov rsi,[rbp+INPUTLEN]
 mov rdx,[rbp+REPLY]
 mov rcx,[rbp+REPLYLEN]
 mov r8,[rbp+WORK]
 mov r9,[rbp+WORKLEN]
 .byte 0xe8
driver_call_hole: .long 0
 mov rbx,[rbp+WORK]
 add rbx,EVENT
 cmp eax,0xfffffffd
 je private_fail
 cmp eax,0xfffffffe
 je grow_work
 cmp eax,128
 jne private_fail
 mov rax,0x3130454242414948 /* HIABBE01 */
 cmp [rbx],rax
 jne private_fail
 mov rax,[rbx+8]
 cmp rax,0
 je completed
 cmp rax,1
 je decoder_request
 cmp rax,3
 je refused
 cmp rax,4
 je private_fail
 cmp rax,5
 je compiler_request
 cmp rax,6
 je packer_request
 cmp rax,7
 je self_request
 cmp rax,8
 je call_controller
 cmp rax,9
 je capture_prefix
 jmp private_fail
capture_prefix:
 mov rax,[rbx+24]
 mov rcx,[rbx+32]
 cmp rcx,64
 jne private_fail
 cmp rax,[rbp+WORKLEN]
 ja private_fail
 mov rdx,[rbp+WORKLEN]
 sub rdx,rax
 cmp rcx,rdx
 ja private_fail
 mov r12,[rbp+WORK]
 add r12,rax
 mov rdi,[rbp+RAWLEN]
 add rdi,64
 jc private_fail
 mov [rbp+INPUTLEN],rdi
 mov esi,0x22
 call map_rw
 mov [rbp+INPUT],rax
 mov rdi,rax
 mov rsi,r12
 mov ecx,64
 rep movsb
 mov rsi,[rbp+RAW]
 mov rcx,[rbp+RAWLEN]
 rep movsb
 mov rdi,[rbp+INPUT]
 mov rsi,[rbp+INPUTLEN]
 call readonly
 mov rdi,[rbp+RAW]
 mov rsi,[rbp+RAWCAP]
 mov eax,11
 syscall
 test rax,rax
 js io_fail
 mov QWORD PTR [rbp+RAW],0
 jmp call_controller
grow_work:
 cmp QWORD PTR [rbx+8],2
 jne private_fail
 mov rdx,[rbx+40]
 cmp rdx,[rbp+WORKLEN]
 jbe private_fail
 mov rdi,[rbp+WORK]
 mov rsi,[rbp+WORKLEN]
 mov [rbp+WORKLEN],rdx
 mov r10d,1
 mov eax,25
 syscall
 cmp rax,-4095
 jae io_fail
 mov [rbp+WORK],rax
 jmp call_controller
decoder_request:
 mov QWORD PTR [rbp+PEER],1
 mov rax,[rip+.Ldecoder_offset_value]
 add rax,0x400000
 jc private_fail
 mov [rbp+CODE],rax
 mov QWORD PTR [rbp+CODEOWN],0
 mov rax,[rbp+INPUT]
 mov rdx,[rbp+INPUTLEN]
 jmp input_view
compiler_request:
 mov QWORD PTR [rbp+PEER],2
 jmp dynamic_code
packer_request:
 mov QWORD PTR [rbp+PEER],3
dynamic_code:
 mov rax,[rbx+80]
 cmp rax,1
 je code_input
 cmp rax,2
 jne private_fail
 mov rsi,[rbp+WORK]
 mov rdx,[rbp+WORKLEN]
 jmp code_view
code_input:
 mov rsi,[rbp+INPUT]
 mov rdx,[rbp+INPUTLEN]
code_view:
 mov rax,[rbx+64]
 mov rcx,[rbx+72]
 cmp rax,rdx
 ja private_fail
 sub rdx,rax
 cmp rcx,rdx
 ja private_fail
 test rcx,rcx
 jz private_fail
 cmp rcx,1048576
 ja private_fail
 add rsi,rax
 mov r12,rsi
 mov r13,rcx
 mov rdi,rcx
 mov esi,0x22
 call map_rw
 mov [rbp+CODE],rax
 mov [rbp+CODELEN],r13
 mov QWORD PTR [rbp+CODEOWN],1
 mov rdi,rax
 mov rsi,r12
 mov rcx,r13
 rep movsb
 mov rdi,[rbp+CODE]
 mov rsi,r13
 mov edx,5
 mov eax,10
 syscall
 test rax,rax
 js io_fail
 cmp QWORD PTR [rbp+PEER],2
 je source_input
 mov rax,[rbp+WORK]
 mov rdx,[rbp+WORKLEN]
 jmp input_view
source_input:
 mov rax,[rbp+INPUT]
 mov rdx,[rbp+INPUTLEN]
input_view:
 mov rsi,[rbx+24]
 mov rcx,[rbx+32]
 cmp rsi,rdx
 ja private_fail
 sub rdx,rsi
 cmp rcx,rdx
 ja private_fail
 add rax,rsi
 mov r12,rax
 mov [rbp+SRCLEN],rcx
 mov rdi,rcx
 test rdi,rdi
 jnz source_nonempty
 mov edi,1
source_nonempty:
 mov esi,0x22
 call map_rw
 mov [rbp+SRC],rax
 mov rdi,rax
 mov rsi,r12
 mov rcx,[rbp+SRCLEN]
 rep movsb
 mov rdi,[rbp+SRC]
 mov rsi,[rbp+SRCLEN]
 test rsi,rsi
 jnz source_protect
 mov esi,1
source_protect:
 call readonly
 mov rax,[rbx+16]
 mov [rbp+SEQUENCE],rax
 mov rdi,[rbx+40]
 test rdi,rdi
 jz private_fail
 mov [rbp+OUTLEN],rdi
 mov esi,0x21
 call map_rw
 mov [rbp+OUT],rax
 mov rdi,[rbx+48]
 test rdi,rdi
 jz private_fail
 mov [rbp+SCRATCHLEN],rdi
 mov esi,0x21
 call map_rw
 mov [rbp+SCRATCH],rax
 cmp QWORD PTR [rbp+PEER],1
 jne peer_configured
 cmp QWORD PTR [rbp+SCRATCHLEN],64
 jb private_fail
 mov rax,[rbx+64]
 mov rdx,[rbp+SCRATCH]
 mov [rdx+48],rax
 mov rax,[rbx+72]
 mov [rdx+56],rax
peer_configured:
 mov edi,4096
 mov esi,0x21
 call map_rw
 mov [rbp+RESULT],rax
 mov QWORD PTR [rbp+STATUS],0
 mov eax,57
 syscall
 test rax,rax
 js io_fail
 jz child
 mov [rbp+CHILD],rax
wait_child:
 mov rdi,[rbp+CHILD]
 lea rsi,[rbp+STATUS]
 xor edx,edx
 lea r10,[rbp+1024]
 mov eax,61
 syscall
 cmp rax,-4
 je wait_child
 cmp rax,[rbp+CHILD]
 jne io_fail
 mov r12,[rbp+RESULT]
 xor r13d,r13d
 cmp QWORD PTR [rbp+STATUS],0
 jne peer_finished
 cmp QWORD PTR [r12+8],1
 jne private_fail
 mov r13,[rbp+OUTLEN]
 cmp QWORD PTR [rbp+PEER],1
 jne peer_finished
 mov r13,[r12]
 mov eax,0xfffffffc
 cmp r13,rax
 jae decoder_refusal
 test r13,r13
 jz private_fail
 cmp r13,[rbp+OUTLEN]
 ja private_fail
 jmp peer_finished
decoder_refusal:
 xor r13d,r13d
peer_finished:
 call release_reply
 lea rdi,[r13+64]
 mov [rbp+REPLYLEN],rdi
 mov esi,0x22
 call map_rw
 mov [rbp+REPLY],rax
 mov rdi,rax
 mov rax,0x3130505242414948 /* HIABRP01 */
 mov [rdi],rax
 mov rax,[rbp+SEQUENCE]
 mov [rdi+8],rax
 mov rax,[rbp+PEER]
 mov [rdi+16],rax
 mov rax,[r12]
 mov [rdi+24],rax
 mov [rdi+32],r13
 mov eax,DWORD PTR [rbp+STATUS]
 mov [rdi+40],rax
 /* Child records actual clock difference only when its entry returned. */
 mov rax,[r12+48]
 cmp QWORD PTR [rbp+PEER],1
 jne keep_clock
 xor eax,eax
keep_clock:
 mov [rdi+48],rax
 mov QWORD PTR [rdi+56],0
 add rdi,64
 mov rsi,[rbp+OUT]
 mov rcx,r13
 rep movsb
 mov rdi,[rbp+REPLY]
 mov rsi,[rbp+REPLYLEN]
 call readonly
 call release_peer
 jmp call_controller
child:
 mov edi,1
 mov esi,9
 mov eax,157
 syscall
 test rax,rax
 js child_bad
 mov eax,110
 syscall
 cmp rax,[rbp+PARENT]
 jne child_bad
 mov edi,4
 xor esi,esi
 mov eax,157
 syscall
 test rax,rax
 js child_bad
 /* Original per-invocation CPU / address / stack / no-core profile. */
 mov QWORD PTR [rbp+512],10
 mov QWORD PTR [rbp+520],10
 xor edi,edi
 call limit
 mov QWORD PTR [rbp+512],268435456
 mov QWORD PTR [rbp+520],268435456
 mov edi,9
 call limit
 mov QWORD PTR [rbp+512],8388608
 mov QWORD PTR [rbp+520],8388608
 mov edi,3
 call limit
 mov QWORD PTR [rbp+512],0
 mov QWORD PTR [rbp+520],0
 mov edi,4
 call limit
 mov QWORD PTR [rbp+560],0
 mov QWORD PTR [rbp+568],0
 mov QWORD PTR [rbp+576],20
 mov QWORD PTR [rbp+584],0
 xor edi,edi
 lea rsi,[rbp+560]
 xor edx,edx
 mov eax,38
 syscall
 test rax,rax
 js child_bad
 mov r12,[rbp+RESULT]
 mov edi,1
 lea rsi,[r12+16]
 mov eax,228
 syscall
 test rax,rax
 js child_bad
 mov rdi,[rbp+SRC]
 mov rsi,[rbp+SRCLEN]
 mov rdx,[rbp+OUT]
 mov rcx,[rbp+OUTLEN]
 mov r8,[rbp+SCRATCH]
 mov r9,[rbp+SCRATCHLEN]
 call QWORD PTR [rbp+CODE]
 mov eax,eax
 mov [r12],rax
 mov edi,1
 lea rsi,[r12+32]
 mov eax,228
 syscall
 test rax,rax
 js child_bad
 mov rax,[r12+32]
 sub rax,[r12+16]
 imul rax,rax,1000000000
 add rax,[r12+40]
 sub rax,[r12+24]
 mov [r12+48],rax
 mov QWORD PTR [r12+8],1
 xor edi,edi
 mov eax,60
 syscall
limit:
 lea rsi,[rbp+512]
 mov eax,160
 syscall
 test rax,rax
 js child_bad
 ret
child_bad:
 mov edi,125
 mov eax,60
 syscall
self_request:
 mov rax,[rbx+16]
 mov [rbp+SEQUENCE],rax
 call release_reply
 mov r13,[rip+.Lself_size_value]
 lea rdi,[r13+64]
 mov [rbp+REPLYLEN],rdi
 mov esi,0x22
 call map_rw
 mov [rbp+REPLY],rax
 mov rdi,rax
 mov rax,0x3130505242414948
 mov [rdi],rax
 mov rax,[rbp+SEQUENCE]
 mov [rdi+8],rax
 mov QWORD PTR [rdi+16],4
 mov [rdi+24],r13
 mov [rdi+32],r13
 add rdi,64
 mov esi,0x400000
 mov rcx,r13
 rep movsb
 mov rdi,[rbp+REPLY]
 mov rsi,[rbp+REPLYLEN]
 call readonly
 jmp call_controller
completed:
 mov rax,[rbx+24]
 mov rdx,[rbx+32]
 cmp rax,[rbp+WORKLEN]
 ja private_fail
 mov rcx,[rbp+WORKLEN]
 sub rcx,rax
 cmp rdx,rcx
 ja private_fail
 mov rsi,[rbp+WORK]
 add rsi,rax
 mov edi,1
 call write_all
 mov edi,2
 mov rsi,rbx
 mov edx,128
 call write_all
 xor edi,edi
 mov eax,60
 syscall
refused:
 mov edi,2
 mov rsi,rbx
 mov edx,128
 call write_all
 mov edi,2
 mov eax,60
 syscall
private_fail:
 mov edi,126
 mov eax,60
 syscall
io_fail:
 mov edi,74
 mov eax,60
 syscall
map_rw:
 mov r10,rsi
 mov rsi,rdi
 xor edi,edi
 mov edx,3
 mov r8,-1
 xor r9d,r9d
 mov eax,9
 syscall
 cmp rax,-4095
 jae io_fail
 ret
readonly:
 mov edx,1
 mov eax,10
 syscall
 test rax,rax
 js io_fail
 ret
release_reply:
 mov rdi,[rbp+REPLY]
 test rdi,rdi
 jz reply_released
 mov rsi,[rbp+REPLYLEN]
 mov eax,11
 syscall
 test rax,rax
 js io_fail
 mov QWORD PTR [rbp+REPLY],0
 mov QWORD PTR [rbp+REPLYLEN],0
reply_released:
 ret
release_peer:
 mov rdi,[rbp+SRC]
 mov rsi,[rbp+SRCLEN]
 test rsi,rsi
 jnz source_release
 mov esi,1
source_release:
 mov eax,11
 syscall
 test rax,rax
 js io_fail
 mov rdi,[rbp+OUT]
 mov rsi,[rbp+OUTLEN]
 mov eax,11
 syscall
 test rax,rax
 js io_fail
 mov rdi,[rbp+SCRATCH]
 mov rsi,[rbp+SCRATCHLEN]
 mov eax,11
 syscall
 test rax,rax
 js io_fail
 mov rdi,[rbp+RESULT]
 mov esi,4096
 mov eax,11
 syscall
 test rax,rax
 js io_fail
 cmp QWORD PTR [rbp+CODEOWN],0
 je peer_released
 mov rdi,[rbp+CODE]
 mov rsi,[rbp+CODELEN]
 mov eax,11
 syscall
 test rax,rax
 js io_fail
peer_released:
 ret
write_all:
 test rdx,rdx
 jz written
write_next:
 mov eax,1
 syscall
 cmp rax,-4
 je write_next
 test rax,rax
 jle io_fail
 add rsi,rax
 sub rdx,rax
 jnz write_next
written:
 ret
.balign 8
.Ldecoder_offset_value:
decoder_offset_value: .quad 0
.Lself_size_value:
self_size_value: .quad 0
