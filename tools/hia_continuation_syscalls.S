/* Fixed Linux x86-64 effects only. HIA chooses every image, phase, frame
 * extent and internal handoff. Embedded images are RX, anonymous state RW.
 * No files, children, loader, libc or runtime assembler are used.
 */
.intel_syntax noprefix
.text
.global _start, policy_hole, metadata_hole, metadata_size_hole
_start:
.Lentry_base:
 mov r15,[rsp]
 xor edi,edi
 mov esi,MAPSIZE
 mov edx,3
 mov r10d,0x22
 mov r8,-1
 xor r9d,r9d
 mov eax,9
 syscall
 cmp rax,-4095
 jae io_exit
 mov rbp,rax
 mov [rbp+PW+16],r15
 /* Ignore SIGPIPE only in this executable, so EPIPE is authoritative. */
 mov QWORD PTR [rbp+256],1
 mov edi,13
 lea rsi,[rbp+256]
 xor edx,edx
 mov r10d,8
 mov eax,13
 syscall
 test rax,rax
 js io_exit
 lea r12,[rip+.Lentry_base]
 .byte 0x49,0x81,0xc4
metadata_hole: .long 0
 mov rdi,r12
 .byte 0xbe
metadata_size_hole: .long 0
policy_next:
 call policy_call
 cmp rax,0
 je success
 cmp rax,1
 je image_call
 cmp rax,2
 je read_packet
 cmp rax,3
 je write_event
 cmp rax,255
 ja protocol_exit
 mov edi,eax
 jmp exit
image_call:
 lea rax,[rip+.Lentry_base]
 add rax,[rbp+PW+136]
 lea rdi,[rbp+PACKET]
 cmp QWORD PTR [rbp+PW+168],0
 je image_input_ready
 lea rdi,[rbp+PW+2048]
image_input_ready:
 mov rsi,[rbp+PW+144]
 lea rdx,[rbp+OUT]
 mov rcx,[rbp+PW+152]
 lea r8,[rbp+UNIT_WORK]
 mov r9,[rbp+PW+160]
 call rax
 /* Preserve the complete 64-bit native result, including dirty high bits. */
 mov [rbp+PW+8],rax
 lea rdi,[rbp+OUT]
 mov rsi,[rbp+PW+152]
 jmp policy_next
read_packet:
 lea rdi,[rbp+PACKET]
 mov esi,4096
 mov edx,3
 mov eax,10
 syscall
 test rax,rax
 js io_exit
 xor r14d,r14d
read_next:
 xor edi,edi
 lea rsi,[rbp+PACKET]
 add rsi,r14
 mov edx,128
 sub rdx,r14
 xor eax,eax
 syscall
 cmp rax,-4
 je read_next
 test rax,rax
 js io_exit
 jz protocol_exit
 add r14,rax
 cmp r14,128
 jb read_next
 lea rdi,[rbp+PACKET]
 mov esi,4096
 mov edx,1
 mov eax,10
 syscall
 test rax,rax
 js io_exit
 lea rdi,[rbp+PACKET]
 mov esi,128
 jmp policy_next
write_event:
 lea r14,[rbp+HEADER]
 mov r15d,64
 call write_all
 lea r14,[rbp+OUT]
 mov r15,[rbp+PW+176]
 call write_all
 lea rdi,[rbp+HEADER]
 xor esi,esi
 jmp policy_next
write_all:
 test r15,r15
 jz write_done
 mov edi,1
 mov rsi,r14
 mov rdx,r15
 mov eax,1
 syscall
 cmp rax,-4
 je write_all
 test rax,rax
 jle io_exit
 add r14,rax
 sub r15,rax
 jmp write_all
write_done:
 ret
policy_call:
 lea rdx,[rbp+HEADER]
 mov ecx,128
 lea r8,[rbp+PW]
 mov r9d,PW_BYTES
 sub rsp,8
 .byte 0xe8
policy_hole: .long 0
 add rsp,8
 ret
success:
 xor edi,edi
 jmp exit
protocol_exit:
 mov edi,16
 jmp exit
io_exit:
 mov edi,15
exit:
 mov eax,60
 syscall
 ud2
