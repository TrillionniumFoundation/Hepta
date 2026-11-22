/* Fixed Linux transport. HIA owns paths, names, modes, sizes, identity,
 * byte layout, SHA admission and final authority. No libc/subprocess. */
.intel_syntax noprefix
.text
.global _start,policy_initial_hole,policy_hole,sha_hole
.equ WIRE,128<<20
.equ WORK,WIRE+4096
.equ PATHBUF,WIRE+69632
.equ SHAIN,WIRE+77824
.equ SHAOUT,WIRE+143368
.equ SHAWORK,WIRE+147456
.equ MAPSIZE,WIRE+155648
.macro retry name
 mov [rbp+WORK+3072],rax
\name:
 mov rax,[rbp+WORK+3072]
 syscall
 cmp rax,-4
 je \name
.endm
.macro gate phase
 mov QWORD PTR [rbp+WORK],\phase
 call policy_call
 test eax,eax
 jnz policy_exit
.endm
.macro statfd fd
 mov rdi,\fd
 lea rsi,[rbp+WORK+416]
 mov eax,5
 retry stat_retry_\@
 test rax,rax
 js io_exit
.endm
_start:
 mov r15,rsp
 cmp QWORD PTR [r15],2
 jne usage
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
 mov QWORD PTR [rbp+WORK+3000],1
 mov edi,13
 lea rsi,[rbp+WORK+3000]
 xor edx,edx
 mov r10d,8
 mov eax,13
 syscall
 test rax,rax
 js io_exit
 mov rdi,[r15+16]
 xor eax,eax
arglen:
 cmp rax,4096
 jae usage
 cmp BYTE PTR [rdi+rax],0
 je argdone
 inc rax
 jmp arglen
argdone:
 mov rsi,rax
 mov rdi,[r15+16]
 lea rdx,[rbp+PATHBUF]
 mov ecx,8192
 lea r8,[rbp+WORK]
 mov r9d,65536
 .byte 0xe8
policy_initial_hole: .long 0
 test eax,eax
 jnz policy_exit
 mov eax,107
 syscall
 mov [rbp+WORK+64],rax
 mov edi,-100
 lea rsi,[rip+slash]
 mov edx,0xb0000
 xor r10d,r10d
 mov eax,257
 retry openroot
 test rax,rax
 js io_exit
 mov r12,rax
 mov ebx,1
walk:
 cmp rbx,[rbp+WORK+88]
 jae walked
 mov rdi,r12
 lea rsi,[rbp+PATHBUF+rbx]
 mov edx,0xb0000
 xor r10d,r10d
 mov eax,257
 retry opencomponent
 test rax,rax
 js io_exit
 mov r13,rax
 mov rdi,r12
 mov eax,3
 syscall
 test rax,rax
 js io_exit
 mov r12,r13
walkskip:
 cmp BYTE PTR [rbp+PATHBUF+rbx],0
 je walknext
 inc rbx
 jmp walkskip
walknext:
 inc rbx
 jmp walk
walked:
 statfd r12
 gate 1
directory_next:
 mov rdi,r12
 lea rsi,[rbp+SHAIN]
 mov edx,65536
 mov eax,217
 retry directory_read
 test rax,rax
 js io_exit
 jz directory_done
 cmp rax,65536
 ja io_exit
 mov [rbp+WORK+96],rax
 gate 8
 jmp directory_next
directory_done:
 gate 9
nextfile:
 gate 2
 mov rdi,r12
 lea rsi,[rbp+WORK+2048]
 mov edx,0xa0800
 xor r10d,r10d
 mov eax,257
 retry openfile
 test rax,rax
 js io_exit
 mov r13,rax
 statfd r13
 gate 3
 xor r14d,r14d
readnext:
 mov rdx,[rbp+WORK+48]
 inc rdx
 sub rdx,r14
 cmp rdx,65536
 jbe readcount
 mov edx,65536
readcount:
 mov rdi,r13
 mov rsi,[rbp+WORK+40]
 add rsi,rbp
 add rsi,r14
 xor eax,eax
 retry fileread
 test rax,rax
 js io_exit
 jz readdone
 add r14,rax
 cmp r14,[rbp+WORK+48]
 ja input_exit
 jmp readnext
readdone:
 mov [rbp+WORK+72],r14
 statfd r13
 gate 4
 mov rdi,r12
 lea rsi,[rbp+WORK+2048]
 lea rdx,[rbp+WORK+416]
 mov r10d,256
 mov eax,262
 retry pathstat
 test rax,rax
 js io_exit
 gate 4
 mov rdi,r13
 mov eax,3
 syscall
 test rax,rax
 js io_exit
 /* No per-file expected digest in this general format. Whole admitted wire
  * is still hashed once below; phase5 only advances captured extent. */
 gate 5
 mov rax,[rbp+WORK+32]
 cmp rax,[rbp+WORK+24]
 jb nextfile
 statfd r12
 gate 6
 mov rdi,r12
 mov eax,3
 syscall
 test rax,rax
 js io_exit
 xor r14d,r14d
 mov r13,[rbp+WORK+56]
 call hash_region
 gate 7
 /* HIA renders exact65-byte final SHA receipt; no hosted package parser. */
 xor r14d,r14d
digest_write:
 mov edi,2
 lea rsi,[rbp+WORK+1536+r14]
 mov edx,65
 sub rdx,r14
 mov [rbp+WORK+3080],rdx
 mov eax,1
 retry digest_outputwrite
 test rax,rax
 jle io_exit
 cmp rax,[rbp+WORK+3080]
 ja io_exit
 add r14,rax
 cmp r14,65
 jb digest_write
 /* Protect admitted wire before the first external byte. */
 mov rdi,rbp
 mov esi,WIRE+4096
 mov edx,1
 mov eax,10
 syscall
 test rax,rax
 js io_exit
 xor r14d,r14d
writenext:
 cmp r14,[rbp+WORK+56]
 je success
 mov edi,1
 lea rsi,[rbp+r14]
 mov rdx,[rbp+WORK+56]
 sub rdx,r14
 mov [rbp+WORK+3080],rdx
 mov eax,1
 retry outputwrite
 test rax,rax
 jle io_exit
 cmp rax,[rbp+WORK+3080]
 ja io_exit
 add r14,rax
 jmp writenext
success:
 xor edi,edi
 jmp exit
hash_region:
 mov BYTE PTR [rbp+SHAIN],0
 mov esi,1
 call sha_call
 test eax,eax
 jnz input_exit
hashnext:
 test r13,r13
 jz hashend
 mov rcx,r13
 cmp rcx,65536
 jbe hashcount
 mov ecx,65536
hashcount:
 mov [rbp+WORK+3096],rcx
 lea rsi,[rbp+r14]
 lea rdi,[rbp+SHAIN+1]
 rep movsb
 mov BYTE PTR [rbp+SHAIN],1
 mov rsi,[rbp+WORK+3096]
 add r14,rsi
 sub r13,rsi
 inc rsi
 call sha_call
 test eax,eax
 jnz input_exit
 jmp hashnext
hashend:
 mov BYTE PTR [rbp+SHAIN],2
 mov esi,1
 call sha_call
 cmp eax,32
 jne input_exit
 lea rsi,[rbp+SHAOUT]
 lea rdi,[rbp+WORK+768]
 mov ecx,32
 rep movsb
 ret
policy_call:
 lea rdi,[rbp+PATHBUF]
 mov rsi,[rbp+WORK+88]
 cmp QWORD PTR [rbp+WORK],8
 jne policy_source_done
 lea rdi,[rbp+SHAIN]
 mov rsi,[rbp+WORK+96]
policy_source_done:
 mov rdx,rbp
 mov ecx,WIRE
 lea r8,[rbp+WORK]
 mov r9d,65536
 sub rsp,8
 .byte 0xe8
policy_hole: .long 0
 add rsp,8
 ret
sha_call:
 lea rdi,[rbp+SHAIN]
 lea rdx,[rbp+SHAOUT]
 mov ecx,32
 lea r8,[rbp+SHAWORK]
 mov r9d,4096
 sub rsp,8
 .byte 0xe8
sha_hole: .long 0
 add rsp,8
 ret
policy_exit:
 mov edi,eax
 jmp exit
usage:
 mov edi,16
 jmp exit
input_exit:
 mov edi,11
 jmp exit
io_exit:
 mov edi,15
exit:
 mov eax,60
 syscall
 ud2
slash: .asciz "/"
