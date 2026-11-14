/* Fixed standalone native custodian, UNCOMPILED bootstrap source.
 *
 * fd0: 128-byte client command frames; fd1: result128 + diagnostic1024 +
 * PAGE bytes when status129. fd3: inherited held directory. fd4: mandatory
 * lossless audit pipe, drained by the custodian. argv[1]: DB basename.
 *
 * HIA is the only source of file/lock/map/retry/page-source requests.
 * This file only frames IPC, owns allocations, calls two fixed entries,
 * copies exact receipts, and ends the process on failed transport custody.
 * It never invokes libc, Python, a SQL engine, or an arbitrary function.
 */
.intel_syntax noprefix
.text
.global _start
.type _start,@function
.extern pager_hia_entry
.extern pager_os_once
.equ EV,0
.equ REQ,69632
.equ IO,73728
.equ W,143360
.equ CTX,217088
.equ DR,221184
.equ MAPSIZE,225280
.equ EVENT_MAGIC,0x3256454750414948
.equ CONTEXT_MAGIC,0x32585443534f4750
.equ AUDIT_MAGIC,0x3255414750414948

_start:
 mov r15,rsp
 cmp QWORD PTR [r15],2
 jne driver_usage
 xor edi,edi
 mov esi,MAPSIZE
 mov edx,3
 mov r10d,0x22
 mov r8,-1
 xor r9d,r9d
 mov eax,9
 syscall
 cmp rax,-4095
 jae driver_io_exit
 mov rbp,rax
 mov rax,CONTEXT_MAGIC
 mov [rbp+CTX],rax
 mov QWORD PTR [rbp+CTX+8],2
 mov QWORD PTR [rbp+CTX+24],3
 mov QWORD PTR [rbp+CTX+32],-1
 mov QWORD PTR [rbp+CTX+40],-1
 mov QWORD PTR [rbp+CTX+48],-1
 /* Bootstrap capability check only; no DB/WAL file is opened here. */
 mov edi,3
 lea rsi,[rbp+DR+512]
 mov eax,5
 syscall
 test rax,rax
 jnz driver_io_exit
 mov eax,DWORD PTR [rbp+DR+536]
 and eax,0xf000
 cmp eax,0x4000
 jne driver_usage
 /* fd4 is a pipe by native admission, before BEGIN or any DB/WAL effect.
  * fstat's raw nonzero result (including EBADF) takes the existing IO exit;
  * a valid non-FIFO descriptor takes the existing usage refusal.
  */
 mov edi,4
 lea rsi,[rbp+DR+512]
 mov eax,5
 syscall
 test rax,rax
 jnz driver_io_exit
 mov eax,DWORD PTR [rbp+DR+536]
 and eax,0xf000
 cmp eax,0x1000
 jne driver_usage
 /* One Linux NAME_MAX-compatible basename; derived suffix names are exact. */
 mov rsi,[r15+16]
 xor ecx,ecx
basename_next:
 cmp ecx,252
 jae driver_usage
 mov al,[rsi+rcx]
 test al,al
 jz basename_end
 cmp al,'/'
 je driver_usage
 mov [rbp+CTX+rcx+256],al
 mov [rbp+CTX+rcx+512],al
 mov [rbp+CTX+rcx+768],al
 inc ecx
 jmp basename_next
basename_end:
 test ecx,ecx
 jz driver_usage
 cmp BYTE PTR [rbp+CTX+256],'.'
 jne basename_valid
 cmp ecx,1
 je driver_usage
 cmp ecx,2
 jne basename_valid
 cmp BYTE PTR [rbp+CTX+257],'.'
 je driver_usage
basename_valid:
 mov DWORD PTR [rbp+CTX+rcx+512],0x6c61772d
 mov DWORD PTR [rbp+CTX+rcx+768],0x6d68732d
 /* Fresh mmap bytes provide all string terminators and zero private state. */

client_next:
 xor r12d,r12d
client_read:
 xor edi,edi
 lea rsi,[rbp+EV+r12]
 mov edx,128
 sub rdx,r12
 xor eax,eax
 syscall
 cmp rax,-4
 je client_read
 test rax,rax
 js driver_io_exit
 jz client_eof
 add r12,rax
 cmp r12,128
 jb client_read
 cmp QWORD PTR [rbp+EV+56],0
 jne driver_protocol_exit
 mov rax,[rbp+EV+24]
 cmp rax,1
 je client_kind_ok
 cmp rax,3
 je client_kind_ok
 cmp rax,4
 jne driver_protocol_exit
client_kind_ok:
 cmp QWORD PTR [rbp+W],0
 jne kernel_loop
 mov rax,[rbp+EV+16]
 mov [rbp+CTX+16],rax
 jmp kernel_loop

client_eof:
 test r12,r12
 jnz driver_protocol_exit
 cmp QWORD PTR [rbp+W+8],200
 jne driver_protocol_exit
 /* Clean command EOF means CLOSE only when HIA is READY with no loan. */
 call clear_event
 mov QWORD PTR [rbp+EV+24],4
 mov r12d,128

kernel_loop:
 /* Complete raw HIA input before the actual fixed entry. */
 mov edi,10
 lea rsi,[rbp+EV]
 mov rdx,r12
 xor ecx,ecx
 call audit_record
 mov edi,13
 lea rsi,[rbp+REQ]
 mov edx,128
 xor ecx,ecx
 call audit_record
 mov edi,14
 lea rsi,[rbp+W]
 mov edx,73728
 xor ecx,ecx
 call audit_record
 lea rdi,[rbp+EV]
 mov rsi,r12
 lea rdx,[rbp+REQ]
 mov ecx,128
 lea r8,[rbp+W]
 mov r9d,73728
 call pager_hia_entry
 mov eax,eax
 mov [rbp+DR],rax
 /* Raw result/output and complete state are retained before any projection
  * or the next OS effect. This includes secondary cleanup errors and prefix. */
 mov edi,11
 lea rsi,[rbp+REQ]
 mov edx,128
 mov rcx,[rbp+DR]
 call audit_record
 mov edi,12
 lea rsi,[rbp+W]
 mov edx,73728
 mov rcx,[rbp+DR]
 call audit_record
 mov rax,[rbp+DR]
 cmp rax,1
 je os_action
 cmp rax,128
 je ready_result
 cmp rax,129
 je page_result
 cmp rax,130
 je closed_result
 cmp rax,131
 je failed_result
 cmp rax,132
 je owned_failure_result
 jmp driver_protocol_exit

os_action:
 mov edi,20
 lea rsi,[rbp+REQ]
 mov edx,128
 xor ecx,ecx
 call audit_record
 mov edi,22
 lea rsi,[rbp+IO]
 mov edx,65664
 xor ecx,ecx
 call audit_record
 mov edi,23
 lea rsi,[rbp+CTX]
 mov edx,4096
 xor ecx,ecx
 call audit_record
 lea rdi,[rbp+REQ]
 mov esi,128
 lea rdx,[rbp+IO]
 mov ecx,65664
 lea r8,[rbp+CTX]
 mov r9d,4096
 call pager_os_once
 mov eax,eax
 mov [rbp+DR+24],rax
 /* Preserve full returned spans and raw u32 before any ABI/receipt assertion. */
 mov edi,21
 lea rsi,[rbp+IO]
 mov edx,65664
 mov rcx,[rbp+DR+24]
 call audit_record
 mov edi,25
 lea rsi,[rbp+CTX]
 mov edx,4096
 mov rcx,[rbp+DR+24]
 call audit_record
 cmp QWORD PTR [rbp+DR+24],0
 jne driver_protocol_exit
 mov rax,0x324f494750414948
 cmp [rbp+IO],rax
 jne driver_protocol_exit
 cmp QWORD PTR [rbp+IO+8],2
 jne driver_protocol_exit
 cmp QWORD PTR [rbp+IO+48],65536
 ja driver_protocol_exit
 mov ecx,56
receipt_reserved:
 cmp QWORD PTR [rbp+IO+rcx],0
 jne driver_protocol_exit
 add ecx,8
 cmp ecx,128
 jb receipt_reserved
 call clear_event
 mov rax,[rbp+IO+16]
 mov [rbp+EV+16],rax
 mov QWORD PTR [rbp+EV+24],2
 mov rax,[rbp+IO+24]
 mov [rbp+EV+32],rax
 mov rax,[rbp+IO+32]
 mov [rbp+EV+40],rax
 mov rax,[rbp+IO+40]
 mov [rbp+EV+48],rax
 mov rcx,[rbp+IO+48]
 mov [rbp+EV+56],rcx
 mov r12,rcx
 add r12,128
 lea rsi,[rbp+IO+128]
 lea rdi,[rbp+EV+128]
 rep movsb
 jmp kernel_loop

ready_result:
 cmp QWORD PTR [rbp+DR+16],0
 je publish_ready
 mov QWORD PTR [rbp+DR+16],0
 jmp client_next
publish_ready:
 call publish_result
 jmp client_next

page_result:
 call publish_result
 mov edi,1
 lea rsi,[rbp+W+4096]
 mov rdx,[rbp+W+128]
 call write_exact
 /* A PAGE loan is released only after every result byte reached the pipe.
  * No fresh read may overwrite its memory while a short write is pending. */
 call clear_event
 mov QWORD PTR [rbp+EV+24],5
 mov rax,[rbp+W+280]
 mov [rbp+EV+64],rax
 mov QWORD PTR [rbp+DR+16],1
 mov r12d,128
 jmp kernel_loop

closed_result:
 call publish_result
 xor edi,edi
 jmp driver_exit
failed_result:
 call publish_result
 mov edi,1
 jmp driver_exit
owned_failure_result:
 call publish_result
 /* HIA did not report resource release. Kernel process termination is a
  * separate observable custody event, never a rewritten CLOSED success. */
 mov edi,2
 jmp driver_exit

clear_event:
 lea rdi,[rbp+EV]
 xor eax,eax
 mov ecx,16
 rep stosq
 mov rax,EVENT_MAGIC
 mov [rbp+EV],rax
 mov QWORD PTR [rbp+EV+8],2
 mov rax,[rbp+CTX+16]
 mov [rbp+EV+16],rax
 ret

publish_result:
 sub rsp,8
 mov edi,1
 lea rsi,[rbp+REQ]
 mov edx,128
 call write_exact
 mov edi,1
 lea rsi,[rbp+W]
 mov edx,1024
 call write_exact
 add rsp,8
 ret

/* (type, body, bytes, raw_status). Every write is exact and ordered.
 * The audit sink is a required private pipe. Failure terminates the owner;
 * no subsequent request can run without its preceding raw evidence.
 */
audit_record:
 push r12
 push r13
 push r14
 push r15
 sub rsp,8
 mov r12,rdi
 mov r13,rsi
 mov r14,rdx
 mov r15,rcx
 mov rax,AUDIT_MAGIC
 mov [rbp+DR+256],rax
 mov QWORD PTR [rbp+DR+264],2
 mov rax,[rbp+CTX+16]
 mov [rbp+DR+272],rax
 mov rax,[rbp+DR+8]
 inc rax
 jz driver_protocol_exit
 mov [rbp+DR+8],rax
 mov [rbp+DR+280],rax
 mov [rbp+DR+288],r12
 mov [rbp+DR+296],r14
 mov [rbp+DR+304],r15
 mov rax,[rbp+W+24]
 mov [rbp+DR+312],rax
 mov edi,4
 lea rsi,[rbp+DR+256]
 mov edx,64
 call write_exact
 mov edi,4
 mov rsi,r13
 mov rdx,r14
 call write_exact
 add rsp,8
 pop r15
 pop r14
 pop r13
 pop r12
 ret

/* IPC transport short writes/EINTR only. No file/Pager retry policy. */
write_exact:
 mov r10,rdi
 mov r8,rsi
 mov r9,rdx
write_next:
 test r9,r9
 jz write_done
 mov rdi,r10
 mov rsi,r8
 mov rdx,r9
 mov eax,1
 syscall
 cmp rax,-4
 je write_next
 test rax,rax
 jle driver_io_exit
 add r8,rax
 sub r9,rax
 jmp write_next
write_done:
 ret

driver_usage:
 mov edi,64
 jmp driver_exit
driver_protocol_exit:
 mov edi,65
 jmp driver_exit
driver_io_exit:
 mov edi,74
driver_exit:
 mov eax,60
 syscall
 ud2
.size _start,.-_start
.section .note.GNU-stack,"",@progbits
