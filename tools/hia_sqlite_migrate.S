/* Fixed Linux effects commissioned by the HIA migration coordinator.
 * Native child bytes are bound in the release; nothing is searched in PATH.
 */
.intel_syntax noprefix
.text
.global _start
.type _start,@function
.extern pager_start, pager_end, staging_start, staging_end
.extern initializer_start, initializer_end, publisher_start, publisher_end

_start:
 cmp QWORD PTR [rsp+8],7
 jne malformed
 mov r15,rsp
 sub rsp,8
 mov edi,3
 mov esi,-1
 xor edx,edx
 mov eax,436
 syscall
 test rax,rax
 jnz io_error
 xor ebx,ebx
stdio_open:
 mov edi,ebx
 mov esi,1
 mov eax,72
 syscall
 test rax,rax
 js io_error
 inc ebx
 cmp ebx,3
 jb stdio_open
 mov eax,39
 syscall
 mov [rip+parent_pid],rax
 lea rsi,[rip+sigpipe]
 mov edi,13
 xor edx,edx
 mov r10d,8
 mov eax,13
 syscall
 test rax,rax
 jnz io_error
 lea rax,[rip+pager_name]
 mov [rip+pager_args],rax
 mov rax,[r15+24]
 mov [rip+pager_args+8],rax
 mov rax,[r15+32]
 mov [rip+pager_args+16],rax
 lea rax,[rip+publisher_name]
 mov [rip+publisher_args],rax
 mov rax,[r15+40]
 mov [rip+publisher_args+8],rax
 mov rax,[r15+48]
 mov [rip+initialize_args+8],rax
 lea rax,[rip+initialize_name]
 mov [rip+initialize_args],rax
 lea rax,[rip+store_name]
 mov [rip+initialize_args+16],rax
 lea rax,[rip+stage_name]
 mov [rip+stage_args],rax
 lea rax,[rip+stage_flag]
 mov [rip+stage_args+8],rax
 mov rax,[r15+56]
 cmp BYTE PTR [rax+1],0
 jne malformed
 movzx eax,BYTE PTR [rax]
 sub eax,'0'
 mov [rip+input],rax
 mov rsi,[r15+64]
 xor eax,eax
 mov ecx,5
profile_digit:
 movzx edx,BYTE PTR [rsi]
 sub edx,'0'
 cmp edx,9
 ja malformed
 imul eax,eax,10
 add eax,edx
 inc rsi
 dec ecx
 jnz profile_digit
 cmp BYTE PTR [rsi],0
 jne malformed
 mov [rip+input+8],rax

next:
 lea rdi,[rip+input]
 mov esi,1312
 lea rdx,[rip+output]
 mov ecx,128
 lea r8,[rip+state]
 mov r9d,64
 call owner
 test eax,eax
 jz receipt
 cmp eax,1
 je open_pager
 cmp eax,2
 je export
 cmp eax,3
 je capture
 cmp eax,4
 je project
 cmp eax,5
 je initialize
 cmp eax,6
 je publish
 cmp eax,7
 je finish
 cmp eax,65
 je failed
 jmp malformed
effect_ok:
 xor eax,eax
effect_status:
 mov [rip+state],rax
 jmp next

open_pager:
 call prepare_destination
 lea rsi,[rip+null_path]
 mov edi,-100
 mov edx,0xa0002
 xor r10d,r10d
 mov eax,257
 syscall
 test rax,rax
 js io_error
 mov [rip+null_fd],eax
 lea rdi,[rip+command_pipe]
 call make_pipe
 lea rdi,[rip+reply_pipe]
 call make_pipe
 lea rdi,[rip+audit_pipe]
 call make_pipe
 mov eax,57
 syscall
 test rax,rax
 js io_error
 jz audit_relay
 mov [rip+audit_pid],eax
 lea rdi,[rip+pager_name]
 lea rsi,[rip+pager_start]
 lea rdx,[rip+pager_end]
 sub rdx,rsi
 call executable
 mov edi,eax
 lea rsi,[rip+pager_args]
 mov edx,[rip+command_pipe]
 mov ecx,[rip+reply_pipe+4]
 mov r8d,[rip+audit_pipe+4]
 call spawn
 mov [rip+pager_pid],eax
 mov edi,[rip+command_pipe]
 call close_fd
 mov edi,[rip+reply_pipe+4]
 call close_fd
 mov edi,[rip+audit_pipe]
 call close_fd
 mov edi,[rip+audit_pipe+4]
 call close_fd
 call command
 call pager_reply
 jmp effect_ok

export:
 call command
 mov edi,[rip+reply_pipe]
 lea rsi,[rip+input+1216]
 mov edx,64
 call read_exact
 jmp effect_ok

capture:
 lea rdi,[rip+snapshot_name]
 call memfd
 mov [rip+snapshot_fd],eax
 mov edi,eax
 lea rsi,[rip+input+1216]
 mov edx,64
 call write_exact
 mov r12,[rip+state+32]
capture_page_bytes:
 mov r13,r12
 cmp r13,65536
 mov eax,65536
 cmova r13,rax
 mov rdx,r13
 mov edi,[rip+reply_pipe]
 lea rsi,[rip+transfer]
 call read_exact
 mov rdx,r13
 mov edi,[rip+snapshot_fd]
 lea rsi,[rip+transfer]
 call write_exact
 sub r12,r13
 jnz capture_page_bytes
 mov edi,[rip+snapshot_fd]
 mov esi,0x100
 call seal
 jmp effect_ok

project:
 lea rdi,[rip+staged_name]
 call memfd
 mov [rip+stage_fd],eax
 lea rdi,[rip+stage_name]
 lea rsi,[rip+staging_start]
 lea rdx,[rip+staging_end]
 sub rdx,rsi
 call executable
 mov edi,eax
 lea rsi,[rip+stage_args]
 mov edx,[rip+snapshot_fd]
 mov ecx,[rip+stage_fd]
 mov r8d,2
 call run
 test eax,eax
 jnz effect_status
 mov edi,[rip+snapshot_fd]
 call close_fd
 mov edi,[rip+stage_fd]
 call extent
 cmp rax,56
 jb failed
 cmp rax,128<<20
 ja failed
 mov edi,[rip+stage_fd]
 mov esi,0x100
 call seal
 mov edi,[rip+stage_fd]
 call read_result
 mov edi,[rip+stage_fd]
 call rewind
 jmp effect_ok

initialize:
 mov edi,[rip+destination_fd]
 lea rsi,[rip+store_name]
 call absent_entry
 mov edi,[rip+destination_fd]
 lea rsi,[rip+artifacts_name]
 mov edx,0x1c0
 mov eax,258
 syscall
 test rax,rax
 jnz failed
 lea rdi,[rip+initialize_name]
 lea rsi,[rip+initializer_start]
 lea rdx,[rip+initializer_end]
 sub rdx,rsi
 call executable
 mov edi,eax
 lea rsi,[rip+initialize_args]
 mov edx,[rip+null_fd]
 mov ecx,edx
 mov r8d,2
 call run
 jmp effect_status

publish:
 lea rdi,[rip+durable_name]
 call memfd
 mov [rip+durable_fd],eax
 lea rdi,[rip+publisher_name]
 lea rsi,[rip+publisher_start]
 lea rdx,[rip+publisher_end]
 sub rdx,rsi
 call executable
 mov edi,eax
 lea rsi,[rip+publisher_args]
 mov edx,[rip+stage_fd]
 mov ecx,[rip+durable_fd]
 mov r8d,2
 call run
 test eax,eax
 jnz effect_status
 mov edi,[rip+durable_fd]
 call extent
 cmp rax,32
 jne failed
 mov edi,[rip+durable_fd]
 call rewind
 mov edi,[rip+durable_fd]
 call read_result
 jmp effect_ok

finish:
 call command
 call pager_reply
 mov edi,[rip+command_pipe+4]
 call close_fd
 mov edi,[rip+pager_pid]
 call wait_child
 test eax,eax
 jnz effect_status
 mov edi,[rip+audit_pid]
 call wait_child
 jmp effect_status

audit_relay:
 call hold_parent
 mov edi,[rip+command_pipe]
 call close_fd
 mov edi,[rip+command_pipe+4]
 call close_fd
 mov edi,[rip+reply_pipe]
 call close_fd
 mov edi,[rip+reply_pipe+4]
 call close_fd
 mov edi,[rip+audit_pipe+4]
 call close_fd
audit_read:
 mov edi,[rip+audit_pipe]
 lea rsi,[rip+transfer]
 mov edx,65536
 xor eax,eax
 syscall
 cmp rax,-4
 je audit_read
 test rax,rax
 js io_error
 jz success
 mov rdx,rax
 mov edi,2
 lea rsi,[rip+transfer]
 call write_exact
 jmp audit_read

prepare_destination:
 mov rsi,[rip+pager_args+8]
 call open_directory
 mov ebx,eax
 mov edi,eax
 lea rsi,[rip+source_stat]
 call identity
 mov edi,ebx
 call close_fd
 mov rsi,[rip+initialize_args+8]
 call open_directory
 mov [rip+destination_fd],eax
 mov edi,eax
 lea rsi,[rip+target_stat]
 call identity
 cmp DWORD PTR [rip+target_stat+24],0x41c0
 jne failed
 mov eax,107
 syscall
 cmp DWORD PTR [rip+target_stat+28],eax
 jne failed
 mov rax,[rip+source_stat]
 cmp [rip+target_stat],rax
 jne path_names
 mov rax,[rip+source_stat+8]
 cmp [rip+target_stat+8],rax
 je failed
path_names:
 mov rsi,[rip+initialize_args+8]
 lea rdi,[rip+artifacts_path]
 lea rdx,[rip+artifacts_name]
 call join_path
 lea rax,[rip+artifacts_path]
 mov [rip+publisher_args+16],rax
 mov rsi,[rip+initialize_args+8]
 lea rdi,[rip+store_path]
 lea rdx,[rip+store_name]
 call join_path
 lea rax,[rip+store_path]
 mov [rip+publisher_args+24],rax
 ret
join_path:
 mov ecx,4085
path_next:
 lodsb
 test al,al
 jz path_suffix
 stosb
 dec ecx
 jnz path_next
 jmp malformed
path_suffix:
 mov al,'/'
 stosb
 mov rsi,rdx
suffix_next:
 lodsb
 stosb
 test al,al
 jnz suffix_next
 ret
open_directory:
 mov edi,-100
 mov edx,0xb0000
 xor r10d,r10d
 mov eax,257
 syscall
 cmp rax,-4
 je open_directory
 test rax,rax
 js failed
 ret
identity:
 mov eax,5
 syscall
 cmp rax,-4
 je identity
 test rax,rax
 jnz io_error
 ret
absent_entry:
 lea rdx,[rip+target_stat]
 mov r10d,256
 mov eax,262
 syscall
 cmp rax,-4
 je absent_entry
 cmp rax,-2
 jne failed
 ret

command:
 mov edi,[rip+command_pipe+4]
 lea rsi,[rip+output]
 mov edx,128
 jmp write_exact
pager_reply:
 mov edi,[rip+reply_pipe]
 lea rsi,[rip+input+64]
 mov edx,1152
 jmp read_exact
read_result:
 lea rsi,[rip+input+1280]
 mov edx,32
 jmp read_exact
make_pipe:
 mov esi,0x80000
 mov eax,293
 syscall
 test rax,rax
 jnz io_error
 ret
close_fd:
 mov eax,3
 syscall
 ret
wait_child:
 lea rsi,[rip+wait_status]
 xor edx,edx
 xor r10d,r10d
 mov eax,61
 syscall
 cmp rax,-4
 je wait_child
 test rax,rax
 js io_error
 mov eax,[rip+wait_status]
 ret
run:
 call spawn
 mov edi,eax
 jmp wait_child
spawn:
 mov [rip+exec_fd],edi
 mov [rip+exec_args],rsi
 mov [rip+exec_input],edx
 mov [rip+exec_output],ecx
 mov [rip+exec_errors],r8d
 mov eax,57
 syscall
 test rax,rax
 js io_error
 jnz parent
 call hold_parent
 mov edi,[rip+exec_input]
 xor esi,esi
 call duplicate
 mov edi,[rip+exec_output]
 mov esi,1
 call duplicate
 mov edi,[rip+exec_errors]
 mov esi,2
 call duplicate
 mov edi,[rip+exec_fd]
 lea rsi,[rip+empty_name]
 mov rdx,[rip+exec_args]
 lea r10,[rip+empty_environment]
 mov r8d,0x1000
 mov eax,322
 syscall
 jmp io_error
parent:
 ret
hold_parent:
 mov edi,1
 mov esi,9
 xor edx,edx
 xor r10d,r10d
 xor r8d,r8d
 mov eax,157
 syscall
 test rax,rax
 jnz io_error
 mov eax,110
 syscall
 cmp rax,[rip+parent_pid]
 jne io_error
 ret
duplicate:
 cmp edi,esi
 je parent
 mov eax,33
 syscall
 cmp rax,-4
 je duplicate
 test rax,rax
 js io_error
 ret

executable:
 push rsi
 push rdx
 call memfd
 pop rdx
 pop rsi
 push rax
 mov edi,eax
 call write_exact
 mov edi,[rsp]
 mov esi,0x140
 call seal
 pop rax
 ret
memfd:
 mov esi,3
 mov eax,319
 syscall
 test rax,rax
 js io_error
 ret
seal:
 mov r8d,edi
 mov eax,91
 syscall
 test rax,rax
 jnz io_error
 mov edi,r8d
 mov esi,1033
 mov edx,15
 mov eax,72
 syscall
 test rax,rax
 jnz io_error
 mov edi,r8d
rewind:
 xor edx,edx
 jmp seek
extent:
 mov edx,2
seek:
 xor esi,esi
 mov eax,8
 syscall
 cmp rax,-4
 je seek
 test rax,rax
 js io_error
 ret
read_exact:
 xor eax,eax
 syscall
 cmp rax,-4
 je read_exact
 test rax,rax
 js io_error
 jz failed
 add rsi,rax
 sub rdx,rax
 jnz read_exact
 ret
write_exact:
 mov eax,1
 syscall
 cmp rax,-4
 je write_exact
 test rax,rax
 jle io_error
 add rsi,rax
 sub rdx,rax
 jnz write_exact
 ret

receipt:
 mov edi,1
 lea rsi,[rip+output]
 mov edx,32
 call write_exact
success:
 xor edi,edi
 jmp exit
malformed:
 mov edi,64
 jmp exit
failed:
 mov edi,65
 jmp exit
io_error:
 mov edi,74
exit:
 mov eax,60
 syscall
 ud2
.size _start,.-_start

null_path: .asciz "/dev/null"
pager_name: .asciz "hia-sqlite-pager"
stage_name: .asciz "hia-sqlite-migration-projection"
stage_flag: .asciz "--stage"
initialize_name: .asciz "hia-agent-store-init"
publisher_name: .asciz "hia-sqlite-migration-publish"
snapshot_name: .asciz "hia-migration-snapshot"
staged_name: .asciz "hia-migration-staged"
durable_name: .asciz "hia-migration-durable"
artifacts_name: .asciz "artifacts"
store_name: .asciz "store"
empty_name: .byte 0
.balign 8
sigpipe: .quad 1,0,0,0
.balign 16
owner: .incbin "sqlite-migrate.image.bin"

.bss
.balign 8
parent_pid: .skip 8
empty_environment: .skip 8
input: .skip 1312
output: .skip 128
state: .skip 64
source_stat: .skip 144
target_stat: .skip 144
pager_args: .skip 32
stage_args: .skip 24
initialize_args: .skip 32
publisher_args: .skip 40
exec_args: .skip 8
exec_fd: .skip 4
exec_input: .skip 4
exec_output: .skip 4
exec_errors: .skip 4
destination_fd: .skip 4
null_fd: .skip 4
pager_pid: .skip 4
audit_pid: .skip 4
wait_status: .skip 4
snapshot_fd: .skip 4
stage_fd: .skip 4
durable_fd: .skip 4
command_pipe: .skip 8
reply_pipe: .skip 8
audit_pipe: .skip 8
artifacts_path: .skip 4096
store_path: .skip 4096
transfer: .skip 65536
.section .note.GNU-stack,"",@progbits
