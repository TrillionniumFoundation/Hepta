/* Linux transport for the HIA migration publisher.
 * The HIA owner validates the frame and issues one bounded effect at a time.
 * Only two exact embedded executables may run; stdout is a single receipt.
 */
.intel_syntax noprefix
.text
.global _start
.type _start,@function
.equ CAPACITY,128<<20
.equ CATALOG_CAPACITY,64<<20

_start:
 cmp QWORD PTR [rsp+8],4
 jne usage
 mov rax,[rsp+24]
 mov [rip+old_artifacts],rax
 mov rax,[rsp+32]
 mov [rip+new_artifacts],rax
 mov rax,[rsp+40]
 mov [rip+store_path],rax
 sub rsp,8
 mov edi,3
 mov esi,-1
 xor edx,edx
 mov eax,436                  /* close_range: only stdio is inherited */
 syscall
 test rax,rax
 jnz io_error
 xor ebx,ebx
stdio_open:
 mov edi,ebx
 mov esi,1                     /* F_GETFD */
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
 lea rsi,[rip+header]
 mov edx,32
 call read_exact
 lea rdi,[rip+header]
 mov r12d,32
 mov ecx,1
begin_length:
 mov rax,[rdi+rcx*8]
 cmp rax,CAPACITY
 ja bad_input
 add r12,rax
 inc ecx
 cmp ecx,4
 jb begin_length
 cmp r12,56
 jb bad_input
 cmp r12,CAPACITY
 ja bad_input
 mov rsi,r12
 call allocate
 mov r13,rax
 mov rdi,r13
 lea rsi,[rip+header]
 mov ecx,4
 rep movsq
 lea rsi,[r13+32]
 mov rdx,r12
 sub rdx,32
 call read_exact
framing_eof:
 xor edi,edi
 lea rsi,[rip+spare_byte]
 mov edx,1
 xor eax,eax
 syscall
 cmp rax,-4
 je framing_eof
 test rax,rax
 js io_error
 jnz bad_input
 mov rdi,r13
 mov rsi,r12
 mov edx,1
 mov eax,10
 syscall
 test rax,rax
 jnz io_error
 mov esi,CATALOG_CAPACITY
 call allocate
 mov r14,rax
 lea r15,[rip+state]

next:
 mov rdi,r13
 mov rsi,r12
 mov rdx,r14
 mov ecx,CATALOG_CAPACITY
 mov r8,r15
 mov r9d,48
 call owner
 test eax,eax
 jz publish_receipt
 cmp eax,64
 jae refusal
 mov ebx,eax
 cmp ebx,5
 je completed
 cmp ebx,6
 je check_target
 mov rax,[r15+16]
 cmp rax,r12
 ja bad_input
 mov rdx,r12
 sub rdx,rax
 cmp [r15+24],rdx
 ja bad_input
 lea rdi,[r13+rax]
 mov rsi,[r15+24]
 cmp ebx,1
 je catalog
 cmp ebx,2
 je artifact
 cmp ebx,3
 je transaction
 cmp ebx,4
 jne bad_input
 jmp transaction
completed:
 xor eax,eax
save_result:
 mov eax,eax
 mov [r15],rax
 jmp next
check_target:
 mov edi,-100
 mov rsi,[rip+store_path]
 mov edx,0xb0000
 xor r10d,r10d
 mov eax,257
 syscall
 cmp rax,-4
 je check_target
 test rax,rax
 js rejected_target
 mov [rip+probe_fd],eax
 mov edi,eax
 lea rsi,[rip+stat_bytes]
 mov eax,5
 syscall
 test rax,rax
 jnz close_target
 cmp DWORD PTR [rip+stat_bytes+24],0x41c0 /* owned directory, exactly 0700 */
 jne close_target
 mov eax,107                            /* geteuid */
 syscall
 cmp DWORD PTR [rip+stat_bytes+28],eax
 jne close_target
 mov [rip+owner_uid],eax
 lea rsi,[rip+anchor_zero]
 call stat_target_entry
 test rax,rax
 jnz close_target
 cmp DWORD PTR [rip+stat_bytes+24],0x8100 /* immutable ordinary anchor, 0400 */
 jne close_target
 mov eax,[rip+owner_uid]
 cmp DWORD PTR [rip+stat_bytes+28],eax
 jne close_target
 cmp QWORD PTR [rip+stat_bytes+16],1     /* link count */
 jne close_target
 cmp QWORD PTR [rip+stat_bytes+48],128
 jne close_target
 lea rsi,[rip+anchor_one]
 call stat_target_entry
 cmp rax,-2
 jne close_target
 lea rsi,[rip+wal_name]
 call stat_target_entry
 test rax,rax
 jnz close_target
 cmp DWORD PTR [rip+stat_bytes+24],0x8180 /* ordinary private WAL, 0600 */
 jne close_target
 mov eax,[rip+owner_uid]
 cmp DWORD PTR [rip+stat_bytes+28],eax
 jne close_target
 cmp QWORD PTR [rip+stat_bytes+16],1
 jne close_target
 cmp QWORD PTR [rip+stat_bytes+48],0
 jne close_target
 mov edi,[rip+probe_fd]
 call close_fd
 jmp completed
close_target:
 mov edi,[rip+probe_fd]
 call close_fd
rejected_target:
 mov eax,65
 jmp refusal
stat_target_entry:
 mov edi,[rip+probe_fd]
 lea rdx,[rip+stat_bytes]
 mov r10d,256                            /* AT_SYMLINK_NOFOLLOW */
 mov eax,262                            /* newfstatat */
 syscall
 cmp rax,-4
 je stat_target_entry
 ret
catalog:
 mov rcx,[r13+16]
 cmp rcx,CATALOG_CAPACITY-32
 ja bad_input
 lea rdx,[r14+32]
 lea r8,[rip+spare_byte]
 xor r9d,r9d
 call artifact_catalog
 jmp save_result

artifact:
 cmp rsi,64
 jne bad_input
 mov rsi,rdi
 lea rdi,[rip+digest_name]
 mov ecx,8
 rep movsq
 call prepare_helpers
 lea rdi,[rip+payload_name]
 call memfd
 mov [rip+tx_fd],eax
 mov eax,57
 syscall
 test rax,rax
 js io_error
 jz child_get
 mov edi,eax
 call wait_child
 test eax,eax
 jnz finish_artifact
 /* Publish nothing until the source executable has verified every byte. */
 mov edi,[rip+tx_fd]
 mov esi,0x100
 call finish_memfd
 mov eax,57
 syscall
 test rax,rax
 js io_error
 jz child_put
 mov edi,eax
 call wait_child
finish_artifact:
 mov ebx,eax
 mov edi,[rip+tx_fd]
 call close_fd
 mov eax,ebx
 jmp save_result
child_get:
 mov edi,[rip+null_fd]
 xor esi,esi
 call dup_to
 mov edi,[rip+tx_fd]
 mov esi,1
 call dup_to
 lea rsi,[rip+args_get]
 lea rax,[rip+artifact_name]
 mov [rsi],rax
 lea rax,[rip+get_name]
 mov [rsi+8],rax
 mov rax,[rip+old_artifacts]
 mov [rsi+16],rax
 lea rax,[rip+digest_name]
 mov [rsi+24],rax
 mov edi,[rip+artifact_fd]
 jmp execute_child
child_put:
 mov edi,[rip+tx_fd]
 xor esi,esi
 call dup_to
 mov edi,[rip+null_fd]
 mov esi,1
 call dup_to
 lea rsi,[rip+args_put]
 lea rax,[rip+artifact_name]
 mov [rsi],rax
 lea rax,[rip+put_name]
 mov [rsi+8],rax
 mov rax,[rip+new_artifacts]
 mov [rsi+16],rax
 lea rax,[rip+dash_name]
 mov [rsi+24],rax
 mov edi,[rip+artifact_fd]
 jmp execute_child

transaction:
 mov [rip+tx_address],rdi
 mov [rip+tx_size],rsi
 call prepare_helpers
 lea rdi,[rip+frame_name]
 call memfd
 mov [rip+tx_fd],eax
 mov edi,eax
 lea rsi,[rip+tx_size]
 mov edx,8
 call write_exact
 mov edi,[rip+tx_fd]
 mov rsi,[rip+tx_address]
 mov rdx,[rip+tx_size]
 call write_exact
 mov edi,[rip+tx_fd]
 mov esi,0x100
 call finish_memfd
 mov eax,57
 syscall
 test rax,rax
 js io_error
 jz child_commit
 mov ebx,eax
 mov edi,[rip+tx_fd]
 call close_fd
 mov edi,ebx
 call wait_child
 jmp save_result
child_commit:
 mov edi,[rip+tx_fd]
 xor esi,esi
 call dup_to
 mov edi,[rip+null_fd]
 mov esi,1
 call dup_to
 lea rsi,[rip+args_write]
 lea rax,[rip+writer_name]
 mov [rsi],rax
 mov rax,[rip+store_path]
 mov [rsi+8],rax
 cmp ebx,3
 je execute_writer
 lea rax,[rip+generation_zero]
 cmp QWORD PTR [r15+40],2
 jne use_generation
 lea rax,[rip+generation_one]
use_generation:
 mov [rsi+16],rax
execute_writer:
 mov edi,[rip+writer_fd]

execute_child:
 mov r12d,edi
 mov r13,rsi
 mov edi,1                     /* PR_SET_PDEATHSIG */
 mov esi,9
 xor edx,edx
 xor r10d,r10d
 xor r8d,r8d
 mov eax,157
 syscall
 test rax,rax
 jnz io_error
 mov eax,110                   /* getppid, closing the death-notification race */
 syscall
 cmp rax,[rip+parent_pid]
 jne io_error
 mov edi,r12d
 lea rsi,[rip+empty_name]
 mov rdx,r13
 lea r10,[rip+empty_environment]
 mov r8d,0x1000                /* AT_EMPTY_PATH */
 mov eax,322                   /* execveat */
 syscall
 jmp io_error

prepare_helpers:
 cmp DWORD PTR [rip+null_fd],0
 jne helpers_ready
 lea rsi,[rip+null_path]
 mov edi,-100
 mov edx,0xa0002               /* CLOEXEC | NOFOLLOW | RDWR */
 xor r10d,r10d
 mov eax,257
 syscall
 test rax,rax
 js io_error
 mov [rip+null_fd],eax
 lea rdi,[rip+artifact_name]
 lea rsi,[rip+artifact_elf]
.ifdef HIA_MIGRATION_EMBEDDED_OBJECTS
 lea rdx,[rip+artifact_end]
 sub rdx,rsi
.else
 mov edx,artifact_end-artifact_elf
.endif
 call executable_memfd
 mov [rip+artifact_fd],eax
 lea rdi,[rip+writer_name]
 lea rsi,[rip+writer_elf]
.ifdef HIA_MIGRATION_EMBEDDED_OBJECTS
 lea rdx,[rip+writer_end]
 sub rdx,rsi
.else
 mov edx,writer_end-writer_elf
.endif
 call executable_memfd
 mov [rip+writer_fd],eax
helpers_ready:
 ret
executable_memfd:
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
 call finish_memfd
 pop rax
 ret
memfd:
 mov esi,3                     /* CLOEXEC | ALLOW_SEALING */
 mov eax,319
 syscall
 test rax,rax
 js io_error
 ret
finish_memfd:
 mov r8d,edi
 mov eax,91                    /* fchmod */
 syscall
 test rax,rax
 jnz io_error
 mov edi,r8d
 mov esi,1033                  /* F_ADD_SEALS */
 mov edx,15
 mov eax,72
 syscall
 test rax,rax
 jnz io_error
 mov edi,r8d
 xor esi,esi
 xor edx,edx
 mov eax,8                     /* lseek */
 syscall
 test rax,rax
 jnz io_error
 ret

dup_to:
 cmp edi,esi
 je same_fd
 mov eax,33                    /* dup2 */
 syscall
 cmp rax,-4
 je dup_to
 test rax,rax
 js io_error
same_fd:
 ret
close_fd:
 mov eax,3
 syscall
 ret
wait_child:
 lea rsi,[rip+wait_status]
 xor edx,edx
 xor r10d,r10d
 mov eax,61                    /* wait4 */
 syscall
 cmp rax,-4
 je wait_child
 test rax,rax
 js io_error
 mov eax,[rip+wait_status]
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
read_exact:
 xor edi,edi
 xor eax,eax
 syscall
 cmp rax,-4
 je read_exact
 test rax,rax
 js io_error
 jz bad_input
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
publish_receipt:
 mov edi,1
 mov rsi,r14
 mov edx,32
 call write_exact
 xor edi,edi
 jmp exit
usage:
bad_input:
 mov edi,64
 jmp exit
refusal:
 cmp eax,65
 ja bad_input
 mov edi,eax
 jmp exit
io_error:
 mov edi,74
exit:
 mov eax,60
 syscall
 ud2
.size _start,.-_start

null_path: .asciz "/dev/null"
artifact_name: .asciz "hia-artifact"
writer_name: .asciz "hia-agent-batch-commit"
get_name: .asciz "store-get"
put_name: .asciz "store-put"
dash_name: .asciz "-"
generation_zero: .asciz "0000000000000000"
generation_one: .asciz "0000000000000001"
frame_name: .asciz "hia-migration-transaction"
payload_name: .asciz "hia-migration-artifact"
anchor_zero: .asciz "anchor.0000000000000000"
anchor_one: .asciz "anchor.0000000000000001"
wal_name: .asciz "wal.data"
empty_name: .byte 0
.balign 8
sigpipe: .quad 1,0,0,0
.ifdef HIA_MIGRATION_EMBEDDED_OBJECTS
.set owner, migration_publish_start
.set artifact_catalog, migration_artifact_catalog_start
.set artifact_elf, migration_artifact_start
.set artifact_end, migration_artifact_end
.set writer_elf, migration_writer_start
.set writer_end, migration_writer_end
.else
.balign 16
owner: .incbin "sqlite-migration-publish.image.bin"
.balign 16
artifact_catalog: .incbin "sqlite-agent-artifact-catalog.image.bin"
.balign 16
artifact_elf: .incbin "hia-artifact.embedded.elf"
artifact_end:
.balign 16
writer_elf: .incbin "hia-agent-batch-commit.embedded.elf"
writer_end:
.endif

.bss
.balign 8
state: .skip 48
header: .skip 32
args_get: .skip 40
args_put: .skip 40
args_write: .skip 32
empty_environment: .skip 8
parent_pid: .skip 8
old_artifacts: .skip 8
new_artifacts: .skip 8
store_path: .skip 8
tx_address: .skip 8
tx_size: .skip 8
stat_bytes: .skip 144
null_fd: .skip 4
probe_fd: .skip 4
owner_uid: .skip 4
artifact_fd: .skip 4
writer_fd: .skip 4
tx_fd: .skip 4
wait_status: .skip 4
digest_name: .skip 65
spare_byte: .skip 1
.section .note.GNU-stack,"",@progbits
