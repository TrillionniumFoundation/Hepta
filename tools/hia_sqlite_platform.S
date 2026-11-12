/* Closed Linux x86-64 / SQLite ABI transport.
 *
 * No SQL statement, transaction/replay policy, row predicate, descriptor
 * comparison or application error decision is implemented here. All effects
 * originate in the embedded HIA driver. Public input is a REQUEST packet, never
 * an effect/event. Raw SQLite pointers remain in the private table.
 *
 * fd0/fd1: u64 length + request/response packet. fd2: append-only binary trace:
 * u64 kind, u64 length, exact bytes (1 request, 2 effect, 3 event, 4 response).
 * This is a development transport, not the full ordinary Agent worker.
 */
.intel_syntax noprefix
.global _start
.global hia_platform_main
.equ INPTR,0
.equ INCAP,8
.equ OUTPTR,16
.equ OUTCAP,24
.equ WORKPTR,32
.equ WORKCAP,40
.equ JSONPTR,48
.equ JSONCAP,56
.equ JSONWORK,64
.equ JSONWORKCAP,72
.equ INPUTLEN,80
.equ EFFECTLEN,88
.equ SEQUENCE,96
.equ MAXINPUT,104
.equ SCRATCH,112
.equ ACTIVE_DRIVER,384
.equ HANDLES,512
.equ HSIZE,48
.equ H_PTR,0
.equ H_GEN,8
.equ H_ROLE,16
.equ H_PARENT,24
.equ H_PARENTGEN,32
.equ H_LIVE,40
.equ REQUEST_MAGIC,0x3151525153414948
.equ EVENT_MAGIC,0x3156455153414948
.equ EFFECT_MAGIC,0x3158465153414948
.section .text
_start:
 xor ebp,ebp
 mov r9,rdx
 pop rsi
 mov rdx,rsp
 and rsp,-16
 push rax
 push rsp
 xor r8d,r8d
 xor ecx,ecx
 lea rdi,[rip+hia_platform_main]
 call __libc_start_main@PLT
 hlt

/* Keep the stack aligned at every C call. The driver follows the same SysV
 * six-word three-buffer convention as its qualified flat compiler. */
hia_platform_main:
 push rbp
 mov rbp,rsp
 push rbx
 push r12
 push r13
 push r14
 push r15
 sub rsp,8
 lea r15,[rip+context]
 cmp edi,1
 jne fatal_protocol
 lea rdi,[r15+INPTR]
 mov esi,4096
 call reserve_buffer
 test rax,rax
 js fatal_memory
 lea rdi,[r15+OUTPTR]
 mov esi,4096
 call reserve_buffer
 test rax,rax
 js fatal_memory
 lea rdi,[r15+WORKPTR]
 mov esi,65536
 call reserve_buffer
 test rax,rax
 js fatal_memory
 mov rax,0x314b4f5153414948
 mov [r15+SCRATCH],rax
 mov edi,1
 lea rsi,[r15+SCRATCH]
 mov edx,8
 call write_exact
 test eax,eax
 jnz fatal_io
request_next:
 xor edi,edi
 lea rsi,[r15+SCRATCH]
 mov edx,8
 call read_exact
 test eax,eax
 jnz fatal_io
 mov rsi,[r15+SCRATCH]
 cmp rsi,128
 jb fatal_protocol
 cmp rsi,0x7fffffff
 ja request_large_length
 jmp request_length_ok
request_large_length:
 /* No new application limit: only checked address arithmetic below. */
 mov rax,rsi
 shr rax,60
 jnz fatal_memory
request_length_ok:
 mov [r15+INPUTLEN],rsi
 lea rdi,[r15+INPTR]
 call reserve_buffer
 test rax,rax
 js fatal_memory
 xor edi,edi
 mov rsi,[r15+INPTR]
 mov rdx,[r15+INPUTLEN]
 call read_exact
 test eax,eax
 jnz fatal_io
 mov rax,[r15+INPTR]
 mov rdx,REQUEST_MAGIC
 cmp [rax],rdx
 jne fatal_protocol
 mov edi,1
 mov rsi,rax
 mov rdx,[r15+INPUTLEN]
 call trace_record
driver_next:
 call reserve_driver_buffers
driver_call_ready:
 mov rdi,[r15+INPTR]
 mov rsi,[r15+INPUTLEN]
 mov rdx,[r15+OUTPTR]
 mov rcx,[r15+OUTCAP]
 mov r8,[r15+WORKPTR]
 mov r9,[r15+WORKCAP]
 cmp QWORD PTR [r15+ACTIVE_DRIVER],0
 jne agent_driver_call
 call hia_platform_driver_start
 jmp native_driver_return
agent_driver_call:
 cmp QWORD PTR [r15+ACTIVE_DRIVER],1
 jne fatal_protocol
 call hia_platform_agent_start
native_driver_return:
 cmp eax,0xfffffffc
 jae fatal_protocol
 cmp eax,136
 jb fatal_protocol
 cmp rax,[r15+OUTCAP]
 ja fatal_protocol
 mov [r15+EFFECTLEN],rax
 call validate_effect
 mov edi,2
 mov rsi,[r15+OUTPTR]
 mov rdx,[r15+EFFECTLEN]
 call trace_record
 mov rbx,[r15+OUTPTR]
 mov eax,[rbx+8]
 cmp eax,0
 je respond
 cmp eax,1
 je do_open
 cmp eax,2
 je do_close
 cmp eax,3
 je do_busy
 cmp eax,4
 je do_prepare
 cmp eax,5
 je do_bind
 cmp eax,6
 je do_step
 cmp eax,7
 je do_column
 cmp eax,8
 je do_finalize
 cmp eax,9
 je do_autocommit
 cmp eax,10
 je do_canonical
 cmp eax,11
 je do_lstat
 cmp eax,12
 je normal_exit
 cmp eax,13
 je do_agent_enter
 cmp eax,14
 je do_journal
 cmp eax,15
 je do_clock
 cmp eax,16
 je do_rollback_policy
 cmp eax,17
 je do_fd_open
 cmp eax,18
 je do_fd_stat
 cmp eax,19
 je do_fd_read
 cmp eax,20
 je do_fd_write
 cmp eax,21
 je do_fd_fsync
 cmp eax,22
 je do_fd_link
 cmp eax,23
 je do_fd_unlink
 cmp eax,24
 je do_fd_close
 cmp eax,25
 je do_fd_random
 cmp eax,26
 je do_fd_workspace
 cmp eax,27
 je do_fd_pathstat
 cmp eax,28
 je do_sha_stream
 cmp eax,29
 je do_fd_getdents
 cmp eax,30
 je do_agent_preflight
 cmp eax,31
 je do_agent_decode
 cmp eax,32
 je do_agent_binary64
 jmp fatal_protocol

respond:
 mov QWORD PTR [r15+ACTIVE_DRIVER],0
 call require_no_resource
 mov edi,4
 mov rsi,[r15+OUTPTR]
 mov rdx,[r15+EFFECTLEN]
 call trace_record
 mov edi,1
 lea rsi,[r15+EFFECTLEN]
 mov edx,8
 call write_exact
 test eax,eax
 jnz fatal_io
 mov edi,1
 mov rsi,[r15+OUTPTR]
 mov rdx,[r15+EFFECTLEN]
 call write_exact
 test eax,eax
 jnz fatal_io
 jmp request_next

do_open:
 mov rax,[rbx+32]
 cmp rax,1
 jb fatal_protocol
 cmp rax,2
 ja fatal_protocol
 mov rcx,rax
 dec rcx
 cmp rcx,[rbx+40]
 jne fatal_protocol
 imul rcx,HSIZE
 lea r12,[r15+HANDLES+rcx]
 cmp QWORD PTR [r12+H_LIVE],0
 jne fatal_protocol
 cmp QWORD PTR [r12+H_PTR],0
 jne fatal_protocol
 mov rdx,[r12+H_GEN]
 cmp [rbx+48],rdx
 jne fatal_protocol
 cmp rdx,-1
 je fatal_protocol
 cmp QWORD PTR [rbx+56],0
 jne fatal_protocol
 cmp QWORD PTR [rbx+64],2
 jne fatal_protocol
 mov rcx,[rbx+128]
 cmp rcx,[rbx+96]
 jne fatal_protocol
 lea rdi,[rbx+136]
 add rcx,136
 cmp rcx,[r15+OUTCAP]
 jae fatal_protocol
 mov BYTE PTR [rbx+rcx],0
 mov QWORD PTR [r15+SCRATCH],0
 lea rsi,[r15+SCRATCH]
 mov edx,2
 xor ecx,ecx
 call sqlite3_open_v2@PLT
 mov r13d,eax
 test eax,eax
 jnz open_failed
 mov rax,[r15+SCRATCH]
 test rax,rax
 jz fatal_protocol
 mov [r12+H_PTR],rax
 inc QWORD PTR [r12+H_GEN]
 mov rax,[rbx+32]
 mov [r12+H_ROLE],rax
 mov QWORD PTR [r12+H_LIVE],1
 xor edi,edi
 xor esi,esi
 call event_header
 mov rax,[r15+INPTR]
 mov rdx,[r12+H_GEN]
 mov [rax+48],rdx
 jmp event_ready
open_failed:
 /* SQLite may return an error connection. It is never published as a handle. */
 mov rdi,[r15+SCRATCH]
 test rdi,rdi
 jz open_error_event
 call sqlite3_close@PLT
open_error_event:
 mov edi,r13d
 xor esi,esi
 call event_header
 jmp event_ready

do_close:
 call resolve_database
 mov r12,rax
 call sqlite3_close@PLT
 mov r13d,eax
 test eax,eax
 jnz close_event
 mov QWORD PTR [r12+H_PTR],0
 mov QWORD PTR [r12+H_LIVE],0
close_event:
 mov edi,r13d
 xor esi,esi
 call event_header
 jmp event_ready

do_busy:
 call resolve_database
 mov rax,[rbx+64]
 cmp rax,0x7fffffff
 ja fatal_protocol
 mov esi,eax
 call sqlite3_busy_timeout@PLT
 mov edi,eax
 xor esi,esi
 call event_header
 jmp event_ready

do_prepare:
 call resolve_database
 mov r12,rax
 lea r13,[r15+HANDLES+HSIZE*2]
 cmp QWORD PTR [r13+H_LIVE],0
 jne fatal_protocol
 cmp QWORD PTR [r13+H_PTR],0
 jne fatal_protocol
 cmp QWORD PTR [r13+H_GEN],-1
 je fatal_protocol
 mov rdx,[rbx+128]
 cmp rdx,0x7fffffff
 ja fatal_protocol
 lea rsi,[rbx+136]
 mov QWORD PTR [r15+SCRATCH],0
 mov QWORD PTR [r15+SCRATCH+8],0
 lea rcx,[r15+SCRATCH]
 lea r8,[r15+SCRATCH+8]
 call sqlite3_prepare_v2@PLT
 mov r14d,eax
 test eax,eax
 jnz prepare_error
 mov rax,[r15+SCRATCH]
 test rax,rax
 jz fatal_protocol
 mov [r13+H_PTR],rax
 inc QWORD PTR [r13+H_GEN]
 mov QWORD PTR [r13+H_ROLE],3
 mov rax,[r12+H_ROLE]
 mov [r13+H_PARENT],rax
 mov rax,[r12+H_GEN]
 mov [r13+H_PARENTGEN],rax
 mov QWORD PTR [r13+H_LIVE],1
 /* Exactly the HIA-supplied statement span must have been consumed. */
 lea rax,[rbx+136]
 add rax,[rbx+128]
 cmp rax,[r15+SCRATCH+8]
 jne fatal_protocol
 xor edi,edi
 xor esi,esi
 call event_header
 mov rax,[r15+INPTR]
 mov QWORD PTR [rax+32],3
 mov QWORD PTR [rax+40],2
 mov rdx,[r13+H_GEN]
 mov [rax+48],rdx
 mov rdx,[r13+H_PARENT]
 mov [rax+56],rdx
 jmp event_ready
prepare_error:
 mov rdi,[r15+SCRATCH]
 test rdi,rdi
 jz prepare_error_event
 call sqlite3_finalize@PLT
prepare_error_event:
 mov edi,r14d
 xor esi,esi
 call event_header
 jmp event_ready

do_bind:
 call resolve_statement
 mov rax,[rbx+64]
 test rax,rax
 jz fatal_protocol
 cmp rax,0x7fffffff
 ja fatal_protocol
 mov esi,eax
 mov rax,[rbx+72]
 cmp rax,0
 je bind_null
 cmp rax,1
 je bind_false
 cmp rax,2
 je bind_true
 cmp rax,3
 je bind_integer
 cmp rax,4
 je bind_float
 cmp rax,5
 je bind_text
 cmp rax,6
 je bind_blob
 jmp fatal_protocol
bind_null:
 cmp QWORD PTR [rbx+128],0
 jne fatal_protocol
 call sqlite3_bind_null@PLT
 jmp bind_result
bind_false:
 cmp QWORD PTR [rbx+128],0
 jne fatal_protocol
 xor edx,edx
 call sqlite3_bind_int64@PLT
 jmp bind_result
bind_true:
 cmp QWORD PTR [rbx+128],0
 jne fatal_protocol
 mov edx,1
 call sqlite3_bind_int64@PLT
 jmp bind_result
bind_integer:
 cmp QWORD PTR [rbx+128],8
 jne fatal_protocol
 mov rdx,[rbx+136]
 call sqlite3_bind_int64@PLT
 jmp bind_result
bind_float:
 cmp QWORD PTR [rbx+128],8
 jne fatal_protocol
 movq xmm0,[rbx+136]
 call sqlite3_bind_double@PLT
 jmp bind_result
bind_text:
 lea rdx,[rbx+136]
 mov rcx,[rbx+128]
 mov r8,-1
 mov r9d,1
 call sqlite3_bind_text64@PLT
 jmp bind_result
bind_blob:
 lea rdx,[rbx+136]
 mov rcx,[rbx+128]
 mov r8,-1
 call sqlite3_bind_blob64@PLT
bind_result:
 mov edi,eax
 xor esi,esi
 call event_header
 jmp event_ready

do_step:
 call resolve_statement
 call sqlite3_step@PLT
 mov edi,eax
 xor esi,esi
 call event_header
 jmp event_ready

do_finalize:
 call resolve_statement
 mov r12,rax
 call sqlite3_finalize@PLT
 mov r13d,eax
 /* finalize always destroys the prepared statement, including error returns. */
 mov QWORD PTR [r12+H_PTR],0
 mov QWORD PTR [r12+H_LIVE],0
 mov edi,r13d
 xor esi,esi
 call event_header
 jmp event_ready

do_autocommit:
 call resolve_database
 call sqlite3_get_autocommit@PLT
 mov r12d,eax
 xor edi,edi
 xor esi,esi
 call event_header
 mov rax,[r15+INPTR]
 mov [rax+64],r12
 jmp event_ready

do_column:
 call resolve_statement
 mov r12,rdi
 call sqlite3_column_count@PLT
 test eax,eax
 js fatal_protocol
 mov r14d,eax
 mov rsi,[rbx+64]
 cmp rsi,r14
 jae fatal_protocol
 mov rdi,r12
 call sqlite3_column_type@PLT
 mov r13d,eax
 cmp eax,1
 je column_integer
 cmp eax,2
 je column_float
 cmp eax,3
 je column_text
 cmp eax,4
 je column_blob
 cmp eax,5
 je column_null
 jmp fatal_protocol
column_integer:
 mov rdi,r12
 mov esi,DWORD PTR [rbx+64]
 call sqlite3_column_int64@PLT
 mov [r15+SCRATCH],rax
 xor edi,edi
 mov esi,8
 call event_header
 mov rax,[r15+INPTR]
 mov rdx,[r15+SCRATCH]
 mov [rax+136],rdx
 jmp column_event
column_float:
 mov rdi,r12
 mov esi,DWORD PTR [rbx+64]
 call sqlite3_column_double@PLT
 movq [r15+SCRATCH],xmm0
 xor edi,edi
 mov esi,8
 call event_header
 mov rax,[r15+INPTR]
 mov rdx,[r15+SCRATCH]
 mov [rax+136],rdx
 jmp column_event
column_text:
 mov rdi,r12
 mov esi,DWORD PTR [rbx+64]
 call sqlite3_column_text@PLT
 jmp column_bytes
column_blob:
 mov rdi,r12
 mov esi,DWORD PTR [rbx+64]
 call sqlite3_column_blob@PLT
column_bytes:
 mov [r15+SCRATCH],rax
 mov rdi,r12
 mov esi,DWORD PTR [rbx+64]
 call sqlite3_column_bytes@PLT
 test eax,eax
 js fatal_protocol
 mov [r15+SCRATCH+8],rax
 test eax,eax
 jz column_copy
 cmp QWORD PTR [r15+SCRATCH],0
 je fatal_memory
column_copy:
 xor edi,edi
 mov rsi,[r15+SCRATCH+8]
 call event_header
 mov rdi,[r15+INPTR]
 add rdi,136
 mov rsi,[r15+SCRATCH]
 mov rcx,[r15+SCRATCH+8]
 rep movsb
 jmp column_event
column_null:
 xor edi,edi
 xor esi,esi
 call event_header
column_event:
 mov rax,[r15+INPTR]
 mov [rax+64],r13
 mov [rax+72],r14
 jmp event_ready

do_canonical:
 call require_no_resource
 mov r12,[rbx+128]
 /* Decoder o is reused for key slots, the 6,320-byte container stack,
    then canonical output. 8*B+8192 covers all three disjoint phases.
    The HIA parser retains its original byte/node/depth admission. */
 mov rsi,r12
 mov rax,rsi
 shr rax,61
 jnz fatal_memory
 shl rsi,3
 add rsi,8192
 jc fatal_memory
 lea rdi,[r15+JSONPTR]
 call reserve_buffer
 test rax,rax
 js fatal_memory
 mov rsi,r12
 add rsi,1
 jc fatal_memory
 mov rax,rsi
 shr rax,58
 jnz fatal_memory
 shl rsi,6
 add rsi,4096
 jc fatal_memory
 lea rdi,[r15+JSONWORK]
 call reserve_buffer
 test rax,rax
 js fatal_memory
 mov r8,[r15+JSONWORK]
 mov rax,[rbx+64]
 mov [r8+48],rax
 mov rax,[rbx+72]
 mov [r8+56],rax
 lea rdi,[rbx+136]
 mov rsi,r12
 mov rdx,[r15+JSONPTR]
 mov rcx,[r15+JSONCAP]
 mov r9,[r15+JSONWORKCAP]
 call hia_platform_canonical_start
 cmp eax,0xfffffffc
 jae canonical_error
 mov r12d,eax
 cmp r12,[r15+JSONCAP]
 ja fatal_protocol
 xor edi,edi
 mov rsi,r12
 call event_header
 mov rdi,[r15+INPTR]
 add rdi,136
 mov rsi,[r15+JSONPTR]
 mov rcx,r12
 rep movsb
 jmp event_ready
canonical_error:
 mov edi,eax
 xor esi,esi
 call event_header
 jmp event_ready


/* Closed continuation into the separately admitted HIA transaction component.
 * No SQL or row predicates are selected here. */
do_agent_enter:
 call require_no_resource
 cmp QWORD PTR [r15+ACTIVE_DRIVER],0
 jne fatal_protocol
 cmp QWORD PTR [rbx+64],1
 jne fatal_protocol
 cmp QWORD PTR [rbx+72],0
 jne fatal_protocol
 mov r12,[rbx+128]
 cmp r12,128
 jb fatal_protocol
 lea rdi,[r15+INPTR]
 mov rsi,r12
 call reserve_buffer
 test rax,rax
 js fatal_memory
 mov rdi,[r15+INPTR]
 lea rsi,[rbx+136]
 mov rcx,r12
 rep movsb
 mov [r15+INPUTLEN],r12
 mov QWORD PTR [r15+ACTIVE_DRIVER],1
 jmp driver_next

/* Fixed journal three-buffer ABI; state/action/SQL policy remains in HIA. */
do_journal:
 call require_no_resource
 cmp QWORD PTR [r15+ACTIVE_DRIVER],1
 jne fatal_protocol
 mov r12,[rbx+128]
 cmp r12,512
 jb fatal_protocol
 sub r12,512
 mov r13,[rbx+136+336]
 cmp r13,262144
 ja fatal_protocol
 cmp r13,r12
 ja fatal_protocol
 sub r12,r13
 cmp QWORD PTR [rbx+64],0
 je journal_foreign_ready
 test r13,r13
 jnz fatal_protocol
journal_foreign_ready:
 /* Fresh mappings preserve original zero-initialized component workspace.
  * 72*(B+1)+73728+F covers decoder nodes/string/key/stack and private state. */
 lea rdi,[r15+JSONPTR]
 call reset_buffer
 lea rdi,[r15+JSONPTR]
 mov esi,16777728
 call reserve_buffer
 test rax,rax
 js fatal_memory
 lea rdi,[r15+JSONWORK]
 call reset_buffer
 mov rsi,r12
 add rsi,1
 jc fatal_memory
 mov rax,rsi
 mov edx,72
 mul rdx
 test rdx,rdx
 jnz fatal_memory
 mov rsi,rax
 add rsi,73728
 jc fatal_memory
 add rsi,r13
 jc fatal_memory
 lea rdi,[r15+JSONWORK]
 call reserve_buffer
 test rax,rax
 js fatal_memory
 mov rdi,[r15+JSONWORK]
 add rdi,[r15+JSONWORKCAP]
 sub rdi,32768
 lea rsi,[rbx+136]
 mov ecx,512
 rep movsb
 mov rdi,[r15+JSONWORK]
 add rdi,[r15+JSONWORKCAP]
 sub rdi,32768
 sub rdi,r13
 lea rsi,[rbx+648]
 mov rcx,r13
 rep movsb
 mov r8,[r15+JSONWORK]
 mov rax,[rbx+64]
 mov [r8],rax
 mov rax,[rbx+72]
 mov [r8+8],rax
 lea rdi,[rbx+648]
 add rdi,r13
 mov rsi,r12
 mov rdx,[r15+JSONPTR]
 mov rcx,[r15+JSONCAP]
 mov r9,[r15+JSONWORKCAP]
 call hia_platform_journal_start
 mov r14d,eax
 cmp eax,0xffffffe0
 jae journal_component_error
 mov rax,[r15+JSONPTR]
 mov r12,[rax+16777216+272]
 mov r13,[rax+16777216+280]
 cmp r12,8388608
 ja fatal_protocol
 cmp r13,8388608
 ja fatal_protocol
 mov rsi,r12
 add rsi,r13
 jc fatal_memory
 add rsi,512
 jc fatal_memory
 mov edi,r14d
 call event_header
 mov rdi,[r15+INPTR]
 add rdi,136
 mov rsi,[r15+JSONPTR]
 add rsi,16777216
 mov ecx,512
 rep movsb
 mov rsi,[r15+JSONPTR]
 mov rcx,r12
 rep movsb
 mov rsi,[r15+JSONPTR]
 add rsi,8388608
 mov rcx,r13
 rep movsb
 jmp event_ready
journal_component_error:
 /* Preserve the original component diagnostic header verbatim. HIA owns
  * phase validation, UTF-8/domain interpretation and the rollback decision. */
 mov edi,r14d
 mov esi,512
 call event_header
 mov rdi,[r15+INPTR]
 add rdi,136
 mov rsi,[r15+JSONPTR]
 add rsi,16777216
 mov ecx,512
 rep movsb
 jmp event_ready

/* The fixed rollback-schema HIA image receives only the raw request already
 * admitted by the bound journal. No row, SQL or result decision is in ASM. */
do_rollback_policy:
 call require_no_resource
 cmp QWORD PTR [r15+ACTIVE_DRIVER],1
 jne fatal_protocol
 cmp QWORD PTR [rbx+64],0
 jne fatal_protocol
 cmp QWORD PTR [rbx+72],0
 jne fatal_protocol
 mov r12,[rbx+128]
 cmp r12,8388608
 ja fatal_protocol
 lea rdi,[r15+JSONPTR]
 call reset_buffer
 lea rdi,[r15+JSONPTR]
 mov esi,4194304
 call reserve_buffer
 test rax,rax
 js fatal_memory
 lea rdi,[r15+JSONWORK]
 call reset_buffer
 mov rax,r12
 add rax,1
 jc fatal_memory
 mov edx,72
 mul rdx
 test rdx,rdx
 jnz fatal_memory
 add rax,73728
 jc fatal_memory
 mov rsi,rax
 lea rdi,[r15+JSONWORK]
 call reserve_buffer
 test rax,rax
 js fatal_memory
 lea rdi,[rbx+136]
 mov rsi,r12
 mov rdx,[r15+JSONPTR]
 mov rcx,[r15+JSONCAP]
 mov r8,[r15+JSONWORK]
 mov r9,[r15+JSONWORKCAP]
 call hia_platform_policy_start
 mov r14d,eax
 cmp eax,0xffffffe0
 jae rollback_policy_error
 cmp eax,64
 jb fatal_protocol
 cmp rax,[r15+JSONCAP]
 ja fatal_protocol
 mov r12,rax
 mov edi,r14d
 mov rsi,r12
 call event_header
 mov rdi,[r15+INPTR]
 add rdi,136
 mov rsi,[r15+JSONPTR]
 mov rcx,r12
 rep movsb
 jmp event_ready
rollback_policy_error:
 mov edi,r14d
 xor esi,esi
 call event_header
 jmp event_ready


/* Closed fd capabilities. These effects choose no SQL, filename, digest,
 * publication step or business error. HIA supplies all of those decisions.
 * Roles 64/65/66 are directory/readable-content/private-writable-file.
 * Public packets cannot supply effects. Each child retains its exact root
 * generation; only the private table contains an OS descriptor. */
.equ FD_HANDLES,1024
.equ FD_PATHPTR,1200
.equ FD_PATHCAP,1208

fd_token:
 mov rax,[rbx+32]
 cmp rax,64
 jb fatal_protocol
 cmp rax,66
 ja fatal_protocol
 sub rax,64
 cmp rax,[rbx+40]
 jne fatal_protocol
 imul rax,HSIZE
 lea rax,[r15+FD_HANDLES+rax]
 mov rdx,[rax+H_GEN]
 cmp rdx,[rbx+48]
 jne fatal_protocol
 ret

resolve_fd:
 call fd_token
 cmp QWORD PTR [rax+H_LIVE],1
 jne fatal_protocol
 mov rdx,[rax+H_ROLE]
 cmp rdx,[rbx+32]
 jne fatal_protocol
 cmp rdx,64
 je fd_root_parent
 cmp QWORD PTR [rbx+56],0
 je fd_root_parent
 cmp QWORD PTR [rbx+56],64
 jne fatal_protocol
 cmp QWORD PTR [rax+H_PARENT],64
 jne fatal_protocol
 cmp QWORD PTR [r15+FD_HANDLES+H_LIVE],1
 jne fatal_protocol
 mov rdx,[r15+FD_HANDLES+H_GEN]
 cmp rdx,[rax+H_PARENTGEN]
 jne fatal_protocol
 jmp fd_resolved
fd_root_parent:
 cmp QWORD PTR [rbx+56],0
 jne fatal_protocol
 cmp QWORD PTR [rax+H_PARENT],0
 jne fatal_protocol
fd_resolved:
 mov rdi,[rax+H_PTR]
 ret

/* A C-string crossing is exact: embedded NUL never silently shortens it.
 * The child form is a basename capability, so /, . and .. cannot escape
 * the directory descriptor even if an internal native component is faulty.
 * This is ABI structure; HIA still chooses and validates the actual name. */
fd_basename:
 test rcx,rcx
 jz fatal_protocol
 xor eax,eax
fd_basename_next:
 cmp BYTE PTR [rsi+rax],0
 je fatal_protocol
 cmp BYTE PTR [rsi+rax],47
 je fatal_protocol
 inc rax
 cmp rax,rcx
 jb fd_basename_next
 cmp rcx,1
 jne fd_basename_two
 cmp BYTE PTR [rsi],46
 je fatal_protocol
fd_basename_two:
 cmp rcx,2
 jne fd_basename_done
 cmp WORD PTR [rsi],0x2e2e
 je fatal_protocol
fd_basename_done:
 ret

/* Copy a single exact byte span into private NUL-terminated scratch.
 * rsi/span, rcx/length, edx=1 for a child basename; returned rsi is stable
 * across the immediately following syscall. No mutable caller path is read. */
fd_copy_name:
 push rbp
 mov rbp,rsp
 sub rsp,32
 mov [rbp-8],rsi
 mov [rbp-16],rcx
 mov [rbp-24],rdx
 test rcx,rcx
 jz fatal_protocol
 test edx,edx
 jz fd_name_nul
 call fd_basename
 jmp fd_name_alloc
fd_name_nul:
 xor eax,eax
fd_name_nul_next:
 cmp BYTE PTR [rsi+rax],0
 je fatal_protocol
 inc rax
 cmp rax,rcx
 jb fd_name_nul_next
fd_name_alloc:
 mov rsi,[rbp-16]
 add rsi,1
 jc fatal_memory
 lea rdi,[r15+FD_PATHPTR]
 call reserve_buffer
 test rax,rax
 js fatal_memory
 mov rdi,[r15+FD_PATHPTR]
 mov rsi,[rbp-8]
 mov rcx,[rbp-16]
 rep movsb
 mov BYTE PTR [rdi],0
 mov rsi,[r15+FD_PATHPTR]
 leave
 ret

do_fd_open:
 cmp QWORD PTR [r15+ACTIVE_DRIVER],1
 jne fatal_protocol
 call fd_token
 mov r12,rax
 cmp QWORD PTR [r12+H_LIVE],0
 jne fatal_protocol
 cmp QWORD PTR [r12+H_GEN],-1
 je fatal_protocol
 mov rax,[rbx+32]
 cmp rax,64
 je fd_open_root
 cmp QWORD PTR [rbx+56],0
 je fd_open_independent
 cmp QWORD PTR [rbx+56],64
 jne fatal_protocol
 cmp QWORD PTR [r15+FD_HANDLES+H_LIVE],1
 jne fatal_protocol
fd_open_independent:
 cmp rax,65
 jne fd_open_private
 cmp QWORD PTR [rbx+64],0xa0800
 je fd_read_flags_ok
 cmp QWORD PTR [rbx+64],0x80000
 jne fatal_protocol
fd_read_flags_ok:
 cmp QWORD PTR [rbx+72],0
 jne fatal_protocol
 jmp fd_open_child_ready
fd_open_private:
 cmp QWORD PTR [rbx+56],64
 jne fatal_protocol
 cmp QWORD PTR [rbx+64],0xa00c1
 jne fatal_protocol
 cmp QWORD PTR [rbx+72],256
 jne fatal_protocol
fd_open_child_ready:
 lea rsi,[rbx+136]
 mov rcx,[rbx+128]
 xor edx,edx
 cmp QWORD PTR [rbx+56],64
 sete dl
 call fd_copy_name
 mov rdi,-100
 cmp QWORD PTR [rbx+56],64
 jne fd_open_call
 mov rdi,[r15+FD_HANDLES+H_PTR]
 jmp fd_open_call
fd_open_root:
 cmp QWORD PTR [rbx+56],0
 jne fatal_protocol
 cmp QWORD PTR [rbx+64],0xb0000
 je fd_directory_flags_ok
 cmp QWORD PTR [rbx+64],0x90000
 jne fatal_protocol
fd_directory_flags_ok:
 cmp QWORD PTR [rbx+72],0
 jne fatal_protocol
 lea rsi,[rbx+136]
 mov rcx,[rbx+128]
 xor edx,edx
 call fd_copy_name
 mov rdi,-100
fd_open_call:
 mov rdx,[rbx+64]
 mov r10,[rbx+72]
fd_open_retry:
 mov eax,257
 syscall
 cmp rax,-4
 je fd_open_retry
 test rax,rax
 js fd_open_error
 mov [r12+H_PTR],rax
 inc QWORD PTR [r12+H_GEN]
 mov rax,[rbx+32]
 mov [r12+H_ROLE],rax
 mov QWORD PTR [r12+H_LIVE],1
 mov QWORD PTR [r12+H_PARENT],0
 mov QWORD PTR [r12+H_PARENTGEN],0
 cmp rax,64
 je fd_open_success
 cmp QWORD PTR [rbx+56],0
 je fd_open_success
 mov QWORD PTR [r12+H_PARENT],64
 mov rax,[r15+FD_HANDLES+H_GEN]
 mov [r12+H_PARENTGEN],rax
fd_open_success:
 xor edi,edi
 xor esi,esi
 call event_header
 mov rax,[r15+INPTR]
 mov rdx,[r12+H_GEN]
 mov [rax+48],rdx
 jmp event_ready
fd_open_error:
 mov rdi,rax
 xor esi,esi
 call event_header
 jmp event_ready

do_fd_stat:
 cmp QWORD PTR [rbx+128],0
 jne fatal_protocol
 call resolve_fd
 lea rsi,[r15+SCRATCH+32]
fd_stat_retry:
 mov eax,5
 syscall
 cmp rax,-4
 je fd_stat_retry
 test rax,rax
 js fd_plain_error
 xor edi,edi
 mov esi,144
 call event_header
 mov rdi,[r15+INPTR]
 add rdi,136
 lea rsi,[r15+SCRATCH+32]
 mov ecx,144
 rep movsb
 mov eax,107
 syscall
 mov rdx,[r15+INPTR]
 mov [rdx+64],rax
 jmp event_ready

do_fd_read:
 cmp QWORD PTR [rbx+32],65
 jne fatal_protocol
 cmp QWORD PTR [rbx+128],0
 jne fatal_protocol
 call resolve_fd
 mov r12,rdi
 mov r13,[rbx+64]
 test r13,r13
 jz fatal_protocol
 cmp r13,65536
 ja fatal_protocol
 xor edi,edi
 mov rsi,r13
 call event_header
 mov rdi,r12
 mov rsi,[r15+INPTR]
 add rsi,136
 mov rdx,r13
fd_read_retry:
 xor eax,eax
 syscall
 cmp rax,-4
 je fd_read_retry
 mov rcx,[r15+INPTR]
 test rax,rax
 js fd_read_error
 mov [rcx+96],rax
 mov [rcx+128],rax
 add rax,136
 mov [r15+INPUTLEN],rax
 jmp event_ready
fd_read_error:
 mov [rcx+24],rax
 mov QWORD PTR [rcx+96],0
 mov QWORD PTR [rcx+128],0
 mov QWORD PTR [r15+INPUTLEN],136
 jmp event_ready

do_fd_write:
 cmp QWORD PTR [rbx+32],66
 jne fatal_protocol
 call resolve_fd
 lea rsi,[rbx+136]
 mov rdx,[rbx+128]
fd_write_retry:
 mov eax,1
 syscall
 cmp rax,-4
 je fd_write_retry
 test rax,rax
 js fd_plain_error
 mov r12,rax
 xor edi,edi
 xor esi,esi
 call event_header
 mov rax,[r15+INPTR]
 mov [rax+64],r12
 jmp event_ready

do_fd_fsync:
 cmp QWORD PTR [rbx+128],0
 jne fatal_protocol
 cmp QWORD PTR [rbx+32],65
 je fatal_protocol
 call resolve_fd
fd_sync_retry:
 mov eax,74
 syscall
 cmp rax,-4
 je fd_sync_retry
 jmp fd_plain_error

/* Pair payload is 2Q lengths followed by source and destination basename
 * bytes. linkat's no-replace outcome is returned raw; HIA chooses dedup. */
do_fd_link:
 cmp QWORD PTR [rbx+32],64
 jne fatal_protocol
 call resolve_fd
 mov r12,rdi
 mov rax,[rbx+128]
 cmp rax,18
 jb fatal_protocol
 mov r13,[rbx+136]
 mov r14,[rbx+144]
 mov rcx,r13
 add rcx,r14
 jc fatal_protocol
 add rcx,16
 jc fatal_protocol
 cmp rcx,rax
 jne fatal_protocol
 lea rsi,[rbx+152]
 mov rcx,r13
 call fd_basename
 lea rsi,[rbx+152]
 add rsi,r13
 mov rcx,r14
 call fd_basename
 mov rsi,r13
 add rsi,r14
 jc fatal_memory
 add rsi,2
 jc fatal_memory
 lea rdi,[r15+FD_PATHPTR]
 call reserve_buffer
 test rax,rax
 js fatal_memory
 mov rdi,[r15+FD_PATHPTR]
 lea rsi,[rbx+152]
 mov rcx,r13
 rep movsb
 mov BYTE PTR [rdi],0
 inc rdi
 mov rcx,r14
 rep movsb
 mov BYTE PTR [rdi],0
 mov rdi,r12
 mov rdx,r12
 mov rsi,[r15+FD_PATHPTR]
 lea r10,[rsi+r13+1]
 xor r8d,r8d
fd_link_retry:
 mov eax,265
 syscall
 cmp rax,-4
 je fd_link_retry
 jmp fd_plain_error

do_fd_unlink:
 cmp QWORD PTR [rbx+32],64
 jne fatal_protocol
 call resolve_fd
 mov r12,rdi
 lea rsi,[rbx+136]
 mov rcx,[rbx+128]
 mov edx,1
 call fd_copy_name
 mov rdi,r12
 xor edx,edx
fd_unlink_retry:
 mov eax,263
 syscall
 cmp rax,-4
 je fd_unlink_retry
 jmp fd_plain_error

do_fd_close:
 cmp QWORD PTR [rbx+128],0
 jne fatal_protocol
 call resolve_fd
 mov r12,rax
 cmp QWORD PTR [rbx+32],64
 jne fd_close_call
 cmp QWORD PTR [r15+FD_HANDLES+HSIZE+H_LIVE],0
 jne fatal_protocol
 cmp QWORD PTR [r15+FD_HANDLES+HSIZE*2+H_LIVE],0
 jne fatal_protocol
fd_close_call:
 mov eax,3
 syscall
 /* Linux consumes an owned descriptor even on EINTR. Never retry close. */
 mov QWORD PTR [r12+H_LIVE],0
 mov QWORD PTR [r12+H_PTR],0
 jmp fd_plain_error

do_fd_random:
 call require_no_resource
 cmp QWORD PTR [rbx+128],0
 jne fatal_protocol
 mov r12,[rbx+64]
 test r12,r12
 jz fatal_protocol
 cmp r12,16
 ja fatal_protocol
 xor edi,edi
 mov rsi,r12
 call event_header
 mov rdi,[r15+INPTR]
 add rdi,136
 mov rsi,r12
 xor edx,edx
fd_random_retry:
 mov eax,318
 syscall
 cmp rax,-4
 je fd_random_retry
 mov rcx,[r15+INPTR]
 test rax,rax
 js fd_read_error
 mov [rcx+96],rax
 mov [rcx+128],rax
 add rax,136
 mov [r15+INPUTLEN],rax
 jmp event_ready

do_fd_workspace:
 call require_no_resource
 cmp QWORD PTR [r15+ACTIVE_DRIVER],1
 jne fatal_protocol
 cmp QWORD PTR [rbx+128],0
 jne fatal_protocol
 mov r12,[rbx+72]
 mov rsi,[rbx+64]
 lea rdi,[r15+WORKPTR]
 call reserve_buffer
 test rax,rax
 js fatal_memory
 mov rsi,r12
 lea rdi,[r15+OUTPTR]
 call reserve_buffer
 test rax,rax
 js fatal_memory
 xor edi,edi
 xor esi,esi
 call event_header
 mov rax,[r15+INPTR]
 mov rdx,[r15+WORKCAP]
 mov [rax+64],rdx
 mov rdx,[r15+OUTCAP]
 mov [rax+72],rdx
 jmp event_ready

do_fd_pathstat:
 cmp QWORD PTR [rbx+32],64
 jne fatal_protocol
 call resolve_fd
 mov r12,rdi
 lea rsi,[rbx+136]
 mov rcx,[rbx+128]
 mov edx,1
 call fd_copy_name
 mov rdi,r12
 lea rdx,[r15+SCRATCH+32]
 mov r10d,256
fd_pathstat_retry:
 mov eax,262
 syscall
 cmp rax,-4
 je fd_pathstat_retry
 test rax,rax
 js fd_plain_error
 xor edi,edi
 mov esi,144
 call event_header
 mov rdi,[r15+INPTR]
 add rdi,136
 lea rsi,[r15+SCRATCH+32]
 mov ecx,144
 rep movsb
 jmp event_ready

fd_plain_error:
 mov rdi,rax
 xor esi,esi
 call event_header
 jmp event_ready

/* The directory kernel record stream is opaque. HIA, not this bridge, owns
 * parsing d_reclen/names, d_type fallback, exclusion, traversal and ordering. */
do_fd_getdents:
 cmp QWORD PTR [rbx+32],64
 jne fatal_protocol
 cmp QWORD PTR [rbx+128],0
 jne fatal_protocol
 call resolve_fd
 mov r12,rdi
 mov r13,[rbx+64]
 test r13,r13
 jz fatal_protocol
 cmp r13,65536
 ja fatal_protocol
 xor edi,edi
 mov rsi,r13
 call event_header
 mov rdi,r12
 mov rsi,[r15+INPTR]
 add rsi,136
 mov rdx,r13
fd_getdents_retry:
 mov eax,217
 syscall
 cmp rax,-4
 je fd_getdents_retry
 mov rcx,[r15+INPTR]
 test rax,rax
 js fd_read_error
 mov [rcx+96],rax
 mov [rcx+128],rax
 add rax,136
 mov [r15+INPUTLEN],rax
 jmp event_ready

/* Fixed existing HIA stream image. The request carries its entire private
 * 1184-byte state followed by command+chunk. No foreign hash implementation. */
do_sha_stream:
 call require_no_resource
 cmp QWORD PTR [r15+ACTIVE_DRIVER],1
 jne fatal_protocol
 cmp QWORD PTR [rbx+72],0
 jne fatal_protocol
 mov r12,[rbx+128]
 cmp r12,1185
 jb fatal_protocol
 cmp r12,66721
 ja fatal_protocol
 movzx eax,BYTE PTR [rbx+1320]
 cmp rax,[rbx+64]
 jne fatal_protocol
 cmp rax,2
 ja fatal_protocol
 lea rdi,[r15+JSONPTR]
 mov esi,32
 call reserve_buffer
 test rax,rax
 js fatal_memory
 lea rdi,[r15+JSONWORK]
 mov esi,1184
 call reserve_buffer
 test rax,rax
 js fatal_memory
 mov rdi,[r15+JSONWORK]
 lea rsi,[rbx+136]
 mov ecx,1184
 rep movsb
 lea rdi,[rbx+1320]
 lea rsi,[r12-1184]
 mov rdx,[r15+JSONPTR]
 mov ecx,32
 mov r8,[r15+JSONWORK]
 mov r9d,1184
 call hia_platform_sha_stream_start
 mov r14d,eax
 cmp eax,0
 je sha_stream_success
 cmp eax,32
 jne sha_stream_error
sha_stream_success:
 mov edi,r14d
 lea rsi,[r14+1184]
 call event_header
 mov rdi,[r15+INPTR]
 add rdi,136
 mov rsi,[r15+JSONWORK]
 mov ecx,1184
 rep movsb
 mov rsi,[r15+JSONPTR]
 mov rcx,r14
 rep movsb
 jmp event_ready
sha_stream_error:
 mov edi,r14d
 xor esi,esi
 call event_header
 jmp event_ready


/* Three closed, source-bound HIA JSON components. The bridge forwards complete
 * native bytes/status; HIA chooses grammar, number order and public errors. */
do_agent_preflight:
 call require_no_resource
 cmp QWORD PTR [r15+ACTIVE_DRIVER],1
 jne fatal_protocol
 cmp QWORD PTR [rbx+64],262144
 jne fatal_protocol
 cmp QWORD PTR [rbx+72],128
 jne fatal_protocol
 mov r12,[rbx+128]
 cmp r12,8388608
 ja fatal_protocol
 lea rdi,[r15+JSONPTR]
 mov esi,4194304
 call reserve_buffer
 test rax,rax
 js fatal_memory
 lea rdi,[r15+JSONWORK]
 mov esi,6320
 call reserve_buffer
 test rax,rax
 js fatal_memory
 mov r8,[r15+JSONWORK]
 mov QWORD PTR [r8+48],262144
 mov QWORD PTR [r8+56],128
 lea rdi,[rbx+136]
 mov rsi,r12
 mov rdx,[r15+JSONPTR]
 mov rcx,[r15+JSONCAP]
 mov r9,[r15+JSONWORKCAP]
 call hia_platform_preflight_start
 mov r14d,eax
 mov edi,r14d
 mov esi,16
 call event_header
 mov rax,[r15+INPTR]
 mov rdx,[r15+JSONWORK]
 mov rcx,[rdx+32]
 mov [rax+136],rcx
 mov rcx,[rdx]
 mov [rax+144],rcx
 jmp event_ready

do_agent_decode:
 call require_no_resource
 cmp QWORD PTR [r15+ACTIVE_DRIVER],1
 jne fatal_protocol
 cmp QWORD PTR [rbx+64],262144
 jne fatal_protocol
 cmp QWORD PTR [rbx+72],128
 jne fatal_protocol
 mov r12,[rbx+128]
 cmp r12,8388608
 ja fatal_protocol
 mov rax,r12
 add rax,1
 jc fatal_memory
 shr rax,1
 add rax,1
 cmp rax,262144
 jbe agent_decode_nodes
 mov eax,262144
agent_decode_nodes:
 mov edx,56
 mul rdx
 test rdx,rdx
 jnz fatal_memory
 add rax,64
 jc fatal_memory
 add rax,r12
 jc fatal_memory
 cmp rax,4256
 jae agent_decode_output
 mov eax,4256
agent_decode_output:
 mov rsi,rax
 lea rdi,[r15+JSONPTR]
 call reserve_buffer
 test rax,rax
 js fatal_memory
 lea rdi,[r15+JSONWORK]
 mov esi,4194304
 call reserve_buffer
 test rax,rax
 js fatal_memory
 mov r8,[r15+JSONWORK]
 mov QWORD PTR [r8+48],262144
 mov QWORD PTR [r8+56],128
 lea rdi,[rbx+136]
 mov rsi,r12
 mov rdx,[r15+JSONPTR]
 mov rcx,[r15+JSONCAP]
 mov r9,[r15+JSONWORKCAP]
 call hia_platform_data_json_start
 mov r14d,eax
 cmp eax,0xfffffffc
 jae agent_decode_error
 cmp eax,64
 jb fatal_protocol
 cmp rax,[r15+JSONCAP]
 ja fatal_protocol
 mov r12,rax
 mov edi,r14d
 mov rsi,r12
 call event_header
 mov rdi,[r15+INPTR]
 add rdi,136
 mov rsi,[r15+JSONPTR]
 mov rcx,r12
 rep movsb
 /* Phase 420 already grew the live HIA buffers to the complete checked
  * arena+bits upper bound. This native arena return adds no application
  * input and does not multiply the existing MAXINPUT allocation bound. */
 mov edi,3
 mov rsi,[r15+INPTR]
 mov rdx,[r15+INPUTLEN]
 call trace_record
 jmp driver_call_ready
agent_decode_error:
 mov edi,r14d
 xor esi,esi
 call event_header
 jmp event_ready

do_agent_binary64:
 call require_no_resource
 cmp QWORD PTR [r15+ACTIVE_DRIVER],1
 jne fatal_protocol
 cmp QWORD PTR [rbx+64],0
 jne fatal_protocol
 cmp QWORD PTR [rbx+72],0
 jne fatal_protocol
 mov r12,[rbx+128]
 cmp r12,8388608
 ja fatal_protocol
 lea rdi,[r15+JSONPTR]
 mov esi,8
 call reserve_buffer
 test rax,rax
 js fatal_memory
 lea rdi,[r15+JSONWORK]
 mov esi,4096
 call reserve_buffer
 test rax,rax
 js fatal_memory
 lea rdi,[rbx+136]
 mov rsi,r12
 mov rdx,[r15+JSONPTR]
 mov ecx,8
 mov r8,[r15+JSONWORK]
 mov r9d,4096
 call hia_platform_binary64_start
 mov r14d,eax
 cmp eax,8
 jne agent_binary64_error
 mov edi,r14d
 mov esi,8
 call event_header
 mov rax,[r15+JSONPTR]
 mov rdx,[rax]
 mov rax,[r15+INPTR]
 mov [rax+136],rdx
 jmp event_ready
agent_binary64_error:
 mov edi,r14d
 xor esi,esi
 call event_header
 jmp event_ready


do_clock:
 call require_no_resource
 cmp QWORD PTR [r15+ACTIVE_DRIVER],1
 jne fatal_protocol
 mov rdi,[rbx+64]
 cmp rdi,1
 ja fatal_protocol
 cmp QWORD PTR [rbx+128],0
 jne fatal_protocol
 lea rsi,[r15+SCRATCH+32]
 mov eax,228
 syscall
 mov r12,rax
 mov rdi,rax
 xor esi,esi
 test rax,rax
 jnz clock_return
 mov esi,16
clock_return:
 call event_header
 test r12,r12
 jnz event_ready
 mov rax,[r15+INPTR]
 mov rdx,[r15+SCRATCH+32]
 mov [rax+136],rdx
 mov rdx,[r15+SCRATCH+40]
 mov [rax+144],rdx
 jmp event_ready

/* Only this bridge's private scratch mapping is discarded. */
reset_buffer:
 push rbx
 mov rbx,rdi
 mov rdi,[rbx]
 test rdi,rdi
 jz reset_empty
 mov rsi,[rbx+8]
 mov eax,11
 syscall
 test rax,rax
 jnz fatal_memory
reset_empty:
 mov QWORD PTR [rbx],0
 mov QWORD PTR [rbx+8],0
 pop rbx
 ret

do_lstat:
 call require_no_resource
 mov rcx,[rbx+128]
 add rcx,136
 jc fatal_memory
 cmp rcx,[r15+OUTCAP]
 jae fatal_protocol
 mov BYTE PTR [rbx+rcx],0
 mov edi,-100
 lea rsi,[rbx+136]
 lea rdx,[r15+SCRATCH+32]
 mov r10d,256
 mov eax,262
 syscall
 mov r12,rax
 mov rdi,rax
 xor esi,esi
 call event_header
 test r12,r12
 jnz event_ready
 mov eax,107
 syscall
 mov rdx,[r15+INPTR]
 mov [rdx+56],rax
 mov eax,DWORD PTR [r15+SCRATCH+32+24]
 mov [rdx+64],rax
 mov eax,DWORD PTR [r15+SCRATCH+32+28]
 mov [rdx+72],rax
 mov rax,[r15+SCRATCH+32]
 mov [rdx+80],rax
 mov rax,[r15+SCRATCH+32+8]
 mov [rdx+88],rax
 jmp event_ready

event_ready:
 mov edi,3
 mov rsi,[r15+INPTR]
 mov rdx,[r15+INPUTLEN]
 call trace_record
 jmp driver_next

/* Standard C-call handles: role, slot and generation are checked together.
 * A statement carries its exact live parent connection generation. */
resolve_database:
 mov rax,[rbx+32]
 cmp rax,1
 jb fatal_protocol
 cmp rax,2
 ja fatal_protocol
 dec rax
 cmp rax,[rbx+40]
 jne fatal_protocol
 imul rax,HSIZE
 lea rax,[r15+HANDLES+rax]
 cmp QWORD PTR [rax+H_LIVE],1
 jne fatal_protocol
 mov rdx,[rax+H_ROLE]
 cmp rdx,[rbx+32]
 jne fatal_protocol
 mov rdx,[rax+H_GEN]
 cmp rdx,[rbx+48]
 jne fatal_protocol
 cmp QWORD PTR [rbx+56],0
 jne fatal_protocol
 mov rdi,[rax+H_PTR]
 test rdi,rdi
 jz fatal_protocol
 ret

resolve_statement:
 cmp QWORD PTR [rbx+32],3
 jne fatal_protocol
 cmp QWORD PTR [rbx+40],2
 jne fatal_protocol
 lea rax,[r15+HANDLES+HSIZE*2]
 cmp QWORD PTR [rax+H_LIVE],1
 jne fatal_protocol
 cmp QWORD PTR [rax+H_ROLE],3
 jne fatal_protocol
 mov rdx,[rax+H_GEN]
 cmp rdx,[rbx+48]
 jne fatal_protocol
 mov rcx,[rax+H_PARENT]
 cmp rcx,[rbx+56]
 jne fatal_protocol
 cmp rcx,1
 jb fatal_protocol
 cmp rcx,2
 ja fatal_protocol
 dec rcx
 imul rcx,HSIZE
 lea rcx,[r15+HANDLES+rcx]
 cmp QWORD PTR [rcx+H_LIVE],1
 jne fatal_protocol
 mov rdx,[rcx+H_GEN]
 cmp rdx,[rax+H_PARENTGEN]
 jne fatal_protocol
 mov rdi,[rax+H_PTR]
 test rdi,rdi
 jz fatal_protocol
 ret

require_no_resource:
 cmp QWORD PTR [rbx+32],0
 jne fatal_protocol
 cmp QWORD PTR [rbx+40],0
 jne fatal_protocol
 cmp QWORD PTR [rbx+48],0
 jne fatal_protocol
 ret

validate_effect:
 mov rbx,[r15+OUTPTR]
 mov rax,EFFECT_MAGIC
 cmp [rbx],rax
 jne fatal_protocol
 cmp QWORD PTR [rbx+8],32
 ja fatal_protocol
 mov rax,[r15+SEQUENCE]
 add rax,1
 jc fatal_protocol
 cmp rax,[rbx+16]
 jne fatal_protocol
 mov [r15+SEQUENCE],rax
 cmp QWORD PTR [rbx+24],0
 jne fatal_protocol
 cmp QWORD PTR [rbx+104],1
 jne fatal_protocol
 cmp QWORD PTR [rbx+112],0
 jne fatal_protocol
 cmp QWORD PTR [rbx+120],0
 jne fatal_protocol
 mov rax,[rbx+96]
 cmp rax,[rbx+128]
 jne fatal_protocol
 add rax,136
 jc fatal_protocol
 cmp rax,[r15+EFFECTLEN]
 jne fatal_protocol
 ret

/* Event construction is mechanical: same operation/sequence/resource token,
 * raw return code, and exactly one opaque byte field. Call-specific scalar
 * observations (type/count/mode/uid/inode/autocommit) are copied by the caller. */
event_header:
 push rbp
 mov rbp,rsp
 sub rsp,32
 mov [rbp-8],rdi
 mov [rbp-16],rsi
 add rsi,136
 jc fatal_memory
 mov [r15+INPUTLEN],rsi
 lea rdi,[r15+INPTR]
 call reserve_buffer
 test rax,rax
 js fatal_memory
 mov rdi,[r15+INPTR]
 mov rsi,[r15+OUTPTR]
 mov ecx,128
 rep movsb
 mov rax,[r15+INPTR]
 mov rdx,EVENT_MAGIC
 mov [rax],rdx
 mov rdx,[rbp-8]
 mov [rax+24],rdx
 mov rdx,[rbp-16]
 mov [rax+96],rdx
 mov [rax+128],rdx
 leave
 ret

reserve_driver_buffers:
 push rbp
 mov rbp,rsp
 mov rax,[r15+INPUTLEN]
 cmp rax,[r15+MAXINPUT]
 jbe reserve_known
 mov [r15+MAXINPUT],rax
reserve_known:
 cmp QWORD PTR [r15+ACTIVE_DRIVER],1
 je reserve_agent_buffers
 mov rsi,[r15+MAXINPUT]
 mov rax,rsi
 shr rax,59
 jnz fatal_memory
 shl rsi,4
 add rsi,65536
 jc fatal_memory
 lea rdi,[r15+WORKPTR]
 call reserve_buffer
 test rax,rax
 js fatal_memory
 mov rsi,[r15+MAXINPUT]
 shl rsi,1
 jc fatal_memory
 add rsi,4096
 jc fatal_memory
 lea rdi,[r15+OUTPTR]
 call reserve_buffer
 test rax,rax
 js fatal_memory
 leave
 ret

/* The internal agent retains path, request, six observed columns and their
 * exact JSON wire simultaneously. The bound is <=20*M+fixed; 32*M+65536
 * covers it. The largest effect is <=12*M+fixed and still subject to the
 * original component JSON limit; 16*M+4096 covers its private output.
 * This changes allocation only. ACTIVE_DRIVER=0 retains the original code. */
reserve_agent_buffers:
 mov rax,[r15+MAXINPUT]
 mov edx,32
 mul rdx
 test rdx,rdx
 jnz fatal_memory
 add rax,65536
 jc fatal_memory
 mov rsi,rax
 lea rdi,[r15+WORKPTR]
 call reserve_buffer
 test rax,rax
 js fatal_memory
 mov rax,[r15+MAXINPUT]
 mov edx,16
 mul rdx
 test rdx,rdx
 jnz fatal_memory
 add rax,4096
 jc fatal_memory
 mov rsi,rax
 lea rdi,[r15+OUTPTR]
 call reserve_buffer
 test rax,rax
 js fatal_memory
 leave
 ret

/* ptr/cap adjacency, checked growth only. No reset of live HIA workspace. */
reserve_buffer:
 mov r8,rdi
 cmp rsi,[r8+8]
 jbe reserve_done
 add rsi,4095
 jc reserve_bad
 and rsi,-4096
 mov r9,rsi
 mov rdi,[r8]
 test rdi,rdi
 jz reserve_new
 mov rsi,[r8+8]
 mov rdx,r9
 mov r10d,1
 mov eax,25
 syscall
 jmp reserve_result
reserve_new:
 xor edi,edi
 mov rsi,r9
 mov edx,3
 mov r10d,0x22
 push r8
 mov r8,-1
 xor r9d,r9d
 mov eax,9
 syscall
 pop r8
 mov r9,rsi
reserve_result:
 cmp rax,-4095
 jae reserve_return
 mov [r8],rax
 mov [r8+8],r9
reserve_done:
 xor eax,eax
reserve_return:
 ret
reserve_bad:
 mov rax,-12
 ret

read_exact:
 mov r8,rdx
 mov r9,rdi
 mov r10,rsi
read_loop:
 test r8,r8
 jz io_complete
 mov rdi,r9
 mov rsi,r10
 mov rdx,r8
 xor eax,eax
 syscall
 cmp rax,-4
 je read_loop
 test rax,rax
 jle io_failed
 add r10,rax
 sub r8,rax
 jmp read_loop
write_exact:
 mov r8,rdx
 mov r9,rdi
 mov r10,rsi
write_loop:
 test r8,r8
 jz io_complete
 mov rdi,r9
 mov rsi,r10
 mov rdx,r8
 mov eax,1
 syscall
 cmp rax,-4
 je write_loop
 test rax,rax
 jle io_failed
 add r10,rax
 sub r8,rax
 jmp write_loop
io_complete:
 xor eax,eax
 ret
io_failed:
 mov eax,1
 ret

trace_record:
 push rbp
 mov rbp,rsp
 sub rsp,32
 mov [rbp-32],rdi
 mov [rbp-24],rdx
 mov [rbp-16],rsi
 mov edi,2
 lea rsi,[rbp-32]
 mov edx,16
 call write_exact
 test eax,eax
 jnz fatal_io
 mov edi,2
 mov rsi,[rbp-16]
 mov rdx,[rbp-24]
 call write_exact
 test eax,eax
 jnz fatal_io
 leave
 ret

normal_exit:
 call require_no_resource
 cmp QWORD PTR [r15+HANDLES+H_LIVE],0
 jne fatal_protocol
 cmp QWORD PTR [r15+HANDLES+HSIZE+H_LIVE],0
 jne fatal_protocol
 cmp QWORD PTR [r15+HANDLES+HSIZE*2+H_LIVE],0
 jne fatal_protocol
 cmp QWORD PTR [r15+FD_HANDLES+H_LIVE],0
 jne fatal_protocol
 cmp QWORD PTR [r15+FD_HANDLES+HSIZE+H_LIVE],0
 jne fatal_protocol
 cmp QWORD PTR [r15+FD_HANDLES+HSIZE*2+H_LIVE],0
 jne fatal_protocol
 xor edi,edi
 mov eax,231
 syscall
fatal_protocol:
 mov edi,70
 jmp fatal_exit
fatal_memory:
 mov edi,71
 jmp fatal_exit
fatal_io:
 mov edi,74
fatal_exit:
 /* Any failure loses the authority to publish a response. Close may roll back
  * an uncommitted engine transaction; no compensating SQL is invented here. */
 mov r14d,edi
 and rsp,-16
 lea r12,[r15+FD_HANDLES]
 mov r13d,3
fatal_fd_next:
 cmp QWORD PTR [r12+H_LIVE],1
 jne fatal_fd_skip
 mov rdi,[r12+H_PTR]
 mov eax,3
 syscall
 mov QWORD PTR [r12+H_LIVE],0
 mov QWORD PTR [r12+H_PTR],0
fatal_fd_skip:
 add r12,HSIZE
 dec r13
 jnz fatal_fd_next
 mov rdi,[r15+HANDLES+HSIZE*2+H_PTR]
 test rdi,rdi
 jz fatal_budget
 call sqlite3_finalize@PLT
fatal_budget:
 mov rdi,[r15+HANDLES+HSIZE+H_PTR]
 test rdi,rdi
 jz fatal_main
 call sqlite3_close@PLT
fatal_main:
 mov rdi,[r15+HANDLES+H_PTR]
 test rdi,rdi
 jz fatal_done
 call sqlite3_close@PLT
fatal_done:
 mov edi,r14d
 mov eax,231
 syscall
 hlt

.balign 16
.global hia_platform_driver_start
.global hia_platform_driver_end
hia_platform_driver_start:
.incbin "driver.image"
hia_platform_driver_end:
.balign 16
.global hia_platform_canonical_start
.global hia_platform_canonical_end
hia_platform_canonical_start:
.incbin "canonical.image"
hia_platform_canonical_end:
.balign 16
.global hia_platform_agent_start
.global hia_platform_agent_end
hia_platform_agent_start:
.incbin "agent.image"
hia_platform_agent_end:
.balign 16
.global hia_platform_journal_start
.global hia_platform_journal_end
hia_platform_journal_start:
.incbin "journal.image"
hia_platform_journal_end:
.p2align 4
hia_platform_policy_start:
.incbin "policy.image"
hia_platform_policy_end:

.balign 16
.global hia_platform_sha_stream_start
.global hia_platform_sha_stream_end
hia_platform_sha_stream_start:
.incbin "sha-stream.image"
hia_platform_sha_stream_end:

.balign 16
hia_platform_preflight_start:
.incbin "preflight.image"
hia_platform_preflight_end:

.balign 16
hia_platform_data_json_start:
.incbin "data-json.image"
hia_platform_data_json_end:

.balign 16
hia_platform_binary64_start:
.incbin "binary64.image"
hia_platform_binary64_end:

.section .bss
.balign 64
context:
 .zero 1280
.section .note.GNU-stack,"",@progbits
