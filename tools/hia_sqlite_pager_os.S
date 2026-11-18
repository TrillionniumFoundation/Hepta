/* Fixed Linux x86-64 primitive transport.
 * No SQLite search, retry, endmark selection or cleanup policy lives here.
 * Each valid request consumes one nonce/sequence and performs one primitive.
 * The caller owns three disjoint live allocations for the entire call.
 * Exact raw syscall return is kept; close consumes its handle before syscall.
 * This assembly is an explicit bootstrap boundary, not all-HIA completion.
 */
.intel_syntax noprefix
.text
.global pager_os_once
.type pager_os_once,@function
.equ REQUEST_MAGIC, 0x32534f4750414948
.equ RECEIPT_MAGIC, 0x324f494750414948
.equ CONTEXT_MAGIC, 0x32585443534f4750
.equ ABI_REFUSE, 4294967293

/* rdi=request, rsi=128, rdx=io, rcx=65664, r8=context, r9=4096 */
pager_os_once:
 push rbp
 push rbx
 push r12
 push r13
 push r14
 push r15
 sub rsp,8
 mov r12,rdi
 mov r13,rdx
 mov r14,r8
 cmp rsi,128
 jne .Lbad
 cmp rcx,65664
 jne .Lbad
 cmp r9,4096
 jne .Lbad
 test r12,r12
 jz .Lbad
 test r13,r13
 jz .Lbad
 test r14,r14
 jz .Lbad
 /* Exact extents, overflow and pairwise overlap before the first memory read. */
 mov rax,r12
 add rax,128
 jc .Lbad
 mov rdx,r13
 add rdx,65664
 jc .Lbad
 mov rcx,r14
 add rcx,4096
 jc .Lbad
 cmp rax,r13
 jbe .Lsep_ri
 cmp rdx,r12
 ja .Lbad
.Lsep_ri:
 cmp rax,r14
 jbe .Lsep_rc
 cmp rcx,r12
 ja .Lbad
.Lsep_rc:
 cmp rdx,r14
 jbe .Lsep_ic
 cmp rcx,r13
 ja .Lbad
.Lsep_ic:
 mov rax,REQUEST_MAGIC
 cmp [r12],rax
 jne .Lbad
 cmp QWORD PTR [r12+8],2
 jne .Lbad
 mov rax,CONTEXT_MAGIC
 cmp [r14],rax
 jne .Lbad
 cmp QWORD PTR [r14+8],2
 jne .Lbad
 mov rax,[r12+16]
 test rax,rax
 jz .Lbad
 cmp rax,[r14+16]
 jne .Lbad
 mov rax,[r14+56]
 inc rax
 jz .Lbad
 cmp rax,[r12+24]
 jne .Lbad
 mov ecx,72
.Lreserved:
 cmp QWORD PTR [r12+rcx],0
 jne .Lbad
 add ecx,8
 cmp ecx,128
 jb .Lreserved
 mov rbx,[r12+40]
 mov r15,[r12+32]
 cmp r15,12
 je .Lnamed_stat
 cmp rbx,2
 ja .Lbad
 cmp r15,1
 je .Lopen
 cmp r15,2
 je .Lstat
 cmp r15,3
 je .Lpread
 cmp r15,4
 je .Llock
 cmp r15,5
 je .Lmap
 cmp r15,6
 je .Lcopy
 cmp r15,7
 je .Lmark
 cmp r15,8
 je .Lunmap
 cmp r15,9
 je .Lclose
 cmp r15,10
 je .Lsleep
 cmp r15,11
 je .Lquery
 jmp .Lbad

/* Guard helpers are inline: no failure jumps through an unpopped call. */
.macro zero_args
 cmp QWORD PTR [r12+48],0
 jne .Lbad
 cmp QWORD PTR [r12+56],0
 jne .Lbad
 cmp QWORD PTR [r12+64],0
 jne .Lbad
.endm
.macro live_fd
 bt QWORD PTR [r14+80],rbx
 jnc .Lbad
 mov rbp,[r14+rbx*8+32]
 test rbp,rbp
 js .Lbad
.endm

.Lopen:
 cmp QWORD PTR [r12+56],0
 jne .Lbad
 cmp QWORD PTR [r12+64],0
 jne .Lbad
 cmp QWORD PTR [r12+48],0
 je .Lopen_guard
 cmp QWORD PTR [r12+48],1
 jne .Lbad
 test rbx,rbx
 jne .Lbad
.Lopen_guard:
 bt QWORD PTR [r14+80],rbx
 jc .Lbad
 cmp QWORD PTR [r14+rbx*8+32],-1
 jne .Lbad
 bt QWORD PTR [r14+192],rbx
 jc .Lbad
 mov rax,rbx
 shl rax,8
 lea rsi,[r14+rax+256]
 cmp BYTE PTR [rsi],0
 je .Lbad
 cmp BYTE PTR [rsi],'.'
 jne .Lname_scan
 cmp BYTE PTR [rsi+1],0
 je .Lbad
 cmp BYTE PTR [rsi+1],'.'
 jne .Lname_scan
 cmp BYTE PTR [rsi+2],0
 je .Lbad
.Lname_scan:
 xor ecx,ecx
.Lname_loop:
 cmp ecx,256
 jae .Lbad
 mov al,[rsi+rcx]
 test al,al
 jz .Lname_ok
 cmp al,'/'
 je .Lbad
 inc ecx
 jmp .Lname_loop
.Lname_ok:
 call .Lprepare
 mov rax,rbx
 shl rax,8
 lea rsi,[r14+rax+256]
 mov rdi,[r14+24]
 mov edx,0xa0000
 cmp QWORD PTR [r12+48],1
 jne .Lopen_ordinary
 or edx,0x802                /* O_RDWR | O_NONBLOCK, with no creation or write. */
 jmp .Lopen_flags
.Lopen_ordinary:
 cmp rbx,2
 jne .Lopen_flags
 or edx,2
.Lopen_flags:
 xor r10d,r10d
 mov eax,257
 syscall
 cmp rax,-4095
 jae .Lreturn_raw
 mov [r14+rbx*8+32],rax
 bts QWORD PTR [r14+80],rbx
 bts QWORD PTR [r14+192],rbx
 cmp QWORD PTR [r12+48],1
 jne .Lreturn_raw
 mov QWORD PTR [r14+200],1
 jmp .Lreturn_raw

/* Report the name's ordinary metadata or raw errno without following it.
 * Only the fixed four names of a checkpointed source can be observed. */
.Lnamed_stat:
 zero_args
 cmp rbx,3
 ja .Lbad
 cmp QWORD PTR [r14+200],1
 jne .Lbad
 test QWORD PTR [r14+168],1
 jz .Lbad
 call .Lprepare
 lea rdi,[r13+128]
 xor eax,eax
 mov ecx,18
 rep stosq
 mov rax,rbx
 shl rax,8
 lea rsi,[r14+rax+256]
 mov rdi,[r14+24]
 lea rdx,[r13+128]
 mov r10d,0x100              /* AT_SYMLINK_NOFOLLOW */
 mov eax,262                 /* newfstatat */
 syscall
 test rax,rax
 jnz .Lreturn_raw
 mov QWORD PTR [r13+48],144
 jmp .Lreturn_raw

.Lstat:
 zero_args
 live_fd
 call .Lprepare
 lea rdi,[r13+128]
 xor eax,eax
 mov ecx,18
 rep stosq
 mov rdi,rbp
 lea rsi,[r13+128]
 mov eax,5
 syscall
 test rax,rax
 jnz .Lreturn_raw
 mov QWORD PTR [r13+48],144
 cmp rbx,2
 jne .Lreturn_raw
 mov rdx,[r13+176]
 mov [r14+184],rdx
 jmp .Lreturn_raw

.Lpread:
 cmp rbx,1
 ja .Lbad
 cmp QWORD PTR [r12+64],0
 jne .Lbad
 mov rax,[r12+56]
 test rax,rax
 jz .Lbad
 cmp rax,65536
 ja .Lbad
 add rax,[r12+48]
 jc .Lbad
 test rax,rax
 js .Lbad
 live_fd
 call .Lprepare
 mov rdi,rbp
 lea rsi,[r13+128]
 mov rdx,[r12+56]
 mov r10,[r12+48]
 mov eax,17
 syscall
 test rax,rax
 jle .Lreturn_raw
 mov [r13+48],rax
 jmp .Lreturn_raw

.Llock:
 cmp QWORD PTR [r12+48],2
 ja .Lbad
 cmp rbx,0
 je .Ldb_lock_guard
 cmp rbx,2
 jne .Lbad
 cmp QWORD PTR [r12+64],1
 jne .Lbad
 mov rax,[r12+56]
 sub rax,120
 cmp rax,8
 ja .Lbad
 cmp rax,1
 je .Lbad
 cmp rax,0
 jne .Lnot_writer
 cmp QWORD PTR [r12+48],0
 je .Lbad
 jmp .Lshm_mode_ok
.Lnot_writer:
 cmp rax,2
 je .Lno_exclusive
 cmp rax,3
 je .Lno_exclusive
 cmp rax,8
 jne .Lshm_mode_ok
.Lno_exclusive:
 cmp QWORD PTR [r12+48],1
 je .Lbad
.Lshm_mode_ok:
 /* DMS and each individual byte are shadowed only after successful fcntl. */
 mov rdx,[r14+152]
 or rdx,[r14+160]
 cmp QWORD PTR [r12+48],2
 je .Lshm_unlock_guard
 bt rdx,rax
 jc .Lbad
 jmp .Llock_ready
.Lshm_unlock_guard:
 bt rdx,rax
 jnc .Lbad
 jmp .Llock_ready
.Ldb_lock_guard:
 cmp QWORD PTR [r14+200],1
 jne .Ldb_shared_guard
 /* Whole SQLite PENDING/RESERVED/SHARED range is one exclusive capability. */
 cmp QWORD PTR [r12+48],0
 je .Lbad
 cmp QWORD PTR [r12+56],1073741824
 jne .Lbad
 cmp QWORD PTR [r12+64],512
 jne .Lbad
 xor eax,eax
 jmp .Ldb_mode_guard
.Ldb_shared_guard:
 cmp QWORD PTR [r12+48],1
 je .Lbad
 xor eax,eax
 cmp QWORD PTR [r12+56],1073741824
 je .Ldb_pending_guard
 cmp QWORD PTR [r12+56],1073741826
 jne .Lbad
 cmp QWORD PTR [r12+64],510
 jne .Lbad
 mov eax,1
 jmp .Ldb_mode_guard
.Ldb_pending_guard:
 cmp QWORD PTR [r12+64],1
 jne .Lbad
.Ldb_mode_guard:
 mov rdx,[r14+168]
 cmp QWORD PTR [r12+48],2
 je .Ldb_unlock_guard
 bt rdx,rax
 jc .Lbad
 jmp .Llock_ready
.Ldb_unlock_guard:
 bt rdx,rax
 jnc .Lbad
.Llock_ready:
 live_fd
 call .Lprepare
 call .Lclear_scratch
 mov ax,WORD PTR [r12+48]
 mov WORD PTR [r14+96],ax
 mov rax,[r12+56]
 mov [r14+104],rax
 mov rax,[r12+64]
 mov [r14+112],rax
 mov rdi,rbp
 mov esi,6
 lea rdx,[r14+96]
 mov eax,72
 syscall
 test rax,rax
 jnz .Lreturn_raw
 cmp rbx,0
 je .Ldb_lock_update
 mov rcx,[r12+56]
 sub rcx,120
 btr QWORD PTR [r14+152],rcx
 btr QWORD PTR [r14+160],rcx
 cmp QWORD PTR [r12+48],2
 je .Lreturn_raw
 cmp QWORD PTR [r12+48],0
 je .Lshm_set_shared
 bts QWORD PTR [r14+152],rcx
 jmp .Lreturn_raw
.Lshm_set_shared:
 bts QWORD PTR [r14+160],rcx
 jmp .Lreturn_raw
.Ldb_lock_update:
 xor ecx,ecx
 cmp QWORD PTR [r12+56],1073741824
 je .Ldb_bit_ready
 mov ecx,1
.Ldb_bit_ready:
 btr QWORD PTR [r14+168],rcx
 cmp QWORD PTR [r12+48],2
 je .Lreturn_raw
 bts QWORD PTR [r14+168],rcx
 jmp .Lreturn_raw

.Lmap:
 cmp rbx,2
 jne .Lbad
 cmp QWORD PTR [r12+64],0
 jne .Lbad
 cmp QWORD PTR [r12+48],1048576
 ja .Lbad
 mov rcx,[r12+56]
 cmp rcx,1
 ja .Lbad
 bt QWORD PTR [r14+88],rcx
 jc .Lbad
 test rcx,rcx
 jnz .Lmap_index_guard
 cmp QWORD PTR [r12+48],0
 jne .Lbad
 jmp .Lmap_region_guard
.Lmap_index_guard:
 cmp QWORD PTR [r12+48],0
 je .Lbad
 mov rax,[r14+160]
 and eax,248
 jz .Lbad
.Lmap_region_guard:
 bt QWORD PTR [r14+160],8
 jnc .Lbad
 mov rax,[r12+48]
 inc rax
 shl rax,15
 cmp rax,[r14+184]
 ja .Lbad
 live_fd
 call .Lprepare
 xor edi,edi
 mov esi,32768
 mov edx,3
 cmp QWORD PTR [r12+56],0
 je .Lmap_prot
 mov edx,1
.Lmap_prot:
 mov r10d,1
 mov r8,rbp
 mov r9,[r12+48]
 shl r9,15
 mov eax,9
 syscall
 cmp rax,-4095
 jae .Lreturn_raw
 mov rcx,[r12+56]
 bts QWORD PTR [r14+88],rcx
 test rcx,rcx
 jnz .Lmapped_index
 mov [r14+64],rax
 mov QWORD PTR [r14+72],32768
 jmp .Lreturn_raw
.Lmapped_index:
 mov [r14+128],rax
 mov QWORD PTR [r14+136],32768
 mov rdx,[r12+48]
 mov [r14+144],rdx
 jmp .Lreturn_raw

.Lcopy:
 cmp rbx,2
 jne .Lbad
 mov rcx,[r12+64]
 cmp rcx,1
 ja .Lbad
 bt QWORD PTR [r14+88],rcx
 jnc .Lbad
 mov rax,[r12+48]
 test rax,3
 jnz .Lbad
 mov rdx,[r12+56]
 test rdx,rdx
 jz .Lbad
 test rdx,3
 jnz .Lbad
 add rdx,rax
 jc .Lbad
 cmp rdx,16384
 ja .Lbad
 test rcx,rcx
 jnz .Lcopy_guard_done
 cmp rax,128
 jae .Lcopy_guard_done
 cmp rdx,120
 ja .Lbad
.Lcopy_guard_done:
 call .Lprepare
 mov rbp,[r14+64]
 cmp QWORD PTR [r12+64],0
 je .Lcopy_base
 mov rbp,[r14+128]
.Lcopy_base:
 add rbp,[r12+48]
 xor ecx,ecx
 mfence
.Lcopy_words:
 mov edx,DWORD PTR [rbp+rcx]
 mov DWORD PTR [r13+rcx+128],edx
 add rcx,4
 cmp rcx,[r12+56]
 jb .Lcopy_words
 mfence
 mov [r13+48],rcx
 xor eax,eax
 jmp .Lreturn_raw

.Lmark:
 cmp rbx,2
 jne .Lbad
 cmp QWORD PTR [r12+64],0
 jne .Lbad
 mov rcx,[r12+48]
 cmp rcx,1
 jb .Lbad
 cmp rcx,4
 ja .Lbad
 mov rax,[r12+56]
 shr rax,32
 jnz .Lbad
 bt QWORD PTR [r14+88],0
 jnc .Lbad
 add rcx,3
 bt QWORD PTR [r14+152],rcx
 jnc .Lbad
 call .Lprepare
 mov rcx,[r12+48]
 mov rbp,[r14+64]
 mov edx,DWORD PTR [r12+56]
 mfence
 mov DWORD PTR [rbp+rcx*4+100],edx
 mfence
 xor eax,eax
 jmp .Lreturn_raw

.Lunmap:
 cmp rbx,2
 jne .Lbad
 cmp QWORD PTR [r12+56],0
 jne .Lbad
 cmp QWORD PTR [r12+64],0
 jne .Lbad
 mov rcx,[r12+48]
 cmp rcx,1
 ja .Lbad
 bt QWORD PTR [r14+88],rcx
 jnc .Lbad
 call .Lprepare
 mov rdi,[r14+64]
 cmp QWORD PTR [r12+48],0
 je .Lunmap_base
 mov rdi,[r14+128]
.Lunmap_base:
 mov esi,32768
 mov eax,11
 syscall
 test rax,rax
 jnz .Lreturn_raw
 mov rcx,[r12+48]
 btr QWORD PTR [r14+88],rcx
 test rcx,rcx
 jnz .Lunmapped_index
 mov QWORD PTR [r14+64],0
 mov QWORD PTR [r14+72],0
 jmp .Lreturn_raw
.Lunmapped_index:
 mov QWORD PTR [r14+128],0
 mov QWORD PTR [r14+136],0
 mov QWORD PTR [r14+144],0
 jmp .Lreturn_raw

.Lclose:
 zero_args
 live_fd
 cmp rbx,2
 jne .Lclose_db_guard
 cmp QWORD PTR [r14+88],0
 jne .Lbad
 cmp QWORD PTR [r14+152],0
 jne .Lbad
 cmp QWORD PTR [r14+160],0
 jne .Lbad
 jmp .Lclose_ready
.Lclose_db_guard:
 cmp rbx,0
 jne .Lclose_ready
 cmp QWORD PTR [r14+168],0
 jne .Lbad
.Lclose_ready:
 call .Lprepare
 btr QWORD PTR [r14+80],rbx
 mov QWORD PTR [r14+rbx*8+32],-1
 mov rdi,rbp
 mov eax,3
 syscall
 jmp .Lreturn_raw

.Lsleep:
 cmp rbx,0
 jne .Lbad
 cmp QWORD PTR [r12+48],1000000000
 ja .Lbad
 cmp QWORD PTR [r12+56],0
 jne .Lbad
 cmp QWORD PTR [r12+64],0
 jne .Lbad
 call .Lprepare
 call .Lclear_scratch
 mov rax,[r12+48]
 cmp rax,1000000000
 jne .Lsleep_ns
 mov QWORD PTR [r14+96],1
 xor eax,eax
.Lsleep_ns:
 mov [r14+104],rax
 lea rdi,[r14+96]
 lea rsi,[r14+112]
 mov eax,35
 syscall
 cmp rax,-4
 jne .Lreturn_raw
 mov rdx,[r14+112]
 mov [r13+128],rdx
 mov rdx,[r14+120]
 mov [r13+136],rdx
 mov QWORD PTR [r13+48],16
 jmp .Lreturn_raw

.Lquery:
 cmp rbx,2
 jne .Lbad
 zero_args
 live_fd
 call .Lprepare
 call .Lclear_scratch
 mov WORD PTR [r14+96],1
 mov QWORD PTR [r14+104],128
 mov QWORD PTR [r14+112],1
 mov rdi,rbp
 mov esi,5
 lea rdx,[r14+96]
 mov eax,72
 syscall
 test rax,rax
 jnz .Lreturn_raw
 mov rdx,[r14+96]
 mov [r13+128],rdx
 mov rdx,[r14+104]
 mov [r13+136],rdx
 mov rdx,[r14+112]
 mov [r13+144],rdx
 mov rdx,[r14+120]
 mov [r13+152],rdx
 mov QWORD PTR [r13+48],32
 jmp .Lreturn_raw

/* No branch below can issue another primitive or perform an implicit retry. */
.Lprepare:
 mov rax,[r12+24]
 mov [r14+56],rax
 mov rdi,r13
 xor eax,eax
 mov ecx,16
 rep stosq
 mov rax,RECEIPT_MAGIC
 mov [r13],rax
 mov QWORD PTR [r13+8],2
 mov rax,[r12+16]
 mov [r13+16],rax
 mov rax,[r12+24]
 mov [r13+24],rax
 mov [r13+32],r15
 ret

.Lclear_scratch:
 mov QWORD PTR [r14+96],0
 mov QWORD PTR [r14+104],0
 mov QWORD PTR [r14+112],0
 mov QWORD PTR [r14+120],0
 ret

.Lreturn_raw:
 mov [r13+40],rax
 xor eax,eax
 jmp .Ldone
.Lbad:
 mov eax,ABI_REFUSE
.Ldone:
 add rsp,8
 pop r15
 pop r14
 pop r13
 pop r12
 pop rbx
 pop rbp
 ret
.size pager_os_once,.-pager_os_once
.section .note.GNU-stack,"",@progbits
