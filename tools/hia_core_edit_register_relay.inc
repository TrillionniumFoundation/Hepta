# ABI: r12 is the admitted source arena (with a writable layout tail);
# rbp is the adapter state and [rbp+88] is the exact Core byte count.
# rsi is the sealed Plan byte count; rdx is an optional expected SHA-256 hex.
.equ REGISTER_OUTPUT_N,16777216
.equ REGISTER_WORK_N,134217728
.equ REGISTER_ARENA_N,4096
.equ PLAN_LENGTH,0
.equ PLAN_DIGEST,8
.equ JSON_PACKET,16
.equ JSON_LENGTH,24
.equ NATIVE_OUTPUT,32
.equ NATIVE_WORK,40
.equ SCHEDULE_LENGTH,48
.equ HASH_DIGEST,64
.equ HASH_WORK,96
.equ HASH_HEX,1184
realize_register_plan:
 push rbx
 push rsi
 push rdx
 mov esi,REGISTER_ARENA_N
 call allocate
 mov rbx,rax
 pop QWORD PTR [rbx+PLAN_DIGEST]
 pop QWORD PTR [rbx+PLAN_LENGTH]
 cmp QWORD PTR [rbx+PLAN_DIGEST],0
 je register_core_digest
 lea rdi,[r12+SOURCE_N]
 mov rsi,[rbx+PLAN_LENGTH]
 lea rdx,[rbx+HASH_DIGEST]
 lea r8,[rbx+HASH_WORK]
 call hash_register_bytes
 lea rdi,[rbx+HASH_HEX]
 call write_register_hex
 lea rsi,[rbx+HASH_HEX]
 mov rdi,[rbx+PLAN_DIGEST]
 mov ecx,64
 cld
 repe cmpsb
 jne invalid
register_core_digest:
 mov rdi,r12
 mov rsi,[rbp+88]
 lea rdx,[rbx+HASH_DIGEST]
 lea r8,[rbx+HASH_WORK]
 call hash_register_bytes
 mov rsi,[rbp+88]
 add rsi,[rbx+PLAN_LENGTH]
 add rsi,70
 mov [rbx+JSON_LENGTH],rsi
 call allocate
 mov [rbx+JSON_PACKET],rax
 mov rdi,rax
 mov al,91
 cld
 stosb
 mov rsi,r12
 mov rcx,[rbp+88]
 rep movsb
 mov ax,0x222c
 stosw
 call write_register_hex
 mov ax,0x2c22
 stosw
 lea rsi,[r12+SOURCE_N]
 mov rcx,[rbx+PLAN_LENGTH]
 rep movsb
 mov al,93
 stosb
 sub rdi,[rbx+JSON_PACKET]
 cmp rdi,[rbx+JSON_LENGTH]
 jne invalid
 mov rdi,[rbx+JSON_PACKET]
 mov rsi,[rbx+JSON_LENGTH]
 mov edx,1
 call protect
 mov esi,REGISTER_OUTPUT_N
 call allocate
 mov [rbx+NATIVE_OUTPUT],rax
 mov esi,REGISTER_WORK_N
 call allocate
 mov [rbx+NATIVE_WORK],rax
 mov rdi,[rbx+JSON_PACKET]
 mov rsi,[rbx+JSON_LENGTH]
 mov rdx,[rbx+NATIVE_OUTPUT]
 mov ecx,REGISTER_OUTPUT_N
 mov r8,rax
 mov r9d,REGISTER_WORK_N
 .ifdef HIA_NOMINAL_REGISTERS
 call build_register_schedule_start
 .else
 .byte 0xe8
register_schedule_hole: .long 0
 .endif
 cmp rax,80
 jb invalid
 cmp rax,LAYOUT_N
 ja native_status
 mov [rbx+SCHEDULE_LENGTH],rax
 mov rcx,rax
 lea rdi,[r12+SOURCE_N]
 mov rsi,[rbx+NATIVE_OUTPUT]
 rep movsb
 mov rdi,[rbx+JSON_PACKET]
 mov rsi,[rbx+JSON_LENGTH]
 mov rdx,[rbx+NATIVE_OUTPUT]
 mov ecx,REGISTER_OUTPUT_N
 mov r8,[rbx+NATIVE_WORK]
 mov r9d,REGISTER_WORK_N
 .ifdef HIA_NOMINAL_REGISTERS
 call build_register_layout_start
 .else
 .byte 0xe8
register_layout_hole: .long 0
 .endif
 cmp rax,96
 jb invalid
 cmp rax,LAYOUT_N
 ja native_status
 mov rcx,rax
 add rax,[rbx+SCHEDULE_LENGTH]
 cmp rax,LAYOUT_N
 ja capacity
 lea rdi,[r12+SOURCE_N]
 add rdi,[rbx+SCHEDULE_LENGTH]
 mov rsi,[rbx+NATIVE_OUTPUT]
 rep movsb
 mov rdi,[rbx+JSON_PACKET]
 mov rsi,[rbx+JSON_LENGTH]
 call release
 mov rdi,[rbx+NATIVE_OUTPUT]
 mov esi,REGISTER_OUTPUT_N
 call release
 mov rdi,[rbx+NATIVE_WORK]
 mov esi,REGISTER_WORK_N
 call release
 mov rdi,rbx
 mov esi,REGISTER_ARENA_N
 call release
 pop rbx
 ret

hash_register_bytes:
 sub rsp,8
 mov ecx,32
 mov r9d,1088
 .ifdef HIA_NOMINAL_REGISTERS
 call build_register_hash_start
 .else
 .byte 0xe8
register_hash_hole: .long 0
 .endif
 cmp rax,32
 jne invalid
 add rsp,8
 ret

write_register_hex:
 xor r10d,r10d
 lea r11,[rip+register_hex_digits]
register_hex:
 movzx eax,BYTE PTR [rbx+r10+HASH_DIGEST]
 mov edx,eax
 shr eax,4
 and edx,15
 mov al,[r11+rax]
 stosb
 mov al,[r11+rdx]
 stosb
 inc r10
 cmp r10,32
 jb register_hex
 ret
register_hex_digits:
 .ascii "0123456789abcdef"
