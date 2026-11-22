.intel_syntax noprefix
.text
.global _start
.equ CORE_N,67108864
.equ SOURCE_N,41943040
.equ LAYOUT_N,8388608
.equ RAW_N,8388608
.equ EVT_N,34880
.equ EVT_MAP,36864
.equ CODE_N,16777280
.equ ART_N,67108864
.equ WRITE_W,33554432
.equ C,67092480
.equ BORROW_INPUT_N,8454144
.equ BORROW_PLAN_N,8388608
.equ BORROW_TABLE_N,32768
.equ BORROW_TEXT_N,262144
.equ BORROW_PACKET_N,266240
.equ borrow_plan,184
.equ borrow_table,192
.equ borrow_text,200
.equ borrow_scratch,208
.equ borrow_packet,216
.equ borrow_pending,224
.equ borrow_call,232
.equ borrow_width,240
.equ borrow_end,248
.equ source_extent,280
.equ layout_extent,288
.equ layout_progress,296
.equ layout_fd,304
.equ layout_stat,320
_start:
 xor r15d,r15d
 xor ebx,ebx
 cmp QWORD PTR [rsp],1
 je initialize
 cmp QWORD PTR [rsp],3
 jne usage
 mov rsi,[rsp+16]
 lea rdi,[rip+layout_argument]
 mov ecx,17
 cld
 repe cmpsb
 jne usage
 mov rsi,[rsp+24]
layout_digit:
 movzx eax,BYTE PTR [rsi]
 test eax,eax
 jz layout_argument_ready
 sub eax,48
 cmp eax,9
 ja usage
 imul rbx,rbx,10
 add rbx,rax
 cmp rbx,2147483647
 ja usage
 inc rsi
 jmp layout_digit
layout_argument_ready:
 cmp rbx,3
 jb usage
 mov r15d,LAYOUT_N
initialize:
 .byte 0x4c,0x8d,0x35
byte_address_hole: .long 0
 mov esi,4096
 call allocate
 mov rbp,rax
 mov [rbp+layout_fd],rbx
 lea rsi,[r15+SOURCE_N]
 mov [rbp+source_extent],rsi
 call allocate
 mov r12,rax
 mov [rbp],rax
 mov esi,CORE_N
 call allocate
 mov r13,rax
 mov [rbp+8],rax
 mov esi,EVT_MAP
 call allocate
 mov [rbp+16],rax
 test r15,r15
 jz read_input
 call capture_layout
read_input:
 xor edi,edi
 mov rax,[rbp+88]
 lea rsi,[r12+rax]
 mov edx,RAW_N+1
 cmp BYTE PTR [r12],91
 jne input_read_extent
 mov edx,BORROW_INPUT_N+1
input_read_extent:
 sub rdx,rax
 xor eax,eax
 syscall
 cmp rax,-4
 je read_input
 test rax,rax
 js io_failure
 jz input_complete
 add [rbp+88],rax
 cmp BYTE PTR [r12],91
 je input_borrow_extent
 cmp QWORD PTR [rbp+88],RAW_N
 ja capacity
 jmp read_input
input_borrow_extent:
 cmp QWORD PTR [rbp+88],BORROW_INPUT_N
 ja capacity
 jmp read_input
input_complete:
 cmp BYTE PTR [r12],91
 jne admit_core_input
 call bind_borrowed_input
admit_core_input:
 mov rdi,r12
 mov esi,RAW_N
 mov edx,1
 call protect
 mov rdi,r12
 mov rsi,[rbp+88]
 mov rdx,r13
 mov ecx,CORE_N
 lea r8,[r12+RAW_N]
 mov r9d,33554432
 .byte 0xe8
core_hole: .long 0
 test rax,rax
 jnz native_status
 mov rdi,r12
 mov esi,SOURCE_N
 mov edx,1
 call protect
 mov rdi,r12
 mov esi,SOURCE_N
 mov rdx,[rbp+16]
 mov ecx,EVT_N
 mov r8,r13
 mov r9d,CORE_N
 .byte 0xe8
frame_hole: .long 0
 test rax,rax
 jnz native_status
 cmp QWORD PTR [rbp+borrow_table],0
 je bind_public_exports
 mov rbx,[rbp+16]
 movabs rax,0x3130425842414948  # HIABXB01
 mov [rbx+16384],rax
 mov rsi,[rbp+borrow_table]
 lea rdi,[rbx+16408]
 mov ecx,1024
copy_borrow_extents:
 mov rax,[rsi]
 mov [rdi],rax
 add rsi,32
 add rdi,8
 dec ecx
 jnz copy_borrow_extents
bind_public_exports:
 mov rdi,r12
 mov esi,SOURCE_N
 mov rdx,[rbp+16]
 mov ecx,EVT_N
 mov r8,r13
 mov r9d,CORE_N
 .byte 0xe8
exports_hole: .long 0
 test rax,rax
 jnz native_status
 movabs rax,3616483217365879112
 mov [rbp+768],rax
 mov QWORD PTR [rbp+776],1
codegen_loop:
 mov rdi,r12
 mov rsi,[rbp+source_extent]
 mov rdx,[rbp+16]
 mov ecx,EVT_N
 mov r8,r13
 mov r9d,CORE_N
 .byte 0xe8
codegen_hole: .long 0
 test rax,rax
 jnz native_status
 mov rdi,[rbp+16]
 mov esi,EVT_MAP
 mov edx,1
 call protect
 mov rbx,[rbp+16]
 movabs rax,3544425636246407496
 cmp [rbx],rax
 jne io_failure
 mov rax,[rbx+8]
 cmp rax,128
 ja io_failure
 mov [rbp+112],rax
 mov [rbp+104],rax
 imul rax,272
 add rax,64
 cmp [rbx+16],rax
 jne io_failure
 mov rax,[rbx+40]
 mov [rbp+120],rax
 cmp QWORD PTR [rbx+48],1
 je codegen_complete
 cmp QWORD PTR [rbx+48],0
 jne io_failure
 lea rax,[rbx+64]
 mov [rbp+96],rax
next_event:
 cmp QWORD PTR [rbp+104],0
 je capture_batch
 mov rbx,[rbp+96]
 cmp QWORD PTR [rbx],1
 je numeric_event
 cmp QWORD PTR [rbx],3
 je borrowed_event
 cmp QWORD PTR [rbx],2
 jne io_failure
 lea rdi,[rbx+8]
 mov esi,64
 mov rax,[rbx+16]
 test rax,rax
 jz initialize_code
 cmp QWORD PTR [rbp+24],0
 je io_failure
 cmp rax,4
 je named_event
 cmp rax,5
 je named_event
 cmp rax,2
 je invoke_state
 cmp rax,3
 je invoke_state
 cmp rax,6
 je invoke_state
 cmp rax,7
 jne io_failure
 jmp invoke_state
named_event:
 mov rax,[rbx+24]
 test rax,rax
 jz io_failure
 cmp rax,192
 ja io_failure
 add rsi,rax
 jmp invoke_state
initialize_code:
 cmp QWORD PTR [rbp+24],0
 jne io_failure
 lea rdi,[rbx+8]
 push 64
 pop rsi
 lea rdx,[rbp+512]
 push 8
 pop rcx
 lea r8,[rbp+600]
 push 8
 pop r9
 call r14
 mov edx,0xffffff00
 cmp rax,rdx
 jae native_status
 test rax,rax
 jz io_failure
 mov [rbp+32],rax
 mov rsi,rax
 call allocate
 mov [rbp+40],rax
 mov esi,CODE_N
 call allocate
 mov [rbp+24],rax
 lea rdi,[rbx+8]
 mov esi,64
invoke_state:
 call byte_state
 jmp event_complete
numeric_event:
 cmp QWORD PTR [rbp+24],0
 je io_failure
 lea rdi,[rbx+8]
 mov esi,64
 lea rdx,[rbp+512]
 mov ecx,80
 lea r8,[rbp+600]
 mov r9d,8
 call r14
 test rax,rax
 jnz native_status
 mov rcx,[rbp+512]
 cmp rcx,63
 ja io_failure
 lea rax,[rcx+8]
 cmp [rbp+600],rax
 jne io_failure
 mov [rbp+784],rcx
 lea rsi,[rbp+520]
 lea rdi,[rbp+832]
 rep movsb
 lea rdi,[rbp+768]
 mov rsi,[rbp+784]
 add rsi,64
 call byte_state
 event_complete:
 add QWORD PTR [rbp+96],272
 dec QWORD PTR [rbp+104]
 jmp next_event
capture_batch:
 mov rbx,[rbp+24]
 test rbx,rbx
 jz io_failure
 movabs rax,3616465607999965512
 cmp [rbx],rax
 jne io_failure
 mov rax,[rbx+8]
 cmp rax,16777216
 ja io_failure
 mov [r13+C+48],rax
 mov rax,[rbp+120]
 mov [r13+C+184],rax
 mov rax,[rbp+112]
 mov [r13+C+200],rax
 mov QWORD PTR [r13+C+208],0
 mov rax,[rbx+40]
 mov [r13+C+216],rax
 mov rdi,[rbp+16]
 mov esi,EVT_MAP
 mov edx,3
 call protect
 jmp codegen_loop
codegen_complete:
 cmp QWORD PTR [rbp+112],0
 jne io_failure
 cmp QWORD PTR [rbp+borrow_pending],0
 jne io_failure
 cmp QWORD PTR [rbp+borrow_table],0
 je codegen_state_complete
 mov rdi,[rbp+borrow_plan]
 mov esi,BORROW_PLAN_N
 call release
 mov rdi,[rbp+borrow_table]
 mov esi,BORROW_TABLE_N
 call release
 mov rdi,[rbp+borrow_text]
 mov esi,BORROW_TEXT_N
 call release
 mov rdi,[rbp+borrow_scratch]
 mov esi,4096
 call release
 mov rdi,[rbp+borrow_packet]
 mov esi,BORROW_PACKET_N
 call release
codegen_state_complete:
 mov rbx,[rbp+24]
 test rbx,rbx
 jz io_failure
 cmp QWORD PTR [rbx+40],1
 jne io_failure
 mov rdi,rbx
 mov esi,CODE_N
 mov edx,1
 call protect
 mov rdi,[rbp+40]
 mov rsi,[rbp+32]
 mov edx,1
 call protect
 mov rdi,r13
 mov esi,CORE_N
 mov edx,1
 call protect
 mov esi,20480
 call allocate
 mov [rbp+136],rax
 mov rdi,r12
 mov esi,SOURCE_N
 mov rdx,rax
 mov ecx,20480
 mov r8,r13
 mov r9d,CORE_N
 .byte 0xe8
expectations_hole: .long 0
 test rax,rax
 jz io_failure
 cmp rax,18496
 ja native_status
 cmp rax,64
 jb io_failure
 mov [rbp+144],rax
 mov rdi,[rbp+136]
 cmp [rdi+24],rax
 jne io_failure
 cmp QWORD PTR [rdi+32],0
 jne io_failure
 mov esi,20480
 mov edx,1
 call protect
 mov rdi,r12
 mov rsi,[rbp+source_extent]
 call release
 mov rdi,r13
 mov esi,CORE_N
 call release
 mov rdi,[rbp+16]
 mov esi,EVT_MAP
 call release
 mov esi,ART_N
 call allocate
 mov [rbp+64],rax
 mov rdi,[rbp+24]
 mov esi,CODE_N
 mov rdx,rax
 mov ecx,ART_N
 mov r8,[rbp+40]
 mov r9,[rbp+32]
 call r14
 test rax,rax
 jz io_failure
 cmp rax,ART_N
 ja native_status
 mov [rbp+72],rax
 mov rdi,[rbp+64]
 mov esi,ART_N
 mov edx,1
 call protect
 mov rdi,[rbp+24]
 mov esi,CODE_N
 call release
 mov rdi,[rbp+40]
 mov rsi,[rbp+32]
 call release
 mov esi,ART_N
 call allocate
 mov [rbp+48],rax
 mov esi,WRITE_W
 call allocate
 mov [rbp+80],rax
 mov rdi,[rbp+64]
 mov rsi,[rbp+72]
 mov rdx,[rbp+48]
 mov ecx,ART_N
 mov r8,rax
 mov r9d,WRITE_W
 call r14
 test rax,rax
 jz io_failure
 cmp rax,ART_N
 ja native_status
 mov [rbp+56],rax
 mov rdi,[rbp+48]
 movabs rax,282584257676671
 cmp [rdi],rax
 jne io_failure
 mov esi,ART_N
 mov edx,1
 call protect
 mov rdi,[rbp+64]
 mov esi,ART_N
 call release
 mov rdi,[rbp+80]
 mov esi,WRITE_W
 call release
 mov rax,[rbp+144]
 add rax,[rbp+56]
 jc io_failure
 cmp rax,67127360
 ja io_failure
 mov [rbp+160],rax
 mov esi,67129344
 call allocate
 mov [rbp+152],rax
 mov rdi,rax
 mov rsi,[rbp+136]
 mov rcx,[rbp+144]
 cld
 rep movsb
 mov rax,[rbp+56]
 mov rbx,[rbp+152]
 mov [rbx+32],rax
 mov rsi,[rbp+48]
 mov rcx,rax
 rep movsb
 mov rdi,[rbp+152]
 mov esi,67129344
 mov edx,1
 call protect
 mov esi,32768
 call allocate
 mov [rbp+168],rax
 mov esi,4096
 call allocate
 mov [rbp+176],rax
 mov rdi,[rbp+152]
 mov rsi,[rbp+160]
 mov rdx,[rbp+168]
 mov ecx,32768
 mov r8,rax
 mov r9d,4096
 call r14
 test rax,rax
 jz io_failure
 cmp rax,32768
 ja native_status
 mov rdi,[rbp+168]
 mov esi,32768
 mov edx,1
 call protect
 mov rdi,[rbp+136]
 mov esi,20480
 call release
 mov rdi,[rbp+152]
 mov esi,67129344
 call release
 mov rdi,[rbp+168]
 mov esi,32768
 call release
 mov rdi,[rbp+176]
 mov esi,4096
 call release
write_output:
 mov rax,[rbp+56]
 sub rax,[rbp+128]
 jz output_complete
 mov edx,4096
 cmp rax,rdx
 cmovb rdx,rax
 mov rsi,[rbp+48]
 add rsi,[rbp+128]
 mov edi,1
 mov eax,1
 syscall
 cmp rax,-4
 je write_output
 test rax,rax
 jle io_failure
 add [rbp+128],rax
 cmp rax,rdx
 ja io_failure
 jmp write_output
output_complete:
 mov rdi,[rbp+48]
 mov esi,ART_N
 call release
 mov rdi,rbp
 mov esi,4096
 call release
 xor edi,edi
 jmp exit
allocate:
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
protect:
 mov eax,10
 syscall
 test rax,rax
 jnz io_failure
 ret
release:
 mov eax,11
 syscall
 test rax,rax
 jnz io_failure
 ret
byte_state:
 mov rdx,[rbp+24]
 mov ecx,CODE_N
 mov r8,[rbp+40]
 mov r9,[rbp+32]
 sub rsp,8
 call r14
 add rsp,8
 test rax,rax
 jnz native_status
 ret
native_status:
 mov rdx,rax
 shr rdx,32
 jnz io_failure
 mov edx,0xfffffffe
 cmp rax,rdx
 je capacity
 mov edx,0xfffffffd
 cmp rax,rdx
 je io_failure
invalid:
 mov edi,2
 jmp exit
capacity:
 mov edi,3
 jmp exit
io_failure:
 mov edi,4
 jmp exit
usage:
 mov edi,64
exit:
 mov eax,60
 syscall
 ud2

# This is a dedicated, already authorized bounded plan descriptor. The HIA
# emitter validates the row geometry and resolves its original Core ordinals.
capture_layout:
 mov rdi,[rbp+layout_fd]
 mov esi,1034
 mov eax,72
 syscall
 cmp rax,15
 jne invalid
 mov rdi,[rbp+layout_fd]
 lea rsi,[rbp+layout_stat]
 mov eax,5
 syscall
 test rax,rax
 jne io_failure
 mov rax,[rbp+layout_stat+48]
 cmp rax,40
 jb invalid
 cmp rax,LAYOUT_N
 ja capacity
 mov [rbp+layout_extent],rax
read_layout:
 mov r10,[rbp+layout_progress]
 mov rdx,[rbp+layout_extent]
 sub rdx,r10
 jz layout_captured
 lea rsi,[r12+r10+SOURCE_N]
 mov rdi,[rbp+layout_fd]
 mov eax,17
 syscall
 cmp rax,-4
 je read_layout
 test rax,rax
 jle io_failure
 add [rbp+layout_progress],rax
 jmp read_layout
layout_captured:
 lea rdi,[r12+SOURCE_N]
 cmp [rdi+16],r10
 jne invalid
 mov esi,LAYOUT_N
 mov edx,1
 jmp protect

# The pinned HIA binder returns the span of the *same* Core and a bounded
# per-ordinal wrapper request. This port moves only checked spans.
bind_borrowed_input:
 sub rsp,8
 mov esi,BORROW_PLAN_N
 call allocate
 mov [rbp+borrow_plan],rax
 mov esi,WRITE_W
 call allocate
 mov [rbp+borrow_scratch],rax
 mov rdi,r12
 mov rsi,[rbp+88]
 mov rdx,[rbp+borrow_plan]
 mov ecx,BORROW_PLAN_N
 mov r8,rax
 mov r9d,WRITE_W
 .byte 0xe8
borrowed_export_hole: .long 0
 cmp rax,32
 jb invalid
 cmp rax,BORROW_PLAN_N
 ja native_status
 mov rbx,[rbp+borrow_plan]
 lea rcx,[rbx+rax]
 mov [rbp+borrow_end],rcx
 movabs rcx,0x3330584542414948  # HIABEX03
 cmp [rbx],rcx
 jne invalid
 mov rax,[rbx+8]
 test rax,rax
 jz invalid
 cmp rax,128
 ja invalid
 mov [rbp+borrow_pending],rax
 mov rsi,[rbx+16]
 mov rcx,[rbx+24]
 test rcx,rcx
 jz invalid
 cmp rcx,RAW_N
 ja capacity
 mov rax,[rbp+88]
 cmp rsi,rax
 ja invalid
 sub rax,rsi
 cmp rcx,rax
 ja invalid
 mov [rbp+88],rcx
 add rsi,r12
 mov rdi,r12
 cld
 rep movsb
 mov rdi,[rbp+borrow_scratch]
 mov esi,WRITE_W
 call release
 mov esi,BORROW_TABLE_N
 call allocate
 mov [rbp+borrow_table],rax
 mov r11,rax
 mov r10,[rbp+borrow_end]
 lea rsi,[rbx+32]
 mov rcx,[rbp+borrow_pending]
bind_borrowed_row:
 mov rax,r10
 sub rax,rsi
 cmp rax,40
 jb invalid
 mov rdi,[rsi]
 cmp rdi,1024
 jae invalid
 shl rdi,5
 add rdi,r11
 cmp QWORD PTR [rdi],0
 jne invalid
 mov rdx,[rsi+8]
 cmp rdx,24
 jb invalid
 sub rax,16
 cmp rdx,rax
 ja invalid
 test dl,7
 jnz invalid
 movabs rax,0x3130525742414948 # HIABWR01
 cmp [rsi+16],rax
 jne invalid
 mov rax,[rsi+24]
 test rax,rax
 jz invalid
 cmp rax,1048576
 ja invalid
 mov [rdi],rax
 lea rsi,[rsi+16]
 mov [rdi+8],rsi
 mov [rdi+16],rdx
 add rsi,rdx
 dec rcx
 jnz bind_borrowed_row
 cmp rsi,r10
 jne invalid
 mov rdi,rbx
 mov esi,BORROW_PLAN_N
 mov edx,1
 call protect
 mov esi,4096
 call allocate
 mov [rbp+borrow_scratch],rax
 mov esi,BORROW_TEXT_N
 call allocate
 mov [rbp+borrow_text],rax
 mov esi,BORROW_PACKET_N
 call allocate
 mov [rbp+borrow_packet],rax
 add rsp,8
 ret

# The admitted event names an original Core ordinal. The HIA wrapper role
# returns text with one reserved call, which the existing native writer owns.
borrowed_event:
 cmp QWORD PTR [rbp+24],0
 je io_failure
 mov r15,[rbp+borrow_table]
 test r15,r15
 jz io_failure
 movabs rax,0x3130564542414948  # HIABEV01
 cmp [rbx+8],rax
 jne io_failure
 cmp QWORD PTR [rbx+16],1
 jne io_failure
 mov rax,[rbx+24]
 cmp rax,1024
 jae io_failure
 shl rax,5
 add r15,rax
 mov rax,[rbx+32]
 test rax,rax
 jz io_failure
 cmp [r15],rax
 jne io_failure
 cmp QWORD PTR [r15+24],0
 jne io_failure
 mov QWORD PTR [r15+24],1
 dec QWORD PTR [rbp+borrow_pending]
 mov rdi,[r15+8]
 mov rsi,[r15+16]
 mov rdx,[rbp+borrow_text]
 mov ecx,BORROW_TEXT_N
 mov r8,[rbp+borrow_scratch]
 mov r9d,4096
 .byte 0xe8
borrowed_wrapper_hole: .long 0
 cmp rax,32
 jb io_failure
 cmp rax,BORROW_TEXT_N
 ja native_status
 mov r15,[rbp+borrow_text]
 movabs rcx,0x31304f5742414948  # HIABWO01
 cmp [r15],rcx
 jne io_failure
 sub rax,32
 cmp [r15+8],rax
 jne io_failure
 mov [rbp+borrow_width],rax
 mov rcx,[r15+16]
 test rcx,rcx
 jz io_failure
 cmp rcx,rax
 ja io_failure
 mov [rbp+borrow_call],rcx
 add rcx,4
 cmp rcx,rax
 ja io_failure
 lea rsi,[r15+32]
 mov rcx,[rbp+borrow_call]
 dec rcx
 cmp BYTE PTR [rsi+rcx],0xe8
 jne io_failure
 cmp DWORD PTR [rsi+rcx+1],0
 jne io_failure
 call append_borrowed_bytes

 # Encode only the fixed internal prefix and the already bounded ordinal.
 mov rdi,[rbp+borrow_packet]
 lea rsi,[rip+borrowed_function_prefix]
 add rdi,64
 mov ecx,16
 rep movsb
 mov rax,[rbx+24]
 mov r10d,10
 xor ecx,ecx
 lea rsi,[rbp+256]
borrow_decimal:
 xor edx,edx
 div r10
 add dl,48
 mov [rsi+rcx],dl
 inc ecx
 test rax,rax
 jnz borrow_decimal
 lea rax,[rcx+16]
 mov rdi,[rbp+borrow_packet]
 mov QWORD PTR [rdi+8],4
 mov [rdi+16],rax
 add rdi,80
borrow_decimal_copy:
 dec ecx
 mov dl,[rsi+rcx]
 mov [rdi],dl
 inc rdi
 test ecx,ecx
 jnz borrow_decimal_copy
 mov rdi,[rbp+borrow_packet]
 lea rsi,[rax+64]
 call byte_state
 mov rsi,[rbp+borrow_text]
 mov rax,[rbp+borrow_call]
 add rax,4
 mov rcx,[rbp+borrow_width]
 sub rcx,rax
 lea rsi,[rsi+rax+32]
 call append_borrowed_bytes
 jmp event_complete

append_borrowed_bytes:
 test rcx,rcx
 jz append_borrowed_empty
 mov rdi,[rbp+borrow_packet]
 movabs rax,3616483217365879112  # HIACST02
 mov [rdi],rax
 mov QWORD PTR [rdi+8],1
 mov [rdi+16],rcx
 add rdi,64
 rep movsb
 mov rdi,[rbp+borrow_packet]
 mov rsi,[rdi+16]
 add rsi,64
 jmp byte_state
append_borrowed_empty:
 ret
borrowed_function_prefix:
 .ascii "__hia_native_fn_"
layout_argument:
 .asciz "--planned-layout"
