# Only actual syscall, futex-word atomics, malloc/free, byte copying and fixed
# six-word calls. Decimal arithmetic and ownership transitions are HIA policy.
.intel_syntax noprefix
.text
.global hia_background_native_context
.type hia_background_native_context,@function
hia_background_native_context:
.Lcontext_start:
    push rbx
    push rbp
    push r12
    push r13
    push r14
    push r15
    sub rsp,136
    mov r12,rdi
    mov r15,rsi
    mov r13,rdx
    mov rbp,rcx
    mov r14,r8
    mov rbx,r9
    cmp rbp,16384
    jb .Lbad
    cmp rbx,512
    jne .Lbad
    test r12,r12
    jz .Lbad
    test r13,r13
    jz .Lbad
    test r14,r14
    jz .Lbad
    test r14,7
    jnz .Lbad
    mov rax,r12
    add rax,r15
    jc .Lbad
    mov rdx,r13
    add rdx,rbp
    jc .Lbad
    mov rcx,r14
    add rcx,rbx
    jc .Lbad
    cmp r12,rdx
    jae .Lso_ok
    cmp r13,rax
    jb .Lbad
.Lso_ok:
    cmp r12,rcx
    jae .Lsw_ok
    cmp r14,rax
    jb .Lbad
.Lsw_ok:
    cmp r13,rcx
    jae .Low_ok
    cmp r14,rdx
    jb .Lbad
.Low_ok:
    mov qword ptr [r13+128],0
    mov qword ptr [rsp],0
    mov [rsp+8],r14
    mov [rsp+16],r12
    mov [rsp+24],r13
.Lloop:
    mov rdi,r12
    mov rsi,r15
    mov rdx,r13
    mov rcx,rbp
    mov r8,r14
    mov r9,rbx
    .byte 0xe8
policy_hole:
    .long 0
    test eax,eax
    je .Lreturn
    cmp eax,10
    je .Lloop
    cmp eax,1
    je .Lsyscall
    cmp eax,2
    je .Lcas
    cmp eax,3
    je .Lexchange
    cmp eax,6
    je .Lallocate
    cmp eax,7
    je .Lfree
    cmp eax,8
    je .Lcopy
    cmp eax,9
    je .Lprovider
    cmp eax,15
    je .Lfacts
.Lbad:
    mov eax,0xfffffffd
    jmp .Lreturn
.Lfacts:
    mov [r13+1024],r14
    lea rax,[rip+.Lcontext_start]
    mov [r13+1032],rax
    .byte 0x48,0x8d,0x05
table_queue_hole:
    .long 0
    mov [r13+3456],rax
    .byte 0x48,0x8d,0x05
table_ledger_hole:
    .long 0
    mov [r13+3464],rax
    .byte 0x48,0x8d,0x05
table_decimal_hole:
    .long 0
    mov [r13+3472],rax
    .byte 0x48,0x8d,0x05
table_jobs_hole:
    .long 0
    mov [r13+3480],rax
    .byte 0x48,0x8d,0x05
table_job_refs_hole:
    .long 0
    mov [r13+3488],rax
    .byte 0x48,0x8d,0x05
table_worker_hole:
    .long 0
    mov [r13+3496],rax
    .byte 0x48,0x8d,0x05
table_submission_hole:
    .long 0
    mov [r13+3504],rax
    .byte 0x48,0x8d,0x05
table_business_hole:
    .long 0
    mov [r13+3512],rax
    .byte 0x48,0x8d,0x05
table_execution_hole:
    .long 0
    mov [r13+3520],rax
    .byte 0x48,0x8d,0x05
table_account_hole:
    .long 0
    mov [r13+3528],rax
    .byte 0x48,0x8d,0x05
table_snapshot_hole:
    .long 0
    mov [r13+3536],rax
    .byte 0x48,0x8d,0x05
table_shutdown_hole:
    .long 0
    mov [r13+3544],rax
    .byte 0x48,0x8d,0x05
table_report_hole:
    .long 0
    mov [r13+3552],rax
    .byte 0x48,0x8d,0x05
table_structure_deferred_hole:
    .long 0
    mov [r13+3560],rax
    .byte 0x48,0x8d,0x05
table_transport_deferred_hole:
    .long 0
    mov [r13+3568],rax
    .byte 0x48,0x8d,0x05
table_freeze_deferred_hole:
    .long 0
    mov [r13+3576],rax
    .byte 0x48,0x8d,0x05
table_constructor_hole:
    .long 0
    mov [r13+3584],rax
    .byte 0x48,0x8d,0x05
table_options_hole:
    .long 0
    mov [r13+3592],rax
    .byte 0x48,0x8d,0x05
table_bridge_paths_hole:
    .long 0
    mov [r13+3600],rax
    .byte 0x48,0x8d,0x05
table_constructor_binding_hole:
    .long 0
    mov [r13+3608],rax
    .byte 0x48,0x8d,0x05
table_path_value_hole:
    .long 0
    mov [r13+3616],rax
    .byte 0x48,0x8d,0x05
table_path_resolve_hole:
    .long 0
    mov [r13+3624],rax
    .byte 0x48,0x8d,0x05
table_path_error_hole:
    .long 0
    mov [r13+3632],rax
    .byte 0x48,0x8d,0x05
table_path_string_codec_hole:
    .long 0
    mov [r13+3640],rax
    .byte 0x48,0x8d,0x05
table_posix_factory_hole:
    .long 0
    mov [r13+3648],rax
    .byte 0x48,0x8d,0x05
table_verifier_hole:
    .long 0
    mov [r13+3656],rax
    .byte 0x48,0x8d,0x05
table_json_capture_hole:
    .long 0
    mov [r13+3664],rax
    .byte 0x48,0x8d,0x05
table_sha256_hole:
    .long 0
    mov [r13+3672],rax
    .byte 0x48,0x8d,0x05
table_checked_freezer_hole:
    .long 0
    mov [r13+3680],rax
    .byte 0x48,0x8d,0x05
table_prepare_process_hole:
    .long 0
    mov [r13+3688],rax
    .byte 0x48,0x8d,0x05
table_verify_raw_hole:
    .long 0
    mov [r13+3696],rax
    .byte 0x48,0x8d,0x05
table_decision_hole:
    .long 0
    mov [r13+3704],rax
    .byte 0x48,0x8d,0x05
table_registry_hole:
    .long 0
    mov [r13+3712],rax
    mov qword ptr [r13+3720],0
    .byte 0x48,0x8d,0x05
table_structure_compat_hole:
    .long 0
    mov [r13+3728],rax
    .byte 0x48,0x8d,0x05
table_transport_compat_hole:
    .long 0
    mov [r13+3736],rax
    .byte 0x48,0x8d,0x05
table_freeze_compat_hole:
    .long 0
    mov [r13+3744],rax
    .byte 0x48,0x8d,0x05
table_rank_hole:
    .long 0
    mov [r13+3752],rax
    .byte 0x48,0x8d,0x05
table_admission_hole:
    .long 0
    mov [r13+3760],rax
    .byte 0x48,0x8d,0x05
table_decision_policy_hole:
    .long 0
    mov [r13+3768],rax
    xor eax,eax
    jmp .Lfeedback
.Lsyscall:
    mov qword ptr [rsp+120],0
    jmp .Ltranslate_begin
.Lprovider:
    mov qword ptr [rsp+120],1
.Ltranslate_begin:
    mov r10,[r13+8]
    xor ecx,ecx
.Ltranslate:
    mov rax,[r13+16+rcx*8]
    mov r11,r10
    and r11d,3
    add rax,[rsp+r11*8]
    mov [rsp+32+rcx*8],rax
    shr r10,2
    inc ecx
    cmp ecx,6
    jb .Ltranslate
    mov rdi,[rsp+32]
    mov rsi,[rsp+40]
    mov rdx,[rsp+48]
    mov r10,[rsp+56]
    mov r8,[rsp+64]
    mov r9,[rsp+72]
    cmp qword ptr [rsp+120],0
    jne .Linvoke
    mov rax,[r13]
    syscall
    jmp .Lfeedback
.Linvoke:
    mov rcx,r10
    mov r11,[r13]
    call r11
    mov eax,eax
    jmp .Lfeedback
.Lcas:
    cmp qword ptr [r13],176
    jne .Lbad
    lea rdx,[r14+176]
    mov eax,[r13+8]
    mov ecx,[r13+16]
    lock cmpxchg dword ptr [rdx],ecx
    jmp .Lfeedback
.Lexchange:
    cmp qword ptr [r13],176
    jne .Lbad
    lea rdx,[r14+176]
    mov eax,[r13+8]
    xchg dword ptr [rdx],eax
    jmp .Lfeedback
.Lallocate:
    mov rdi,[r13]
    call malloc
    jmp .Lfeedback
.Lfree:
    mov rdi,[r13]
    call free
    xor eax,eax
    jmp .Lfeedback
.Lcopy:
    mov rax,[r13]
    cmp rax,3
    ja .Lbad
    mov rsi,[r13+8]
    add rsi,[rsp+rax*8]
    mov rax,[r13+16]
    cmp rax,3
    ja .Lbad
    mov rdi,[r13+24]
    add rdi,[rsp+rax*8]
    mov rcx,[r13+32]
    cld
    rep movsb
    xor eax,eax
    jmp .Lfeedback
.Lfeedback:
    mov [r13+136],rax
    jmp .Lloop
.Lreturn:
    add rsp,136
    pop r15
    pop r14
    pop r13
    pop r12
    pop rbp
    pop rbx
    ret
.size hia_background_native_context,.-hia_background_native_context
.section .note.GNU-stack,"",@progbits
