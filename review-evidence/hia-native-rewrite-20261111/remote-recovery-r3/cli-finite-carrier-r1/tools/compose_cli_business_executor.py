"""Deterministic finite CLI/service carrier composition; NEW, unexecuted source.

The two input executors are exact archived originals. This authoring program
does not interpret a CLI option or business packet. It makes explicit local
mechanical extensions and retains original bounded program-child code.
"""
from pathlib import Path
from hashlib import sha256
import argparse, json, re

CLI_SHA = "717f23a65686cabc8a2599e28079fa37645393eaa31e5e30cdc0cad6aef86c26"
SERVICE_SHA = "6c8e7c8dfdbbbe1da653834c67e19f733922937f86531c88179713c018770cac"
CHILD_SHA = "0cb964ac6415cd06699b20fd74777220d4bd8eaa612c04b8683ccd209476c3ee"
PARENT_EXTENSION = r'''
/* Private outer service contexts. The service interpreter's original internal
 * KIND/DEPTH/PARENT graph remains unchanged; SERVICE_HOST is a separate edge. */
.equ BUS_CHILD,2464
.equ BUS_ID,2472
.equ BUS_LEASE,2480
.equ BUS_SEQ,2488
.equ BUS_LIFECYCLE,2496
.equ BUS_TARGET,2504
.equ BUS_PINNED,2512
.equ BUS_PIN_TEMP,2520
.equ BUS_COMMAND_PTR,2528
.equ BUS_COMMAND_LEN,2536
.equ BUS_TABLE_PTR,2544
.equ BUS_TABLE_COUNT,2552
.equ BUS_VERB,2560
.equ BUS_MASK,2568
.equ BUS_MASK_TEMP,2576
.equ BUS_ROW_TARGET,2584
.equ BUS_ROW_SOURCE,2592
.equ SVC_HOST,2304
.equ SVC_SERVICE_ID,2312
.equ SVC_SERVICE_LEASE,2320
.equ SVC_WAITING,2328
.equ SVC_TABLE_PTR,2336

op_business:
    cmp qword ptr [r15+FD],-1
    jne abi_error
    cmp qword ptr [r12+120],0
    jne abi_error
    mov rax,[r12+32]
    cmp rax,1
    jb abi_error
    cmp rax,3
    ja abi_error
    mov [r15+BUS_VERB],rax
    mov rcx,[r12+40]
    cmp rcx,1
    jb abi_error
    cmp rcx,2
    ja abi_error
    cmp qword ptr [r12+48],0
    je abi_error
    cmp rax,1
    je business_new
    cmp qword ptr [r15+BUS_CHILD],0
    je abi_error
    cmp rcx,[r15+BUS_ID]
    jne abi_error
    mov rcx,[r12+48]
    cmp rcx,[r15+BUS_LEASE]
    jne abi_error
    mov rcx,[r12+112]
    cmp rcx,[r15+BUS_SEQ]
    jne abi_error
    cmp rax,3
    je business_retire
    cmp qword ptr [r15+BUS_LIFECYCLE],0
    jne abi_error
    mov rcx,[r15+BUS_CHILD]
    cmp qword ptr [rcx+SVC_WAITING],1
    jne abi_error
    jmp business_inputs
business_new:
    cmp qword ptr [r15+BUS_CHILD],0
    jne abi_error
    cmp qword ptr [r12+112],0
    jne abi_error
business_inputs:
    mov rax,[r12+104]
    cmp rax,4
    jb abi_error
    cmp rax,63
    ja abi_error
    mov rcx,[r15+BUS_PINNED]
    bt rcx,rax
    jc abi_error
    shl rax,5
    cmp qword ptr [r15+rax],0
    jne abi_error
    cmp qword ptr [r12+72],128
    jne abi_error
    mov rdi,[r12+56]
    mov rsi,[r12+64]
    mov rdx,[r12+72]
    call range_view
    cmp qword ptr [rcx+24],1
    jne abi_error
    mov [r15+BUS_COMMAND_PTR],rax
    mov [r15+BUS_COMMAND_LEN],rdx
    mov rdi,[r12+80]
    mov rsi,[r12+88]
    mov rdx,[r12+96]
    call range_view
    cmp qword ptr [rcx+24],1
    jne abi_error
    cmp rdx,32
    jb abi_error
    mov [r15+BUS_TABLE_PTR],rax
    mov rcx,0x313056534c414948
    cmp [rax],rcx
    jne abi_error
    cmp qword ptr [rax+8],1
    jne abi_error
    mov rcx,[rax+16]
    cmp rcx,4
    ja abi_error
    mov [r15+BUS_TABLE_COUNT],rcx
    shl rcx,5
    add rcx,32
    cmp rcx,rdx
    jne abi_error
    cmp [rax+24],rdx
    jne abi_error
    mov qword ptr [r15+BUS_MASK_TEMP],0
    mov qword ptr [r15+BUS_PIN_TEMP],0
    xor ebx,ebx
business_validate_rows:
    cmp rbx,[r15+BUS_TABLE_COUNT]
    jae business_rows_validated
    mov rax,rbx
    shl rax,5
    add rax,[r15+BUS_TABLE_PTR]
    add rax,32
    mov rdi,[rax]
    cmp rdi,63
    ja abi_error
    mov [r15+BUS_ROW_SOURCE],rdi
    mov rsi,[rax+8]
    mov rdx,[rax+16]
    mov rcx,[rax+24]
    cmp rcx,63
    ja abi_error
    mov [r15+BUS_ROW_TARGET],rcx
    cmp qword ptr [r15+BUS_VERB],1
    je business_validate_initial_target
    cmp rcx,4
    jb abi_error
    mov r8,[r15+BUS_MASK]
    bt r8,rcx
    jnc abi_error
    mov r8,[r15+BUS_CHILD]
    mov r9,rcx
    shl r9,5
    cmp qword ptr [r8+r9],0
    jne abi_error
    jmp business_target_valid
business_validate_initial_target:
    cmp rcx,1
    je business_target_valid
    cmp rcx,4
    je business_target_valid
    cmp rcx,5
    jne abi_error
business_target_valid:
    mov r8,[r15+BUS_MASK_TEMP]
    bts r8,rcx
    jc abi_error
    mov [r15+BUS_MASK_TEMP],r8
    call range_view
    cmp qword ptr [rcx+24],1
    jne abi_error
    mov rcx,[r15+BUS_ROW_SOURCE]
    mov r8,[r15+BUS_PIN_TEMP]
    bts r8,rcx
    mov [r15+BUS_PIN_TEMP],r8
    inc rbx
    jmp business_validate_rows
business_rows_validated:
    mov rax,[r15+BUS_MASK_TEMP]
    cmp qword ptr [r15+BUS_VERB],1
    jne business_resume_mask
    cmp rax,0x32
    jne abi_error
    jmp business_validated
business_resume_mask:
    cmp rax,[r15+BUS_MASK]
    jne abi_error
business_validated:
    mov rax,[r12+104]
    mov [r15+BUS_TARGET],rax
    mov rax,[r15+BUS_PIN_TEMP]
    or [r15+BUS_PINNED],rax
    cmp qword ptr [r15+BUS_VERB],1
    jne business_install_rows
    mov rax,[r12+40]
    mov [r15+BUS_ID],rax
    mov rax,[r12+48]
    mov [r15+BUS_LEASE],rax
    xor edi,edi
    mov esi,16384
    call map_rw
    mov [r15+BUS_CHILD],rax
    mov [rax+SVC_HOST],r15
    mov rdx,[r15+BUS_ID]
    mov [rax+SVC_SERVICE_ID],rdx
    mov rdx,[r15+BUS_LEASE]
    mov [rax+SVC_SERVICE_LEASE],rdx
    mov [rax+svc_LEASE],rdx
    mov qword ptr [rax+svc_FDS],-1
    mov qword ptr [rax+svc_FDS+8],-1
    mov qword ptr [rax+svc_KIND],2
    mov qword ptr [rax+svc_DEPTH],0
    mov qword ptr [rax+svc_PARENT],0
    mov qword ptr [rax+svc_ROLE],56
    lea rdx,[rip+service_image_table_1]
    cmp qword ptr [r15+BUS_ID],1
    je business_table_selected
    lea rdx,[rip+service_image_table_2]
business_table_selected:
    mov [rax+SVC_TABLE_PTR],rdx
    xor edi,edi
    mov esi,4096
    call map_rw
    mov rdx,[r15+BUS_CHILD]
    mov [rdx+svc_CMDMAP],rax
    mov [rdx+svc_CMDPTR],rax
    xor edi,edi
    mov esi,4096
    call map_rw
    mov rdx,[r15+BUS_CHILD]
    mov [rdx+svc_FRAMEMAP],rax
    push r15
    mov r15,rdx
    xor edi,edi
    mov esi,1
    call svc_resize_slot
    xor edi,edi
    mov esi,1
    call svc_protect_slot
    mov edi,2
    mov esi,1048576
    call svc_resize_slot
    mov rax,[r15+2*32]
    mov qword ptr [rax+4096],1
    mov qword ptr [rax+4096+2*8],1048576
    pop r15
business_install_rows:
    xor ebx,ebx
business_install_loop:
    cmp rbx,[r15+BUS_TABLE_COUNT]
    jae business_command_install
    mov rax,rbx
    shl rax,5
    add rax,[r15+BUS_TABLE_PTR]
    add rax,32
    mov r9,[rax+24]
    mov r8,[r15+BUS_CHILD]
    mov qword ptr [r8+svc_BORROWED+r9*8],1
    mov r10,r9
    shl r10,5
    lea rdi,[r8+r10]
    mov rsi,[rax]
    shl rsi,5
    add rsi,r15
    mov ecx,4
    rep movsq
    mov rcx,[rax+8]
    add [r8+r10],rcx
    mov rcx,[rax+16]
    mov [r8+r10+8],rcx
    /* BEGIN alone initializes the fixed HIA capacity inventory. RESUME
     * installs descriptors only; HIA commits its capacity after checking ACK. */
    cmp qword ptr [r15+BUS_VERB],1
    jne business_install_next
    mov rdx,[r8+2*32]
    mov [rdx+4096+r9*8],rcx
business_install_next:
    inc rbx
    jmp business_install_loop
business_command_install:
    mov rbx,[r15+BUS_CHILD]
    mov rdi,[rbx+svc_CMDMAP]
    cmp qword ptr [r15+BUS_VERB],1
    je business_initial_command
    /* Resume is the actual operation-18 ACK plus the exact HIA reply view. */
    mov rax,svc_ACK
    mov [rdi],rax
    mov rax,[rbx+svc_LEASE]
    mov [rdi+8],rax
    mov rax,[rbx+svc_SEQ]
    cmp rax,[r15+BUS_SEQ]
    jne abi_error
    mov [rdi+16],rax
    mov qword ptr [rdi+24],18
    mov qword ptr [rdi+32],0
    mov qword ptr [rdi+40],0
    mov qword ptr [rdi+48],128
    mov qword ptr [rdi+56],0
    add rdi,64
business_initial_command:
    mov rsi,[r15+BUS_COMMAND_PTR]
    mov rcx,[r15+BUS_COMMAND_LEN]
    rep movsb
    mov rax,[rbx+svc_CMDMAP]
    mov [rbx+svc_CMDPTR],rax
    mov rax,[r15+BUS_COMMAND_LEN]
    cmp qword ptr [r15+BUS_VERB],1
    je business_command_size_ready
    add rax,64
business_command_size_ready:
    mov [rbx+svc_CMDLEN],rax
    mov qword ptr [rbx+SVC_WAITING],0
    mov r15,rbx
    mov r13,[r15+svc_CMDMAP]
    mov r12,[r15+svc_FRAMEMAP]
    mov r14,[r15+SVC_TABLE_PTR]
    jmp svc_controller_entry

business_retire:
    mov edi,7
business_retire_zero:
    cmp edi,14
    jae business_retire_begin
    cmp qword ptr [r12+rdi*8],0
    jne abi_error
    inc edi
    jmp business_retire_zero
business_retire_begin:
    mov rbx,r15
    mov r15,[r15+BUS_CHILD]
    cmp qword ptr [r15+SVC_WAITING],1
    jne abi_error
    xor r8d,r8d
business_retire_maps:
    cmp qword ptr [r15+svc_BORROWED+r8*8],0
    jne business_retire_next
    mov r9,r8
    shl r9,5
    mov rdi,[r15+r9]
    test rdi,rdi
    jz business_retire_next
    mov rsi,[r15+r9+16]
    mov eax,11
    syscall
    test rax,rax
    jnz io_error
business_retire_next:
    inc r8
    cmp r8,64
    jb business_retire_maps
    xor r8d,r8d
business_retire_files:
    mov rdi,[r15+svc_FDS+r8*8]
    mov qword ptr [r15+svc_FDS+r8*8],-1
    test rdi,rdi
    js business_retire_file_next
    mov eax,3
    syscall
    test rax,rax
    jnz io_error
business_retire_file_next:
    inc r8
    cmp r8,2
    jb business_retire_files
    mov rdi,[r15+svc_CMDMAP]
    mov esi,4096
    mov eax,11
    syscall
    test rax,rax
    jnz io_error
    mov rdi,[r15+svc_FRAMEMAP]
    mov esi,4096
    mov eax,11
    syscall
    test rax,rax
    jnz io_error
    mov rdi,r15
    mov esi,16384
    mov eax,11
    syscall
    test rax,rax
    jnz io_error
    mov r15,rbx
    mov r13,[r15+CMDMAP]
    mov r12,[r15+FRAMEMAP]
    mov qword ptr [r15+BUS_CHILD],0
    mov qword ptr [r15+BUS_ID],0
    mov qword ptr [r15+BUS_LEASE],0
    mov qword ptr [r15+BUS_SEQ],0
    mov qword ptr [r15+BUS_LIFECYCLE],0
    mov qword ptr [r15+BUS_MASK],0
    mov qword ptr [r15+BUS_PINNED],0
    jmp controller_entry
'''
YIELD_EXTENSION = r'''
/* The external CLI edge is independent of the existing internal child edge. */
svc_op_yield:
    cmp qword ptr [r15+svc_KIND],2
    jne svc_abi_error
    cmp qword ptr [r15+svc_DEPTH],0
    jne svc_abi_error
    cmp qword ptr [r15+svc_PARENT],0
    jne svc_abi_error
    cmp qword ptr [r15+svc_ROLE],56
    jne svc_abi_error
    cmp qword ptr [r15+SVC_WAITING],0
    jne svc_abi_error
    mov rbx,[r15+SVC_HOST]
    test rbx,rbx
    jz svc_abi_error
    cmp [rbx+BUS_CHILD],r15
    jne svc_abi_error
    mov rax,[r15+SVC_SERVICE_ID]
    cmp [rbx+BUS_ID],rax
    jne svc_abi_error
    mov rax,[r15+SVC_SERVICE_LEASE]
    cmp [rbx+BUS_LEASE],rax
    jne svc_abi_error
    cmp [r12+32],rax
    jne svc_abi_error
    cmp [r15+svc_LEASE],rax
    jne svc_abi_error
    mov rax,[rbx+FRAMEMAP]
    cmp qword ptr [rax+8],17
    jne svc_abi_error
    mov rcx,[rbx+BUS_VERB]
    cmp [rax+32],rcx
    jne svc_abi_error
    mov rcx,[rbx+SEQ]
    cmp [rax+24],rcx
    jne svc_abi_error
    mov edi,10
    call svc_reserved_tail
    cmp qword ptr [r12+40],1
    ja svc_abi_error
    mov rax,[r12+72]
    test al,15
    jnz svc_abi_error
    cmp qword ptr [r12+40],0
    je svc_yield_mask_count
    test rax,rax
    jnz svc_abi_error
svc_yield_mask_count:
    mov rcx,rax
    xor edx,edx
svc_yield_mask_loop:
    test rcx,rcx
    jz svc_yield_mask_valid
    lea r8,[rcx-1]
    and rcx,r8
    inc edx
    cmp edx,4
    ja svc_abi_error
    jmp svc_yield_mask_loop
svc_yield_mask_valid:
    mov rdi,[r12+48]
    mov rsi,[r12+56]
    mov rdx,[r12+64]
    call svc_range_view
    cmp qword ptr [rcx+24],1
    jne svc_abi_error
    mov [r15+svc_IO_PTR],rax
    mov [r15+svc_IO_LEFT],rdx
    mov rax,[rbx+BUS_TARGET]
    cmp rax,4
    jb svc_abi_error
    cmp rax,63
    ja svc_abi_error
    mov rcx,[rbx+BUS_PINNED]
    bt rcx,rax
    jc svc_abi_error
    shl rax,5
    cmp qword ptr [rbx+rax],0
    jne svc_abi_error
    push r15
    mov rdi,[rbx+BUS_TARGET]
    mov rsi,[r15+svc_IO_LEFT]
    mov r15,rbx
    call resize_slot
    pop r15
    mov rax,[rbx+BUS_TARGET]
    shl rax,5
    mov rdi,[rbx+rax]
    mov rsi,[r15+svc_IO_PTR]
    mov rcx,[r15+svc_IO_LEFT]
    rep movsb
    push r15
    mov rdi,[rbx+BUS_TARGET]
    mov esi,1
    mov r15,rbx
    call protect_slot
    pop r15
    mov rax,[r15+svc_SEQ]
    cmp rax,[rbx+BUS_SEQ]
    jbe svc_abi_error
    mov [rbx+BUS_SEQ],rax
    mov rcx,[r12+40]
    mov [rbx+BUS_LIFECYCLE],rcx
    mov rcx,[r12+72]
    mov [rbx+BUS_MASK],rcx
    mov qword ptr [r15+SVC_WAITING],1
    mov rdi,[rbx+CMDMAP]
    mov qword ptr [rdi+40],0
    mov qword ptr [rdi+48],128
    mov rax,0x3130414243414948
    mov [rdi+64],rax
    mov qword ptr [rdi+72],1
    mov rax,[rbx+BUS_ID]
    mov [rdi+80],rax
    mov rax,[rbx+BUS_LEASE]
    mov [rdi+88],rax
    mov rax,[r15+svc_LEASE]
    mov [rdi+96],rax
    mov rax,[r15+svc_SEQ]
    mov [rdi+104],rax
    mov rax,[r15+svc_ROLE]
    mov [rdi+112],rax
    mov rax,[rbx+BUS_LIFECYCLE]
    mov [rdi+120],rax
    mov rax,[rbx+BUS_TARGET]
    mov [rdi+128],rax
    mov rax,[r15+svc_IO_LEFT]
    mov [rdi+136],rax
    mov rax,[rbx+BUS_VERB]
    mov [rdi+144],rax
    mov rax,[rbx+SEQ]
    mov [rdi+152],rax
    mov qword ptr [rdi+160],0
    mov qword ptr [rdi+168],0
    mov qword ptr [rdi+176],0
    mov qword ptr [rdi+184],0
    mov qword ptr [rbx+CMDLEN],192
    mov r15,rbx
    mov r13,[r15+CMDMAP]
    mov r12,[r15+FRAMEMAP]
    lea r14,[rip+image_table]
    jmp controller_entry

    .p2align 3
service_image_table_1:
    .zero 512
service_image_table_2:
    .zero 512
'''

def once(text, old, new):
    if text.count(old) != 1:
        raise ValueError(("nonexact authoring edit", old[:96], text.count(old)))
    return text.replace(old, new, 1)

def service_interpreter(source):
    constants = "\n".join(line for line in source.splitlines()
                          if line.startswith(".equ ")) + "\n"
    body = source[source.index("controller_entry:"):source.index("image_table:\n")]
    body = once(body,
        "    cmp rax,15\n    je op_run_child\n    jmp abi_error\n",
        "    cmp rax,15\n    je op_run_child\n    cmp rax,18\n    je op_yield\n    jmp abi_error\n")
    # A's component 60 is a read-only command projector; E's 60 remains RWW.
    body = once(body, "component_role_checked:\n",
        "component_role_checked:\n"
        "    cmp qword ptr [r15+KIND],2\n"
        "    jne service_component_identity_checked\n"
        "    cmp qword ptr [r15+SVC_SERVICE_ID],1\n"
        "    jne service_component_identity_checked\n"
        "    cmp rax,60\n    jne service_component_identity_checked\n"
        "    cmp qword ptr [r15+ROLE],56\n    jne abi_error\n"
        "service_component_identity_checked:\n")
    mask = "    mov rax,TWO_READ_MASK\n"
    assert body.count(mask) == 2
    body = body.replace(mask, "    call service_two_read_mask\n")
    start = body.index("edit_publication:")
    end = body.index("raw_handoff:")
    body = body[:start] + (
        "edit_publication:\n"
        "    /* The CLI service root must yield; it never writes process streams. */\n"
        "    jmp abi_error\n\n") + body[end:]
    body = body[:body.index("semantic_error:")] + (
        "semantic_error:\n"
        "    cmp qword ptr [r15+PARENT],0\n"
        "    jne child_complete\n"
        "    /* A service-root result must be a typed private yield, never process I/O. */\n"
        "    jmp abi_error\n\n"
        "abi_error:\n    jmp CLI_ABI_ERROR\n"
        "io_error:\n    jmp CLI_IO_ERROR\n"
        "early_io:\n    jmp CLI_IO_ERROR\n"
        "early_usage:\n    jmp CLI_ABI_ERROR\n"
        "success:\n    jmp CLI_ABI_ERROR\n"
        "terminate:\n    jmp CLI_ABI_ERROR\n"
        "service_two_read_mask:\n"
        "    mov rax,TWO_READ_MASK\n"
        "    cmp qword ptr [r15+KIND],2\n    jne service_mask_ready\n"
        "    cmp qword ptr [r15+SVC_SERVICE_ID],1\n    jne service_mask_ready\n"
        "    bts rax,60\n"
        "service_mask_ready:\n    ret\n"
        'spool_name:\n    .asciz "hia-private-spool"\n')
    names = set(re.findall(r"^([A-Za-z_][A-Za-z0-9_]*):", source, re.M))
    names.update(re.findall(r"^\.equ ([A-Za-z_][A-Za-z0-9_]*),", source, re.M))
    names.update({"op_yield", "service_component_identity_checked",
                  "service_two_read_mask", "service_mask_ready"})
    result = re.sub(r"\b[A-Za-z_][A-Za-z0-9_]*\b",
        lambda match: "svc_" + match[0] if match[0] in names else match[0],
        constants + body)
    return result.replace("CLI_ABI_ERROR", "abi_error").replace("CLI_IO_ERROR", "io_error")

def compose(cli, service):
    original = service[service.index("op_run_child:"):service.index("/* Leaf helpers.")]
    assert sha256(original.encode()).hexdigest() == CHILD_SHA
    svc = service_interpreter(service)
    current = svc[svc.index("svc_op_run_child:"):svc.index("/* Leaf helpers.")]
    assert re.sub(r"\bsvc_", "", current) == original
    text = once(cli,
        "Fixed Linux x86-64 CLI mechanics, new development source.",
        "Fixed Linux x86-64 CLI and finite service-context mechanics, new development.")
    text = once(text,
        " * allocation/protocol failure. It is not a reusable nested-context executor.",
        " * allocation/protocol failure. Service lifetimes use the explicit finite ABI.")
    text = once(text, ".global executor_start,image_table,executor_end\n",
                         ".global executor_start\n")
    text = once(text,
        "    xor edi,edi\n    mov esi,4096\n    call map_rw\n    mov r15,rax\n",
        "    xor edi,edi\n    mov esi,16384\n    call map_rw\n    mov r15,rax\n")
    text = once(text,
        "    /* 17 is the explicit unconnected business-service handoff in r1. */\n"
        "    jmp abi_error\n",
        "    cmp rax,17\n    je op_business\n    jmp abi_error\n")
    release = (
        "    cmp rax,63\n    ja abi_error\n    shl rax,5\n"
        "    lea rbx,[r15+rax]\n")
    text = once(text, release,
        "    cmp rax,63\n    ja abi_error\n"
        "    mov rcx,[r15+BUS_PINNED]\n    bt rcx,rax\n    jc abi_error\n"
        "    shl rax,5\n    lea rbx,[r15+rax]\n")
    text = once(text,
        "protect_slot:\n    cmp rdi,63\n    ja abi_error\n"
        "    cmp rsi,1\n    ja abi_error\n    shl rdi,5\n",
        "protect_slot:\n    cmp rdi,63\n    ja abi_error\n"
        "    cmp rsi,1\n    ja abi_error\n    cmp rsi,1\n"
        "    je parent_protection_checked\n"
        "    mov rax,[r15+BUS_PINNED]\n    bt rax,rdi\n    jc abi_error\n"
        "parent_protection_checked:\n    shl rdi,5\n")
    text = once(text,
        "resize_slot:\n    cmp rdi,63\n    ja abi_error\n"
        "    test rsi,rsi\n    js abi_error\n    push rbx\n",
        "resize_slot:\n    cmp rdi,63\n    ja abi_error\n"
        "    test rsi,rsi\n    js abi_error\n"
        "    mov rax,[r15+BUS_PINNED]\n    bt rax,rdi\n    jc abi_error\n"
        "    push rbx\n")
    marker = "    .p2align 3\nimage_table:\n"
    text = once(text, marker, "\n" + PARENT_EXTENSION + "\n" + svc + "\n" +
                                  YIELD_EXTENSION + "\n" + marker)
    labels = re.findall(r"^([A-Za-z_][A-Za-z0-9_]*):", text, re.M)
    equates = re.findall(r"^\.equ ([A-Za-z_][A-Za-z0-9_]*),", text, re.M)
    assert len(labels) == len(set(labels)) and len(equates) == len(set(equates))
    refs = re.findall(r"^\s*(?:j\w+|call)\s+([A-Za-z_][A-Za-z0-9_]*)\s*$", text, re.M)
    registers = {"rax","rbx","rcx","rdx","rsi","rdi","r8","r9","r10","r11","r12","r13","r14","r15"}
    assert set(refs) <= set(labels) | registers
    return text, dict(original_internal_child_bytes=len(original.encode()),
        original_internal_child_sha256=CHILD_SHA,
        prefix_normalized_internal_child_body_exact=True,
        labels=len(labels), equates=len(equates),
        undefined_direct_branch_labels=[])

def main():
    parser=argparse.ArgumentParser()
    parser.add_argument("--cli-reference",required=True,type=Path)
    parser.add_argument("--service-reference",required=True,type=Path)
    parser.add_argument("--output",required=True,type=Path)
    options=parser.parse_args()
    cli_raw=options.cli_reference.read_bytes()
    service_raw=options.service_reference.read_bytes()
    assert sha256(cli_raw).hexdigest()==CLI_SHA and len(cli_raw)==14594
    assert sha256(service_raw).hexdigest()==SERVICE_SHA and len(service_raw)==32247
    text,checks=compose(cli_raw.decode("utf-8"),service_raw.decode("utf-8"))
    raw=text.encode("utf-8")
    options.output.parent.mkdir(parents=True,exist_ok=True)
    with options.output.open("xb") as stream:stream.write(raw)
    assert options.output.read_bytes()==raw
    assert options.cli_reference.read_bytes()==cli_raw
    assert options.service_reference.read_bytes()==service_raw
    row=dict(schema="hia-cli-finite-carrier-source-v1",
        scope="NEW_AUTHORING_NOT_NATIVE_EXECUTION",
        source_bytes=len(raw),source_sha256=sha256(raw).hexdigest(),
        cli_reference_sha256=CLI_SHA,service_reference_sha256=SERVICE_SHA,
        source_readback=True,**checks)
    options.output.with_suffix(".source.json").write_text(json.dumps(row,sort_keys=True,indent=2)+"\n")
    print(json.dumps(row,sort_keys=True),flush=True)

if __name__=="__main__":main()
