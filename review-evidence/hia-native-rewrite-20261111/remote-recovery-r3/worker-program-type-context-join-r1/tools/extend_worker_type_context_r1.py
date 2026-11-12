"""P16 consumes the actual readonly type-context capsule from program role46.

The existing adapter enum continuation remains for errors without an issued
context. The complete actual context text is copied, never regenerated here.
"""
from __future__ import annotations
import ast,copy
from hashlib import sha256
from tools.type_context_routes_common_r1 import (
 definitions,functions,unique_replace,changed_inventory)

BODY=r'''
def worker_type_context_start(w:mutbuf) -> u64:
    if get(w, E_ERROR_GROUP) != 2 or tcx_error(get(w, E_ERROR_CODE)) == 0:
        return refuse(w, 14200)
    if get(w, E_ERROR_BYTES) < 129 or get(w, E_ERROR_BYTES) > TC_MAX_EXTENT:
        return refuse(w, 14201)
    if cap(w, B_PROGRAM_FRAME) != get(w, E_ERROR_BYTES) or get(w, WC_ACTIVE) != 0:
        return refuse(w, 14202)
    if get(w, WD_ACTIVE) != 0 or get(w, WP_RESULT_KIND) != 0:
        return refuse(w, 14203)
    lease = get(w, E_CHILD_EVENT + 16)
    if lease == 0 or lease > MAX - 2 or get(w, E_CHILD_EVENT + 24) == 0:
        return refuse(w, 14204)
    if get(w, E_CHILD_EVENT) != EVENT_MAGIC or get(w, E_CHILD_EVENT + 8) != 7:
        return refuse(w, 14205)
    if get(w, E_CHILD_EVENT + 32) != 2 or get(w, E_CHILD_EVENT + 40) != get(w, E_ERROR_CODE):
        return refuse(w, 14206)
    put(w, WC_EXPECT_LEASE, lease + 2)
    put(w, WC_ACTIVE, 1)
    put(w, C_PHASE, 87600)
    return 0

def worker_type_context_step(o:mutbuf, w:mutbuf, phase:u64) -> u64:
    if get(w, WC_ACTIVE) != 1:
        return refuse(w, 14207)
    if phase == 87600:
        return view(o, w, B_PROGRAM_FRAME, 0, 128, 87601)
    if phase == 87601:
        if get(w, C_RETURN) != 0:
            return refuse(w, 14208)
        if tcx_header(w, OBS, get(w, WC_EXPECT_LEASE), get(w, E_ERROR_CODE), get(w, E_CHILD_EVENT + 48), get(w, E_ERROR_BYTES)) == 0:
            return refuse(w, 14209)
        tcx_copy(w, WC_HEADER, OBS, 128)
        return worker_result_begin(w, 4, 1, 0, 0, B_PROGRAM_FRAME, 128, get(w, E_ERROR_BYTES) - 128)
    if phase == 87602:
        if get(w, WP_PAYLOAD_SLOT) != B_PROGRAM_FRAME or get(w, WP_PAYLOAD_AT) != 128:
            return refuse(w, 14210)
        if get(w, WP_PAYLOAD_BYTES) + 128 != get(w, E_ERROR_BYTES):
            return refuse(w, 14211)
        return release(o, w, B_PROGRAM_FRAME, 87603)
    if phase == 87603:
        if cap(w, B_PROGRAM_FRAME) != 0:
            return refuse(w, 14212)
        put(w, WC_ACTIVE, 2)
        put(w, C_PHASE, 88007)
        return 0
    return refuse(w, 14213)
'''

def attach(generator,reader):
    original={name:ast.dump(node,include_attributes=False)
              for name,node in generator.working.items()}
    assembly_before=generator.expanded("assembly_service")[0]
    shared,constants,rows=definitions(reader)
    constants.update(WC_ACTIVE=79616,WC_EXPECT_LEASE=79624,WC_HEADER=79680)
    assert not(set(constants)&set(generator.CONSTANTS))
    assert generator.CONSTANTS["WD_HEADER"]+128<=constants["WC_ACTIVE"]
    assert constants["WC_HEADER"]+128<generator.CONSTANTS["MIN_WORK"]
    generator.CONSTANTS.update(constants)
    frame=copy.deepcopy(generator.working["program_child_frame"])
    frame.name="worker_type_context_child_frame"
    branch=next(n for n in frame.body if isinstance(n,ast.If) and ast.unparse(n.test)=="group != 0")
    tail=next(n for n in branch.body if isinstance(n,ast.If) and ast.unparse(n.test)=="extent != 0")
    at=branch.body.index(tail)
    branch.body[at:at]=ast.parse(
        "if group == 2 and extent != 0:\n"
        "    if role != 46 or tcx_error(error) == 0 or extent < 129 or extent > TC_MAX_EXTENT:\n"
        "        return 0\n"
        "    put(w, CAPS + B_PROGRAM_FRAME * 8, extent)\n"
        "    put(w, E_ERROR_BYTES, extent)\n"
        "    return 2").body
    assert frame.name not in generator.working
    generator.working[frame.name]=frame
    text=ast.unparse(generator.working["worker_admission_step"])
    text=unique_replace(text,"state = program_child_frame(w)",
                             "state = worker_type_context_child_frame(w)")
    generator.working["worker_admission_step"]=ast.parse(text).body[0]
    text=ast.unparse(generator.working["prefix_failure"])
    text=unique_replace(text,
        "    elif group >= 1 and group <= 5:\n        return worker_fixed_diagnostic_start(w)",
        "    elif group == 2 and get(w, E_ERROR_BYTES) != 0:\n"
        "        return worker_type_context_start(w)\n"
        "    elif group >= 1 and group <= 5:\n"
        "        return worker_fixed_diagnostic_start(w)")
    generator.working["prefix_failure"]=ast.parse(text).body[0]
    text=ast.unparse(generator.working["worker_program_service"])
    text=unique_replace(text,
        "        elif phase >= 87500 and phase < 87510:\n"
        "            result = worker_fixed_diagnostic_step(o, w, phase)",
        "        elif phase >= 87500 and phase < 87510:\n"
        "            result = worker_fixed_diagnostic_step(o, w, phase)\n"
        "        elif phase >= 87600 and phase < 87610:\n"
        "            result = worker_type_context_step(o, w, phase)")
    generator.working["worker_program_service"]=ast.parse(text).body[0]
    text=ast.unparse(generator.working["worker_result_step"])
    text=unique_replace(text,
        "        if get(w, WD_ACTIVE) == 1:\n",
        "        if get(w, WC_ACTIVE) == 1:\n"
        "            if get(w, WP_PAYLOAD_SLOT) != B_PROGRAM_FRAME:\n"
        "                return refuse(w, 14214)\n"
        "            return copy(o, w, B_PROGRAM_FRAME, get(w, WP_PAYLOAD_AT), B_RESULT, get(w, WP_PAYLOAD_OUT), get(w, WP_PAYLOAD_BYTES), 87602)\n"
        "        if get(w, WD_ACTIVE) == 1:\n")
    generator.working["worker_result_step"]=ast.parse(text).body[0]
    added=functions(shared+"\n"+BODY)
    assert not(set(added)&set(generator.working))
    generator.working.update(added)
    changed={"worker_program_service","worker_admission_step","prefix_failure","worker_result_step"}
    assert all(ast.dump(generator.working[name],include_attributes=False)==old
               for name,old in original.items() if name not in changed)
    assert ast.dump(generator.working["program_child_frame"],include_attributes=False)==original["program_child_frame"]
    assert generator.expanded("assembly_service")[0]==assembly_before
    assert all(path.read_bytes()==raw for path,raw in generator.INPUTS.items())
    return dict(schema="hia-worker-program-native-type-context-route-r1",
        changed_original_methods=sorted(changed),new_private_child_frame=frame.name,
        added_methods=sorted(added),all_other_method_AST_exact=True,
        original_assembly_child_frame_AST_exact=True,
        original_assembly_service_expanded_bytes_exact=True,
        parent_type_text_formatted=False,context_payload_from_actual_readonly_child=True,
        actual_program_terminal_lease_error_request_checked=True,
        lower_lease_is_actual_program_terminal_lease_plus2=True,
        original_context_header_bytes_preserved=True,
        context_source_slot=generator.CONSTANTS["B_PROGRAM_FRAME"],
        context_source_released_after_complete_result_copy_before_publication=True,
        original_fixed_enum_fallback_preserved=True,
        original_group6_and9_open=True,
        new_constants=constants,unissued_foreign_frames_authenticated=False,
        public_contexts_not_yet_executed=True)

OLD_TRANSFER=r'''child_diagnostic_transfer:
    /* No diagnostic text/header is interpreted by the fixed executor. */
    cmp qword ptr [r12+32],8
    jne child_cleanup
    mov rax,[r15+ROLE]
    cmp [r15+PUB_ROLE],rax
    jne abi_error
    cmp qword ptr [r15+57*32],0
    je abi_error
    cmp qword ptr [r15+57*32+8],65
    jb abi_error
    cmp qword ptr [r15+57*32+24],1
    jne abi_error
    cmp qword ptr [r15+BORROWED+57*8],0
    jne abi_error
    mov rax,[r15+CHILD_TARGET]
    shl rax,5
    lea rdi,[rbx+rax]
    cmp qword ptr [rdi],0
    jne abi_error
    lea rsi,[r15+57*32]
    mov ecx,4
    rep movsq
    mov rax,[r15+57*32+8]
    mov rdi,[rbx+CMDMAP]
    mov [rdi+192],rax
    lea rdi,[r15+57*32]
    xor eax,eax
    mov ecx,4
    rep stosq
    jmp child_cleanup
'''
NEW_TRANSFER=r'''child_diagnostic_transfer:
    /* Only a real owned readonly slot is moved; no context text is parsed. */
    cmp qword ptr [r12+32],8
    je child_core_diagnostic_transfer
    cmp qword ptr [r12+32],2
    jne child_cleanup
    cmp qword ptr [r15+57*32],0
    je child_cleanup
    cmp qword ptr [r12+40],1
    je child_type_diagnostic_role
    cmp qword ptr [r12+40],5
    je child_type_diagnostic_role
    cmp qword ptr [r12+40],6
    jne abi_error
child_type_diagnostic_role:
    cmp qword ptr [r15+RUN_MODE],0
    jne child_type_program_role
    cmp qword ptr [r15+ROLE],40
    jne abi_error
    jmp child_type_diagnostic_extent
child_type_program_role:
    cmp qword ptr [r15+RUN_MODE],2
    jne abi_error
    cmp qword ptr [r15+ROLE],46
    jne abi_error
child_type_diagnostic_extent:
    cmp qword ptr [r15+57*32+8],129
    jb abi_error
    jmp child_diagnostic_owned_transfer
child_core_diagnostic_transfer:
    mov rax,[r15+ROLE]
    cmp [r15+PUB_ROLE],rax
    jne abi_error
    cmp qword ptr [r15+57*32],0
    je abi_error
    cmp qword ptr [r15+57*32+8],65
    jb abi_error
child_diagnostic_owned_transfer:
    cmp qword ptr [r15+57*32+24],1
    jne abi_error
    cmp qword ptr [r15+BORROWED+57*8],0
    jne abi_error
    mov rax,[r15+CHILD_TARGET]
    shl rax,5
    lea rdi,[rbx+rax]
    cmp qword ptr [rdi],0
    jne abi_error
    lea rsi,[r15+57*32]
    mov ecx,4
    rep movsq
    mov rax,[r15+57*32+8]
    mov rdi,[rbx+CMDMAP]
    mov [rdi+192],rax
    lea rdi,[r15+57*32]
    xor eax,eax
    mov ecx,4
    rep stosq
    jmp child_cleanup
'''

def compose_executor(fixed_extension,original_composer,raw):
    prior,previous_proof=fixed_extension.compose_executor(original_composer,raw)
    before=OLD_TRANSFER.encode("ascii");after=NEW_TRANSFER.encode("ascii")
    assert prior.count(before)==1
    result=prior.replace(before,after,1)
    assert result.replace(after,before,1)==prior
    old_mask=0x60bf80bee2ac0462
    assert old_mask&(1<<50) and old_mask&(1<<51)
    expected=old_mask&~(1<<51)
    line=(".equ TWO_READ_MASK,"+hex(expected)).encode("ascii")
    assert prior.count(line)==1 and result.count(line)==1
    return result,dict(schema="hia-worker-type-context-fixed-executor-r1",
        original_composed_sha256=sha256(prior).hexdigest(),
        source_sha256=sha256(result).hexdigest(),source_bytes=len(result),
        old_enum_mask_proof=previous_proof,only_new_transfer_branch=True,
        exact_reverse_restoration_equal=True,all_other_instruction_text_exact=True,
        two_read_mask_unchanged_from_fixed_diagnostic_P16=True,reader_role50_RRW=True,
        allowed_new_group=2,allowed_new_errors=[1,5,6],allowed_new_terminal_roles=[40,46],
        original_depth_kind_parent_pending_mode_sequence_binding_preserved=True,
        original_Core_group8_owned_transfer_preserved=True,
        immutable_owned_exact_extent_transferred_then_source_descriptor_cleared=True,
        no_type_where_mask_node_or_text_interpretation=True,
        unissued_contexts_authenticated=False,runtime_executed=False)
