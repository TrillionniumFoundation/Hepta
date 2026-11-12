"""Capture actual type context before the original constructor/function cleanup.

Independent HIA authoring revision.  No Python dispatch, type materialization,
error-location reconstruction or lifetime shortcut participates at runtime.
"""
from __future__ import annotations
import ast,copy
from hashlib import sha256
from tools.type_context_routes_common_r1 import (
 definitions,functions,unique_replace,changed_inventory)

CAPTURE=r'''
def tcx_capture_header(w:mutbuf, request:u64) -> u64:
    needed = get(w, OBS + 88)
    if tcx_header(w, OBS, get(w, C_LEASE), get(w, C_TYPE_ERROR), request, needed) == 0:
        return 0
    if get(w, OBS + 24) != get(w, C_TYPE_SEQUENCE) or get(w, OBS + 40) != get(w, C_TYPE_OP):
        return 0
    if get(w, OBS + 56) != get(w, TC_SNAPSHOT + 24) or get(w, OBS + 64) != get(w, TC_SNAPSHOT + 32):
        return 0
    if get(w, OBS + 72) != get(w, TC_SNAPSHOT + 40):
        return 0
    if get(w, OBS + 96) != get(w, TC_NATIVE + 32) or get(w, OBS + 104) != get(w, TC_NATIVE + 40):
        return 0
    if get(w, OBS + 112) != get(w, TC_NATIVE + 48):
        return 0
    return 1

def tcx_capture_step(o:mutbuf, w:mutbuf, request:u64) -> u64:
    phase = get(w, C_PHASE)
    if phase == 22400:
        if get(w, C_RETURN) != 0 or tcx_error(get(w, C_TYPE_ERROR)) == 0:
            return refuse(w, 14000)
        if get(w, OBS) == 0:
            at = 0
            while at < 64:
                if get(w, OBS + at) != 0:
                    return refuse(w, 14001)
                at = at + 8
            return release(o, w, B_RESPONSE, 22300)
        if get(w, OBS) != TC_CONTEXT or get(w, OBS + 8) != 1 or get(w, OBS + 16) != get(w, C_TYPE_ERROR):
            return refuse(w, 14002)
        if get(w, OBS + 48) != 0 or get(w, OBS + 56) != 0:
            return refuse(w, 14003)
        if cap(w, TC_SLOT) != 0 or cap(w, TC_COMMAND_SLOT) != 0 or get(w, TC_ACTIVE) != 0:
            return refuse(w, 14004)
        if cap(w, B_TYPES) != TYPES_BYTES or get(w, C_FRAME_BYTES) < 64 or get(w, C_FRAME_BYTES) > TYPE_OUTPUT_BYTES:
            return refuse(w, 14005)
        if get(w, TC_NATIVE + 8) != get(w, C_TYPE_ERROR) or get(w, TC_NATIVE + 24) != get(w, C_FRAME_BYTES) - 64:
            return refuse(w, 14006)
        tcx_copy(w, TC_SNAPSHOT, OBS, 64)
        return grow(o, w, TC_COMMAND_SLOT, 128, 22401)
    if phase == 22401:
        wire8(w, TC_COMMAND, 1, get(w, C_LEASE), get(w, C_TYPE_SEQUENCE), request, get(w, C_TYPE_OP), get(w, C_FRAME_BYTES), 0)
        tcx_copy(w, WIRE + 64, TC_NATIVE, 64)
        return copy(o, w, B_CONTROLLER, WIRE, TC_COMMAND_SLOT, 0, 128, 22402)
    if phase == 22402:
        return protect(o, w, TC_COMMAND_SLOT, 1, 22403)
    if phase == 22403:
        return protect(o, w, B_TYPES, 1, 22404)
    if phase == 22404:
        return grow(o, w, TC_SLOT, 128, 22405)
    if phase == 22405:
        return invoke(o, w, TC_READER, B_TYPES, 0, TYPES_BYTES, TC_COMMAND_SLOT, 128, TC_SLOT, cap(w, TC_SLOT), TC_SLOT, 0, 128, 22406)
    if phase == 22406:
        if get(w, C_RETURN) != 4294967294 or cap(w, TC_SLOT) != 128:
            return refuse(w, 14007)
        if tcx_capture_header(w, request) == 0:
            return refuse(w, 14008)
        put(w, TC_NEEDED, get(w, OBS + 88))
        tcx_copy(w, TC_RENDER, OBS, 128)
        return grow(o, w, TC_SLOT, get(w, TC_NEEDED), 22407)
    if phase == 22407:
        return invoke(o, w, TC_READER, B_TYPES, 0, TYPES_BYTES, TC_COMMAND_SLOT, 128, TC_SLOT, cap(w, TC_SLOT), TC_SLOT, 0, 128, 22408)
    if phase == 22408:
        if get(w, C_RETURN) != get(w, TC_NEEDED) or cap(w, TC_SLOT) != get(w, TC_NEEDED):
            return refuse(w, 14009)
        index = 0
        while index < 128:
            if byte(w, OBS + index) != byte(w, TC_RENDER + index):
                return refuse(w, 14010)
            index = index + 1
        return protect(o, w, TC_SLOT, 1, 22409)
    if phase == 22409:
        return protect(o, w, B_TYPES, 0, 22410)
    if phase == 22410:
        return release(o, w, TC_COMMAND_SLOT, 22411)
    if phase == 22411:
        if cap(w, TC_COMMAND_SLOT) != 0 or cap(w, TC_SLOT) != get(w, TC_NEEDED):
            return refuse(w, 14011)
        put(w, TC_ACTIVE, 1)
        return release(o, w, B_RESPONSE, 22300)
    return refuse(w, 14012)
'''

MAIN=r'''
def tcx_ctor_handoff(w:mutbuf) -> u64:
    if get(w, C_ERROR_GROUP) != 2 or get(w, TC_ACTIVE) != 1:
        return 0
    if cap(w, TC_COMMAND_SLOT) != 0 or cap(w, TC_SLOT) != get(w, TC_NEEDED):
        return 0
    if tcx_header(w, TC_RENDER, get(w, C_LEASE), get(w, C_FINAL_ERROR), get(w, C_CTOR_REQUEST), cap(w, TC_SLOT)) == 0:
        return 0
    if get(w, TC_RENDER + 24) != get(w, C_TYPE_SEQUENCE) or get(w, TC_RENDER + 40) != get(w, C_TYPE_OP):
        return 0
    return 1

def tcx_lower_finish(o:mutbuf, w:mutbuf, initial:u64) -> u64:
    error = get(w, L_FINAL_ERROR)
    request = get(w, L_FN_REQUEST)
    if initial == 1:
        error = get(w, C_FINAL_ERROR)
        request = get(w, C_CTOR_REQUEST)
        if get(w, C_ERROR_GROUP) != 2:
            return refuse(w, 14013)
    elif get(w, L_FINAL_GROUP) != 2:
        return refuse(w, 14014)
    if get(w, C_RETURN) != 0 or tcx_header(w, OBS, get(w, C_LEASE), error, request, cap(w, TC_SLOT)) == 0:
        return refuse(w, 14015)
    if get(w, OBS + 24) != get(w, C_TYPE_SEQUENCE) or get(w, OBS + 40) != get(w, C_TYPE_OP):
        return refuse(w, 14016)
    return finish(o, w, 2, error, request)
'''

def phase_branch(node,phase):
    rows=[n for n in node.body if isinstance(n,ast.If) and ast.unparse(n.test)==f"phase == {phase}"]
    assert len(rows)==1,(node.name,phase,len(rows))
    return rows[0]

def add_capture(body,request_field):
    nodes=functions(body);node=nodes["type_service_step"]
    assert ast.unparse(node.body[0])=="phase = get(w, C_PHASE)"
    node.body[1:1]=ast.parse(
        f"if phase >= 22400 and phase < 22420:\n"
        f"    return tcx_capture_step(o, w, get(w, {request_field}))").body
    branch=phase_branch(node,22200)
    assert ast.unparse(branch.body[-1])=="return grow(o, w, B_TYPE_WIRE, get(w, C_WIRE_BYTES), 22201)"
    branch.body[-1:-1]=ast.parse("tcx_copy(w, TC_NATIVE, OBS, 64)").body
    branch=phase_branch(node,22204)
    assert ast.unparse(branch.body[-1])=="return release(o, w, B_RESPONSE, 22300)"
    branch.body[-1:-1]=ast.parse(
        "if tcx_error(get(w, C_TYPE_ERROR)) == 1:\n"
        "    return view(o, w, B_TYPES, TC_CONTEXT_AT, 64, 22400)").body
    result="\n\n".join(ast.unparse(n) for n in nodes.values())+"\n"+CAPTURE
    proof=changed_inventory(body,result,{"type_service_step"})
    return result,proof

def attach(common,main,services,ctor,reader):
    """All inputs are private imported copies; no published source is changed."""
    original=dict(common=common.COMMON,main=main.BODY,services=services.BODY,ctor=ctor.BODY)
    shared,constants,rows=definitions(reader)
    assert not(set(constants)&set(common.CONSTANTS))
    assert common.CONSTANTS["OBJECT_BASE"]==65536
    assert common.CONSTANTS["TYPE_OUTPUT_BYTES"]==64*1024*1024
    assert common.CONSTANTS["TYPES_BYTES"]==128*1024*1024
    assert constants["TC_PARENT_HEADER"]+128<common.CONSTANTS["OBJECT_BASE"]
    new_services,service_proof=add_capture(original["services"],"L_FN_REQUEST")
    new_ctor,ctor_proof=add_capture(original["ctor"],"C_CTOR_REQUEST")
    nodes=functions(original["main"])
    node=nodes["begin_lower"]
    text=ast.unparse(node)
    text=unique_replace(text,
        "        if cap(w, i) != 0:\n            return 0",
        "        if cap(w, i) != 0:\n"
        "            if i != TC_SLOT or tcx_ctor_handoff(w) == 0:\n"
        "                return 0")
    nodes["begin_lower"]=ast.parse(text).body[0]
    node=nodes["main_step"]
    branch=phase_branch(node,10000)
    refuse=branch.body[0]
    assert isinstance(refuse,ast.If) and ast.unparse(refuse.test)=="get(w, C_ERROR_GROUP) != 0"
    assert ast.unparse(refuse.body[-1])=="return finish(o, w, get(w, C_ERROR_GROUP), get(w, C_FINAL_ERROR), get(w, C_CTOR_REQUEST))"
    refuse.body[-1:-1]=ast.parse(
        "if cap(w, TC_SLOT) != 0:\n"
        "    if get(w, C_ERROR_GROUP) != 2:\n"
        "        return refuse(w, 14017)\n"
        "    return view(o, w, TC_SLOT, 0, 128, 10990)").body
    branch=phase_branch(node,12320)
    assert ast.unparse(branch.body[-1])=="return finish(o, w, get(w, L_FINAL_GROUP), get(w, L_FINAL_ERROR), get(w, L_FN_REQUEST))"
    branch.body[-1:-1]=ast.parse(
        "if cap(w, TC_SLOT) != 0:\n"
        "    if get(w, L_FINAL_GROUP) != 2:\n"
        "        return refuse(w, 14018)\n"
        "    return view(o, w, TC_SLOT, 0, 128, 12321)").body
    node.body[1:1]=ast.parse(
        "if phase == 10990:\n    return tcx_lower_finish(o, w, 1)\n"
        "if phase == 12321:\n    return tcx_lower_finish(o, w, 0)").body
    new_main="\n\n".join(ast.unparse(n) for n in nodes.values())+"\n"+shared+"\n"+MAIN
    main_proof=changed_inventory(original["main"],new_main,{"begin_lower","main_step"})
    new_common=unique_replace(original["common"],
        "or image > 23:","or (image > 23 and image != TC_READER):")
    assert new_common.replace("or (image > 23 and image != TC_READER):","or image > 23:",1)==original["common"]
    return dict(main=new_main,services=new_services,ctor=new_ctor,common=new_common,
        constants=constants,proof=dict(schema="hia-type-context-lowering-route-r1",
            main=main_proof,services=service_proof,ctor=ctor_proof,
            original_body_sha256={k:sha256(v.encode()).hexdigest() for k,v in original.items()},
            context_command_slot=58,context_result_slot=57,reader_role=50,
            reader_abi="R/R/W",original_type_validator_REPLY_precedes_context=True,
            actual_native_header_captured_before_REPLY_growth=True,
            no_type_owner_or_REPLY_replay_during_context_growth=True,
            type_workspace_RO_between_measure_and_complete=True,
            command_RO_before_reader=True,result_RO_before_original_response=True,
            type_workspace_RW_restored_and_temporary_command_released_before_response=True,
            original_constructor_failed_init_release_order_preserved=True,
            original_function_metadata_and_outer_fail_call_order_preserved=True,
            constructor_handoff_accepts_only_completed_correlated_type_slot57=True,
            immutable_context_revalidated_after_ctor_and_function_cleanup=True,
            state_offset_begin=constants["TC_NATIVE"],state_offset_end=constants["TC_PARENT_HEADER"]+128,
            planned_catalog_entries=len(rows),same_private_issuer_required=True,
            arbitrary_external_context_authenticated=False,
            AST_generation_B3_native_executed_here=False))
