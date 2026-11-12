"""Public A-service continuation for actual native-issued fixed refusals.

All admission, child-frame and public handoff rules stay in the exact retained
HIA owner. This revision only routes the already validated groups 1..5 through
the native catalog at fixed role51 in this A-service context. Groups6/9 are still OPEN.
"""
from __future__ import annotations
import importlib.util
from hashlib import sha256
from pathlib import Path
from tools.generate_fixed_diagnostic_catalog_r1 import catalog,COMMAND,RESULT

ORIGINAL_SHA="f378c5cd7ef6a053ec63090cc3b3322929f54ef566a29fbaa3f687318c6779d9"

CONTINUATION=r'''
def fixed_diagnostic_start(w:mutbuf) -> u64:
    group = get(w, E_ERROR_GROUP)
    if group < 1 or group > 5 or get(w, E_ERROR_CODE) == 0:
        return refuse(w, 2100)
    if get(w, C_LEASE) == 0 or get(w, C_LEASE) > MAX - 3 or get(w, C_SEQUENCE) == 0:
        return refuse(w, 2101)
    if get(w, E_CHILD_EVENT) != EVENT_MAGIC or get(w, E_CHILD_EVENT + 8) != 7:
        return refuse(w, 2102)
    if get(w, E_CHILD_EVENT + 16) != get(w, C_LEASE) + 2 or get(w, E_CHILD_EVENT + 24) == 0:
        return refuse(w, 2103)
    if get(w, E_CHILD_EVENT + 32) != group or get(w, E_CHILD_EVENT + 40) != get(w, E_ERROR_CODE):
        return refuse(w, 2104)
    if cap(w, F_DIAG_OUTPUT) != 0 or cap(w, F_DIAG_WORK) != 0:
        return refuse(w, 2105)
    put(w, F_DIAG_SEQUENCE, get(w, C_SEQUENCE))
    wire8(w, F_DIAG_COMMAND, 1, get(w, C_LEASE), get(w, F_DIAG_SEQUENCE), get(w, E_CHILD_EVENT + 16), get(w, E_CHILD_EVENT + 24), 46, 0)
    copy_local(w, WIRE + 64, E_CHILD_EVENT, 128)
    put(w, C_PHASE, 70)
    return 0

def fixed_diagnostic_header(w:mutbuf) -> u64:
    if get(w, OBS) != F_DIAG_RESULT or get(w, OBS + 8) != 1:
        return 0
    if get(w, OBS + 16) != get(w, C_LEASE) or get(w, OBS + 24) != get(w, F_DIAG_SEQUENCE):
        return 0
    if get(w, OBS + 32) != get(w, E_CHILD_EVENT + 16) or get(w, OBS + 40) != get(w, E_CHILD_EVENT + 24):
        return 0
    if get(w, OBS + 48) != get(w, E_ERROR_GROUP) or get(w, OBS + 56) != get(w, E_ERROR_CODE):
        return 0
    if get(w, OBS + 64) != get(w, E_CHILD_EVENT + 48) or get(w, OBS + 88) != 0:
        return 0
    size = get(w, OBS + 72)
    if size == 0 or size > F_DIAG_MAX_TEXT or get(w, OBS + 80) != 128 + size:
        return 0
    at = 0
    while at < 32:
        if byte(w, OBS + 96 + at) != byte(w, E_CHILD_EVENT + 96 + at):
            return 0
        at = at + 1
    return 1

def fixed_diagnostic_step(o:mutbuf, w:mutbuf) -> u64:
    phase = get(w, C_PHASE)
    if phase == 70:
        return grow(o, w, F_DIAG_OUTPUT, 128, 71)
    if phase == 71:
        return grow(o, w, F_DIAG_WORK, F_DIAG_ROM_BYTES, 72)
    if phase == 72:
        return invoke(o, w, 51, B_CONTROLLER, WIRE, 192, F_DIAG_OUTPUT, 128, F_DIAG_WORK, F_DIAG_ROM_BYTES, F_DIAG_OUTPUT, 0, 128, 73)
    if phase == 73:
        if get(w, C_RETURN) != 4294967294 or cap(w, F_DIAG_OUTPUT) != 128 or fixed_diagnostic_header(w) == 0:
            return refuse(w, 2106)
        put(w, F_DIAG_NEEDED, get(w, OBS + 80))
        copy_local(w, F_DIAG_HEADER, OBS, 128)
        return grow(o, w, F_DIAG_OUTPUT, get(w, F_DIAG_NEEDED), 74)
    if phase == 74:
        return invoke(o, w, 51, B_CONTROLLER, WIRE, 192, F_DIAG_OUTPUT, get(w, F_DIAG_NEEDED), F_DIAG_WORK, F_DIAG_ROM_BYTES, F_DIAG_OUTPUT, 0, 128, 75)
    if phase == 75:
        if get(w, C_RETURN) != get(w, F_DIAG_NEEDED) or cap(w, F_DIAG_OUTPUT) != get(w, F_DIAG_NEEDED):
            return refuse(w, 2107)
        at = 0
        while at < 128:
            if byte(w, OBS + at) != byte(w, F_DIAG_HEADER + at):
                return refuse(w, 2108)
            at = at + 1
        return protect(o, w, F_DIAG_OUTPUT, 1, 76)
    if phase == 76:
        return release(o, w, F_DIAG_WORK, 77)
    if phase == 77:
        return start_result(w, 4, 1, 2, 0, 0, 0, F_DIAG_OUTPUT, 128, get(w, F_DIAG_NEEDED) - 128)
    if phase == 79:
        return release(o, w, F_DIAG_OUTPUT, 802)
    return refuse(w, 2109)
'''

def replace_once(source,before,after):
    assert source.count(before)==1,(before,source.count(before))
    return source.replace(before,after)

def original_module(path):
    path=Path(path);raw=path.read_bytes()
    assert sha256(raw).hexdigest()==ORIGINAL_SHA
    spec=importlib.util.spec_from_file_location("exact_program_service_owner_for_fixed_diagnostics",path)
    value=importlib.util.module_from_spec(spec);spec.loader.exec_module(value)
    return value,raw

def generated_document(reference,original):
    old,raw=original_module(original)
    rows,rom,pins=catalog(reference)
    source=old.SOURCE
    source=replace_once(source,
        "        elif phase >= 30 and phase < 50:\n            result = projection_step(o, w)",
        "        elif phase >= 70 and phase < 80:\n            result = fixed_diagnostic_step(o, w)\n        elif phase >= 30 and phase < 50:\n            result = projection_step(o, w)")
    source=replace_once(source,
        "    else:\n        return refuse(w, 2027)\n    size = prefix_message(w, message)",
        "    elif group >= 1 and group <= 5:\n        return fixed_diagnostic_start(w)\n    else:\n        return refuse(w, 2027)\n    size = prefix_message(w, message)")
    source=replace_once(source,
        "    if phase == 801:\n        return copy(o, w, get(w, A_RESULT_SOURCE), get(w, A_RESULT_AT), B_RESULT, 128, get(w, A_RESULT_BYTES), 802)",
        "    if phase == 801:\n        if get(w, A_RESULT_SOURCE) == F_DIAG_OUTPUT:\n            return copy(o, w, F_DIAG_OUTPUT, get(w, A_RESULT_AT), B_RESULT, 128, get(w, A_RESULT_BYTES), 79)\n        return copy(o, w, get(w, A_RESULT_SOURCE), get(w, A_RESULT_AT), B_RESULT, 128, get(w, A_RESULT_BYTES), 802)")
    additions=dict(F_DIAG_COMMAND=COMMAND,F_DIAG_RESULT=RESULT,
        F_DIAG_OUTPUT=54,F_DIAG_WORK=55,F_DIAG_ROM_BYTES=len(rom),
        F_DIAG_MAX_TEXT=max(len(r["text"]) for r in rows),
        F_DIAG_SEQUENCE=36000,F_DIAG_NEEDED=36008,F_DIAG_HEADER=36032)
    assert not set(additions)&set(old.CONSTANTS)
    old.CONSTANTS.update(additions);old.SOURCE=source+"\n"+CONTINUATION
    text=old.expanded_source();doc=old.document(text)
    doc["module"]="cli_program_service_fixed_diagnostics_r1"
    assert Path(original).read_bytes()==raw
    assert all(path.read_bytes()==data for path,data in old.RAW.items())
    inventory=dict(schema="hia-public-fixed-diagnostic-route-v1",
        original_source_sha256=ORIGINAL_SHA,groups=[1,2,3,4,5],open_groups=[6,9],
        fixed_image_role=51,request_bytes=192,original_child_event_bytes=128,
        live_context_slots=[54,55],ROM_bytes=len(rom),
        parent_child_lease_and_sequence_binding=True,
        all_actual_child_event_digest_bytes_echoed=True,
        two_capacity_calls_with_full128_header_equality=True,
        text_source_released_after_full_result_copy=True,
        workspace_released_before_public_handoff=True,
        original_admission_child_validator_unchanged=True,
        original_group7_8_10_paths_unchanged=True,
        public_CLI_installation_claim=False,whole_public_diagnostics_closed=False)
    return doc,text,inventory
