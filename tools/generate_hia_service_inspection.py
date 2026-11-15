"""Author both complete service inspect and candidate control graphs in HIA.

All method-level choices, membership reduction, comprehension continuation,
error unwinding and final acknowledgement are explicit image transitions.
Opaque lookup, provider calls, codecs and the interpreter's literal-expression
mechanics stay foreign. This file has not been executed by the static draft.
"""
from __future__ import annotations
import ast
from pathlib import Path
import re
import sys

ROOT = Path(__file__).resolve().parents[1]
if __package__ in (None, ''):
    sys.path.insert(0, str(ROOT))
from hepta.hia_agent_assembly import render_assembly
from hepta.hia_service_inspection_protocol import (
    PORT, REQUEST_MAGIC, RESULT_MAGIC, STATE_MAGIC, SOURCE_NAME)
from tools.generate_hia_selfhost import compact_authoring_cfg, total_scalar_functions
from tools.generate_hia_service_context import ContextBuilder

PROTOCOL = r'''
def service_inspection(s:readbuf, o:mutbuf, w:mutbuf) -> u32:
    if length(s) != 128 or length(o) != 96 or length(w) != 192:
        return 4294967293
    if read_word(s, 0) != @REQUEST_MAGIC@:
        return 4294967293
    index = 64
    while index < 128:
        if read_word(s, index) != 0:
            return 4294967293
        index = index + 8
    event = read_word(s, 8)
    if event == 0:
        return initialize(s, o, w)
    if valid_state(w) == 0:
        return 4294967293
    if read_word(s, 40) != get(w, 2) or read_word(s, 48) != get(w, 6) or read_word(s, 56) != get(w, 7):
        return refuse(o, w)
    if read_word(s, 16) != get(w, 4) or read_word(s, 24) != get(w, 3):
        return refuse(o, w)
    observed = read_word(s, 32)
    phase = get(w, 5)
    port = get(w, 3)
    if event == 1:
        if phase != 1 or observed != 0:
            return refuse(o, w)
        set(w, 5, 2)
        seal(w)
        return answer(o, w, 0)
    if event == 2:
        if phase != 2:
            return refuse(o, w)
        if boolean_port(port) == 1:
            if observed > 1:
                return refuse(o, w)
        elif port == @inspect_all_next@:
            if observed > 2:
                return refuse(o, w)
        elif port != @inspect_functions_open@ and port != @inspect_blocks_open@ and observed != 0:
            return refuse(o, w)
        return succeeded(o, w, observed)
    if event == 3:
        if phase != 2 or observed != 0:
            return refuse(o, w)
        set(w, 12, 1)
        if error_port(port) == 0:
            scope = get(w, 8)
            if scope == 1:
                return advance(o, w, @inspect_all_unwind@, 1)
            if scope == 2 or scope == 3:
                return advance(o, w, @inspect_comprehension_unwind@, 1)
            if scope == 4:
                return advance(o, w, @candidate_put_unwind@, 1)
        return advance(o, w, 0, 7)
    if event == 4:
        if port != 0 or observed != 0:
            return refuse(o, w)
        if phase == 6:
            return advance(o, w, 0, 4)
        if phase == 7:
            return advance(o, w, 0, 5)
        return refuse(o, w)
    return refuse(o, w)

def initialize(s:readbuf, o:mutbuf, w:mutbuf) -> u32:
    mode = read_word(s, 40)
    if mode != 1 and mode != 2:
        return 4294967293
    if read_word(s, 16) != 0 or read_word(s, 24) != 0 or read_word(s, 32) != 0:
        return 4294967293
    if read_word(s, 48) == 0 and read_word(s, 56) == 0:
        return 4294967293
    index = 0
    while index < 192:
        if byte(w, index) != 0:
            return 4294967293
        index = index + 1
    set(w, 0, @STATE_MAGIC@)
    set(w, 1, 1)
    set(w, 2, mode)
    if mode == 1:
        set(w, 3, @inspect_import@)
    else:
        set(w, 3, @candidate_assemble_import@)
    set(w, 4, 1)
    set(w, 5, 1)
    set(w, 6, read_word(s, 48))
    set(w, 7, read_word(s, 56))
    seal(w)
    return answer(o, w, 0)

def boolean_port(port:u64) -> u64:
    if port == @inspect_has_cursor@:
        return 1
    if port == @inspect_is_summary@:
        return 1
    if port == @inspect_is_lowering@:
        return 1
    if port == @inspect_is_dependencies@:
        return 1
    if port == @inspect_all_prepare@:
        return 1
    if port == @inspect_all_foreign@:
        return 1
    if port == @inspect_has_function@:
        return 1
    if port == @inspect_functions_next@:
        return 1
    if port == @inspect_function_present@:
        return 1
    if port == @inspect_is_block@:
        return 1
    if port == @inspect_blocks_next@:
        return 1
    if port == @inspect_block_present@:
        return 1
    if port == @candidate_is_import@:
        return 1
    if port == @candidate_is_assembly@:
        return 1
    if port == @candidate_patch_selected@:
        return 1
    if port == @candidate_schema_differs@:
        return 1
    if port == @candidate_payload_selected@:
        return 1
    if port == @candidate_diagnostics_selected@:
        return 1
    return 0

def error_port(port:u64) -> u64:
    if port == @inspect_comprehension_unwind@:
        return 1
    if port == @inspect_all_unwind@:
        return 1
    if port == @candidate_put_unwind@:
        return 1
    return 0

def owned_port(mode:u64, port:u64) -> u64:
    if mode == 1:
        if port >= @inspect_import@ and port <= @inspect_all_unwind@:
            return 1
    if mode == 2:
        if port >= @candidate_assemble_import@ and port <= @candidate_put_unwind@:
            return 1
    return 0

def succeeded(o:mutbuf, w:mutbuf, observed:u64) -> u32:
    port = get(w, 3)
    if port <= @inspect_context@:
        return continuation_1(o, w, observed)
    if port <= @inspect_query@:
        return continuation_2(o, w, observed)
    if port <= @inspect_blocks_open@:
        return continuation_3(o, w, observed)
    if port <= @candidate_assemble_import@:
        return continuation_4(o, w, observed)
    if port <= @candidate_native_patch_import@:
        return continuation_5(o, w, observed)
    if port <= @candidate_put_program@:
        return continuation_6(o, w, observed)
    if port <= @candidate_put_unwind@:
        return continuation_7(o, w, observed)
    return refuse(o, w)

def continuation_1(o:mutbuf, w:mutbuf, observed:u64) -> u32:
    port = get(w, 3)
    if port == @inspect_import@:
        return advance(o, w, @inspect_prepare_import@, 1)
    if port == @inspect_prepare_import@:
        return advance(o, w, @inspect_emit_import@, 1)
    if port == @inspect_emit_import@:
        return advance(o, w, @inspect_program@, 1)
    if port == @inspect_program@:
        return advance(o, w, @inspect_selector@, 1)
    if port == @inspect_selector@:
        return advance(o, w, @inspect_has_cursor@, 1)
    if port == @inspect_has_cursor@:
        if observed == 1:
            return advance(o, w, @inspect_reject_cursor@, 1)
        return advance(o, w, @inspect_view_query@, 1)
    if port == @inspect_reject_cursor@:
        return advance(o, w, @inspect_view_query@, 1)
    if port == @inspect_view_query@:
        return advance(o, w, @inspect_is_summary@, 1)
    if port == @inspect_is_summary@:
        if observed == 1:
            return advance(o, w, @inspect_summary@, 1)
        return advance(o, w, @inspect_is_lowering@, 1)
    if port == @inspect_summary@:
        return advance(o, w, @inspect_result@, 1)
    if port == @inspect_is_lowering@:
        if observed == 1:
            return advance(o, w, @inspect_context@, 1)
        return advance(o, w, @inspect_is_dependencies@, 1)
    if port == @inspect_context@:
        return advance(o, w, @inspect_emit@, 1)
    return refuse(o, w)

def continuation_2(o:mutbuf, w:mutbuf, observed:u64) -> u32:
    port = get(w, 3)
    if port == @inspect_emit@:
        return advance(o, w, @inspect_lowering_result@, 1)
    if port == @inspect_lowering_result@:
        return advance(o, w, @inspect_result@, 1)
    if port == @inspect_is_dependencies@:
        if observed == 1:
            set(w, 8, 1)
            return advance(o, w, @inspect_all_prepare@, 1)
        return advance(o, w, @inspect_has_function@, 1)
    if port == @inspect_all_prepare@:
        if observed == 1:
            return advance(o, w, @inspect_all_next@, 1)
        return advance(o, w, @inspect_all_foreign@, 1)
    if port == @inspect_all_next@:
        if observed == 0:
            return advance(o, w, @inspect_all_false_done@, 1)
        if observed == 2:
            return advance(o, w, @inspect_all_true_done@, 1)
        return advance(o, w, @inspect_all_next@, 1)
    if port == @inspect_all_foreign@:
        if observed == 1:
            return advance(o, w, @inspect_all_true_done@, 1)
        return advance(o, w, @inspect_all_false_done@, 1)
    if port == @inspect_all_false_done@:
        set(w, 8, 0)
        return advance(o, w, @inspect_reject_dependencies@, 1)
    if port == @inspect_all_true_done@:
        set(w, 8, 0)
        return advance(o, w, @inspect_prepare_edit@, 1)
    if port == @inspect_reject_dependencies@:
        return advance(o, w, @inspect_prepare_edit@, 1)
    if port == @inspect_prepare_edit@:
        return advance(o, w, @inspect_prepared_result@, 1)
    if port == @inspect_prepared_result@:
        return advance(o, w, @inspect_query@, 1)
    if port == @inspect_query@:
        return advance(o, w, @inspect_result@, 1)
    return refuse(o, w)

def continuation_3(o:mutbuf, w:mutbuf, observed:u64) -> u32:
    port = get(w, 3)
    if port == @inspect_has_function@:
        if observed == 1:
            set(w, 8, 2)
            return advance(o, w, @inspect_functions_open@, 1)
        return advance(o, w, @inspect_reject_function_required@, 1)
    if port == @inspect_reject_function_required@:
        set(w, 8, 2)
        return advance(o, w, @inspect_functions_open@, 1)
    if port == @inspect_functions_open@:
        set(w, 9, observed)
        if observed != 0:
            return advance(o, w, @inspect_functions_reiterate@, 1)
        return advance(o, w, @inspect_functions_next@, 1)
    if port == @inspect_functions_reiterate@:
        if get(w, 9) == 0:
            return refuse(o, w)
        set(w, 9, get(w, 9) - 1)
        if get(w, 9) != 0:
            return advance(o, w, @inspect_functions_reiterate@, 1)
        return advance(o, w, @inspect_functions_next@, 1)
    if port == @inspect_functions_next@:
        if observed == 1:
            return advance(o, w, @inspect_functions_done@, 1)
        return advance(o, w, @inspect_functions_put@, 1)
    if port == @inspect_functions_put@:
        return advance(o, w, @inspect_functions_next@, 1)
    if port == @inspect_functions_done@:
        set(w, 8, 0)
        set(w, 9, 0)
        return advance(o, w, @inspect_function_present@, 1)
    if port == @inspect_function_present@:
        if observed == 1:
            return advance(o, w, @inspect_function_result@, 1)
        return advance(o, w, @inspect_reject_function_missing@, 1)
    if port == @inspect_reject_function_missing@:
        return advance(o, w, @inspect_function_result@, 1)
    if port == @inspect_function_result@:
        return advance(o, w, @inspect_is_block@, 1)
    if port == @inspect_is_block@:
        if observed == 1:
            set(w, 8, 3)
            return advance(o, w, @inspect_blocks_open@, 1)
        return advance(o, w, @inspect_result@, 1)
    if port == @inspect_blocks_open@:
        set(w, 9, observed)
        if observed != 0:
            return advance(o, w, @inspect_blocks_reiterate@, 1)
        return advance(o, w, @inspect_blocks_next@, 1)
    return refuse(o, w)

def continuation_4(o:mutbuf, w:mutbuf, observed:u64) -> u32:
    port = get(w, 3)
    if port == @inspect_blocks_reiterate@:
        if get(w, 9) == 0:
            return refuse(o, w)
        set(w, 9, get(w, 9) - 1)
        if get(w, 9) != 0:
            return advance(o, w, @inspect_blocks_reiterate@, 1)
        return advance(o, w, @inspect_blocks_next@, 1)
    if port == @inspect_blocks_next@:
        if observed == 1:
            return advance(o, w, @inspect_blocks_done@, 1)
        return advance(o, w, @inspect_blocks_put@, 1)
    if port == @inspect_blocks_put@:
        return advance(o, w, @inspect_blocks_next@, 1)
    if port == @inspect_blocks_done@:
        set(w, 8, 0)
        set(w, 9, 0)
        return advance(o, w, @inspect_block_present@, 1)
    if port == @inspect_block_present@:
        if observed == 1:
            return advance(o, w, @inspect_block_result@, 1)
        return advance(o, w, @inspect_reject_block_missing@, 1)
    if port == @inspect_reject_block_missing@:
        return advance(o, w, @inspect_block_result@, 1)
    if port == @inspect_block_result@:
        return advance(o, w, @inspect_result@, 1)
    if port == @inspect_result@:
        return advance(o, w, @inspect_release@, 1)
    if port == @inspect_release@:
        return advance(o, w, 0, 6)
    if port == @inspect_comprehension_unwind@:
        set(w, 8, 0)
        set(w, 9, 0)
        return advance(o, w, 0, 7)
    if port == @inspect_all_unwind@:
        set(w, 8, 0)
        set(w, 9, 0)
        return advance(o, w, 0, 7)
    if port == @candidate_assemble_import@:
        return advance(o, w, @candidate_patch_import@, 1)
    return refuse(o, w)

def continuation_5(o:mutbuf, w:mutbuf, observed:u64) -> u32:
    port = get(w, 3)
    if port == @candidate_patch_import@:
        return advance(o, w, @candidate_change_base_payloads@, 1)
    if port == @candidate_change_base_payloads@:
        return advance(o, w, @candidate_is_import@, 1)
    if port == @candidate_is_import@:
        if observed == 1:
            return advance(o, w, @candidate_import_data@, 1)
        return advance(o, w, @candidate_base@, 1)
    if port == @candidate_import_data@:
        return advance(o, w, @candidate_is_assembly@, 1)
    if port == @candidate_is_assembly@:
        if observed == 1:
            return advance(o, w, @candidate_assemble@, 1)
        return advance(o, w, @candidate_verify@, 1)
    if port == @candidate_assemble@:
        return advance(o, w, @candidate_import_diagnostics@, 1)
    if port == @candidate_verify@:
        return advance(o, w, @candidate_import_diagnostics@, 1)
    if port == @candidate_import_diagnostics@:
        set(w, 8, 4)
        return advance(o, w, @candidate_put_open@, 1)
    if port == @candidate_base@:
        return advance(o, w, @candidate_patch_selector@, 1)
    if port == @candidate_patch_selector@:
        return advance(o, w, @candidate_patch_selected@, 1)
    if port == @candidate_patch_selected@:
        if observed == 1:
            return advance(o, w, @candidate_native_patch_import@, 1)
        return advance(o, w, @candidate_original_program@, 1)
    if port == @candidate_native_patch_import@:
        return advance(o, w, @candidate_original_bytes@, 1)
    return refuse(o, w)

def continuation_6(o:mutbuf, w:mutbuf, observed:u64) -> u32:
    port = get(w, 3)
    if port == @candidate_original_bytes@:
        return advance(o, w, @candidate_patch_bytes@, 1)
    if port == @candidate_patch_bytes@:
        return advance(o, w, @candidate_apply_native@, 1)
    if port == @candidate_apply_native@:
        set(w, 8, 4)
        return advance(o, w, @candidate_put_open@, 1)
    if port == @candidate_original_program@:
        return advance(o, w, @candidate_patch_document@, 1)
    if port == @candidate_patch_document@:
        return advance(o, w, @candidate_schema_differs@, 1)
    if port == @candidate_schema_differs@:
        if observed == 1:
            return advance(o, w, @candidate_reject_schema@, 1)
        return advance(o, w, @candidate_apply_program@, 1)
    if port == @candidate_reject_schema@:
        return advance(o, w, @candidate_apply_program@, 1)
    if port == @candidate_apply_program@:
        set(w, 8, 4)
        return advance(o, w, @candidate_put_open@, 1)
    if port == @candidate_put_open@:
        return advance(o, w, @candidate_payload_selected@, 1)
    if port == @candidate_payload_selected@:
        if observed == 1:
            return advance(o, w, @candidate_put_native@, 1)
        return advance(o, w, @candidate_put_program@, 1)
    if port == @candidate_put_native@:
        set(w, 8, 0)
        return advance(o, w, @candidate_diagnostics_selected@, 1)
    if port == @candidate_put_program@:
        set(w, 8, 0)
        return advance(o, w, @candidate_diagnostics_selected@, 1)
    return refuse(o, w)

def continuation_7(o:mutbuf, w:mutbuf, observed:u64) -> u32:
    port = get(w, 3)
    if port == @candidate_diagnostics_selected@:
        if observed == 1:
            return advance(o, w, @candidate_diagnostics_native@, 1)
        return advance(o, w, @candidate_diagnostics_json@, 1)
    if port == @candidate_diagnostics_native@:
        return advance(o, w, @candidate_result@, 1)
    if port == @candidate_diagnostics_json@:
        return advance(o, w, @candidate_result@, 1)
    if port == @candidate_result@:
        return advance(o, w, @candidate_release@, 1)
    if port == @candidate_release@:
        return advance(o, w, 0, 6)
    if port == @candidate_put_unwind@:
        set(w, 8, 0)
        set(w, 9, 0)
        return advance(o, w, 0, 7)
    return refuse(o, w)


def valid_state(w:mutbuf) -> u64:
    if get(w, 0) != @STATE_MAGIC@ or get(w, 1) != 1:
        return 0
    mode = get(w, 2)
    if mode != 1 and mode != 2:
        return 0
    phase = get(w, 5)
    port = get(w, 3)
    scope = get(w, 8)
    if get(w, 4) == 0 or phase == 0 or phase == 3 or phase > 8:
        return 0
    if scope > 4 or get(w, 11) != 0 or get(w, 12) > 1:
        return 0
    if mode == 1 and scope == 4:
        return 0
    if mode == 2 and scope != 0 and scope != 4:
        return 0
    if scope != 2 and scope != 3 and get(w, 9) != 0:
        return 0
    index = 13
    while index < 24:
        if get(w, index) != 0:
            return 0
        index = index + 1
    if checksum(w) != get(w, 10):
        return 0
    if phase == 1 or phase == 2:
        if owned_port(mode, port) == 0 or error_port(port) != get(w, 12):
            return 0
    elif port != 0:
        return 0
    if phase == 4 or phase == 6:
        if get(w, 12) != 0 or scope != 0 or get(w, 9) != 0:
            return 0
    if phase == 5 or phase == 7:
        if get(w, 12) != 1:
            return 0
    return 1

def advance(o:mutbuf, w:mutbuf, port:u64, phase:u64) -> u32:
    if get(w, 4) == 18446744073709551615:
        return refuse(o, w)
    set(w, 3, port)
    set(w, 4, get(w, 4) + 1)
    set(w, 5, phase)
    seal(w)
    return answer(o, w, 0)

def refuse(o:mutbuf, w:mutbuf) -> u32:
    set(w, 3, 0)
    set(w, 5, 8)
    seal(w)
    return answer(o, w, 1)

def answer(o:mutbuf, w:mutbuf, status:u64) -> u32:
    set(o, 0, @RESULT_MAGIC@)
    set(o, 1, status)
    set(o, 2, get(w, 3))
    set(o, 3, get(w, 4))
    set(o, 4, get(w, 5))
    set(o, 5, get(w, 2))
    set(o, 6, get(w, 12))
    set(o, 7, 0)
    set(o, 8, get(w, 6))
    set(o, 9, get(w, 7))
    set(o, 10, 0)
    set(o, 11, 0)
    return 96

def checksum(w:mutbuf) -> u64:
    value = 1469598103934665603
    index = 0
    while index < 24:
        if index != 10:
            value = ((value << 7) | (value >> 57)) ^ get(w, index)
        index = index + 1
    return value

def seal(w:mutbuf) -> u64:
    value = checksum(w)
    set(w, 10, value)
    return value

def read_word(s:readbuf, index:u64) -> u64:
    value = 0
    shift = 0
    while shift < 8:
        value = value | (byte(s, index + shift) << (shift * 8))
        shift = shift + 1
    return value

def get(w:mutbuf, index:u64) -> u64:
    value = 0
    shift = 0
    while shift < 8:
        value = value | (byte(w, index * 8 + shift) << (shift * 8))
        shift = shift + 1
    return value

def set(w:mutbuf, index:u64, value:u64) -> u64:
    shift = 0
    while shift < 8:
        store(w, index * 8 + shift, value >> (shift * 8))
        shift = shift + 1
    return value
'''

def source_program():
    values = {**PORT, 'REQUEST_MAGIC': REQUEST_MAGIC,
              'RESULT_MAGIC': RESULT_MAGIC, 'STATE_MAGIC': STATE_MAGIC}
    return re.sub(r'@([A-Za-z_][A-Za-z_0-9]*)@',
                  lambda match: str(values[match[1]]), PROTOCOL)

def document():
    nodes = ast.parse(source_program()).body
    names = {node.name: 'f' + str(index) for index, node in enumerate(nodes)}
    signatures = {node.name: ([arg.annotation.id for arg in node.args.args],
                             node.returns.id) for node in nodes}
    total = total_scalar_functions(nodes)
    functions = []
    for node in nodes:
        builder = ContextBuilder(node, names, signatures, total)
        builder.statements(node.body)
        functions.append({'name': names[node.name],
            'params': [builder.param(value) for value in builder.params],
            'returns': [builder.returns], 'effects': ['read', 'write', 'trap'],
            'entry': 'b0', 'blocks': builder.blocks})
    return compact_authoring_cfg({'schema': 'hepta.hia.program.v8',
        'module': 'service_inspection', 'functions': functions})

if __name__ == '__main__':
    path = ROOT / SOURCE_NAME
    path.write_text(render_assembly(document()))
    print(path.name, path.stat().st_size)
