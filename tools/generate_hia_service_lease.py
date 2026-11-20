"""Author all four complete service lease method control graphs.

HIA owns branch/loop/context cleanup and independent final confirmation.
The Python ports implement literal provider expressions and observations only.
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
from hepta.hia_service_lease_protocol import (
    PORT, PORTS, REQUEST_MAGIC, RESULT_MAGIC, STATE_MAGIC, SOURCE_NAME,
)
from tools.generate_hia_selfhost import compact_authoring_cfg, total_scalar_functions
from tools.generate_hia_service_context import ContextBuilder


PROTOCOL = r'''
def service_lease(s:readbuf, o:mutbuf, w:mutbuf) -> u32:
    if length(s) != 80 or length(o) != 96 or length(w) != 128:
        return 4294967293
    if read_word(s, 0) != @REQUEST_MAGIC@ or read_word(s, 64) != 0 or read_word(s, 72) != 0:
        return 4294967293
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
        if (phase != 1 and phase != 7) or observed != 0:
            return refuse(o, w)
        set(w, 5, 2)
        seal(w)
        return answer(o, w, 0)
    if event == 2:
        if phase != 2 or valid_observation(port, observed) == 0:
            return refuse(o, w)
        return succeeded(o, w, observed)
    if event == 3:
        if phase != 2 or observed != 0:
            return refuse(o, w)
        set(w, 12, 1)
        if port == @exception_stack_release@:
            return advance(o, w, 0, 6)
        if get(w, 8) == 1:
            set(w, 8, 0)
            return advance(o, w, @cm_exit_exception@, 1)
        return advance(o, w, @exception_stack_release@, 1)
    if event == 4:
        if observed != 0 or port != 0:
            return refuse(o, w)
        if phase == 3 and get(w, 12) == 0:
            return advance(o, w, 0, 4)
        if phase == 6 and get(w, 12) == 1:
            return advance(o, w, 0, 5)
    return refuse(o, w)

def valid_observation(port:u64, observed:u64) -> u64:
    if port == @cm_lookup_next@:
        if observed <= 2:
            return 1
        return 0
    if port == @ledger_present@ or port == @cm_exit_truth@ or port == @output_kind_differs@ or port == @function_is_str@ or port == @signature_missing@ or port == @snapshot_prefix@ or port == @captured_next@ or port == @signature_abi@ or port == @result_returned@ or port == @observation_returned@:
        if observed <= 1:
            return 1
        return 0
    if observed == 0:
        return 1
    return 0

def initialize(s:readbuf, o:mutbuf, w:mutbuf) -> u32:
    mode = read_word(s, 40)
    if mode < 1 or mode > 4 or read_word(s, 16) != 0 or read_word(s, 24) != 0 or read_word(s, 32) != 0:
        return 4294967293
    if read_word(s, 48) == 0 and read_word(s, 56) == 0:
        return 4294967293
    i = 0
    while i < 128:
        if byte(w, i) != 0:
            return 4294967293
        i = i + 1
    set(w, 0, @STATE_MAGIC@)
    set(w, 1, 1)
    set(w, 2, mode)
    if mode == 1 or mode == 4:
        set(w, 3, @cm_create@)
    elif mode == 2:
        set(w, 3, @ledger_present@)
    else:
        set(w, 3, @import_runner@)
    set(w, 4, 1)
    set(w, 5, 1)
    set(w, 6, read_word(s, 48))
    set(w, 7, read_word(s, 56))
    seal(w)
    return answer(o, w, 0)

def succeeded(o:mutbuf, w:mutbuf, observed:u64) -> u32:
    port = get(w, 3)
    if port == @normal_release@:
        return advance(o, w, 0, 3)
    if port == @exception_stack_release@:
        set(w, 8, 0)
        set(w, 9, 0)
        set(w, 11, 0)
        set(w, 14, 0)
        set(w, 15, 0)
        return advance(o, w, 0, 6)
    if get(w, 2) != 3:
        return lease_succeeded(o, w, observed)
    if port <= @snapshot_decode@:
        return invoke_admission(o, w, observed)
    return invoke_completion(o, w, observed)

def lease_succeeded(o:mutbuf, w:mutbuf, observed:u64) -> u32:
    port = get(w, 3)
    mode = get(w, 2)
    if port == @cm_create@:
        return advance(o, w, @cm_lookup_next@, 1)
    if port == @cm_lookup_next@:
        mask = get(w, 11)
        if observed == 1 and (mask & 1) == 0:
            set(w, 11, mask | 1)
            return advance(o, w, @cm_lookup_enter@, 1)
        if observed == 2 and (mask & 2) == 0:
            set(w, 11, mask | 2)
            return advance(o, w, @cm_lookup_exit@, 1)
        if observed == 0 and mask == 3:
            return advance(o, w, @cm_enter@, 1)
        return refuse(o, w)
    if port == @cm_lookup_enter@ or port == @cm_lookup_exit@:
        return advance(o, w, @cm_lookup_next@, 1)
    if port == @cm_enter@:
        set(w, 8, 1)
        return advance(o, w, @ledger_present@, 1)
    if port == @ledger_present@:
        if mode == 1:
            if observed == 1:
                return advance(o, w, @acquire_ledger@, 1)
            return advance(o, w, @acquire_reference@, 1)
        if mode == 2:
            if observed == 1:
                return advance(o, w, @lease_ledger@, 1)
            return advance(o, w, @lease_reference@, 1)
        if observed == 1:
            return advance(o, w, @release_ledger@, 1)
        return advance(o, w, @release_reference@, 1)
    if port == @acquire_ledger@ or port == @acquire_reference@ or port == @release_ledger@ or port == @release_reference@:
        set(w, 8, 0)
        return advance(o, w, @cm_exit_normal@, 1)
    if port == @lease_ledger@ or port == @lease_reference@:
        return advance(o, w, @normal_release@, 1)
    if port == @cm_exit_normal@:
        return advance(o, w, @cm_stack_release@, 1)
    if port == @cm_stack_release@:
        return advance(o, w, @normal_release@, 1)
    if port == @cm_exit_exception@:
        return advance(o, w, @cm_exit_truth@, 1)
    if port == @cm_exit_truth@:
        if observed == 1:
            set(w, 12, 0)
            return advance(o, w, @cm_suppressed_release@, 1)
        return advance(o, w, @exception_stack_release@, 1)
    if port == @cm_suppressed_release@:
        return advance(o, w, @implicit_none@, 7)
    if port == @implicit_none@:
        return advance(o, w, @normal_release@, 1)
    return refuse(o, w)

def invoke_admission(o:mutbuf, w:mutbuf, observed:u64) -> u32:
    port = get(w, 3)
    if port == @import_runner@:
        return advance(o, w, @import_validator@, 1)
    if port == @import_validator@:
        return advance(o, w, @invoke_lease_lookup@, 1)
    if port == @invoke_lease_lookup@:
        return advance(o, w, @invoke_native@, 1)
    if port == @invoke_native@:
        return advance(o, w, @output_kind_differs@, 1)
    if port == @reject_kind@:
        return advance(o, w, @function_is_str@, 1)
    if port == @signature_get@:
        return advance(o, w, @signature_missing@, 1)
    if port == @signature_none@:
        return advance(o, w, @signature_missing@, 1)
    if port == @reject_signature@:
        return advance(o, w, @snapshot_prefix@, 1)
    if port == @snapshot_list@:
        return advance(o, w, @snapshot_wire@, 1)
    if port == @snapshot_identity@:
        return advance(o, w, @snapshot_wire@, 1)
    if port == @snapshot_wire@:
        return advance(o, w, @snapshot_decode@, 1)
    if port == @output_kind_differs@:
        if observed == 1:
            return advance(o, w, @reject_kind@, 1)
        return advance(o, w, @function_is_str@, 1)
    if port == @function_is_str@:
        if observed == 1:
            return advance(o, w, @signature_get@, 1)
        return advance(o, w, @signature_none@, 1)
    if port == @signature_missing@:
        if observed == 1:
            return advance(o, w, @reject_signature@, 1)
        return advance(o, w, @snapshot_prefix@, 1)
    if port == @snapshot_prefix@:
        if observed == 1:
            return advance(o, w, @snapshot_list@, 1)
        return advance(o, w, @snapshot_identity@, 1)
    if port == @snapshot_decode@:
        return advance(o, w, @validate_arguments@, 1)
    return refuse(o, w)

def invoke_completion(o:mutbuf, w:mutbuf, observed:u64) -> u32:
    port = get(w, 3)
    if port == @validate_arguments@:
        return advance(o, w, @context_lookup@, 1)
    if port == @context_lookup@:
        return advance(o, w, @run_native@, 1)
    if port == @run_native@:
        return advance(o, w, @buffers_init@, 1)
    if port == @buffers_init@:
        return advance(o, w, @captured_iter@, 1)
    if port == @captured_data@:
        return advance(o, w, @captured_append@, 1)
    if port == @captured_append@:
        return advance(o, w, @captured_next@, 1)
    if port == @captured_iter_release@:
        set(w, 14, 0)
        return advance(o, w, @signature_abi@, 1)
    if port == @external_buffers@:
        return advance(o, w, @result_returned@, 1)
    if port == @external_empty@:
        return advance(o, w, @result_returned@, 1)
    if port == @observation_lookup@:
        return advance(o, w, @observation_returned@, 1)
    if port == @return_values@:
        return advance(o, w, @normal_release@, 1)
    if port == @return_observation@:
        return advance(o, w, @normal_release@, 1)
    if port == @return_status@:
        return advance(o, w, @normal_release@, 1)
    if port == @captured_iter@:
        set(w, 14, 1)
        return advance(o, w, @captured_next@, 1)
    if port == @captured_next@:
        if observed == 1:
            return advance(o, w, @captured_data@, 1)
        return advance(o, w, @captured_iter_release@, 1)
    if port == @signature_abi@:
        if observed == 1:
            return advance(o, w, @external_buffers@, 1)
        return advance(o, w, @external_empty@, 1)
    if port == @result_returned@:
        if observed == 1:
            return advance(o, w, @observation_lookup@, 1)
        return advance(o, w, @return_status@, 1)
    if port == @observation_returned@:
        if observed == 1:
            return advance(o, w, @return_values@, 1)
        return advance(o, w, @return_observation@, 1)
    return refuse(o, w)

def valid_state(w:mutbuf) -> u64:
    mode = get(w, 2)
    phase = get(w, 5)
    port = get(w, 3)
    if get(w, 0) != @STATE_MAGIC@ or get(w, 1) != 1 or mode < 1 or mode > 4:
        return 0
    if get(w, 4) == 0 or phase < 1 or phase > 8:
        return 0
    if get(w, 8) > 1 or get(w, 9) != 0 or get(w, 11) > 3 or get(w, 12) > 1:
        return 0
    if get(w, 13) != 0 or get(w, 14) > 1 or get(w, 15) != 0 or checksum(w) != get(w, 10):
        return 0
    if mode == 2 or mode == 3:
        if get(w, 8) != 0 or get(w, 11) != 0:
            return 0
    if mode != 3 and get(w, 14) != 0:
        return 0
    if phase == 1 or phase == 2 or phase == 7:
        if valid_port(mode, port) == 0:
            return 0
    elif port != 0:
        return 0
    if phase == 7 and (port != @implicit_none@ or get(w, 12) != 0):
        return 0
    if (phase == 3 or phase == 4) and get(w, 12) != 0:
        return 0
    if (phase == 5 or phase == 6) and get(w, 12) != 1:
        return 0
    return 1

def valid_port(mode:u64, port:u64) -> u64:
    if port == @normal_release@ or port == @exception_stack_release@:
        return 1
    if mode == 3:
        if port >= @import_runner@ and port <= @return_status@:
            return 1
        return 0
    if port == @ledger_present@:
        return 1
    if mode == 2:
        if port == @lease_ledger@ or port == @lease_reference@:
            return 1
        return 0
    if (port >= @cm_create@ and port <= @cm_enter@) or (port >= @cm_exit_normal@ and port <= @implicit_none@):
        return 1
    if mode == 1 and (port == @acquire_ledger@ or port == @acquire_reference@):
        return 1
    if mode == 4 and (port == @release_ledger@ or port == @release_reference@):
        return 1
    return 0
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
    i = 0
    while i < 16:
        if i != 10:
            value = ((value << 7) | (value >> 57)) ^ get(w, i)
        i = i + 1
    return value

def seal(w:mutbuf) -> u64:
    value = checksum(w)
    set(w, 10, value)
    return value

def read_word(s:readbuf, index:u64) -> u64:
    value = 0
    i = 0
    while i < 8:
        value = value | (byte(s, index + i) << (i * 8))
        i = i + 1
    return value

def get(w:mutbuf, index:u64) -> u64:
    value = 0
    i = 0
    while i < 8:
        value = value | (byte(w, index * 8 + i) << (i * 8))
        i = i + 1
    return value

def set(w:mutbuf, index:u64, value:u64) -> u64:
    i = 0
    while i < 8:
        store(w, index * 8 + i, value >> (i * 8))
        i = i + 1
    return value
'''

def source_program():
    values = {**PORT, 'REQUEST_MAGIC': REQUEST_MAGIC, 'RESULT_MAGIC': RESULT_MAGIC,
              'STATE_MAGIC': STATE_MAGIC, 'MAX_PORT': len(PORTS)}
    return re.sub(r'@([A-Za-z_][A-Za-z_0-9]*)@', lambda match: str(values[match[1]]), PROTOCOL)


def document():
    nodes = ast.parse(source_program()).body
    names = {node.name: 'f' + str(index) for index, node in enumerate(nodes)}
    signatures = {node.name: ([arg.annotation.id for arg in node.args.args], node.returns.id)
                  for node in nodes}
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
                                  'module': 'service_lease', 'functions': functions})


if __name__ == '__main__':
    path = ROOT / SOURCE_NAME
    path.write_text(render_assembly(document()))
    print(path.name, path.stat().st_size)
