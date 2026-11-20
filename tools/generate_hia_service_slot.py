"""Author the complete original service rollback and adoption control.

HIA owns the independent ledger choices, short-circuit receipt predicates,
effect order and every normal/error continuation. Foreign ports retain only
the exact original literal calls, unpack operations and ordered values.
This generator does not author or qualify the separate Slot SQL owner.
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
from hepta.hia_service_slot_protocol import (
    PORT, PORTS, REQUEST_MAGIC, RESULT_MAGIC, STATE_MAGIC, SOURCE_NAME,
)
from tools.generate_hia_selfhost import compact_authoring_cfg, total_scalar_functions
from tools.generate_hia_service_context import ContextBuilder


PROTOCOL = r'''
def service_slot(s:readbuf, o:mutbuf, w:mutbuf) -> u32:
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
        if phase != 1 or observed != 0:
            return refuse(o, w)
        set(w, 5, 2)
        seal(w)
        return answer(o, w, 0)
    if event == 2:
        if phase != 2:
            return refuse(o, w)
        if port == @rollback_validate_ledger_present@ or port == @rollback_ledger_present@ or port == @adopt_context_differs@ or port == @adopt_candidate_differs@ or port == @adopt_installation_differs@ or port == @adopt_evaluation_ledger_present@ or port == @adopt_net_ledger_present@ or port == @adopt_signatures_differ@ or port == @adopt_ledger_present@:
            if observed > 1:
                return refuse(o, w)
        elif observed != 0:
            return refuse(o, w)
        return succeeded(o, w, observed)
    if event == 3:
        if phase != 2 or observed != 0:
            return refuse(o, w)
        set(w, 12, 1)
        return advance(o, w, 0, 6)
    if event == 4:
        if observed != 0 or port != 0:
            return refuse(o, w)
        if phase == 3 and get(w, 12) == 0:
            return advance(o, w, 0, 4)
        if phase == 6 and get(w, 12) == 1:
            return advance(o, w, 0, 5)
        return refuse(o, w)
    return refuse(o, w)

def initialize(s:readbuf, o:mutbuf, w:mutbuf) -> u32:
    mode = read_word(s, 40)
    if (mode != 1 and mode != 2) or read_word(s, 16) != 0 or read_word(s, 24) != 0 or read_word(s, 32) != 0:
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
    if mode == 1:
        set(w, 3, @rollback_validate_ledger_present@)
    else:
        set(w, 3, @adopt_context@)
    set(w, 4, 1)
    set(w, 5, 1)
    set(w, 6, read_word(s, 48))
    set(w, 7, read_word(s, 56))
    seal(w)
    return answer(o, w, 0)

def succeeded(o:mutbuf, w:mutbuf, observed:u64) -> u32:
    if get(w, 2) == 1:
        return rollback_succeeded(o, w, observed)
    if get(w, 3) <= @adopt_reference_net@:
        return adopt_admission_succeeded(o, w, observed)
    return adopt_publication_succeeded(o, w, observed)

def rollback_succeeded(o:mutbuf, w:mutbuf, observed:u64) -> u32:
    port = get(w, 3)
    if port == @rollback_validate_ledger_present@:
        if observed == 1:
            return advance(o, w, @rollback_ledger_validate@, 1)
        return advance(o, w, @rollback_reference_validate@, 1)
    if port == @rollback_ledger_validate@ or port == @rollback_reference_validate@:
        return advance(o, w, @rollback_snapshot@, 1)
    if port == @rollback_snapshot@:
        return advance(o, w, @rollback_ledger_present@, 1)
    if port == @rollback_ledger_present@:
        if observed == 1:
            return advance(o, w, @rollback_ledger_call@, 1)
        return advance(o, w, @rollback_reference_call@, 1)
    if port == @rollback_ledger_call@ or port == @rollback_reference_call@:
        return advance(o, w, @rollback_receipt@, 1)
    if port == @rollback_receipt@:
        return advance(o, w, @rollback_result@, 1)
    if port == @rollback_result@:
        return advance(o, w, @rollback_release_locals@, 1)
    if port == @rollback_release_locals@:
        return advance(o, w, 0, 3)
    return refuse(o, w)

def adopt_admission_succeeded(o:mutbuf, w:mutbuf, observed:u64) -> u32:
    port = get(w, 3)
    if port == @adopt_context@:
        return advance(o, w, @adopt_evaluation@, 1)
    if port == @adopt_evaluation@:
        return advance(o, w, @adopt_context_differs@, 1)
    if port == @adopt_context_differs@:
        if observed == 1:
            return advance(o, w, @adopt_reject_binding@, 1)
        return advance(o, w, @adopt_candidate_differs@, 1)
    if port == @adopt_candidate_differs@:
        if observed == 1:
            return advance(o, w, @adopt_reject_binding@, 1)
        return advance(o, w, @adopt_installation_differs@, 1)
    if port == @adopt_installation_differs@:
        if observed == 1:
            return advance(o, w, @adopt_reject_binding@, 1)
        return advance(o, w, @adopt_build_receipt@, 1)
    if port == @adopt_reject_binding@:
        return advance(o, w, @adopt_build_receipt@, 1)
    if port == @adopt_build_receipt@:
        return advance(o, w, @adopt_objective@, 1)
    if port == @adopt_objective@:
        return advance(o, w, @adopt_evaluation_ledger_present@, 1)
    if port == @adopt_evaluation_ledger_present@:
        if observed == 1:
            return advance(o, w, @adopt_ledger_evaluation@, 1)
        return advance(o, w, @adopt_reference_evaluation@, 1)
    if port == @adopt_ledger_evaluation@ or port == @adopt_reference_evaluation@:
        return advance(o, w, @adopt_measurements@, 1)
    if port == @adopt_measurements@:
        return advance(o, w, @adopt_full_cost_ledger@, 1)
    if port == @adopt_full_cost_ledger@:
        return advance(o, w, @adopt_net_ledger_present@, 1)
    if port == @adopt_net_ledger_present@:
        if observed == 1:
            return advance(o, w, @adopt_ledger_net@, 1)
        return advance(o, w, @adopt_reference_net@, 1)
    if port == @adopt_ledger_net@ or port == @adopt_reference_net@:
        return advance(o, w, @adopt_native_candidate@, 1)
    return refuse(o, w)

def adopt_publication_succeeded(o:mutbuf, w:mutbuf, observed:u64) -> u32:
    port = get(w, 3)
    if port == @adopt_native_candidate@:
        return advance(o, w, @adopt_native_baseline@, 1)
    if port == @adopt_native_baseline@:
        return advance(o, w, @adopt_signatures_differ@, 1)
    if port == @adopt_signatures_differ@:
        if observed == 1:
            return advance(o, w, @adopt_reject_abi@, 1)
        return advance(o, w, @adopt_snapshot@, 1)
    if port == @adopt_reject_abi@:
        return advance(o, w, @adopt_snapshot@, 1)
    if port == @adopt_snapshot@:
        return advance(o, w, @adopt_abi@, 1)
    if port == @adopt_abi@:
        return advance(o, w, @adopt_ledger_present@, 1)
    if port == @adopt_ledger_present@:
        if observed == 1:
            return advance(o, w, @adopt_ledger_call@, 1)
        return advance(o, w, @adopt_reference_call@, 1)
    if port == @adopt_ledger_call@ or port == @adopt_reference_call@:
        return advance(o, w, @adopt_receipt@, 1)
    if port == @adopt_receipt@:
        return advance(o, w, @adopt_result@, 1)
    if port == @adopt_result@:
        return advance(o, w, @adopt_release_locals@, 1)
    if port == @adopt_release_locals@:
        return advance(o, w, 0, 3)
    return refuse(o, w)

def valid_state(w:mutbuf) -> u64:
    if get(w, 0) != @STATE_MAGIC@ or get(w, 1) != 1 or (get(w, 2) != 1 and get(w, 2) != 2):
        return 0
    phase = get(w, 5)
    port = get(w, 3)
    if get(w, 4) == 0 or (phase != 1 and phase != 2 and phase != 3 and phase != 4 and phase != 5 and phase != 6 and phase != 8):
        return 0
    if get(w, 8) != 0 or get(w, 9) != 0 or get(w, 11) != 0 or get(w, 12) > 1:
        return 0
    if get(w, 13) != 0 or get(w, 14) != 0 or get(w, 15) != 0 or checksum(w) != get(w, 10):
        return 0
    if phase == 1 or phase == 2:
        if port == 0 or port > @MAX_PORT@ or get(w, 12) != 0:
            return 0
        if get(w, 2) == 1 and port > @rollback_release_locals@:
            return 0
        if get(w, 2) == 2 and port < @adopt_context@:
            return 0
    elif port != 0:
        return 0
    if (phase == 3 or phase == 4) and get(w, 12) != 0:
        return 0
    if (phase == 5 or phase == 6) and get(w, 12) != 1:
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
                                  'module': 'service_slot', 'functions': functions})


if __name__ == '__main__':
    path = ROOT / SOURCE_NAME
    path.write_text(render_assembly(document()))
    print(path.name, path.stat().st_size)
