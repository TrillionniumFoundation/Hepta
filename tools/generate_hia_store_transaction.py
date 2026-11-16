"""Author complete lock/BEGIN/body/COMMIT/ROLLBACK/exit control in HIA.

BODY_WAIT is a fully observed suspension, not a completed transaction. It
permits no SQL or cleanup until its one exact normal/error resume arrives.
The Python generator and object protocols supply observations, never policy.
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
from hepta.hia_store_transaction_protocol import (
    PORT, PORTS, REQUEST_MAGIC, RESULT_MAGIC, STATE_MAGIC, SOURCE_NAME,
)
from tools.generate_hia_selfhost import compact_authoring_cfg, total_scalar_functions
from tools.generate_hia_service_context import ContextBuilder


PROTOCOL = r'''
def store_transaction(s:readbuf, o:mutbuf, w:mutbuf) -> u32:
    if length(s) != 80 or length(o) != 96 or length(w) != 128:
        return 4294967293
    if read_word(s, 0) != @REQUEST_MAGIC@ or read_word(s, 64) != 0 or read_word(s, 72) != 0:
        return 4294967293
    event = read_word(s, 8)
    if event == 0:
        return initialize(s, o, w)
    if valid_state(w) == 0:
        return 4294967293
    if read_word(s, 40) != 1 or read_word(s, 48) != get(w, 6) or read_word(s, 56) != get(w, 7):
        return refuse(o, w)
    if read_word(s, 16) != get(w, 4) or read_word(s, 24) != get(w, 3):
        return refuse(o, w)
    observed = read_word(s, 32)
    phase = get(w, 5)
    port = get(w, 3)
    if event == 1:
        if (phase != 1 and phase != 7) or observed != 0:
            return refuse(o, w)
        if port == @lock_exit_normal@ or port == @lock_exit_exception@:
            if (get(w, 8) & 1) == 0:
                return refuse(o, w)
            set(w, 8, get(w, 8) & 18446744073709551614)
        set(w, 5, 2)
        seal(w)
        return answer(o, w, 0)
    if event == 2:
        if phase != 2:
            return refuse(o, w)
        if port == @context_lookup_next@:
            if observed > 2:
                return refuse(o, w)
        elif port == @body_exception_match@ or port == @lock_exit_truth@:
            if observed > 1:
                return refuse(o, w)
        elif observed != 0:
            return refuse(o, w)
        return succeeded(o, w, observed)
    if event == 3:
        if phase != 2 or observed != 0:
            return refuse(o, w)
        if port == @terminal_release@:
            return refuse(o, w)
        set(w, 13, 1)
        return cleanup(o, w)
    if event == 4 or event == 5:
        if phase != 6 or observed != 0 or get(w, 8) != 3 or get(w, 11) != 0:
            return refuse(o, w)
        if event == 4:
            set(w, 11, 1)
            return advance(o, w, @commit@, 1)
        set(w, 11, 2)
        set(w, 13, 1)
        return advance(o, w, @body_exception_match@, 1)
    return refuse(o, w)

def initialize(s:readbuf, o:mutbuf, w:mutbuf) -> u32:
    if read_word(s, 40) != 1 or read_word(s, 16) != 0 or read_word(s, 24) != 0 or read_word(s, 32) != 0:
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
    set(w, 2, 1)
    set(w, 3, @lock_lookup@)
    set(w, 4, 1)
    set(w, 5, 1)
    set(w, 6, read_word(s, 48))
    set(w, 7, read_word(s, 56))
    seal(w)
    return answer(o, w, 0)

def succeeded(o:mutbuf, w:mutbuf, observed:u64) -> u32:
    port = get(w, 3)
    if port == @lock_lookup@:
        return advance(o, w, @context_lookup_next@, 1)
    if port == @context_lookup_next@:
        if observed == 0:
            if get(w, 9) != 3:
                return refuse(o, w)
            return advance(o, w, @lock_enter@, 1)
        if observed == 1:
            if (get(w, 9) & 1) != 0:
                return refuse(o, w)
            return advance(o, w, @context_lookup_enter@, 1)
        if (get(w, 9) & 2) != 0:
            return refuse(o, w)
        return advance(o, w, @context_lookup_exit@, 1)
    if port == @context_lookup_enter@:
        set(w, 9, get(w, 9) | 1)
        return advance(o, w, @context_lookup_next@, 1)
    if port == @context_lookup_exit@:
        set(w, 9, get(w, 9) | 2)
        return advance(o, w, @context_lookup_next@, 1)
    if port == @lock_enter@:
        set(w, 8, 1)
        return advance(o, w, @begin@, 1)
    if port == @begin@:
        set(w, 8, 3)
        return advance(o, w, 0, 6)
    if port == @body_exception_match@:
        if observed == 1:
            return advance(o, w, @rollback@, 1)
        return cleanup(o, w)
    if port == @rollback@:
        return cleanup(o, w)
    if port == @commit@:
        return advance(o, w, @lock_exit_normal@, 1)
    if port == @lock_exit_normal@:
        return advance(o, w, @terminal_release@, 1)
    if port == @lock_exit_exception@:
        return advance(o, w, @lock_exit_truth@, 1)
    if port == @lock_exit_truth@:
        if observed == 0:
            return cleanup(o, w)
        set(w, 13, 0)
        return advance(o, w, @terminal_release@, 7)
    if port == @terminal_release@:
        if get(w, 12) == 1:
            return advance(o, w, 0, 5)
        return advance(o, w, 0, 4)
    return refuse(o, w)

def cleanup(o:mutbuf, w:mutbuf) -> u32:
    if get(w, 13) != 1:
        return refuse(o, w)
    if (get(w, 8) & 1) != 0:
        return advance(o, w, @lock_exit_exception@, 1)
    set(w, 12, 1)
    return advance(o, w, @terminal_release@, 7)

def valid_state(w:mutbuf) -> u64:
    if get(w, 0) != @STATE_MAGIC@ or get(w, 1) != 1 or get(w, 2) != 1:
        return 0
    phase = get(w, 5)
    port = get(w, 3)
    if get(w, 4) == 0 or phase == 0 or phase == 3 or phase > 8:
        return 0
    if get(w, 8) > 3 or get(w, 9) > 3 or get(w, 11) > 2 or get(w, 12) > 1 or get(w, 13) > 1:
        return 0
    if get(w, 14) != 0 or get(w, 15) != 0 or checksum(w) != get(w, 10):
        return 0
    if phase == 1 or phase == 2 or phase == 7:
        if port == 0 or port > @MAX_PORT@:
            return 0
        if phase == 1 and get(w, 12) != 0:
            return 0
        if get(w, 12) != 0 and port != @terminal_release@:
            return 0
    elif port != 0:
        return 0
    if phase == 6:
        if get(w, 8) != 3 or get(w, 9) != 3 or get(w, 11) != 0 or get(w, 12) != 0 or get(w, 13) != 0:
            return 0
    if phase == 7:
        if port != @terminal_release@ or (get(w, 8) & 1) != 0 or get(w, 13) != get(w, 12):
            return 0
    if phase == 4:
        if (get(w, 8) & 1) != 0 or get(w, 12) != 0 or get(w, 13) != 0:
            return 0
    if phase == 5:
        if (get(w, 8) & 1) != 0 or get(w, 12) != 1 or get(w, 13) != 1:
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
    return re.sub(r'@([A-Za-z_]+)@', lambda match: str(values[match[1]]), PROTOCOL)


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
                                  'module': 'store_transaction', 'functions': functions})


if __name__ == '__main__':
    path = ROOT / SOURCE_NAME
    path.write_text(render_assembly(document()))
    print(path.name, path.stat().st_size)
