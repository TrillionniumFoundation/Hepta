"""Author the ordinary request-journal state owner in HIA.

This is development-time HIA authoring, not a Python runtime decision table.
The image parses actual requests and observed rows, computes canonical hashes,
and emits transition instructions. SQLite and business-method effects remain
hosted. See HIA_AGENT_JOURNAL_RECOVERY_WIP_20261111.md for recovery provenance.
"""
from __future__ import annotations

import ast
from hashlib import sha256
import json
from pathlib import Path

from hepta.hia_agent_assembly import render_assembly
from tools.generate_hia_selfhost import Builder, compact_authoring_cfg, total_scalar_functions
from tools.generate_hia_worker_request import (
    ENTRY as WORKER_ENTRY, canonical_program as worker_canonical,
    data_source, decimal_program, format_program, hash_program, replace_once,
)

SOURCE_PATH = 'examples/hia_bootstrap/agent_journal.hiaasm'
PRIVATE_BYTES = 32768
TOOLS = ('hia_describe', 'hia_artifact', 'hia_read', 'hia_context',
         'hia_inspect', 'hia_candidate', 'hia_verify', 'hia_emit',
         'hia_evaluate', 'hia_adopt', 'hia_rollback', 'hia_resource_read')
MAGIC = int.from_bytes(b'HIAJRN01', 'little')

ENTRY = r'''
def agent_journal(s:readbuf, o:mutbuf, w:mutbuf) -> u32:
    bound = (length(s) + 1) >> 1
    bound = bound + 1
    if bound > 262144:
        bound = 262144
    if length(s) > 8388608 or length(o) < 16777728 or length(w) < 64 + bound * 56 + length(s) + 32768:
        return 4294967293
    stage = get(w, 0)
    digits = get(w, 8)
    p = length(w) - 32768
    if get(w, p) == 0:
        put(w, p, MAGIC_VALUE)
    if get(w, p) != MAGIC_VALUE or stage > 9:
        return 4294967293
    put(w, p + 48, 0)
    put(w, p + 56, 0)
    put(w, p + 264, 0)
    put(w, p + 272, 0)
    put(w, p + 280, 0)
    put(w, p + 288, 0)
    put(w, p + 320, 0)
    parsed = False
    if stage == 0 or stage == 1 or stage == 3 or stage == 6 or (stage == 8 and length(s) != 0):
        put(o, 48, 262144)
        put(o, 56, 128)
        status = widen(decode_json(s, w, o))
        if status >= 4294967292:
            return status
        # Cached JSON is materialized by the existing foreign numeric bridge.
        # Its lazy selected-converter and conversion error order are preserved.
        # Identity and terminal canonical bytes still use the HIA numeric core.
        if stage != 3:
            index = 0
            while index < get(w, 8):
                record = 64 + index * 56
                kind = get(w, record)
                start = get(w, record + 24)
                size = get(w, record + 32)
                if kind == 3:
                    count = size
                    if byte(s, start) == 45:
                        count = count - 1
                    if digits != 0 and count > digits:
                        return 4294967280
                if kind == 7:
                    if widen(decimal_convert(s, w, start, size)) != 8:
                        return 4294967280
                index = index + 1
        parsed = True
    else:
        if stage != 9 and length(s) != 0:
            return 4294967293
    answer = dispatch(s, o, w, stage)
    if parsed:
        restore_order(w)
        put(w, 56, 0)
    index = 0
    while index < 512:
        store(o, 16777216 + index, byte(w, p + index))
        index = index + 1
    return answer

def dispatch(s:readbuf, o:mutbuf, w:mutbuf, stage:u64) -> u64:
    p = length(w) - 32768
    phase = get(w, p + 8)
    if stage == 0:
        if phase != 0:
            return 4294967293
        return prepare(s, o, w)
    if stage == 1:
        if phase != 1:
            return 4294967293
        return observe_row(w)
    if stage == 2:
        if phase != 2 or get(w, p + 40) != 0:
            return 4294967293
        put(w, p + 40, 1)
        put(w, p + 8, 3)
        return instruction(w, 1)
    if stage == 3:
        if phase != 5:
            return 4294967293
        put(w, p + 8, 6)
        if get(w, p + 16) == 7:
            if get(w, 64) != 6:
                return refuse(w, 16 + get(w, 64))
            status = field(w, 0, 5)
            if string_is(w, status, 1) == 1:
                return instruction(w, 6)
        return instruction(w, 5)
    if stage == 4:
        if phase != 7:
            return 4294967293
        put(w, p + 16, 3)
        put(w, p + 8, 4)
        return instruction(w, 1)
    if stage == 5:
        if phase != 3 and phase != 4:
            return 4294967293
        put(w, p + 8, 10)
        if get(w, p + 32) != 0:
            return instruction(w, 8)
        return instruction(w, 1)
    if stage == 6:
        if phase != 10 or get(w, p + 32) != 1:
            return 4294967293
        return inline_response(s, o, w)
    if stage == 7:
        if phase != 8 or get(w, p + 40) != 1:
            return 4294967293
        put(w, p + 40, 0)
        put(w, p + 8, 10)
        return instruction(w, 0)
    if stage == 8:
        if phase == 11:
            return 4294967293
        if length(s) == 0:
            put(w, p + 8, 11)
            return instruction(w, 0)
        return terminal_response(s, o, w)
    if stage == 9:
        if phase != 0:
            return 4294967293
        return bind_catalog(s, o, w)
    return 4294967293

def instruction(w:mutbuf, action:u64) -> u64:
    put(w, length(w) - 32768 + 48, action)
    return action

def refuse(w:mutbuf, error:u64) -> u64:
    put(w, length(w) - 32768 + 56, error)
    return instruction(w, 11)

def field(w:mutbuf, node:u64, key:u64) -> u64:
    if node == 18446744073709551615 or get(w, 64 + node * 56) != 6:
        return 18446744073709551615
    child = get(w, 64 + node * 56 + 24)
    while child != 18446744073709551615:
        record = 64 + child * 56
        if field_code(w, get(w, record + 40), get(w, record + 48)) == key:
            return child
        child = get(w, record + 16)
    return 18446744073709551615

def string_is(w:mutbuf, node:u64, value:u64) -> u64:
    if node == 18446744073709551615:
        return 0
    record = 64 + node * 56
    if get(w, record) != 4:
        return 0
    return choose(value_code(w, get(w, record + 24), get(w, record + 32)) == value, 1, 0)

def digest_into(o:mutbuf, w:mutbuf, count:u64, offset:u64) -> u64:
    if count >= 4294967000:
        return count
    if widen(hash_sha256(o, w, count)) != 32:
        return 4294967293
    index = 0
    while index < 32:
        value = byte(w, length(w) - 4096 + 1088 + index)
        store(w, offset + index * 2, hex_digit(value >> 4))
        store(w, offset + index * 2 + 1, hex_digit(value & 15))
        index = index + 1
    return 0

def prepare(s:readbuf, o:mutbuf, w:mutbuf) -> u64:
    p = length(w) - 32768
    if get(w, 64) != 6:
        return 4294967293
    tool = field(w, 0, 1)
    arguments = field(w, 0, 2)
    if tool == 18446744073709551615 or arguments == 18446744073709551615 or get(w, 96) != 2:
        return 4294967293
    put(w, 56, 0)
    count = serialize(s, o, w, 0)
    status = digest_into(o, w, count, p + 64)
    if status != 0:
        return status
    store(w, p + 192, 114)
    store(w, p + 193, 45)
    index = 0
    while index < 64:
        store(w, p + 194 + index, byte(w, p + 64 + index))
        index = index + 1
    record = 64 + tool * 56
    kind = get(w, record)
    code = 0
    if kind == 4:
        code = tool_code(w, get(w, record + 24), get(w, record + 32))
    put(w, p + 16, code)
    if kind == 5:
        return refuse(w, 4)
    if kind == 6:
        return refuse(w, 5)
    if code == 0:
        return refuse(w, 1)
    if code == 12:
        put(w, p + 8, 7)
        return instruction(w, 7)
    put(w, p + 32, choose(code == 10 or code == 11, 1, 0))
    key = field(w, arguments, 3)
    if key != 18446744073709551615:
        record = 64 + key * 56
        if get(w, record) == 4:
            start = get(w, record + 24)
            size = get(w, record + 32)
            characters = 0
            index = 0
            while index < size:
                if (byte(w, start + index) & 192) != 128:
                    characters = characters + 1
                index = index + 1
            if characters >= 1 and characters <= 192:
                put(w, 56, 0)
                key_prefix(o, w)
                append_string(o, w, start, size)
                key_tool(o, w)
                record = 64 + tool * 56
                append_string(o, w, get(w, record + 24), get(w, record + 32))
                append_byte(o, w, 125)
                status = digest_into(o, w, get(w, 56), p + 128)
                if status != 0:
                    return status
                put(w, p + 24, 1)
                put(w, p + 8, 1)
                return instruction(w, 2)
    put(w, p + 8, 4)
    return instruction(w, 1)

def observe_row(w:mutbuf) -> u64:
    p = length(w) - 32768
    if get(w, 64) == 0:
        put(w, p + 8, 2)
        return instruction(w, 3)
    if get(w, 64) != 6:
        return 4294967293
    digest = field(w, 0, 4)
    state = field(w, 0, 6)
    if digest == 18446744073709551615 or state == 18446744073709551615 or get(w, 96) != 2:
        return 4294967293
    record = 64 + digest * 56
    if get(w, record) != 4 or get(w, record + 32) != 64:
        return refuse(w, 2)
    start = get(w, record + 24)
    index = 0
    while index < 64:
        if byte(w, start + index) != byte(w, p + 64 + index):
            return refuse(w, 2)
        index = index + 1
    if string_is(w, state, 1) != 1:
        return refuse(w, 3)
    put(w, p + 8, 5)
    return instruction(w, 4)

def response_status(w:mutbuf) -> u64:
    node = field(w, 0, 5)
    if string_is(w, node, 1) == 1:
        return 1
    if string_is(w, node, 2) == 1:
        return 2
    return 0

def inline_response(s:readbuf, o:mutbuf, w:mutbuf) -> u64:
    p = length(w) - 32768
    if response_status(w) != 1:
        return 4294967293
    if get(w, p + 40) == 0:
        return instruction(w, 0)
    put(w, 56, 0)
    count = serialize(s, o, w, 0)
    if count >= 4294967000:
        return count
    put(w, p + 272, count)
    put(w, p + 264, 1)
    put(w, p + 288, 2)
    put(w, p + 8, 8)
    return instruction(w, 9)

def terminal_response(s:readbuf, o:mutbuf, w:mutbuf) -> u64:
    p = length(w) - 32768
    status = response_status(w)
    if status == 0:
        return 4294967293
    put(w, 56, 0)
    count = serialize(s, o, w, 0)
    if count >= 4294967000:
        return count
    put(w, p + 272, count)
    put(w, p + 264, status)
    put(w, p + 320, 8388608)
    put(w, 56, 0)
    cost_prefix(o, w)
    error = field(w, 0, 7)
    if error == 18446744073709551615:
        null_literal(o, w)
    else:
        count = subtree(s, o, w, error)
        if count >= 4294967000:
            return count
    cost_suffix(o, w)
    if get(w, 56) > 8388608:
        return 4294967274
    put(w, p + 280, get(w, 56))
    put(w, p + 288, 1 + get(w, p + 40) * 2)
    put(w, p + 8, 11)
    return instruction(w, 10)

def subtree(s:readbuf, o:mutbuf, w:mutbuf, node:u64) -> u64:
    record = 64 + node * 56
    parent = get(w, record + 8)
    sibling = get(w, record + 16)
    put(w, record + 8, 18446744073709551615)
    put(w, record + 16, 18446744073709551615)
    count = serialize(s, o, w, node)
    put(w, record + 8, parent)
    put(w, record + 16, sibling)
    return count

def word_at(w:mutbuf, start:u64, size:u64) -> u64:
    value = 0
    index = 0
    while index < size:
        value = value | (byte(w, start + index) << (index * 8))
        index = index + 1
    return value
'''


def matcher(name, values):
    result = f'\ndef {name}(w:mutbuf, start:u64, size:u64) -> u64:\n'
    for number, value in enumerate(values, 1):
        raw = value.encode()
        chunks = [(offset, raw[offset:offset + 8]) for offset in range(0, len(raw), 8)]
        checks = [f'size == {len(raw)}'] + [
            f'word_at(w, start + {offset}, {len(chunk)}) == {int.from_bytes(chunk, "little")}'
            for offset, chunk in chunks]
        result += '    if ' + ' and '.join(checks) + f':\n        return {number}\n'
    return result + '    return 0\n'


def literal(name, value):
    return '\n' + f'def {name}(o:mutbuf, w:mutbuf) -> u64:\n' + ''.join(
        f'    append_byte(o, w, {b})\n' for b in value) + '    return 0\n'


def canonical_program():
    source = worker_canonical()
    source = replace_once(source, 'def serialize(s:readbuf, o:mutbuf, w:mutbuf) -> u64:',
                          'def serialize(s:readbuf, o:mutbuf, w:mutbuf, root:u64) -> u64:')
    source = replace_once(source, '    put(w, 56, 0)\n    node = 0\n', '    node = root\n')
    source = replace_once(source, '    store(o, index, value)\n',
                          '    store(o, get(w, length(w) - 32768 + 320) + index, value)\n')
    return source


def catalog_program():
    path = Path(__file__).resolve().parents[1] / 'docs/HIA_AGENT_NATIVE_TOOL_CATALOG.json'
    raw = path.read_bytes()
    catalog = json.loads(raw)
    if tuple(row['name'] for row in catalog['tools']) != TOOLS[:-1]:
        raise ValueError('journal owner tool vocabulary changed')
    digest = sha256(raw).hexdigest().encode()
    check = ' or '.join(
        f'word_at(w, length(w) - 4096 + 1088 + {offset}, 8) != {int.from_bytes(bytes.fromhex(digest.decode())[offset:offset + 8], "little")}'
        for offset in range(0, 32, 8))
    return f'''
def bind_catalog(s:readbuf, o:mutbuf, w:mutbuf) -> u64:
    index = 0
    while index < length(s):
        store(o, index, byte(s, index))
        index = index + 1
    if widen(hash_sha256(o, w, length(s))) != 32:
        return 4294967293
    if {check}:
        return refuse(w, 7)
    return instruction(w, 12)
'''


def source_program():
    restore = WORKER_ENTRY[WORKER_ENTRY.index('\ndef restore_order('):WORKER_ENTRY.index('\ndef request_fields(')]
    return '\n'.join((
        ENTRY.replace('MAGIC_VALUE', str(MAGIC)), catalog_program(),
        matcher('tool_code', TOOLS),
        matcher('field_code', ('tool', 'arguments', 'request_key', 'digest', 'status', 'state', 'error')),
        matcher('value_code', ('completed', 'rejected')),
        literal('key_prefix', b'{"key":'), literal('key_tool', b',"tool":'),
        literal('cost_prefix', b'{"error":'), literal('null_literal', b'null'),
        literal('cost_suffix', b',"replayed":false}'),
        restore, canonical_program(), data_source(),
        decimal_program(), format_program(), hash_program(),
    ))


def document():
    nodes = ast.parse(source_program()).body
    if len({node.name for node in nodes}) != len(nodes):
        raise ValueError('duplicate composed HIA symbol')
    names = {node.name: 'f' + str(i) for i, node in enumerate(nodes)}
    signatures = {node.name: ([arg.annotation.id for arg in node.args.args], node.returns.id)
                  for node in nodes}
    total = total_scalar_functions(nodes)
    functions = []
    for node in nodes:
        builder = Builder(node, names, signatures, total)
        builder.statements(node.body)
        functions.append({'name': names[node.name],
                          'params': [builder.param(value) for value in builder.params],
                          'returns': [builder.returns], 'effects': ['read', 'write', 'trap'],
                          'entry': 'b0', 'blocks': builder.blocks})
    return compact_authoring_cfg({'schema': 'hepta.hia.program.v8',
                                  'module': 'agent_journal', 'functions': functions})


def main():
    path = Path(__file__).resolve().parents[1] / SOURCE_PATH
    path.write_text(render_assembly(document()))
    print(path.name, path.stat().st_size)


if __name__ == '__main__':
    main()
