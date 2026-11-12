"""Author versioned exception-note control for the experimental JSON graph.

The algorithm follows the retained CPython errors.c and exceptions.c bodies.
It never calls an overridable exception.add_note method.  HIA selects optional
__notes__ lookup, list creation/type rejection, attribute assignment, append,
individual reference release, and primary/secondary exception restoration.
Each numbered effect is one named raw CPython leaf, including the original
Unicode error-format primitive (and its user repr call when the format uses
%R).  This is neither a JSON serializer fallback nor a public selector.

Only source is defined here.  Header binding, raw transaction faults and
native trace equality remain unqualified until their controls actually run.
"""
from __future__ import annotations

import ast
from pathlib import Path


SYMBOLS = {
    'MAGIC': int.from_bytes(b'HCLINTE1', 'little'),
    'ABI': 0xfffffffd, 'STATE_BYTES': 1024,
    'PHASE': 8, 'SEQUENCE': 16, 'PENDING': 24,
    'REPLY_SEQUENCE': 32, 'REPLY_OPERATION': 40, 'REPLY_ERROR': 48,
    'OPERATION': 64, 'ARGUMENTS': 72, 'FINAL_STATUS': 112,
    'NOTE_KIND': 120, 'OBJECT': 128, 'KEY_OR_INDEX': 136,
    'NOTES_NAME': 144, 'TYPE_ERROR': 152, 'ANSWER': 160,
    'ORIGINAL_ERROR': 256, 'NOTE_POINTER': 264, 'NOTES_POINTER': 272,
    'FAILED': 280, 'MESSAGE': 512, 'WRONG_NOTES': 640,
}
LITERALS = {
    'object': b'when serializing %T object\0',
    'index': b'when serializing %T item %zd\0',
    'key': b'when serializing %T item %R\0',
    'wrong_notes': b'Cannot add note: __notes__ is not a list\0',
}


SOURCE = r'''
def cli_json_note(s:readbuf, o:mutbuf, w:mutbuf) -> u32:
    if length(w) != STATE_BYTES or get(w, 0) != MAGIC:
        return ABI
    if get(w, FINAL_STATUS) != 0:
        return ABI
    if get(w, PENDING) != 0:
        if get(w, REPLY_SEQUENCE) != get(w, SEQUENCE) or get(w, REPLY_OPERATION) != get(w, OPERATION):
            return ABI
        put(w, PENDING, 0)
    elif get(w, PHASE) != 0:
        return ABI
    while True:
        phase = get(w, PHASE)
        if phase < 20:
            status = note_body(w, phase)
        elif phase < 100:
            status = note_cleanup(w, phase)
        else:
            status = note_restore(w, phase)
        if status != 4:
            return status
    return ABI

def note_body(w:mutbuf, phase:u64) -> u64:
    if phase == 0:
        if get(w, NOTE_KIND) > 2 or get(w, OBJECT) == 0 or get(w, NOTES_NAME) == 0 or get(w, TYPE_ERROR) == 0:
            return ABI
        return request(w, 16, 0, 0, 0, 0, 1)
    if phase == 1:
        profile = answer(w, 0)
        if profile == 31214:
            # The original Python _make_iterencode has no C error-note step.
            return finish(w)
        if profile != 31404 and profile != 31410:
            return ABI
        return request(w, 42, 0, 0, 0, 0, 2)
    if phase == 2:
        original = answer(w, 0)
        if original == 0:
            return finish(w)
        put(w, ORIGINAL_ERROR, original)
        kind = get(w, NOTE_KIND)
        if kind == 0:
            object_message(w)
            return request(w, 47, MESSAGE, get(w, OBJECT), 0, 0, 3)
        if kind == 1:
            index_message(w)
            return request(w, 48, MESSAGE, get(w, OBJECT), get(w, KEY_OR_INDEX), 0, 3)
        key_message(w)
        return request(w, 49, MESSAGE, get(w, OBJECT), get(w, KEY_OR_INDEX), 0, 3)
    if phase == 3:
        if answer(w, 0) == 0:
            put(w, PHASE, 100)
            return 4
        return request(w, 44, 2, 0, 0, 0, 4)
    if phase == 4:
        put(w, NOTE_POINTER, answer(w, 0))
        return request(w, 50, get(w, ORIGINAL_ERROR), get(w, NOTES_NAME), 0, 0, 5)
    if phase == 5:
        if get(w, REPLY_ERROR) != 0:
            put(w, PHASE, 90)
            return 4
        if answer(w, 0) == 0:
            return request(w, 51, 0, 0, 0, 0, 6)
        if answer(w, 0) != 1:
            return ABI
        return request(w, 44, 3, 0, 0, 0, 7)
    if phase == 6:
        if answer(w, 0) == 0:
            put(w, PHASE, 90)
            return 4
        return request(w, 44, 3, 0, 0, 0, 8)
    if phase == 7:
        put(w, NOTES_POINTER, answer(w, 0))
        return request(w, 46, 3, 0, 0, 0, 9)
    if phase == 8:
        put(w, NOTES_POINTER, answer(w, 0))
        return request(w, 52, get(w, ORIGINAL_ERROR), get(w, NOTES_NAME), get(w, NOTES_POINTER), 0, 10)
    if phase == 9:
        if answer(w, 1) == 0:
            return request(w, 45, 3, 0, 0, 0, 11)
        put(w, PHASE, 12)
        return 4
    if phase == 10:
        if answer(w, 0) != 0:
            return request(w, 45, 3, 0, 0, 0, 91)
        put(w, PHASE, 12)
        return 4
    if phase == 11:
        wrong_notes_message(w)
        # The original decrefs the wrong-type notes object before SetString.
        return request(w, 10, get(w, TYPE_ERROR), WRONG_NOTES, WRONG_NOTES_LENGTH, 0, 90)
    if phase == 12:
        return request(w, 53, get(w, NOTES_POINTER), get(w, NOTE_POINTER), 0, 0, 13)
    if phase == 13:
        put(w, FAILED, choose(answer(w, 0) != 0, 1, 0))
        return request(w, 45, 3, 0, 0, 0, 14)
    if phase == 14:
        return request(w, 45, 2, 0, 0, 0, 15)
    if phase == 15:
        # Match the saved BaseException_add_note return, not a fresh pending
        # error test after DECREF(note). Successful original code unconditionally
        # restores its original raised exception at this point.
        if get(w, FAILED) == 0:
            return request(w, 43, 0, 0, 0, 0, 200)
        put(w, PHASE, 100)
        return 4
    return ABI

def note_cleanup(w:mutbuf, phase:u64) -> u64:
    if phase == 90 or phase == 91:
        return request(w, 45, 2, 0, 0, 0, 100)
    return ABI

def note_restore(w:mutbuf, phase:u64) -> u64:
    if phase == 100:
        return request(w, 42, 1, 0, 0, 0, 101)
    if phase == 101:
        if answer(w, 0) == 0:
            return request(w, 43, 0, 0, 0, 0, 200)
        # _PyErr_ChainExceptions1 consumes the original error as the new
        # error's context, then restores the new pending error. Ambient handled
        # exception state is untouched throughout these individual leaves.
        return request(w, 54, 1, 0, 0, 0, 102)
    if phase == 102:
        return request(w, 43, 1, 0, 0, 0, 200)
    if phase == 200:
        return finish(w)
    return ABI

def request(w:mutbuf, operation:u64, a:u64, b:u64, c:u64, d:u64, phase:u64) -> u64:
    if get(w, PENDING) != 0 or get(w, SEQUENCE) == 18446744073709551615:
        return ABI
    put(w, SEQUENCE, get(w, SEQUENCE) + 1)
    put(w, OPERATION, operation)
    put(w, ARGUMENTS, a)
    put(w, ARGUMENTS + 8, b)
    put(w, ARGUMENTS + 16, c)
    put(w, ARGUMENTS + 24, d)
    put(w, PHASE, phase)
    put(w, PENDING, 1)
    return 2

def finish(w:mutbuf) -> u64:
    put(w, FINAL_STATUS, 1)
    return 0

def answer(w:mutbuf, index:u64) -> u64:
    return get(w, ANSWER + index * 8)

def get(w:mutbuf, at:u64) -> u64:
    value = 0
    index = 0
    while index < 8:
        value = value | (byte(w, at + index) << (index * 8))
        index = index + 1
    return value

def put(w:mutbuf, at:u64, value:u64) -> u64:
    index = 0
    while index < 8:
        store(w, at + index, (value >> (index * 8)) & 255)
        index = index + 1
    return 0
'''


def source_program():
    additions = dict(SYMBOLS)
    additions['WRONG_NOTES_LENGTH'] = len(LITERALS['wrong_notes'])
    literal_functions = []
    for name, raw in LITERALS.items():
        offset = SYMBOLS['WRONG_NOTES'] if name == 'wrong_notes' else SYMBOLS['MESSAGE']
        padded = raw + bytes((-len(raw)) % 8)
        statements = [f'    put(w, {offset + start}, {int.from_bytes(padded[start:start + 8], "little")})'
                      for start in range(0, len(padded), 8)]
        literal_functions += [f'def {name}_message(w:mutbuf) -> u64:', *statements, '    return 0', '']

    class Constants(ast.NodeTransformer):
        def visit_Name(self, node):
            if node.id in additions:
                return ast.copy_location(ast.Constant(additions[node.id]), node)
            return node

    tree = ast.parse(SOURCE + '\n' + '\n'.join(literal_functions))
    return ast.unparse(ast.fix_missing_locations(Constants().visit(tree))) + '\n'


def document():
    from tools.generate_hia_selfhost import Builder, compact_authoring_cfg, total_scalar_functions
    nodes = ast.parse(source_program()).body
    names = {node.name: 'f' + str(index) for index, node in enumerate(nodes)}
    signatures = {node.name: ([arg.annotation.id for arg in node.args.args], node.returns.id)
                  for node in nodes}
    total = total_scalar_functions(nodes)
    functions = []
    for node in nodes:
        builder = Builder(node, names, signatures, total)
        builder.statements(node.body)
        functions.append({'name': names[node.name], 'params': [builder.param(p) for p in builder.params],
                          'returns': [builder.returns], 'effects': ['read', 'write', 'trap'],
                          'entry': 'b0', 'blocks': builder.blocks})
    return compact_authoring_cfg({'schema': 'hepta.hia.program.v8',
                                  'module': 'cli_json_exception_note', 'functions': functions})


if __name__ == '__main__':
    import argparse
    from hepta.hia_agent_assembly import render_assembly
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--output', type=Path, required=True)
    args = parser.parse_args()
    with args.output.open('x') as stream:
        stream.write(render_assembly(document()))
