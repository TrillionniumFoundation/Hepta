"""Author eight complete Store policies, argument continuations and cleanup.

Opaque objects, literal calls, filesystem, SQL, hashing and JSON are foreign
providers. All original Store branches and reference iteration belong to HIA.
The separate transaction context manager is outside this owner.
"""
from __future__ import annotations
import ast
from pathlib import Path
import re
import sys
import textwrap

ROOT = Path(__file__).resolve().parents[1]
if __package__ in (None, ''):
    sys.path.insert(0, str(ROOT))
from hepta.hia_agent_assembly import render_assembly
from hepta.hia_store_artifact_profile_protocol import PORT, PORTS, MODES, ARGUMENT_MODES
from tools.generate_hia_selfhost import compact_authoring_cfg, total_scalar_functions
from tools.generate_hia_service_context import ContextBuilder

REQUEST_MAGIC = int.from_bytes(b'HSAPRQ01', 'little')
RESULT_MAGIC = int.from_bytes(b'HSAPRS01', 'little')
STATE_MAGIC = int.from_bytes(b'HSAPST01', 'little')
SOURCE_NAME = 'examples/hia_bootstrap/store_artifact_profile.hepta'

# False/true successors are chosen by the generated HIA program.
CHOICES = {
    'put_data_not_bytes': ('put_data_limit_exceeded', 'reject_put_limit'),
    'put_data_limit_exceeded': ('put_metadata_is_none', 'reject_put_limit'),
    'put_metadata_is_none': ('put_admission', 'put_empty_metadata'),
    'put_admission_is_none': ('put_native_hash', 'put_native_hash_is_none'),
    'put_native_hash_is_none': ('put_native_content_hash', 'put_python_hash'),
    'put_previous_is_none': ('put_previous_ref', 'put_hash_is_none_for_write'),
    'put_hash_is_none_for_write': ('put_native_put', 'put_destination'),
    'put_native_receipt_differs': ('put_id_uuid', 'reject_put_native_corrupt'),
    'get_row_is_none': ('get_identity_ref', 'reject_get_identity'),
    'get_identity_differs': ('get_kind_is_none', 'reject_get_identity'),
    'get_kind_is_none': ('get_kind_differs', 'get_native'),
    'get_kind_differs': ('get_native', 'reject_get_kind'),
    'get_native_is_none': ('get_metadata', 'get_file_read'),
    'get_hash_differs': ('get_metadata', 'reject_get_corrupt'),
    'resolve_is_none': ('resolve_ref', 'reject_resolve'),
    'check_differs': ('check_find', 'reject_profile_stale'),
    'check_is_none': ('check_call_get_json', 'reject_profile_authority'),
}
JUMPS = {
    'put_native_content_hash': 'put_content_key',
    'put_context_lookup_enter': 'put_context_lookup_next',
    'put_context_lookup_exit': 'put_context_lookup_next',
    'reject_put_limit': 'put_metadata_is_none',
    'reject_put_native_corrupt': 'put_id_uuid',
    'reject_get_identity': 'get_kind_is_none',
    'reject_get_kind': 'get_native',
    'reject_get_corrupt': 'get_metadata',
    'reject_resolve': 'resolve_ref',
    'reject_profile_stale': 'check_find',
    'reject_profile_authority': 'check_call_get_json',
    'arg_wire_value': 'argument_result',
    'arg_temp_name': 'argument_result',
    'arg_stream_descriptor': 'argument_result',
    'arg_insert_tuple': 'argument_result',
    'arg_native_hash': 'argument_result',
    'arg_path_join': 'argument_result',
    'arg_profile_tuple': 'argument_result',
    'arg_reference_decode': 'argument_result',
}
RESULTS = ('put_previous_result', 'put_result', 'json_result', 'ref_result',
           'get_result', 'get_json_result', 'resolve_result', 'profile_result',
           'check_result', 'argument_result')
PREDICATES = set(CHOICES) | {'exception_is_file_exists', 'put_existing_differs', 'put_exit_truth'}
TRANSITIONS = {name: f'if observed == 0:\n    next_port = @{targets[0]}@\nelse:\n    next_port = @{targets[1]}@'
               for name, targets in CHOICES.items()}
TRANSITIONS.update({name: f'next_port = @{target}@' for name, target in JUMPS.items()})
TRANSITIONS.update({name: 'return advance(o, w, 0, 4)' for name in RESULTS})
TRANSITIONS.update({
    'put_open_temporary': 'set(w, 8, get(w, 8) | 1)',
    'put_context_lookup_next': '''if observed == 0:
    next_port = @put_enter@
elif observed == 1:
    next_port = @put_context_lookup_enter@
elif observed == 2:
    next_port = @put_context_lookup_exit@
else:
    return refuse(o, w)''',
    'put_enter': 'set(w, 8, get(w, 8) | 2)',
    'put_open_directory': 'set(w, 8, get(w, 8) | 4)',
    'ref_new': 'set(w, 11, 0)',
    'ref_set': '''set(w, 11, get(w, 11) + 1)
next_port = @ref_get@
if get(w, 11) == 3:
    next_port = @ref_result@''',
    'exception_is_file_exists': '''if observed == 0:
    return cleanup(o, w)
next_port = @put_existing_read@''',
    'put_existing_differs': '''if observed == 1:
    next_port = @reject_put_existing_corrupt@
else:
    set(w, 13, 0)
    return advance(o, w, @put_open_directory@, 7)''',
    'reject_put_existing_corrupt': '''set(w, 13, 0)
return advance(o, w, @put_open_directory@, 7)''',
    'put_exit_exception': 'next_port = @put_exit_truth@',
    'put_exit_truth': '''if observed == 0:
    return cleanup(o, w)
set(w, 13, 0)
return advance(o, w, @put_link@, 7)''',
    'error_cleanup_close': 'return cleanup(o, w)',
    'error_cleanup_unlink': 'return cleanup(o, w)',
    'argument_parent': '''mode = get(w, 2)
if mode == 9:
    next_port = @arg_wire_value@
elif mode == 10:
    next_port = @arg_temp_uuid@
elif mode == 11:
    next_port = @arg_stream_descriptor@
elif mode == 12:
    next_port = @arg_insert_id@
elif mode == 13:
    next_port = @arg_native_hash@
elif mode == 14:
    next_port = @arg_path_root@
elif mode == 15:
    next_port = @arg_profile_sha@
elif mode == 16:
    next_port = @arg_reference_decoder@
else:
    return refuse(o, w)''',
})

PROTOCOL = r'''
def store_artifact_profile(s:readbuf, o:mutbuf, w:mutbuf) -> u32:
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
    if event == 1:
        if (get(w, 5) != 1 and get(w, 5) != 7) or read_word(s, 32) != 0:
            return refuse(o, w)
        port = get(w, 3)
        if port == @put_exit_normal@ or port == @put_exit_exception@:
            set(w, 8, get(w, 8) & 18446744073709551613)
        elif port == @put_close_directory@ or port == @error_cleanup_close@:
            set(w, 8, get(w, 8) & 18446744073709551611)
        elif port == @put_unlink_temporary@ or port == @error_cleanup_unlink@:
            set(w, 8, get(w, 8) & 18446744073709551614)
        set(w, 5, 2)
        seal(w)
        return answer(o, w, 0)
    if event == 2:
        if get(w, 5) != 2:
            return refuse(o, w)
        observed = read_word(s, 32)
        port = get(w, 3)
        if is_predicate(port) == 1:
            if observed > 1:
                return refuse(o, w)
        elif port == @put_context_lookup_next@:
            if observed > 2:
                return refuse(o, w)
        else:
            if observed != 0:
                return refuse(o, w)
        return succeeded(o, w, observed)
    if event == 3:
        if get(w, 5) != 2 or read_word(s, 32) != 0:
            return refuse(o, w)
        set(w, 13, 1)
        if get(w, 3) == @put_link@:
            return advance(o, w, @exception_is_file_exists@, 1)
        return cleanup(o, w)
    return refuse(o, w)

def initialize(s:readbuf, o:mutbuf, w:mutbuf) -> u32:
    mode = read_word(s, 40)
    if mode < 1 or mode > 16 or read_word(s, 16) != 0 or read_word(s, 24) != 0 or read_word(s, 32) != 0:
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
    port = @argument_parent@
    if mode == 1:
        port = @put_arguments@
    elif mode == 2:
        port = @json_arguments@
    elif mode == 3:
        port = @ref_arguments@
    elif mode == 4:
        port = @get_arguments@
    elif mode == 5:
        port = @get_json_arguments@
    elif mode == 6:
        port = @resolve_arguments@
    elif mode == 7:
        port = @profile_arguments@
    elif mode == 8:
        port = @check_arguments@
    set(w, 3, port)
    set(w, 4, 1)
    set(w, 5, 1)
    set(w, 6, read_word(s, 48))
    set(w, 7, read_word(s, 56))
    seal(w)
    return answer(o, w, 0)

def cleanup(o:mutbuf, w:mutbuf) -> u32:
    if get(w, 13) != 1:
        return refuse(o, w)
    flags = get(w, 8)
    if (flags & 2) != 0:
        return advance(o, w, @put_exit_exception@, 1)
    if (flags & 4) != 0:
        return advance(o, w, @error_cleanup_close@, 1)
    if (flags & 1) != 0:
        return advance(o, w, @error_cleanup_unlink@, 1)
    set(w, 12, 1)
    return advance(o, w, 0, 5)

def valid_state(w:mutbuf) -> u64:
    if get(w, 0) != @STATE_MAGIC@ or get(w, 1) != 1 or get(w, 2) < 1 or get(w, 2) > 16:
        return 0
    if get(w, 4) == 0 or get(w, 5) == 0 or get(w, 5) == 3 or get(w, 5) > 7:
        return 0
    if get(w, 8) > 7 or get(w, 9) != 0 or get(w, 11) > 3 or get(w, 12) > 1 or get(w, 13) > 1:
        return 0
    if get(w, 14) != 0 or get(w, 15) != 0 or checksum(w) != get(w, 10):
        return 0
    phase = get(w, 5)
    port = get(w, 3)
    if phase == 1 or phase == 2 or phase == 7:
        if port == 0 or port > @MAX_PORT@ or get(w, 12) != 0:
            return 0
    elif port != 0:
        return 0
    if phase == 7 and get(w, 13) != 0:
        return 0
    if phase == 4 and (get(w, 8) != 0 or get(w, 12) != 0 or get(w, 13) != 0):
        return 0
    if phase == 5 and (get(w, 8) != 0 or get(w, 12) != 1 or get(w, 13) != 1):
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
    set(w, 5, 6)
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
    groups = [PORTS[index:index + 16] for index in range(0, len(PORTS), 16)]
    fragments = [PROTOCOL, 'def succeeded(o:mutbuf, w:mutbuf, observed:u64) -> u32:\n    port = get(w, 3)\n']
    for index, names in enumerate(groups):
        fragments.append(f'    if port <= {PORT[names[-1]]}:\n        return successor_{index}(o, w, observed)\n')
    fragments.append('    return refuse(o, w)\n\n')
    for index, names in enumerate(groups):
        fragments.append(f'def successor_{index}(o:mutbuf, w:mutbuf, observed:u64) -> u32:\n    port = get(w, 3)\n    next_port = port + 1\n')
        first = True
        for name in names:
            if name not in TRANSITIONS:
                continue
            fragments.append(f'    {"if" if first else "elif"} port == {PORT[name]}:\n')
            fragments.append(textwrap.indent(TRANSITIONS[name], '        ') + '\n')
            first = False
        fragments.append('    return advance(o, w, next_port, 1)\n\n')
    fragments.append('def is_predicate(port:u64) -> u64:\n')
    predicates = sorted(PORT[name] for name in PREDICATES)
    for index in range(0, len(predicates), 8):
        condition = ' or '.join(f'port == {value}' for value in predicates[index:index + 8])
        fragments.append('    if ' + condition + ':\n        return 1\n')
    fragments.append('    return 0\n\n')
    values = {**PORT, 'REQUEST_MAGIC': REQUEST_MAGIC, 'RESULT_MAGIC': RESULT_MAGIC,
              'STATE_MAGIC': STATE_MAGIC, 'MAX_PORT': len(PORTS)}
    return re.sub(r'@([A-Za-z_]+)@', lambda match: str(values[match[1]]), ''.join(fragments))


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
        functions.append({'name': names[node.name], 'params': [builder.param(value) for value in builder.params],
            'returns': [builder.returns], 'effects': ['read', 'write', 'trap'],
            'entry': 'b0', 'blocks': builder.blocks})
    return compact_authoring_cfg({'schema': 'hepta.hia.program.v8',
                                  'module': 'store_artifact_profile', 'functions': functions})


if __name__ == '__main__':
    path = ROOT / SOURCE_NAME
    path.write_text(render_assembly(document()))
    print(path.name, path.stat().st_size)
