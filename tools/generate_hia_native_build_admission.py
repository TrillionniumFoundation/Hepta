"""Author four complete original signature/native/build admission owners.

Only opaque object protocols and existing Core, ABI, Store and hash effects
remain hosted. Every original short circuit and iteration belongs to HIA.
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
from hepta.hia_native_build_admission_protocol import PORT, PORTS
from tools.generate_hia_selfhost import compact_authoring_cfg, total_scalar_functions
from tools.generate_hia_service_context import ContextBuilder

REQUEST_MAGIC = int.from_bytes(b'HNBARQ01', 'little')
RESULT_MAGIC = int.from_bytes(b'HNBARS01', 'little')
STATE_MAGIC = int.from_bytes(b'HNBAST01', 'little')
SOURCE_NAME = 'examples/hia_bootstrap/native_build_admission.hepta'
FALSE_TARGETS = {
    'signature_fn_next': 'signature_scalar_release',
    'signature_fn_entry': 'signature_fn_next',
    'signature_param_next': 'signature_param_release_pass',
    'signature_returns_next': 'signature_returns_release_pass',
    'signature_params_next': 'signature_params_release',
    'signature_export_fn_next': 'signature_export_loop_release',
    'signature_export_contains': 'signature_export_fn_next',
    'signature_export_params_next': 'signature_export_params_release',
    'native_context_present': 'native_program',
    'native_exports_next': 'native_exports_finish',
    'native_exports_list_next': 'native_exports_differs',
    'build_metadata_next': 'build_metadata_release_pass',
    'build_output_is_object': 'build_result',
}
TRUE_TARGETS = {
    'native_installation_differs': 'reject_native_subject',
    'native_context_differs': 'reject_native_subject',
    'native_signatures_differs': 'reject_native_identity',
    'native_exports_differs': 'reject_native_identity',
    'build_context_differs': 'reject_build_subject',
    'build_artifact_differs': 'reject_build_subject',
    'build_installation_differs': 'reject_build_subject',
    'build_target_differs': 'reject_build_subject',
    'build_built_not_dict': 'reject_build_bytes',
    'build_object_ref_not_dict': 'reject_build_bytes',
    'build_object_ref_differs': 'reject_build_bytes',
    'build_object_sha_differs': 'reject_build_bytes',
    'build_core_sha_differs': 'reject_build_bytes',
    'build_input_sha_differs': 'reject_build_bytes',
    'build_implementation_differs': 'reject_build_bytes',
    'build_kind_differs': 'reject_build_bytes',
    'build_exports_differs': 'reject_build_bytes',
    'build_final_sha_differs': 'reject_build_bytes',
    'build_object_metadata_differs': 'reject_object',
    'build_object_bytes_sha_differs': 'reject_object',
    'build_ref_object_sha_differs': 'reject_object',
    'build_object_bytes_differs': 'reject_object',
}
CHOICES = {
    'signature_param_allowed': ('signature_param_release_skip', 'signature_param_next'),
    'signature_return_allowed': ('signature_returns_release_skip', 'signature_returns_next'),
    'native_core_differs': ('dispatch_signatures_lookup', 'reject_native_identity'),
    'build_backend_differs': ('dispatch_native_call', 'reject_build_subject'),
    'build_metadata_truth': ('build_metadata_next', 'build_metadata_release_reject'),
    'dispatch_signatures_lookup': ('dispatch_signatures_call', 'signature_imports'),
}
JUMPS = {
    'signature_params_append': 'signature_params_next',
    'signature_scalar_publish': 'signature_fn_next',
    'signature_export_params_append': 'signature_export_params_next',
    'signature_export_publish': 'signature_export_fn_next',
    'native_exports_append': 'native_exports_next',
    'native_exports_list_append': 'native_exports_list_next',
    # A returning test reject keeps the original continuation after the if.
    'reject_native_subject': 'native_program',
    'reject_native_identity': 'native_result',
    'reject_build_subject': 'dispatch_native_call',
    'reject_metadata': 'build_built',
    'reject_build_bytes': 'build_object_get',
    'reject_object': 'build_result',
    'dispatch_native_call': 'build_metadata_init',
    'dispatch_build_inputs_call': 'receipt_result',
    'dispatch_signatures_call': 'native_signatures_differs',
    'signature_scalar_release': 'signature_normalize',
    'signature_param_release_pass': 'signature_return_length',
    'signature_param_release_skip': 'signature_fn_next',
    'signature_returns_release_pass': 'signature_capture_name',
    'signature_returns_release_skip': 'signature_fn_next',
    'signature_params_release': 'signature_scalar_publish',
    'signature_export_loop_release': 'signature_result',
    'signature_export_params_release': 'signature_export_publish',
    'build_metadata_release_pass': 'build_built',
    'build_metadata_release_reject': 'reject_metadata',
}
REITERATIONS = {
    'signature_scalar_init': ('signature_scalar_reiterate', 'signature_fn_next'),
    'signature_param_init': ('signature_param_reiterate', 'signature_param_next'),
    'signature_returns_init': ('signature_returns_reiterate', 'signature_returns_next'),
    'signature_params_init': ('signature_params_reiterate', 'signature_params_next'),
    'signature_export_params_init': ('signature_export_params_reiterate', 'signature_export_params_next'),
    'build_metadata_init': ('build_metadata_reiterate', 'build_metadata_next'),
}
PREDICATES = set(FALSE_TARGETS) | set(TRUE_TARGETS) | set(CHOICES)
TRANSITIONS = {name: f'if observed == 0:\n    next_port = @{target}@'
               for name, target in FALSE_TARGETS.items()}
TRANSITIONS.update({name: f'if observed == 1:\n    next_port = @{target}@'
                    for name, target in TRUE_TARGETS.items()})
TRANSITIONS.update({name: f'if observed == 0:\n    next_port = @{targets[0]}@\nelse:\n    next_port = @{targets[1]}@'
                    for name, targets in CHOICES.items()})
TRANSITIONS.update({name: f'next_port = @{target}@' for name, target in JUMPS.items()})
for initial, (repeated, following) in REITERATIONS.items():
    TRANSITIONS[initial] = f'''set(w, 8, observed)
set(w, 9, observed)
next_port = @{following}@
if get(w, 9) != 0:
    next_port = @{repeated}@'''
    TRANSITIONS[repeated] = f'''if get(w, 9) == 0:
    return refuse(o, w)
set(w, 9, get(w, 9) - 1)
next_port = @{following}@
if get(w, 9) != 0:
    next_port = @{repeated}@'''
TRANSITIONS.update({
    'args_build': 'if get(w, 2) == 4:\n    next_port = @dispatch_build_inputs_call@',
    'signature_return_length': 'if observed > 1:\n    next_port = @signature_fn_next@',
    'signature_result': 'if get(w, 2) == 1:\n    return advance(o, w, 0, 4)\nnext_port = @native_signatures_differs@',
    'native_result': 'if get(w, 2) == 2:\n    return advance(o, w, 0, 4)\nnext_port = @build_metadata_init@',
    'build_result': 'if get(w, 2) == 3:\n    return advance(o, w, 0, 4)',
    'receipt_result': 'return advance(o, w, 0, 4)',
})

PROTOCOL = r'''
def admission(s:readbuf, o:mutbuf, w:mutbuf) -> u32:
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
        if get(w, 5) != 1 or read_word(s, 32) != 0:
            return refuse(o, w)
        set(w, 5, 2)
        seal(w)
        return answer(o, w, 0)
    if event == 2:
        if get(w, 5) != 2:
            return refuse(o, w)
        observed = read_word(s, 32)
        if is_predicate(get(w, 3)) == 1:
            if observed > 1:
                return refuse(o, w)
        elif is_counted_observation(get(w, 3)) == 0:
            if observed != 0:
                return refuse(o, w)
        return succeeded(o, w, observed)
    if event == 3:
        if get(w, 5) != 2 or read_word(s, 32) != 0:
            return refuse(o, w)
        set(w, 12, 1)
        return advance(o, w, 0, 5)
    return refuse(o, w)

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
    port = @args_build@
    if mode == 1:
        port = @args_signatures@
    elif mode == 2:
        port = @args_native@
    set(w, 3, port)
    set(w, 4, 1)
    set(w, 5, 1)
    set(w, 6, read_word(s, 48))
    set(w, 7, read_word(s, 56))
    seal(w)
    return answer(o, w, 0)

def valid_state(w:mutbuf) -> u64:
    if get(w, 0) != @STATE_MAGIC@ or get(w, 1) != 1 or get(w, 2) < 1 or get(w, 2) > 4:
        return 0
    if get(w, 4) == 0 or get(w, 5) == 0 or get(w, 5) == 3 or get(w, 5) > 6:
        return 0
    if get(w, 9) > get(w, 8) or get(w, 11) != 0 or get(w, 12) > 1:
        return 0
    if get(w, 13) != 0 or get(w, 14) != 0 or get(w, 15) != 0:
        return 0
    if checksum(w) != get(w, 10):
        return 0
    port = get(w, 3)
    if get(w, 5) == 1 or get(w, 5) == 2:
        if port == 0 or port > @MAX_PORT@:
            return 0
    elif port != 0:
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
    return put_word(w, index * 8, value)

def put_word(w:mutbuf, index:u64, value:u64) -> u64:
    i = 0
    while i < 8:
        store(w, index + i, value >> (i * 8))
        i = i + 1
    return value
'''


def source_program():
    groups = [PORTS[index:index + 20] for index in range(0, len(PORTS), 20)]
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
    counted = sorted(PORT[name] for name in (*REITERATIONS, 'signature_return_length'))
    fragments.append('def is_counted_observation(port:u64) -> u64:\n')
    fragments.append('    if ' + ' or '.join(f'port == {value}' for value in counted) + ':\n        return 1\n')
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
                                  'module': 'native_build_admission', 'functions': functions})


if __name__ == '__main__':
    path = ROOT / SOURCE_NAME
    path.write_text(render_assembly(document()))
    print(path.name, path.stat().st_size)
