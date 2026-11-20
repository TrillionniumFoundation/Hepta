"""Author complete compile and emission control, including exceptional exit.

Foreign effects keep their original object protocols and implementations.
HIA owns the composite policy branches, ordered loops and cleanup decisions.
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
from hepta.hia_emission_protocol import PORT, PORTS
from tools.generate_hia_selfhost import compact_authoring_cfg, total_scalar_functions
from tools.generate_hia_service_context import ContextBuilder

REQUEST_MAGIC = int.from_bytes(b'HEMIRQ01', 'little')
RESULT_MAGIC = int.from_bytes(b'HEMIRS01', 'little')
STATE_MAGIC = int.from_bytes(b'HEMIST01', 'little')
SOURCE_NAME = 'examples/hia_bootstrap/emission.hepta'
CHOICES = {
    'compile_budget_expired': ('compile_deadline', 'reject_budget'),
    'compile_object_not_bytes': ('compile_temporary', 'reject_object_bytes'),
    'compile_kind_object': ('compile_output_shared', 'compile_output_object'),
    'compile_remaining_positive': ('compile_timeout_zero', 'compile_timeout_remaining'),
    'compile_timeout_below_bound': ('compile_timeout_bound', 'compile_call'),
    'compile_object_digest_differs': ('compile_core_digest_differs', 'reject_build'),
    'compile_artifact_digest_differs': ('compile_final_kind_object', 'reject_build'),
    'compile_final_kind_object': ('compile_store_object', 'compile_final_bytes_differs'),
    'compile_final_bytes_differs': ('compile_store_object', 'reject_build'),
    'emit_receipt_next': ('emit_receipts_release', 'emit_verify_receipt'),
    'emit_canonical': ('emit_plan_profile', 'emit_lowering_profile'),
    'emit_subject_differs': ('emit_checks_init', 'reject_plan'),
    'emit_check_next': ('emit_checks_release_reject', 'emit_claim_compare'),
    'emit_claim_truth': ('emit_check_truth', 'emit_status_compare'),
    'emit_check_truth': ('emit_check_next', 'emit_checks_release_pass'),
    'emit_exports_next': ('emit_exports_finish', 'emit_exports_append'),
    'emit_exports_present': ('emit_compile_without_exports', 'emit_compile_with_exports'),
    'emit_export_lists_next': ('emit_export_lists_release', 'emit_export_lists_append'),
}
JUMPS = {
    'compile_context_lookup_enter': 'compile_context_lookup_next',
    'compile_context_lookup_exit': 'compile_context_lookup_next',
    'compile_output_object': 'compile_remaining',
    'compile_output_shared': 'compile_remaining',
    'compile_timeout_zero': 'compile_timeout_below_bound',
    'compile_timeout_remaining': 'compile_timeout_below_bound',
    'compile_exit_normal': 'compile_pop_output',
    'reject_budget': 'compile_deadline',
    'reject_object_bytes': 'compile_temporary',
    'reject_build': 'compile_store_object',
    'emit_verify_receipt': 'emit_receipt_next',
    'emit_lowering_profile': 'emit_exports_init',
    'reject_plan': 'emit_exports_init',
    'emit_checks_release_pass': 'emit_exports_init',
    'emit_checks_release_reject': 'reject_plan',
    'emit_exports_append': 'emit_exports_next',
    'emit_compile_with_exports': 'emit_metadata_prefix',
    'emit_export_lists_append': 'emit_export_lists_next',
}
PREDICATES = set(CHOICES) | {'compile_core_digest_differs', 'compile_exit_truth'}
TRANSITIONS = {name: f'if observed == 0:\n    next_port = @{targets[0]}@\nelse:\n    next_port = @{targets[1]}@'
               for name, targets in CHOICES.items()}
TRANSITIONS.update({name: f'next_port = @{target}@' for name, target in JUMPS.items()})
TRANSITIONS.update({
    'compile_context_lookup_next': '''if observed == 0:
    next_port = @compile_enter@
elif observed == 1:
    next_port = @compile_context_lookup_enter@
else:
    next_port = @compile_context_lookup_exit@''',
    'compile_enter': 'set(w, 9, 1)',
    'compile_call': 'set(w, 8, get(w, 8) | 1)',
    'compile_read': 'set(w, 8, get(w, 8) | 2)',
    'compile_exit_truth': '''if observed == 0:
    set(w, 12, 1)
    return advance(o, w, 0, 5)
set(w, 11, 0)
next_port = @compile_pop_output@
if (get(w, 8) & 1) == 0:
    next_port = @unbound_compile_result@
return advance(o, w, next_port, 7)''',
    'compile_core_digest_differs': '''if observed == 1:
    next_port = @reject_build@''',
    'compile_artifact_digest_value': '''if (get(w, 8) & 2) == 0:
    next_port = @unbound_compile_data@''',
    'compile_store_object': '''if (get(w, 8) & 2) == 0:
    next_port = @unbound_compile_data@''',
    'compile_result': 'return advance(o, w, 0, 4)',
    'emit_result': 'return advance(o, w, 0, 4)',
    'emit_checks_init': '''set(w, 13, observed)
next_port = @emit_check_next@
if observed != 0:
    next_port = @emit_checks_reiterate@''',
    'emit_checks_reiterate': '''if get(w, 13) == 0:
    return refuse(o, w)
set(w, 13, get(w, 13) - 1)
next_port = @emit_check_next@
if get(w, 13) != 0:
    next_port = @emit_checks_reiterate@''',
    'unbound_compile_result': 'return refuse(o, w)',
    'unbound_compile_data': 'return refuse(o, w)',
})

PROTOCOL = r'''
def emission(s:readbuf, o:mutbuf, w:mutbuf) -> u32:
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
        if get(w, 3) == @compile_exit_normal@:
            set(w, 9, 0)
        set(w, 5, 2)
        seal(w)
        return answer(o, w, 0)
    if event == 2:
        if get(w, 5) != 2:
            return refuse(o, w)
        observed = read_word(s, 32)
        if get(w, 3) != @emit_checks_init@:
            if get(w, 3) == @compile_context_lookup_next@:
                if observed > 2:
                    return refuse(o, w)
            elif is_predicate(get(w, 3)) == 1:
                if observed > 1:
                    return refuse(o, w)
            elif observed != 0:
                return refuse(o, w)
        return succeeded(o, w, observed)
    if event == 3:
        if get(w, 5) != 2 or read_word(s, 32) != 0:
            return refuse(o, w)
        if get(w, 9) == 1:
            set(w, 9, 0)
            set(w, 11, 1)
            return advance(o, w, @compile_exit_exception@, 1)
        set(w, 12, 1)
        return advance(o, w, 0, 5)
    return refuse(o, w)

def initialize(s:readbuf, o:mutbuf, w:mutbuf) -> u32:
    mode = read_word(s, 40)
    if mode < 1 or mode > 2 or read_word(s, 16) != 0 or read_word(s, 24) != 0 or read_word(s, 32) != 0:
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
    port = @compile_arguments@
    if mode == 2:
        port = @emit_arguments_profile@
    set(w, 3, port)
    set(w, 4, 1)
    set(w, 5, 1)
    set(w, 6, read_word(s, 48))
    set(w, 7, read_word(s, 56))
    seal(w)
    return answer(o, w, 0)

def valid_state(w:mutbuf) -> u64:
    if get(w, 0) != @STATE_MAGIC@ or get(w, 1) != 1 or get(w, 2) < 1 or get(w, 2) > 2:
        return 0
    if get(w, 4) == 0 or get(w, 5) == 0 or get(w, 5) == 3 or get(w, 5) > 7:
        return 0
    if get(w, 8) > 3 or get(w, 9) > 1 or get(w, 11) > 1 or get(w, 12) > 1:
        return 0
    if get(w, 14) != 0 or get(w, 15) != 0:
        return 0
    if checksum(w) != get(w, 10):
        return 0
    port = get(w, 3)
    if get(w, 5) == 1 or get(w, 5) == 2 or get(w, 5) == 7:
        if port == 0 or port > @MAX_PORT@:
            return 0
    elif port != 0:
        return 0
    if get(w, 5) == 7:
        if get(w, 9) != 0 or get(w, 11) != 0:
            return 0
        if port != @compile_pop_output@ and port != @unbound_compile_result@:
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
    set(o, 7, get(w, 8) | (get(w, 9) << 8) | (get(w, 11) << 16))
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
                                  'module': 'emission', 'functions': functions})


if __name__ == '__main__':
    path = ROOT / SOURCE_NAME
    path.write_text(render_assembly(document()))
    print(path.name, path.stat().st_size)
