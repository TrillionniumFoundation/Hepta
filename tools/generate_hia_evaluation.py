"""Author the complete original Agent evaluation control/effect order in HIA.

Opaque Agent objects, runner/Store operations, object protocols and binary64
true division remain explicitly named foreign primitives. Every evaluation
branch, loop, six-outcome precedence and effect permission is in this image.
The existing unbounded signed HIA integer kernel supplies deadline arithmetic.
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
from hepta.hia_evaluation_protocol import PORT, PORTS
from tools.generate_hia_selfhost import compact_authoring_cfg, total_scalar_functions
from tools.generate_hia_service_context import ContextBuilder
from tools.hia_service_context_arithmetic import source as arithmetic_source, REQUEST_MAGIC as MATH_MAGIC

REQUEST_MAGIC = int.from_bytes(b'HEVAREQ1', 'little')
RESULT_MAGIC = int.from_bytes(b'HEVARSP1', 'little')
STATE_MAGIC = int.from_bytes(b'HEVASTA1', 'little')
SOURCE_NAME = 'examples/hia_bootstrap/evaluation.hepta'

PREDICATES = {
    'baseline_not_shared', 'candidate_not_shared', 'abi_equal', 'baseline_pinned',
    'baseline_equal', 'exports_next', 'reference_returned', 'reference_complete',
    'reference_budget', 'reference_report_present', 'reference_rows_next',
    'reference_row_budget', 'case_next', 'case_expired', 'case_budget',
    'declared_present', 'declared_buffers', 'declared_without_next',
    'declared_key_buffers', 'declared_equal', 'observables_equal',
    'expected_trapped', 'normal_present', 'normal_cases_next', 'normal_returned',
    'normal_budget', 'normal_completed_differs', 'normal_observations_differ',
    'normal_observations_next', 'normal_mismatch', 'normal_value_equal',
    'trap_next', 'trap_has_buffers', 'trap_buffers_equal', 'trap_is_trapped',
    'trap_terminal_failure', 'trap_is_budget', 'complete_count',
    'complete_rows_next', 'complete_row_baseline', 'complete_row_candidate',
    'metric_artifact', 'before_nonzero', 'metric_latency', 'traps_present',
    'after_smaller', 'ratio_threshold', 'after_greater',
}

# State word 2: correct=1, complete=2, budget_exceeded=4. All writes to these
# policy flags occur in HIA. Python cannot supply an outcome or advance PC.
TRANSITIONS = {
    'baseline_not_shared': 'if observed == 1:\n    next_port = @reject_profile@',
    'candidate_not_shared': 'if observed == 1:\n    next_port = @reject_profile@',
    'abi_equal': 'if observed == 0:\n    next_port = @reject_abi@',
    'baseline_pinned': 'if observed == 0:\n    next_port = @claims@',
    'baseline_equal': 'if observed == 0:\n    next_port = @reject_baseline@',
    'exports_next': 'if observed == 0:\n    next_port = @exports_finish@',
    'exports_append': 'next_port = @exports_next@',
    'collections': 'set(w, 2, 3)',
    'reference_returned': '''if observed == 0:
    set(w, 2, get(w, 2) & 5)
    next_port = @reference_budget@''',
    'reference_complete': '''if observed == 1:
    return next_reference(o, w)
set(w, 2, get(w, 2) & 5)''',
    'reference_budget': '''if observed == 1:
    set(w, 2, get(w, 2) | 4)
    next_port = @cases_init@
else:
    set(w, 2, get(w, 2) & 3)''',
    'reference_report_present': '''if observed == 0:
    set(w, 2, get(w, 2) & 6)
    next_port = @cases_init@''',
    'reference_rows_next': '''if observed == 0:
    set(w, 2, get(w, 2) & 6)
    next_port = @cases_init@''',
    'reference_row_budget': '''if observed == 1:
    set(w, 2, get(w, 2) | 4)
    next_port = @cases_init@
else:
    next_port = @reference_rows_next@''',
    'cases_init': 'set(w, 8, 0)',
    'case_next': '''if observed == 0 or (get(w, 2) & 2) == 0:
    next_port = @reference_done@''',
    'case_expired': '''if observed == 1:
    set(w, 2, (get(w, 2) & 5) | 4)
    next_port = @reference_done@''',
    'case_budget': '''if observed == 1:
    set(w, 2, (get(w, 2) & 5) | 4)
    next_port = @reference_done@''',
    'declared_present': 'if observed == 0:\n    next_port = @observables_equal@',
    'declared_buffers': 'if observed == 0:\n    next_port = @declared_without_init@',
    'declared_with_buffers': 'next_port = @declared_equal@',
    'declared_without_next': 'if observed == 0:\n    next_port = @declared_equal@',
    'declared_key_buffers': 'if observed == 1:\n    next_port = @declared_without_next@',
    'declared_insert': 'next_port = @declared_without_next@',
    'declared_equal': 'if observed == 0:\n    next_port = @reject_expected@',
    'observables_equal': 'if observed == 0:\n    set(w, 2, get(w, 2) & 6)',
    'expected_trapped': 'if observed == 0:\n    next_port = @append_normal@',
    'append_trap': 'set(w, 8, get(w, 8) + 1)\nnext_port = @case_next@',
    'append_normal': 'set(w, 8, get(w, 8) + 1)\nnext_port = @case_next@',
    'claim': 'set(w, 9, 0)',
    'arm_init': 'if (get(w, 2) & 2) == 0:\n    return next_arm(o, w)',
    'normal_present': 'if observed == 0:\n    next_port = @traps_init@',
    'normal_cases_next': 'if observed == 0:\n    next_port = @normal_run@',
    'normal_cases_append': 'next_port = @normal_cases_next@',
    'normal_returned': '''if observed == 0:
    set(w, 2, get(w, 2) & 4)
else:
    next_port = @normal_report@''',
    'normal_budget': '''set_budget(w, observed)
return next_arm(o, w)''',
    'normal_completed_differs': 'if observed == 1:\n    next_port = @reject_report@',
    'normal_observations_differ': 'if observed == 1:\n    next_port = @reject_report@',
    'normal_observations_next': 'if observed == 0:\n    next_port = @traps_init@',
    'normal_mismatch': '''if observed == 1:
    set(w, 2, get(w, 2) & 6)
    next_port = @normal_observations_next@''',
    'normal_value_equal': '''if observed == 0:
    set(w, 2, get(w, 2) & 6)
next_port = @normal_observations_next@''',
    'trap_next': 'if observed == 0:\n    return next_arm(o, w)',
    'trap_has_buffers': 'if observed == 0:\n    next_port = @trap_is_trapped@',
    'trap_buffers_equal': 'if observed == 0:\n    set(w, 2, get(w, 2) & 6)',
    'trap_is_trapped': '''if observed == 1:
    next_port = @trap_next@
else:
    set(w, 2, get(w, 2) & 6)''',
    'trap_terminal_failure': '''if observed == 1:
    set(w, 2, get(w, 2) & 5)
else:
    next_port = @trap_next@''',
    'trap_is_budget': 'set_budget(w, observed)\nreturn next_arm(o, w)',
    'native_ns': 'if (get(w, 2) & 2) == 0:\n    next_port = @metric_artifact@',
    'complete_count': '''if observed == 0:
    set(w, 2, get(w, 2) & 5)
    next_port = @metric_artifact@''',
    'complete_rows_next': 'if observed == 0:\n    next_port = @metric_artifact@',
    'complete_row_baseline': '''if observed == 0:
    set(w, 2, get(w, 2) & 5)
    next_port = @metric_artifact@''',
    'complete_row_candidate': '''if observed == 0:
    set(w, 2, get(w, 2) & 5)
    next_port = @metric_artifact@
else:
    next_port = @complete_rows_next@''',
    'metric_artifact': 'if observed == 0:\n    next_port = @measure_native@',
    'measure_artifact': 'next_port = @before_nonzero@',
    'before_nonzero': 'if observed == 0:\n    next_port = @ratio_zero@',
    'ratio': 'return outcome_prefix(o, w)',
    'ratio_zero': 'return outcome_prefix(o, w)',
    'metric_latency': 'if observed == 0:\n    next_port = @after_smaller@',
    'traps_present': '''if observed == 1:
    return outcome(o, w, 3)''',
    'after_smaller': 'if observed == 0:\n    next_port = @after_greater@',
    'ratio_threshold': 'if observed == 1:\n    return outcome(o, w, 4)',
    'after_greater': '''if observed == 1:
    return outcome(o, w, 5)
return outcome(o, w, 6)''',
    'result': 'return advance(o, w, 0, 4)',
    'reject_profile': 'next_port = @abi_equal@',
    'reject_abi': 'next_port = @baseline_pinned@',
    'reject_baseline': 'next_port = @claims@',
    'reject_expected': 'next_port = @observables_equal@',
    'reject_report': 'next_port = @normal_total@',
}

PROTOCOL = r'''
def evaluation(s:readbuf, o:mutbuf, w:mutbuf) -> u32:
    if length(s) >= 8:
        if read_word(s, 0) == @MATH_MAGIC@:
            return context_math(s, o, w)
    if length(s) != 80 or length(o) != 112 or length(w) != 128:
        return 4294967293
    if read_word(s, 0) != @REQUEST_MAGIC@ or read_word(s, 40) != 0 or read_word(s, 64) != 0 or read_word(s, 72) != 0:
        return 4294967293
    event = read_word(s, 8)
    if event == 0:
        return initialize(s, o, w)
    if valid_state(w) == 0:
        return 4294967293
    if read_word(s, 16) != get(w, 4) or read_word(s, 24) != get(w, 3):
        return refuse(o, w)
    if read_word(s, 48) != get(w, 6) or read_word(s, 56) != get(w, 7):
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
        elif observed != 0:
            return refuse(o, w)
        return succeeded(o, w, observed)
    if event == 3:
        if get(w, 5) != 2 or read_word(s, 32) != 0:
            return refuse(o, w)
        set(w, 12, 1)
        return advance(o, w, 0, 5)
    return refuse(o, w)

def initialize(s:readbuf, o:mutbuf, w:mutbuf) -> u32:
    if read_word(s, 16) != 0 or read_word(s, 24) != 0 or read_word(s, 32) != 0:
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
    set(w, 2, 3)
    set(w, 3, @start@)
    set(w, 4, 1)
    set(w, 5, 1)
    set(w, 6, read_word(s, 48))
    set(w, 7, read_word(s, 56))
    seal(w)
    return answer(o, w, 0)

def next_reference(o:mutbuf, w:mutbuf) -> u32:
    if get(w, 9) == 0:
        set(w, 9, 1)
        return advance(o, w, @reference_run@, 1)
    return advance(o, w, @cases_init@, 1)

def next_arm(o:mutbuf, w:mutbuf) -> u32:
    if get(w, 9) == 0:
        set(w, 9, 1)
        return advance(o, w, @arm_init@, 1)
    return advance(o, w, @claim_complete@, 1)

def set_budget(w:mutbuf, observed:u64) -> u64:
    value = get(w, 2) & 3
    if observed == 1:
        value = value | 4
    set(w, 2, value)
    return value

def outcome_prefix(o:mutbuf, w:mutbuf) -> u32:
    flags = get(w, 2)
    if (flags & 4) != 0:
        return outcome(o, w, 1)
    if (flags & 1) == 0:
        return outcome(o, w, 2)
    if (flags & 2) == 0:
        return outcome(o, w, 3)
    return advance(o, w, @metric_latency@, 1)

def outcome(o:mutbuf, w:mutbuf, value:u64) -> u32:
    set(w, 11, value)
    return advance(o, w, @measurements@, 1)

def valid_state(w:mutbuf) -> u64:
    if get(w, 0) != @STATE_MAGIC@ or get(w, 1) != 1 or get(w, 2) > 7:
        return 0
    if get(w, 4) == 0 or get(w, 5) == 0 or get(w, 5) == 3 or get(w, 5) > 6:
        return 0
    if get(w, 9) > 1 or get(w, 11) > 6 or get(w, 12) > 1:
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
    set(o, 5, get(w, 8))
    set(o, 6, get(w, 9))
    set(o, 7, get(w, 2))
    set(o, 8, get(w, 11))
    set(o, 9, get(w, 12))
    set(o, 10, get(w, 6))
    set(o, 11, get(w, 7))
    set(o, 12, 0)
    set(o, 13, 0)
    return 112

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
    groups = [PORTS[index:index + 24] for index in range(0, len(PORTS), 24)]
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
    fragments.append(arithmetic_source())
    values = {**PORT, 'REQUEST_MAGIC': REQUEST_MAGIC, 'RESULT_MAGIC': RESULT_MAGIC,
              'STATE_MAGIC': STATE_MAGIC, 'MATH_MAGIC': MATH_MAGIC, 'MAX_PORT': len(PORTS)}
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
                                  'module': 'evaluation', 'functions': functions})


if __name__ == '__main__':
    path = ROOT / SOURCE_NAME
    path.write_text(render_assembly(document()))
    print(path.name, path.stat().st_size)
