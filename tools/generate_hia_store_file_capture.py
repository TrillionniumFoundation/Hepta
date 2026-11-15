"""Author all stable_read/capture_path control, including exact error cleanup.

This file is an authoring source. No generated .hepta or runtime evidence is
included in the static package. It never invokes a retained whole handler.
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
from hepta.hia_store_file_capture_protocol import PORT, PORTS, REQUEST_MAGIC, RESULT_MAGIC, STATE_MAGIC, SOURCE_NAME
from tools.generate_hia_selfhost import compact_authoring_cfg, total_scalar_functions
from tools.generate_hia_service_context import ContextBuilder

FLOW = [
  {
    "name": "stable_flags",
    "normal": "stable_open",
    "failure": "throw",
    "max": 0
  },
  {
    "name": "stable_open",
    "normal": "stable_fdopen",
    "failure": "stable_match_oserror",
    "max": 0
  },
  {
    "name": "stable_fdopen",
    "normal": "stable_cm_prepare",
    "failure": "stable_match_oserror",
    "max": 0
  },
  {
    "name": "stable_cm_prepare",
    "normal": "stable_cm_next",
    "failure": "stable_cm_unwind",
    "max": 0
  },
  {
    "name": "stable_cm_next",
    "normal": [
      "stable_enter",
      "stable_lookup_enter",
      "stable_lookup_exit"
    ],
    "failure": "stable_cm_unwind",
    "max": 2
  },
  {
    "name": "stable_lookup_enter",
    "normal": "stable_cm_next",
    "failure": "stable_cm_unwind",
    "max": 0
  },
  {
    "name": "stable_lookup_exit",
    "normal": "stable_cm_next",
    "failure": "stable_cm_unwind",
    "max": 0
  },
  {
    "name": "stable_enter",
    "normal": "stable_before",
    "failure": "stable_enter_unwind",
    "max": 0
  },
  {
    "name": "stable_before",
    "normal": "stable_not_regular",
    "failure": "stable_exit_error",
    "max": 0
  },
  {
    "name": "stable_not_regular",
    "normal": [
      "stable_too_large",
      "stable_reject_file"
    ],
    "failure": "stable_exit_error",
    "max": 1
  },
  {
    "name": "stable_too_large",
    "normal": [
      "stable_read",
      "stable_reject_file"
    ],
    "failure": "stable_exit_error",
    "max": 1
  },
  {
    "name": "stable_reject_file",
    "normal": "stable_read",
    "failure": "stable_exit_error",
    "max": 0
  },
  {
    "name": "stable_read",
    "normal": "stable_after",
    "failure": "stable_exit_error",
    "max": 0
  },
  {
    "name": "stable_after",
    "normal": "stable_identity",
    "failure": "stable_exit_error",
    "max": 0
  },
  {
    "name": "stable_identity",
    "normal": "stable_size_differs",
    "failure": "stable_exit_error",
    "max": 0
  },
  {
    "name": "stable_size_differs",
    "normal": [
      "stable_identity_differs",
      "stable_reject_changed"
    ],
    "failure": "stable_exit_error",
    "max": 1
  },
  {
    "name": "stable_identity_differs",
    "normal": [
      "stable_result",
      "stable_reject_changed"
    ],
    "failure": "stable_exit_error",
    "max": 1
  },
  {
    "name": "stable_reject_changed",
    "normal": "stable_result",
    "failure": "stable_exit_error",
    "max": 0
  },
  {
    "name": "stable_result",
    "normal": "stable_exit_normal",
    "failure": "stable_exit_error",
    "max": 0
  },
  {
    "name": "stable_exit_normal",
    "normal": "stable_release_locals",
    "failure": "stable_cancel_return",
    "max": 0
  },
  {
    "name": "stable_exit_error",
    "normal": "stable_exit_truth",
    "failure": "stable_enter_unwind",
    "max": 0
  },
  {
    "name": "stable_exit_truth",
    "normal": [
      "stable_enter_unwind",
      "resume:stable_suppressed_result"
    ],
    "failure": "stable_enter_unwind",
    "max": 1
  },
  {
    "name": "stable_suppressed_result",
    "normal": "stable_release_locals",
    "failure": "throw",
    "max": 0
  },
  {
    "name": "stable_cancel_return",
    "normal": "stable_match_oserror",
    "failure": "throw",
    "max": 0
  },
  {
    "name": "stable_cm_unwind",
    "normal": "stable_match_oserror",
    "failure": "throw",
    "max": 0
  },
  {
    "name": "stable_enter_unwind",
    "normal": "stable_match_oserror",
    "failure": "throw",
    "max": 0
  },
  {
    "name": "stable_match_oserror",
    "normal": [
      "throw",
      "stable_bind_exception"
    ],
    "failure": "throw",
    "max": 1
  },
  {
    "name": "stable_bind_exception",
    "normal": "stable_wrap_oserror",
    "failure": "throw",
    "max": 0
  },
  {
    "name": "stable_wrap_oserror",
    "normal": "stable_clear_exception",
    "failure": "stable_clear_exception",
    "max": 0
  },
  {
    "name": "stable_clear_exception",
    "normal": "throw",
    "failure": "throw",
    "max": 0
  },
  {
    "name": "stable_release_locals",
    "normal": "return",
    "failure": "throw",
    "max": 0
  },
  {
    "name": "capture_not_string",
    "normal": [
      "capture_not_absolute",
      "capture_reject_absolute"
    ],
    "failure": "throw",
    "max": 1
  },
  {
    "name": "capture_not_absolute",
    "normal": [
      "capture_parts",
      "capture_reject_absolute"
    ],
    "failure": "throw",
    "max": 1
  },
  {
    "name": "capture_reject_absolute",
    "normal": "capture_parts",
    "failure": "throw",
    "max": 0
  },
  {
    "name": "capture_parts",
    "normal": "capture_parent_component",
    "failure": "throw",
    "max": 0
  },
  {
    "name": "capture_parent_component",
    "normal": [
      "capture_dot_component",
      "capture_reject_traversal"
    ],
    "failure": "throw",
    "max": 1
  },
  {
    "name": "capture_dot_component",
    "normal": [
      "capture_nul",
      "capture_reject_traversal"
    ],
    "failure": "throw",
    "max": 1
  },
  {
    "name": "capture_nul",
    "normal": [
      "capture_lexical",
      "capture_reject_traversal"
    ],
    "failure": "throw",
    "max": 1
  },
  {
    "name": "capture_reject_traversal",
    "normal": "capture_lexical",
    "failure": "throw",
    "max": 0
  },
  {
    "name": "capture_lexical",
    "normal": "capture_chosen_none",
    "failure": "throw",
    "max": 0
  },
  {
    "name": "capture_chosen_none",
    "normal": "capture_roots_iter",
    "failure": "throw",
    "max": 0
  },
  {
    "name": "capture_roots_iter",
    "normal": "capture_roots_next",
    "failure": "capture_search_unwind",
    "max": 0
  },
  {
    "name": "capture_roots_next",
    "normal": [
      "capture_no_chosen",
      "capture_relative"
    ],
    "failure": "capture_search_unwind",
    "max": 1
  },
  {
    "name": "capture_relative",
    "normal": "capture_relative_truth",
    "failure": "capture_match_valueerror",
    "max": 0
  },
  {
    "name": "capture_match_valueerror",
    "normal": [
      "capture_search_unwind",
      "resume:capture_roots_next"
    ],
    "failure": "capture_search_unwind",
    "max": 1
  },
  {
    "name": "capture_relative_truth",
    "normal": [
      "capture_roots_next",
      "capture_choose"
    ],
    "failure": "capture_search_unwind",
    "max": 1
  },
  {
    "name": "capture_choose",
    "normal": "capture_roots_release",
    "failure": "capture_search_unwind",
    "max": 0
  },
  {
    "name": "capture_roots_release",
    "normal": "capture_no_chosen",
    "failure": "throw",
    "max": 0
  },
  {
    "name": "capture_search_unwind",
    "normal": "throw",
    "failure": "throw",
    "max": 0
  },
  {
    "name": "capture_no_chosen",
    "normal": [
      "capture_unpack",
      "capture_reject_authority"
    ],
    "failure": "throw",
    "max": 1
  },
  {
    "name": "capture_reject_authority",
    "normal": "capture_unpack",
    "failure": "throw",
    "max": 0
  },
  {
    "name": "capture_unpack",
    "normal": "capture_descriptors",
    "failure": "throw",
    "max": 0
  },
  {
    "name": "capture_descriptors",
    "normal": "capture_open_root",
    "failure": "throw",
    "max": 0
  },
  {
    "name": "capture_open_root",
    "normal": "capture_append_root",
    "failure": "capture_body_unwind",
    "max": 0
  },
  {
    "name": "capture_append_root",
    "normal": "capture_components_iter",
    "failure": "capture_body_unwind",
    "max": 0
  },
  {
    "name": "capture_components_iter",
    "normal": "capture_components_next",
    "failure": "capture_body_unwind",
    "max": 0
  },
  {
    "name": "capture_components_next",
    "normal": [
      "capture_read",
      "capture_open_component"
    ],
    "failure": "capture_body_unwind",
    "max": 1
  },
  {
    "name": "capture_open_component",
    "normal": "capture_append_component",
    "failure": "capture_body_unwind",
    "max": 0
  },
  {
    "name": "capture_append_component",
    "normal": "capture_components_next",
    "failure": "capture_body_unwind",
    "max": 0
  },
  {
    "name": "capture_read",
    "normal": "capture_cleanup_iter",
    "failure": "capture_body_unwind",
    "max": 0
  },
  {
    "name": "capture_body_unwind",
    "normal": "capture_match_oserror",
    "failure": "capture_cleanup_iter",
    "max": 0
  },
  {
    "name": "capture_match_oserror",
    "normal": [
      "capture_cleanup_iter",
      "capture_bind_exception"
    ],
    "failure": "capture_cleanup_iter",
    "max": 1
  },
  {
    "name": "capture_bind_exception",
    "normal": "capture_wrap_oserror",
    "failure": "capture_cleanup_iter",
    "max": 0
  },
  {
    "name": "capture_wrap_oserror",
    "normal": "capture_clear_exception",
    "failure": "capture_clear_exception",
    "max": 0
  },
  {
    "name": "capture_clear_exception",
    "normal": "capture_cleanup_iter",
    "failure": "capture_cleanup_iter",
    "max": 0
  },
  {
    "name": "capture_cleanup_iter",
    "normal": "capture_cleanup_next",
    "failure": "capture_cancel_return",
    "max": 0
  },
  {
    "name": "capture_cleanup_next",
    "normal": [
      "capture-finish",
      "capture_close"
    ],
    "failure": "capture_cancel_return",
    "max": 1
  },
  {
    "name": "capture_close",
    "normal": "capture_cleanup_next",
    "failure": "capture_cleanup_unwind",
    "max": 0
  },
  {
    "name": "capture_cleanup_unwind",
    "normal": "capture_cancel_return",
    "failure": "capture_cancel_return",
    "max": 0
  },
  {
    "name": "capture_cancel_return",
    "normal": "throw",
    "failure": "throw",
    "max": 0
  },
  {
    "name": "capture_release_locals",
    "normal": "return",
    "failure": "throw",
    "max": 0
  }
]

PROTOCOL = r'''
def store_file_capture(s:readbuf, o:mutbuf, w:mutbuf) -> u32:
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
    if event == 1:
        if phase != 1 or observed != 0:
            return refuse(o, w)
        set(w, 5, 2)
        seal(w)
        return answer(o, w, 0)
    if event == 2:
        if phase != 2:
            return refuse(o, w)
        return succeeded(o, w, observed)
    if event == 3:
        if phase != 2 or observed != 0:
            return refuse(o, w)
        set(w, 12, 1)
        return raised(o, w)
    if event == 4:
        if observed != 0 or get(w, 3) != 0 or get(w, 8) != 0:
            return refuse(o, w)
        if phase == 3 and get(w, 12) == 0:
            return advance(o, w, 0, 4)
        if phase == 6 and get(w, 12) == 1:
            return advance(o, w, 0, 5)
        return refuse(o, w)
    if event == 5:
        if phase != 7 or get(w, 12) != 1 or get(w, 8) == 0 or observed != 0:
            return refuse(o, w)
        target = get(w, 8)
        set(w, 8, 0)
        set(w, 12, 0)
        return advance(o, w, target, 1)
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
        set(w, 3, @stable_flags@)
    else:
        set(w, 3, @capture_not_string@)
    set(w, 4, 1)
    set(w, 5, 1)
    set(w, 6, read_word(s, 48))
    set(w, 7, read_word(s, 56))
    seal(w)
    return answer(o, w, 0)

def valid_state(w:mutbuf) -> u64:
    if get(w, 0) != @STATE_MAGIC@ or get(w, 1) != 1:
        return 0
    if get(w, 2) != 1 and get(w, 2) != 2:
        return 0
    if get(w, 4) == 0 or get(w, 5) < 1 or get(w, 5) > 8 or get(w, 12) > 1:
        return 0
    if get(w, 9) != 0 or get(w, 11) != 0 or get(w, 13) != 0 or get(w, 14) != 0 or get(w, 15) != 0:
        return 0
    if get(w, 10) != checksum(w):
        return 0
    port = get(w, 3)
    phase = get(w, 5)
    if phase == 1 or phase == 2:
        if port == 0 or port > @MAX_PORT@ or get(w, 8) != 0:
            return 0
        if get(w, 2) == 1 and port > @stable_release_locals@:
            return 0
        if get(w, 2) == 2 and port <= @stable_release_locals@:
            return 0
    elif port != 0:
        return 0
    if phase == 7:
        if get(w, 12) != 1:
            return 0
        if get(w, 2) == 1:
            if get(w, 8) != @stable_suppressed_result@:
                return 0
        elif get(w, 8) != @capture_roots_next@:
            return 0
    elif get(w, 8) != 0:
        return 0
    if (phase == 3 or phase == 4) and get(w, 12) != 0:
        return 0
    if (phase == 5 or phase == 6) and get(w, 12) != 1:
        return 0
    return 1

def leave_exception(o:mutbuf, w:mutbuf, target:u64) -> u32:
    if get(w, 12) != 1:
        return refuse(o, w)
    set(w, 8, target)
    return advance(o, w, 0, 7)

'''
COMMON = r'''def advance(o:mutbuf, w:mutbuf, port:u64, phase:u64) -> u32:
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
    set(o, 7, get(w, 8))
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

def route(target):
    if target == 'return':
        return ['if get(w, 12) != 0:', '    return refuse(o, w)', 'return advance(o, w, 0, 3)']
    if target == 'throw':
        return ['if get(w, 12) != 1:', '    return refuse(o, w)', 'return advance(o, w, 0, 6)']
    if target.startswith('resume:'):
        return ['return leave_exception(o, w, @' + target.split(':', 1)[1] + '@)']
    if target == 'capture-finish':
        return ['if get(w, 12) == 1:', '    return advance(o, w, 0, 6)',
                'return advance(o, w, @capture_release_locals@, 1)']
    return ['return advance(o, w, @' + target + '@, 1)']

def transition_source():
    lines = []
    for event, name in (('normal', 'succeeded'), ('failure', 'raised')):
        chunks = [FLOW[i:i + 12] for i in range(0, len(FLOW), 12)]
        args = ', observed:u64' if event == 'normal' else ''
        call_args = ', observed' if event == 'normal' else ''
        lines += ['def ' + name + '(o:mutbuf, w:mutbuf' + args + ') -> u32:',
                  '    port = get(w, 3)']
        for index, chunk in enumerate(chunks):
            lines += ['    if port <= @' + chunk[-1]['name'] + '@:',
                      '        return ' + name + '_' + str(index) + '(o, w' + call_args + ')']
        lines += ['    return refuse(o, w)', '']
        for index, chunk in enumerate(chunks):
            lines += ['def ' + name + '_' + str(index) + '(o:mutbuf, w:mutbuf' + args + ') -> u32:',
                      '    port = get(w, 3)']
            for item in chunk:
                lines.append('    if port == @' + item['name'] + '@:')
                if event == 'normal':
                    lines += ['        if observed > ' + str(item['max']) + ':',
                              '            return refuse(o, w)']
                target = item[event]
                if isinstance(target, list):
                    for observed, choice in enumerate(target):
                        lines.append('        if observed == ' + str(observed) + ':')
                        lines.extend('            ' + x for x in route(choice))
                    lines.append('        return refuse(o, w)')
                else:
                    lines.extend('        ' + x for x in route(target))
            lines += ['    return refuse(o, w)', '']
    return '\n'.join(lines)

def source_program():
    values = {**PORT, 'REQUEST_MAGIC': REQUEST_MAGIC, 'RESULT_MAGIC': RESULT_MAGIC,
              'STATE_MAGIC': STATE_MAGIC, 'MAX_PORT': len(PORTS)}
    text = PROTOCOL + '\n' + transition_source() + '\n' + COMMON
    return re.sub(r'@([A-Za-z_][A-Za-z_0-9]*)@', lambda m: str(values[m[1]]), text)

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
        functions.append({'name': names[node.name], 'params': [builder.param(x) for x in builder.params],
                          'returns': [builder.returns], 'effects': ['read', 'write', 'trap'],
                          'entry': 'b0', 'blocks': builder.blocks})
    return compact_authoring_cfg({'schema': 'hepta.hia.program.v8',
                                  'module': 'store_file_capture', 'functions': functions})

if __name__ == '__main__':
    path = ROOT / SOURCE_NAME
    path.write_text(render_assembly(document()))
    print(path.name, path.stat().st_size)
