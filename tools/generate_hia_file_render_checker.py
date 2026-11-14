"""Author the bounded file-render semantic resident from reviewed HIA checks.

This independent resident retains both phase-zero passes AND phase one: the
ordinary compiler checks CFG edges, call signatures/effects and result tuples
in phase one.  Phase two only writes/patches the counted machine encoding.  No
phase-two or ELF/stdio publication code is reachable from this entry.

The ordinary compiler is not changed.  The new entry removes only machine
entry/export ABI restrictions which the public Core renderer never required.
The independently reviewed input function inventory is 256, matching the old
renderer. The ordinary compiler which builds this resident retains its own
128-function author budget. Call views use the declared callee permissions:
the original Core contract permits mutbuf arguments at readbuf formals without
granting mutable access. All other finite source/CFG/SSA/tuple limits remain
explicit; this is not every public Core/CLI diagnostic.
"""
from __future__ import annotations

import argparse
import ast
from hashlib import sha256
import json
from pathlib import Path
import sys
from types import FunctionType

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from tools import generate_hia_selfhost as original
from hepta.hia_agent_assembly import render_assembly

SOURCE = 'examples/hia_bootstrap/file_render_checker.hepta'
ORIGINAL_SOURCE_SHA256 = 'e41a46f3878aecd716f35cbc4044964dd065405711f46a26cfd121e5c20985d9'
ORIGINAL_EXPANDED_SHA256 = '1a4181ab54be30ee0c0544d987168e11d7c9dcbbbd85d96b9f08d5a0ccafc712'
INPUT_FUNCTIONS = 256
SEMANTIC_FBASE = 570368
SEMANTIC_CBASE = SEMANTIC_FBASE + INPUT_FUNCTIONS * 320
SEMANTIC_CSTATE = SEMANTIC_CBASE + INPUT_FUNCTIONS * INPUT_FUNCTIONS


def workspace_layout():
    """Actual live regions; phase-two relocation storage is not live here."""
    regions = [
        ('state', 0, 4096),
        ('blocks', 45056, 536576), ('SSA', 536576, 569344),
        ('arguments', 569344, 570368),
        ('functions256', SEMANTIC_FBASE, SEMANTIC_CBASE),
        ('calls256', SEMANTIC_CBASE, SEMANTIC_CSTATE),
        ('call_state256', SEMANTIC_CSTATE, SEMANTIC_CSTATE + INPUT_FUNCTIONS * 8),
        ('capabilities', 875776, 924928), ('block_marks', 924928, 926464),
        ('cap_tmp', 926464, 926480), ('graph_queue', 926480, 928528),
        ('origins', 928528, 930576), ('block_origins', 930576, 955152),
        ('SSA_names', 955152, 1004304), ('block_names', 1004304, 1010448),
        ('exports256', 1010448, 1010448 + INPUT_FUNCTIONS * 48),
    ]
    previous = 0
    for _, begin, end in regions:
        if not previous <= begin < end <= 1048576:
            raise ValueError('semantic workspace regions overlap or exceed the old limit')
        previous = end
    return [{'name': name, 'begin': begin, 'end': end} for name, begin, end in regions]


def _replace(text, before, after):
    if text.count(before) != 1:
        raise ValueError('reviewed semantic projection preimage changed')
    return text.replace(before, after, 1)


def _prior_projected_source():
    text = original.SOURCE
    if (sha256(text.encode()).hexdigest() != ORIGINAL_SOURCE_SHA256
            or sha256(original.source_program().encode()).hexdigest() != ORIGINAL_EXPANDED_SHA256):
        raise ValueError('ordinary compiler semantic source differs from the reviewed input')
    text = _replace(text, '    while phase < 3:\n', '    while phase < 2:\n')
    text = _replace(text, '''        if get(w, 232) == 1:
            elf_begin(o, w)
        if get(w, 232) == 2:
            cli_begin(o, w)
        if get(w, 640) == 0:
            wrapper(o, w)
''', '''        # This resident verifies owned Core syntax without producing an
        # ELF object or admitting any allocator/loader capability.
        put(w, 232, 1)
''')
    text = _replace(text, '''        if get(w, 232) == 1:
            chain_drop_helper(o, w)
            if get(w, 640) == 1:
                exports_finish(s, o, w)
            else:
                elf_finish(o, w)
        if get(w, 232) == 2:
            cli_finish(o, w)
''', '')
    text = _replace(text, '''    fix_all(o, w)
    if get(w, 40) != 0:
        return 4294967295
    return get(w, 56)
''', '''    # Success is validation, not a machine-image length.  Phase one has
    # completed every function, edge, call/effect and result-type check.
    if get(w, 40) != 0:
        return 4294967295
    return 0
''')
    text = _replace(text, '''    if f == 0 and get(w, 640) == 0:
        if count != 3 or rt != 3 or get(w, fb + 184) != 1:
            fail(w, 5)
        if get(w, fb + 48) != 6 or get(w, fb + 56) != 7 or get(w, fb + 64) != 7:
            fail(w, 5)
''', '')
    text = _replace(text, '''        if export_loader_hook(s, get(w, 456), get(w, 464)) == 1:
            return fail(w, 68)
''', '')
    text = _replace(text, '''    if n == 0 or get(w, 232) == 2:
        return fail(w, 68)
''', '')
    text = _replace(text, '''        if get(w, fb + 184) > 1:
            return fail(w, 68)
        if get(w, fb + 184) == 1:
            if scalar_type(get(w, fb + 32)) == 0:
                return fail(w, 68)
''', '''        j = 0
        while j < get(w, fb + 184):
            if scalar_type(get(w, fb + 192 + j * 8)) == 0:
                return fail(w, 68)
            j = j + 1
''')
    text = _replace(text, '''            if scalar_type(get(w, fb + 48 + j * 8)) == 0 or get(w, fb + 48 + j * 8) == 16:
''', '''            if scalar_type(get(w, fb + 48 + j * 8)) == 0:
''')
    return text


def projected_source():
    text = _prior_projected_source()
    changes = (
        ('fill_range(w, CBASE, 17408, 0)', 'fill_range(w, CBASE, 67584, 0)'),
        ('if f != get(w, 64) or f >= 128:', 'if f != get(w, 64) or f >= 256:'),
        ('        if f >= 128:\n', '        if f >= 256:\n'),
        ('            if x >= 128:\n', '            if x >= 256:\n'),
        ('store(w, CBASE + get(w, 72) * 128 + x, 1)',
         'store(w, CBASE + get(w, 72) * 256 + x, 1)'),
        ('while target < 128:', 'while target < 256:'),
        ('byte(w, CBASE + f * 128 + target)', 'byte(w, CBASE + f * 256 + target)'),
        ('if n >= 128 or get(w, 32) != 0:', 'if n >= 256 or get(w, 32) != 0:'),
    )
    for before, after in changes:
        text = _replace(text, before, after)
    # Ordinary operations and CFG edges keep their original duplicate guard.
    # Only a call defers mutable-view alias checks until its actual callee's
    # complete signature is available. Owners never gain this exception.
    text = _replace(text,
        'if v == get(w, ARGS + j * 8) and ((t >= 7 and t <= 9) or (is_edge == 1 and t == 6)):',
        'if v == get(w, ARGS + j * 8) and ((t >= 8 and t <= 9) or (t == 7 and is_edge != 2) or (is_edge == 1 and t == 6)):')
    text = _replace(text, '    n = args(s, w, 0)\n',
        '    if op == @call@:\n        n = args(s, w, 2)\n    else:\n        n = args(s, w, 0)\n')
    text = _replace(text, '            loan_call(w, n)\n', '')
    text = _replace(text, '''            if get(w, 48) > 0:
                if x >= get(w, 1024):
''', '''            loan_call(w, n, x)
            if get(w, 40) != 0:
                return 0
            if get(w, 48) > 0:
                if x >= get(w, 1024):
''')
    text = _replace(text, '''                    if typ != get(w, fb + 48 + i * 8):
                        fail(w, 25)
''', '''                    if typ != get(w, fb + 48 + i * 8) and (typ != 7 or get(w, fb + 48 + i * 8) != 6):
                        fail(w, 25)
''')
    begin = text.index('\ndef loan_call(')
    end = text.index('\ndef loan_incoming(', begin)
    text = _replace(text, text[begin:end], '''
def loan_call(w:mutbuf, n:u64, callee:u64) -> u64:
    if get(w, 264) == 0:
        return 0
    if callee >= get(w, 1024):
        return fail(w, 23)
    base = FBASE + callee * FSTRIDE
    if n != get(w, base + 24):
        return fail(w, 24)
    i = 0
    j = 0
    v = 0
    other = 0
    typ = 0
    formal = 0
    while i < n:
        v = get(w, ARGS + i * 8)
        typ = variable(w, v)
        formal = get(w, base + 48 + i * 8)
        if typ != formal and (typ != 7 or formal != 6):
            return fail(w, 25)
        if resource_type(typ) == 1:
            if owner_type(typ) == 1:
                owner_free(w, v)
            else:
                loan_access(w, v)
            j = 0
            while j < i:
                other = get(w, ARGS + j * 8)
                if resource_type(variable(w, other)) == 1 and get(w, CAPBASE + v * 24) == get(w, CAPBASE + other * 24):
                    if formal != 6 or get(w, base + 48 + j * 8) != 6:
                        return fail(w, 62)
                j = j + 1
        i = i + 1
    return 0
''')
    workspace_layout()
    return text


def _expanded():
    namespace = dict(original.source_program.__globals__, SOURCE=projected_source(),
                     FBASE=SEMANTIC_FBASE, CBASE=SEMANTIC_CBASE, CSTATE=SEMANTIC_CSTATE)
    text = FunctionType(original.source_program.__code__, namespace,
                        original.source_program.__name__)()
    # The original byte shortcut is valid only through count128. Count256 must
    # not wrap to zero. The full header is cleared before every original pass;
    # a u32 state word suffices, while the ordinal remains in0..255 at byte72.
    if not text.count('byte(w, 64)') or not text.count('store(w, 64,'):
        raise ValueError('reviewed private function-count access changed')
    text = text.replace('byte(w, 64)', 'state_get32(w, 64)')
    text = text.replace('store(w, 64,', 'state_put32(w, 64,')
    return text


def _symbolic(text):
    text = text.replace('KEYWORD_FUNCTION', original.keyword_source(original.W))
    for name, value in original.W.items():
        text = text.replace('@' + name + '@', str(value))
    return {node.name: node for node in ast.parse(text).body}


def source_program():
    """Remove only statically unreachable helpers; retain all visited bodies."""
    text = _expanded()
    nodes = ast.parse(text).body
    table = {node.name: node for node in nodes}
    live, pending = set(), ['compile']
    while pending:
        name = pending.pop()
        if name in live:
            continue
        live.add(name)
        for node in ast.walk(table[name]):
            if isinstance(node, ast.Call) and isinstance(node.func, ast.Name):
                if node.func.id in table and node.func.id not in live:
                    pending.append(node.func.id)
    return '\n\n'.join(ast.get_source_segment(text, node) for node in nodes
                       if node.name in live) + '\n'


def projection():
    before = {node.name: node for node in ast.parse(original.source_program()).body}
    after = {node.name: node for node in ast.parse(source_program()).body}
    changed = [name for name in after if ast.dump(before[name], include_attributes=False)
               != ast.dump(after[name], include_attributes=False)]
    old_symbolic, new_symbolic = _symbolic(original.SOURCE), _symbolic(projected_source())
    semantic_changed = [name for name in new_symbolic
        if ast.dump(old_symbolic[name], include_attributes=False)
           != ast.dump(new_symbolic[name], include_attributes=False)]
    if semantic_changed != ['compile', 'parse_function', 'args', 'instruction', 'check_calls', 'loan_call',
                            'read_function_name', 'read_exports', 'validate_exports']:
        raise ValueError('semantic projection changed an unreviewed symbolic function')
    relocation_users = [name for name, fn in new_symbolic.items() if name in after
                        and any(isinstance(n, ast.Name) and n.id == 'FIXBASE' for n in ast.walk(fn))]
    if relocation_users != ['relocation']:
        raise ValueError('phase-two table gained another reachable user')
    relocation = new_symbolic['relocation']
    fix_refs = [n for n in ast.walk(relocation) if isinstance(n, ast.Name) and n.id == 'FIXBASE']
    phase2 = [n for n in ast.walk(relocation) if isinstance(n, ast.If)
              and ast.unparse(n.test) == 'get(w, 48) == 2']
    if len(phase2) != 1 or set(map(id, fix_refs)) != {
            id(n) for statement in phase2[0].body for n in ast.walk(statement)
            if isinstance(n, ast.Name) and n.id == 'FIXBASE'}:
        raise ValueError('a live relocation-table access escaped phase two')
    phase_two = []
    for name, function in before.items():
        for node in ast.walk(function):
            if isinstance(node, ast.If) and ast.unparse(node.test) in ('phase == 2', 'byte(w, 48) == 2'):
                calls = sorted({n.func.id for statement in node.body for n in ast.walk(statement)
                                if isinstance(n, ast.Call) and isinstance(n.func, ast.Name)})
                if not set(calls) <= {'write4', 'put', 'get', 'state_get32', 'store'}:
                    raise ValueError('a phase-two guard gained a non-encoding call')
                phase_two.append({'function': name, 'condition': ast.unparse(node.test),
                    'body': ast.unparse(ast.Module(body=node.body, type_ignores=[])), 'calls': calls})
    return {'schema': 'hia.file-render-semantic-projection.v2',
        'original_source_sha256': ORIGINAL_SOURCE_SHA256,
        'original_expanded_sha256': ORIGINAL_EXPANDED_SHA256,
        'projected_expanded_sha256': sha256(source_program().encode()).hexdigest(),
        'original_functions': len(before), 'retained_functions': len(after),
        'changed_functions': changed,
        'symbolic_semantic_changed_functions': semantic_changed,
        'retained_symbolic_unchanged_functions': [name for name in after if name not in semantic_changed],
        'workspace_layout': workspace_layout(),
        'reused_phase_two_table': {'begin': 570368, 'end': 858368,
            'only_reachable_user': relocation_users, 'accesses_guarded_by_phase2': True},
        'function_count_header64': 'full u32 state; original byte shortcut explicitly removed',
        'call_view_permission_rule': {
            'reference': 'hepta.hia_program._BlockCheck.instruction call transition',
            'only_coercion': 'actual mutbuf to declared readbuf',
            'alias_check': 'actual root identity; every aliased formal must be readbuf',
            'retained': ['owner uniqueness and owner_free', 'live-view and suspended-parent checks',
                         'exact arity and results', 'declared effects', 'returned-loan origins',
                         'unchanged duplicate-resource rejection on CFG edges and non-call operations'],
            'no_machine_compiler_change': True},
        'compiler_author_inventory_unchanged': {'functions': 128, 'blocks': 1536, 'instructions': 8192},
        'unreachable_functions': [name for name in before if name not in after],
        'retained_unchanged_functions': [name for name in after if name not in changed],
        'phase_two_guards': phase_two,
        'semantic_passes': ['phase0-signatures', 'phase0-all-functions-and-resource-CFG',
                            'phase1-edge-call-effect-result-checks'],
        'success_result': 0, 'machine_output_written': False,
        'exports_presence_and_zero_item_metadata_retained': True,
        'no_synthetic_function_or_renaming': True,
        'source_bytes': 1048576, 'output_bytes': 1048576, 'workspace_bytes': 1048576,
        'functions': INPUT_FUNCTIONS, 'blocks': 1536, 'instructions': 8192,
        'remaining_narrow_domain': ['native identifier/scanner rules', '16 formal/edge arguments',
            '3 function/call results', 'bounded native call graph', 'counted-code-size budget',
            'v8 normalized validation view; v6/v7 independently gated by the frontend',
            'no public Python diagnostic or independent canonical-parser implementation']}


def document():
    projection()
    namespace = dict(original.document.__globals__, source_program=source_program)
    method = FunctionType(original.document.__code__, namespace, original.document.__name__)
    method.__kwdefaults__ = original.document.__kwdefaults__
    doc, _ = method()
    doc['module'] = 'file_render_checker'
    if (len(doc['functions']) > 128
            or sum(len(fn['blocks']) for fn in doc['functions']) > 1536
            or sum(len(block['ops']) for fn in doc['functions'] for block in fn['blocks']) > 8192):
        raise ValueError('semantic resident exceeds the unchanged native inventory')
    return doc


def generated():
    return render_assembly(document())


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--check', action='store_true')
    parser.add_argument('--report', type=Path)
    args = parser.parse_args(argv)
    doc = document()
    raw = render_assembly(doc).encode()
    target = ROOT / SOURCE
    if args.check:
        if target.read_bytes() != raw:
            raise SystemExit('semantic resident differs')
    else:
        target.write_bytes(raw)
    report = dict(projection(), source_bytes=len(raw), sha256=sha256(raw).hexdigest(),
        generated_functions=len(doc['functions']),
        generated_blocks=sum(len(fn['blocks']) for fn in doc['functions']),
        generated_operations=sum(len(block['ops']) for fn in doc['functions'] for block in fn['blocks']))
    if args.report:
        args.report.write_text(json.dumps(report, indent=2, sort_keys=True) + '\n')
    print(json.dumps({key: report[key] for key in ('source_bytes', 'sha256', 'generated_functions',
                     'generated_blocks', 'generated_operations')}, sort_keys=True))


if __name__ == '__main__':
    main()
