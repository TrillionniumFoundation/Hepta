"""Author the independent HIAHLM03 Agent helper owner and stage kit.

HIAHLM01, HIAHLM02 and the original whole release planner are unchanged.
Only roles 20..23, stage 4 operation 3 and check mode 15 enter this kit.
All digest, parser, capacity, byte-output and compiler comparison bodies are
retained from the complete original sources; new role and schema tables are HIA.
"""
from __future__ import annotations

import argparse
from copy import deepcopy
from hashlib import sha256
from pathlib import Path
import sys

ROOT = Path(__file__).resolve().parents[1]
if __package__ in (None, ''):
    sys.path.insert(0, str(ROOT))

from hepta.hia_agent_assembly import render_assembly
from tools.generate_hia_source_helper_manifest import (
    original, function, operation, constant, append_functions, literal, exact_view)

# role, public candidate, HIA module, image stem, complete schema, Core version
AGENT_HELPERS = (
    (20, 'agent-query', 'agent_query', 'agent-query',
     'hepta.hia.agent-query-native.v1', 9),
    (21, 'cli-inspect', 'cli_inspect', 'cli-inspect',
     'hepta.hia.cli-inspect-native.v1', 9),
    (22, 'agent-native-metadata', 'agent_native_metadata', 'agent-native-metadata',
     'hepta.hia.agent-native-metadata.v2', 8),
    (23, 'agent-json-wire', 'agent_json_wire', 'agent-json-wire',
     'hepta.hia.agent-json-wire-native.v1', 8),
)
MAGIC = b'HIAHLM03'
STAGE_OPERATION = 3
CHECK_MODE = 15
COMPILER_ROLE = 24
OUTPUTS = {
    'owner': 'examples/hia_bootstrap/source_agent_helper_manifest.hepta',
    'stage': 'examples/hia_bootstrap/source_agent_helper_stage.hepta',
}


def role_refusal():
    return ' and '.join('role != ' + str(row[0]) for row in AGENT_HELPERS)


def unchanged_profile(document):
    functions = document['functions']
    if (not functions or len(functions) > 128
            or sum(len(f['blocks']) for f in functions) > 1536
            or sum(len(b['ops']) for f in functions for b in f['blocks']) > 8192):
        raise ValueError('Agent helper source exceeds the original compiler profile')
    for f in functions:
        values = {p['name'] for p in f['params']}
        if len(f['blocks']) > 256 or len(f['params']) > 16:
            raise ValueError('Agent helper function exceeds the original compiler profile')
        for block in f['blocks']:
            values.update(p['name'] for p in block['params'])
            if len(block['params']) > 16:
                raise ValueError('Agent helper block parameters exceed the original compiler profile')
            for op in block['ops']:
                values.update(v['name'] for v in op['out'])
                if op['op'] == 'call' and len(op['args']) > 16:
                    raise ValueError('Agent helper call exceeds the original compiler profile')
            term = block['term']
            edges = ([term] if term['op'] == 'jump' else
                     [term['then'], term['else']] if term['op'] == 'branch' else [])
            if any(len(edge['args']) > 16 for edge in edges):
                raise ValueError('Agent helper edge exceeds the original compiler profile')
        if len(values) > 2048:
            raise ValueError('Agent helper value storage exceeds the original compiler profile')
    return document


def owner_program():
    document = original('helper')
    document['module'] = 'source_agent_helper_manifest'
    admit = function(document, 'admit')
    constant(admit, 'v15', int.from_bytes(b'HIAHLM01', 'little'),
             int.from_bytes(MAGIC, 'little'))
    constant(admit, 'v173', 9, COMPILER_ROLE)
    guard = operation(admit, 'v28')
    if guard['op'] != 'compare.gt' or guard['args'] != ['v25', 'v23']:
        raise ValueError('original helper role guard changed')
    guard.update(op='call', args=['v25'], attrs={'function': 'invalid_agent_role'})
    function(document, 'module_header')['name'] = 'module_header_prior'
    function(document, 'protocol_name')['name'] = 'protocol_name_prior'
    render = function(document, 'render')
    calls = [op for b in render['blocks'] for op in b['ops']
             if op['op'] == 'call' and op['attrs'].get('function') == 'protocol_name']
    if len(calls) != 2:
        raise ValueError('original helper render sites changed')
    calls[1]['attrs']['function'] = 'schema_name'
    tails = [op for b in render['blocks'] for op in b['ops']
             if op['op'] == 'call' and op['attrs'].get('function') == 'part4']
    if len(tails) != 1 or tails[0]['args'] != ['v51', 'v67']:
        raise ValueError('original helper schema tail changed')
    tails[0]['attrs']['function'] = 'schema_tail'
    tails[0]['args'].append('v56')
    part = function(document, 'part4')
    suffix = b''.join(operation(part, name)['attrs']['value'].to_bytes(width, 'little')
                      for name, width in (('v4', 8), ('v8', 8), ('v12', 8),
                                          ('v16', 8), ('v20', 1)))
    if len(suffix) != 33 or suffix.count(b'-native.v1') != 1:
        raise ValueError('complete original schema suffix changed')
    source = f'''
def invalid_agent_role(role:u64) -> bool:
    return {role_refusal()}

def module_header(s:readbuf, p:u64, n:u64, role:u64) -> u64:
    if role == {COMPILER_ROLE}:
        return module_header_prior(s, p, n, 9)
'''
    for role, candidate, module, image, schema, core in AGENT_HELPERS:
        prefix = f'hia-asm.v1 hepta.hia.program.v{core} {module}\n'.encode('ascii')
        source += f'    if role == {role}:\n        if n < {len(prefix)}:\n            return 0\n        return header_{role}(s, p, {len(prefix)})\n'
    source += '    return 0\n\ndef protocol_name(o:mutbuf, p:u64, role:u64) -> u64:\n'
    for role, candidate, module, image, schema, core in AGENT_HELPERS:
        source += f'    if role == {role}:\n        return image_name_{role}(o, p)\n'
    source += '    return 0\n\ndef schema_name(o:mutbuf, p:u64, role:u64) -> u64:\n'
    for role, candidate, module, image, schema, core in AGENT_HELPERS:
        source += f'    if role == {role}:\n        return schema_stem_{role}(o, p)\n'
    source += '    return 0\n\ndef schema_tail(o:mutbuf, p:u64, role:u64) -> u64:\n'
    for role, candidate, module, image, schema, core in AGENT_HELPERS:
        source += f'    if role == {role}:\n        return schema_suffix_{role}(o, p)\n'
    source += '    return 0\n\n'
    for role, candidate, module, image, schema, core in AGENT_HELPERS:
        prefix = f'hia-asm.v1 hepta.hia.program.v{core} {module}\n'.encode('ascii')
        if not schema.startswith('hepta.hia.') or not schema.endswith(('.v1', '.v2')):
            raise ValueError('Agent helper schema declaration differs')
        tail = '.v2' if candidate == 'agent-native-metadata' else '-native.v1'
        if not schema.endswith(tail):
            raise ValueError('Agent helper schema stem differs')
        stem = schema[len('hepta.hia.'):-len(tail)]
        source += exact_view(f'header_{role}', prefix, 'uint')
        source += literal(f'image_name_{role}', image.encode('ascii'))
        source += literal(f'schema_stem_{role}', stem.encode('ascii'))
        source += literal(f'schema_suffix_{role}', suffix.replace(b'-native.v1', tail.encode('ascii'), 1))
    append_functions(document, source)
    return unchanged_profile(document)


def stage_program():
    document = original('stage')
    document['module'] = 'source_agent_helper_stage'
    entry = function(document, 'f0')
    plan = [op for b in entry['blocks'] for op in b['ops']
            if op['op'] == 'call' and op['attrs'].get('function') == 'f1']
    if len(plan) != 1:
        raise ValueError('original stage entry changed')
    plan[0]['attrs']['function'] = 'reject_plan'
    current = function(document, 'f26')
    current['name'] = 'check_agent'
    constant(current, 'v64', 11, CHECK_MODE)
    constant(current, 'v470', 5, CHECK_MODE)
    guard = operation(current, 'v497')
    if guard['op'] != 'compare.gt' or guard['args'] != ['v495', 'v496']:
        raise ValueError('original checker role guard changed')
    guard.update(op='call', args=['v495'], attrs={'function': 'invalid_agent_role'})
    function(document, 'f21')['name'] = 'frame_kind_prior'
    function(document, 'f57')['name'] = 'manifest_value_prior'
    source = f'''
def reject_plan(s:readbuf, o:mutbuf, w:mutbuf) -> u32:
    return 16

def invalid_agent_role(role:u64) -> bool:
    return {role_refusal()}

def f26(s:readbuf, o:mutbuf, w:mutbuf) -> u32:
    if length(s) >= 16:
        if f23(s, 8, 8) == {CHECK_MODE}:
            return check_agent(s, o, w)
    return 16

def f21(w:mutbuf) -> u64:
    if f24(w, 128) == 4 and f24(w, 136) == {STAGE_OPERATION}:
        if invalid_agent_role(f24(w, 144)) or f24(w, 160) != 4:
            return 0
        f25(w, 176, 3)
        return {int.from_bytes(MAGIC, 'little')}
    return 0

def f57(s:readbuf, w:mutbuf, key:u64) -> u64:
    role = f24(w, 136)
    p = f24(w, 16016)
    n = f24(w, 16024)
'''
    for role, candidate, module, image, schema, core in AGENT_HELPERS:
        source += f'    if role == {role}:\n        if key == 2:\n            return image_{role}(s, p, n)\n        if key == 4:\n            return schema_{role}(s, p, n)\n        return 0\n'
    source += '    return 0\n\n'
    for role, candidate, module, image, schema, core in AGENT_HELPERS:
        source += exact_view(f'image_{role}', (image + '.image.bin').encode('ascii'), 'f23')
        source += exact_view(f'schema_{role}', schema.encode('ascii'), 'f23')
    append_functions(document, source)
    functions = {f['name']: f for f in document['functions']}
    reachable, pending = set(), ['f0']
    while pending:
        name = pending.pop()
        if name in reachable:
            continue
        if name not in functions:
            raise ValueError('missing complete Agent helper callee: ' + name)
        reachable.add(name)
        pending.extend(op['attrs']['function'] for b in functions[name]['blocks']
                       for op in b['ops'] if op['op'] == 'call')
    document['functions'] = [f for f in document['functions'] if f['name'] in reachable]
    return unchanged_profile(document)


def generated_files():
    return {OUTPUTS['owner']: render_assembly(owner_program()).encode('ascii'),
            OUTPUTS['stage']: render_assembly(stage_program()).encode('ascii')}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--check', action='store_true')
    args = parser.parse_args()
    for name, raw in generated_files().items():
        path = ROOT / name
        if args.check:
            if path.read_bytes() != raw:
                raise SystemExit('Agent helper native source differs: ' + name)
        else:
            path.write_bytes(raw)
        print(name, len(raw), sha256(raw).hexdigest())


if __name__ == '__main__':
    main()
