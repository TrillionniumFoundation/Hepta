"""Author a separate file-render representation resident for primitive v6/v7/v8.

This resident retains the declared schema and the distinction between absent,
empty and nonempty exports. Version-specific policy runs over the actual JSON
tree before rendering; the separately pinned semantic resident checks the
private v8 view. This is not the whole public verifier or canonical roundtrip.
"""
from __future__ import annotations

import argparse
import ast
from dataclasses import asdict
from hashlib import sha256
import inspect
import json
from pathlib import Path
import types

from hepta.hia_agent_assembly import render_assembly
from hepta.hia_opcodes import OPCODES, TYPES, EFFECTS, TERMINATORS
from hepta.hia_schema import PRIMITIVE_FEATURES, SCHEMA_V6, SCHEMA_V7, SCHEMA_V8
from tools import generate_hia_core_json_frontend as original

ROOT = Path(__file__).resolve().parents[1]
SOURCE_PATH = 'examples/hia_bootstrap/file_render_frontend.hepta'
BASE_FRONTEND_SHA256 = '07aaa374f6b83fd54cc03d4578c31c558842783b2e72a0752aeafe93d8a3e532'


def replace_once(text, before, after):
    if text.count(before) != 1:
        raise ValueError('the reviewed frontend template has changed')
    return text.replace(before, after, 1)


LEGACY = r'''
def legacy_parameters(w:mutbuf, values:u64) -> u64:
    if kind(w, values) != 5:
        return 0
    item = child(w, values)
    while item != 18446744073709551615:
        if text_is(w, field(w, item, K_type), L_chain) == 1:
            return 0
        item = next_node(w, item)
    return 1

def legacy_returns(w:mutbuf, values:u64, version:u64) -> u64:
    if kind(w, values) != 5:
        return 0
    item = child(w, values)
    while item != 18446744073709551615:
        if (version == 6 and text_is(w, item, L_chain) == 1) or text_is(w, item, L_readbuf) == 1 or text_is(w, item, L_mutbuf) == 1:
            return 0
        item = next_node(w, item)
    return 1
'''


def version_inventory():
    newer = sorted(name for name, spec in OPCODES.items() if spec.since > 6)
    expected = ['chain.empty', 'chain.head_mut', 'chain.head_read',
                'chain.is_empty', 'chain.pop', 'chain.try_push']
    if newer != expected or any(OPCODES[name].since != 7 for name in newer):
        raise ValueError('new opcode versions require an explicit policy review')
    if (set(TYPES) != {'bool', 'buffer', 'chain', 'i8', 'i16', 'i32', 'i64', 'isize',
                      'u8', 'u16', 'u32', 'u64', 'usize', 'unit', 'readbuf', 'mutbuf'}
            or set(EFFECTS) != {'alloc', 'read', 'write', 'trap'}):
        raise ValueError('new types or effects require an explicit policy review')
    return {
        'schemas': [SCHEMA_V6, SCHEMA_V7, SCHEMA_V8],
        'all_opcode_specs': {name: asdict(spec) for name, spec in OPCODES.items()},
        'all_types': sorted(TYPES), 'all_effects': sorted(EFFECTS),
        'all_terminator_fields': dict(TERMINATORS),
        'features': {schema: sorted(PRIMITIVE_FEATURES[schema])
                     for schema in (SCHEMA_V6, SCHEMA_V7, SCHEMA_V8)},
        'v6_opcode_rejections': newer,
        'v6_type_rejection': {'chain': ['function parameters', 'function returns',
                                     'block parameters', 'instruction outputs']},
        'v6_function_return_rejections': ['readbuf', 'mutbuf'],
        'v6_optional_function_field_rejection': 'return_loans (including null or [])',
        'v7_function_return_rejections': ['readbuf', 'mutbuf'],
        'v7_optional_function_field_rejection': 'return_loans (including null or [])',
        'other_local_type_attribute_effect_rules': 'unchanged original opcode metadata; checked by the pinned validation-only HIA resident after reversible private representation normalization',
        'exports': 'preserve absent/[]/nonempty in presentation and private semantic input without deleting any metadata',
        'exports_validation': 'up to256 actual unique functions; scalar parameters and zero-to-three scalar results, with no machine-entry/ELF-loader namespace authority',
        'canonical_roundtrip': 'independently checked by original public parser/verifier in controls; no claim of a new complete runtime canonical-roundtrip verifier',
    }


def frontend_text():
    inventory = version_inventory()
    text = original.FRONTEND
    text = replace_once(text,
        'if kind(w, exports) != 5 or count(w, exports) == 0 or count(w, exports) > 128:',
        'if kind(w, exports) != 5 or count(w, exports) > 256:')
    text = replace_once(text,
        '''    if text_is(w, field(w, 0, K_schema), L_hepta_hia_program_v8) == 0:
        return 4294967291
''',
        '''    version = 8
    if text_is(w, field(w, 0, K_schema), L_hepta_hia_program_v6) == 1:
        version = 6
    else:
        if text_is(w, field(w, 0, K_schema), L_hepta_hia_program_v7) == 1:
            version = 7
        else:
            if text_is(w, field(w, 0, K_schema), L_hepta_hia_program_v8) == 0:
                return 4294967291
''')
    begin = text.index('    # Require operator selection')
    end = text.index('    emit(o, w, L_header)', begin)
    text = text[:begin] + '''    # This is a file-render representation, not a caller-selected ELF ABI.
    # Special compiler output labels stay outside this finite profile.
    if output_profile != 0 or text_is(w, module, L_selfhost_exec) == 1 or text_is(w, module, L_selfhost_elf) == 1:
        return 4294967291
''' + text[end:]
    text = replace_once(text, '    emit(o, w, L_hepta_hia_program_v8)\n',
        '''    if version == 6:
        emit(o, w, L_hepta_hia_program_v6)
    else:
        if version == 7:
            emit(o, w, L_hepta_hia_program_v7)
        else:
            emit(o, w, L_hepta_hia_program_v8)
''')
    text = replace_once(text, '        render_function(s, o, w, fn)\n',
                        '        render_function(s, o, w, fn, version)\n')
    text = replace_once(text, 'def render_function(s:readbuf, o:mutbuf, w:mutbuf, fn:u64) -> u64:',
                        'def render_function(s:readbuf, o:mutbuf, w:mutbuf, fn:u64, version:u64) -> u64:')
    text = replace_once(text, '    loans = field(w, fn, K_return_loans)\n',
        '''    loans = field(w, fn, K_return_loans)
    if version < 8:
        if loans != 18446744073709551615:
            return fail(w)
        if legacy_returns(w, field(w, fn, K_returns), version) == 0:
            return fail(w)
    if version == 6:
        if legacy_parameters(w, field(w, fn, K_params)) == 0:
            return fail(w)
''')
    text = replace_once(text, '        render_block(s, o, w, block)\n',
                        '        render_block(s, o, w, block, version)\n')
    text = replace_once(text, 'def render_block(s:readbuf, o:mutbuf, w:mutbuf, block:u64) -> u64:',
                        'def render_block(s:readbuf, o:mutbuf, w:mutbuf, block:u64, version:u64) -> u64:')
    text = replace_once(text, '    emit(o, w, L_block)\n',
        '''    if version == 6 and legacy_parameters(w, field(w, block, K_params)) == 0:
        return fail(w)
    emit(o, w, L_block)
''')
    text = replace_once(text, '        render_instruction(s, o, w, ins)\n',
                        '        render_instruction(s, o, w, ins, version)\n')
    text = replace_once(text, 'def render_instruction(s:readbuf, o:mutbuf, w:mutbuf, ins:u64) -> u64:',
                        'def render_instruction(s:readbuf, o:mutbuf, w:mutbuf, ins:u64, version:u64) -> u64:')
    instruction = '    if shape(w, ins, K_op | K_args | K_out | K_attrs) == 0:\n        return fail(w)\n'
    guard = '''    if version == 6:
        if legacy_parameters(w, field(w, ins, K_out)) == 0:
            return fail(w)
        operation = field(w, ins, K_op)
'''
    for name in inventory['v6_opcode_rejections']:
        guard += '        if text_is(w, operation, L_' + name.replace('.', '_') + ') == 1:\n            return fail(w)\n'
    text = replace_once(text, instruction, instruction + guard)
    return text + '\n' + LEGACY


def source_program():
    # Use an isolated namespace for this author's exact original helper body.
    # Do not mutate the shared frontend module or change its generated bytes.
    namespace = dict(vars(original))
    literals = dict(original.LITERALS, hepta_hia_program_v6=SCHEMA_V6, hepta_hia_program_v7=SCHEMA_V7,
                    chain='chain', readbuf='readbuf', mutbuf='mutbuf')
    literals.update({name.replace('.', '_'): name
                     for name in version_inventory()['v6_opcode_rejections']})
    namespace.update(FRONTEND=frontend_text(), LITERALS=literals)
    return types.FunctionType(original.source_program.__code__, namespace)()


def document():
    namespace = dict(vars(original), source_program=source_program)
    doc = types.FunctionType(original.document.__code__, namespace)()
    assert doc['module'] == 'core_json_frontend'
    doc['module'] = 'file_render_frontend'
    return doc


def generated():
    return render_assembly(document())


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--check', action='store_true')
    args = parser.parse_args(argv)
    original_path = ROOT / 'examples/hia_bootstrap/core_json_frontend.hepta'
    original_raw = original_path.read_bytes()
    if sha256(original_raw).hexdigest() != BASE_FRONTEND_SHA256:
        raise ValueError('the reviewed original frontend source changed')
    doc = document()
    raw = render_assembly(doc).encode()
    path = ROOT / SOURCE_PATH
    if args.check:
        if path.read_bytes() != raw:
            raise SystemExit('file-render frontend source differs')
    else:
        path.write_bytes(raw)
    assert original_path.read_bytes() == original_raw
    print(json.dumps({'bytes': len(raw), 'sha256': sha256(raw).hexdigest(),
        'functions': len(doc['functions']), 'blocks': sum(len(fn['blocks']) for fn in doc['functions']),
        'operations': sum(len(block['ops']) for fn in doc['functions'] for block in fn['blocks']),
        'version_inventory': version_inventory(), 'matching_cold': False, 'whole': False}, sort_keys=True))


if __name__ == '__main__':
    main()
