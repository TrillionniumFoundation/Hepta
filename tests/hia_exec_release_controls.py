"""Independent originals, declared cases and VM-only transport witnesses.

This module supplies test setup, never a runtime compiler/provider fallback.
Original expectations are computed in two fresh children before the first new
candidate invocation. It invokes the unchanged public VM and original CLI
reference body; no new policy result supplies an expected value.
"""
from __future__ import annotations
from hashlib import sha256
import json
from pathlib import Path
import struct
import sys

ROOT = Path(__file__).resolve().parents[1]
if __package__ in {None, ''}:
    sys.path.insert(0, str(ROOT))

GROUPS = (
    'source-to-installed-exec', 'refusals', 'kernel-errors',
    'no-replace-and-corruption', 'copied-native-runtime',
)
PROGRAM_INPUTS = ('00', '49', 'ff')
VALID_CASES = ('assembly-echo', 'assembly-constant', 'core-json-echo')
REFUSAL_CASES = (
    'empty', 'bad-header', 'bad-utf8', 'flat-profile', 'invalid-json',
    'source-digest-mismatch', 'upper-digest', 'unknown-syntax',
    'extra-argument', 'assembly-input-overflow', 'json-input-overflow',
)
KERNEL_CASES = ('closed-stdin', 'full-stdout', 'mmap-failure')
SCHEMA = 'hepta.hia.exec-release-originals.v1'


def originals():
    from hepta.hia_agent_assembly import assemble_program
    from hepta.hia_program import execute_program
    from tools.hia_selfhost_loans import reference_source
    from tools.qualify_hia_selfhost_cli import independent_reference
    original = independent_reference()
    flat = original['echo_source']
    marker = 'v8 selfhost\n'
    if flat.count(marker) != 1:
        raise ValueError('the complete original echo module changed')
    assembly = flat.replace(marker, 'v8 selfhost_exec\n', 1)
    changed = assembly.replace('v4:u8 = buffer.load(v0,v3)',
                               'v4:u8 = const() {"value":42}', 1)
    if changed == assembly:
        raise ValueError('the original constant variation anchor changed')
    doc = assemble_program(assembly).as_dict()
    wire = (json.dumps(doc, sort_keys=True, separators=(',', ':')) + '\n').encode()
    inputs = (('assembly-echo', 'assembly', assembly.encode(), assembly),
              ('assembly-constant', 'assembly', changed.encode(), changed),
              ('core-json-echo', 'core-json', wire, assembly))
    rows = []
    for identity, syntax, source, semantic_source in inputs:
        executions = []
        for input_hex in PROGRAM_INPUTS:
            case = {'source': semantic_source, 'source_hex': input_hex, 'initial_hex': 'a5'}
            checked = assemble_program(reference_source(case))
            result = execute_program(checked, 'reference_entry', [])
            if (result['status'] != 'returned' or len(result['values']) != 2
                    or result['values'][0] != 1
                    or result['resources']['live_owners'] != 0
                    or result['resources']['live_local_loans'] != 0):
                raise AssertionError(result)
            executions.append({'input_hex': input_hex, 'core_sha256': checked.sha256,
                'result': result, 'stdout_hex': bytes([result['values'][1]]).hex()})
        rows.append({'id': identity, 'syntax': syntax, 'source_hex': source.hex(),
                     'source_sha256': sha256(source).hexdigest(), 'executions': executions})
    return {'schema': SCHEMA, 'scope': 'three declared source forms and nine original VM executions',
            'original_cli_reference': original, 'cases': rows,
            'all_input_equivalence_proved': False, 'whole_native_delivery_qualified': False}


def request_cases(reference):
    if tuple(row['id'] for row in reference['cases']) != VALID_CASES:
        raise ValueError('frozen original case order changed')
    valid = reference['cases'][0]
    echo = bytes.fromhex(valid['source_hex'])
    flat = echo.replace(b'v8 selfhost_exec\n', b'v8 selfhost\n', 1)
    # These expected refusal codes belong to the explicitly new CLI contract,
    # not to a replayed original result or a relaxation of an old assertion.
    specs = (
        ('empty', b'', 'assembly', None, (), 2),
        ('bad-header', b'not HIA\n', 'assembly', None, (), 2),
        ('bad-utf8', b'\xff', 'assembly', None, (), 2),
        ('flat-profile', flat, 'assembly', None, (), 6),
        ('invalid-json', b'{}', 'core-json', None, (), 2),
        ('source-digest-mismatch', echo, 'assembly', '0' * 64, (), 5),
        ('upper-digest', echo, 'assembly', 'A' * 64, (), 64),
        ('unknown-syntax', echo, 'unknown', None, (), 64),
        ('extra-argument', echo, 'assembly', None, ('unexpected',), 64),
        ('assembly-input-overflow', b' ' * ((1 << 20) + 1), 'assembly', None, (), 3),
        ('json-input-overflow', b' ' * ((8 << 20) + 1), 'core-json', None, (), 3),
    )
    if tuple(row[0] for row in specs) != REFUSAL_CASES:
        raise AssertionError('declared refusal inventory changed')
    return [{'id': name, 'source': raw,
             'arguments': (syntax, digest or sha256(raw).hexdigest(), *extra),
             'expected_returncode': code}
            for name, raw, syntax, digest, extra, code in specs]


def exact_bundle(raw):
    """An independent stream parser; no candidate implementation is imported."""
    import io
    import re
    stream = io.BytesIO(raw)
    head = stream.read(24)
    if len(raw) > 64 << 20 or len(head) != 24:
        raise ValueError('bundle size')
    magic, count, reserved = struct.unpack('<3Q', head)
    if magic != int.from_bytes(b'HIAREL01', 'little') or count != 2 or reserved != 0:
        raise ValueError('bundle header')
    result = []
    for _ in range(2):
        entry = stream.read(24)
        if len(entry) != 24:
            raise ValueError('entry header')
        size, mode, length = struct.unpack('<3Q', entry)
        if not 1 <= size <= 127 or mode not in (0o400, 0o500) or length > len(raw):
            raise ValueError('entry fields')
        name = stream.read(size)
        if (len(name) != size or re.fullmatch(rb'[A-Za-z0-9][A-Za-z0-9._-]*', name) is None
                or name in [row[0] for row in result]):
            raise ValueError('entry name')
        content = stream.read(length)
        if len(content) != length:
            raise ValueError('entry extent')
        result.append((name, mode, content))
    if stream.read() or [row[:2] for row in result] != [(b'source.hepta', 0o400), (b'program', 0o500)]:
        raise ValueError('complete ordered two-member package differs')
    return result


def observe_policy(workspace, *, source=b'x', output_size=4096):
    from hepta.hia_agent_assembly import assemble_program
    from hepta.hia_program import execute_program
    from tools.hia_selfhost_bulk import Body
    b = Body(0)
    owners, views = [], []
    for index, (raw, size) in enumerate(((source, len(source)), (b'', output_size), (workspace, 4096))):
        owner = b.value('buffer', 'buffer.new', [b.const('usize', size)])
        owners.append(owner)
        view = b.value('mutbuf', 'borrow.mut', [owner])
        for at, value in enumerate(raw):
            if value:
                b.effect('buffer.store', [view, b.const('usize', at), b.const('u8', value)])
        if index == 0:
            b.effect('loan.end', [view])
            view = b.value('readbuf', 'borrow.read', [owner])
        views.append(view)
    result = b.value('u32', 'call', views, {'function': 'f0'})
    phase = b.value('u8', 'buffer.load', [views[2], b.const('usize', 56)])
    code = b.value('u8', 'buffer.load', [views[2], b.const('usize', 176)])
    for view in views:
        b.effect('loan.end', [view])
    for owner in owners:
        b.effect('owner.drop', [owner])
    policy = (ROOT / 'examples/hia_bootstrap/exec_release_policy.hepta').read_text()
    wrapper = ('hia-asm.v1 hepta.hia.program.v8 exec_release_reference\n'
        'fn observe() -> (u32,u8,u8) effects(alloc,read,write,trap) entry(b0)\nblock b0()\n'
        + b.text() + '  ret(' + ','.join((result, phase, code)) + ')\nend\n'
        + policy.split('\n', 1)[1])
    actual = execute_program(assemble_program(wrapper), 'observe', [], max_steps=4000000)
    if (actual['status'] != 'returned' or actual['resources']['live_owners'] != 0
            or actual['resources']['live_local_loans'] != 0):
        raise AssertionError(actual)
    return actual


def protocol_witnesses():
    def state(**values):
        raw = bytearray(4096)
        for key, value in values.items():
            struct.pack_into('<Q', raw, int(key[1:]), value)
        return raw
    proper = state(p16=3, p24=8, p32=64)
    proper[256:264] = b'assembly'
    proper[320:384] = b'0' * 64
    cases = [('initial', bytes(proper), [9, 1, 0])]
    for at, value in ((0, 1), (40, 9), (48, 1), (56, 1), (64, 9), (72, 1)):
        struct.pack_into('<Q', proper, at, value)
    cases.append(('arguments-after-signal', bytes(proper), [10, 2, 0]))
    for label, at, value in (('argc', 16, 2), ('mode-length', 24, 16), ('hash-length', 32, 65)):
        changed = bytearray(proper)
        struct.pack_into('<Q', changed, at, value)
        cases.append((label, bytes(changed), [6, 10, 64]))
    changed = bytearray(proper)
    changed[320] = 65
    cases.append(('uppercase-hex', bytes(changed), [6, 10, 64]))
    cases.extend((
        ('ABI-refusal', bytes(state(p0=2)), [6, 10, 16]),
        ('foreign-sequence', bytes(state(p0=1, p40=9, p48=2, p56=1, p64=9, p72=1)), [6, 10, 16]),
        ('signal-error', bytes(state(p0=1, p8=(1 << 64)-22, p40=9, p48=1, p56=1, p64=9, p72=1)), [6, 10, 4]),
        ('mmap-error-before-mapping', bytes(state(p0=1, p8=(1 << 64)-12, p40=10, p48=2, p56=2, p64=10, p72=2)), [6, 10, 4]),
        ('early-diagnostic-return', bytes(state(p0=1, p8=1, p40=6, p48=1, p56=10,
            p64=6, p72=1, p152=1, p176=64, p184=1)), [7, 11, 64]),
    ))
    result = []
    for name, raw, expected in cases:
        actual = observe_policy(raw)
        if actual['values'] != expected:
            raise AssertionError({'case': name, 'actual': actual, 'expected': expected})
        result.append({'id': name, 'input_sha256': sha256(raw).hexdigest(), 'result': actual})
    return result


def complete_vm_packer():
    from hepta.hia_agent_assembly import assemble_program, render_assembly
    from hepta.hia_program import execute_program
    from tools.generate_hia_artifact_publication import document
    from tools.generate_hia_exec_release import MAGIC, template
    from tools.hia_selfhost_bulk import Body
    parts = (b'\xc3', b'\x90\xc3', b'\x90\x90\xc3', b'\x90\x90\x90\xc3')
    frame = struct.pack('<5Q', MAGIC, *(len(part) for part in parts)) + b''.join(parts)
    prefix, holes = template()
    expected = bytearray(prefix + b''.join(parts))
    struct.pack_into('<Q', expected, 96, len(expected))
    struct.pack_into('<Q', expected, 104, len(expected))
    target = len(prefix)
    for name, part in zip(('policy_hole', 'frontend_hole', 'compiler_hole', 'sha_hole'), parts):
        at = holes[name]
        struct.pack_into('<I', expected, at, target - at - 4)
        target += len(part)
    b = Body(0)
    owners, views = [], []
    for index, (data, size) in enumerate(((frame, len(frame)), (b'', len(expected)),
                                        (b'', 1), (bytes(expected), len(expected)))):
        owner = b.value('buffer', 'buffer.new', [b.const('usize', size)])
        owners.append(owner)
        view = b.value('mutbuf', 'borrow.mut', [owner])
        for at, value in enumerate(data):
            if value:
                b.effect('buffer.store', [view, b.const('usize', at), b.const('u8', value)])
        if index in (0, 3):
            b.effect('loan.end', [view])
            view = b.value('readbuf', 'borrow.read', [owner])
        views.append(view)
    size = b.value('u32', 'call', views[:3], {'function': 'f0'})
    mismatch = b.value('u8', 'call', [views[1], views[3]], {'function': 'compare_all'})
    for view in views:
        b.effect('loan.end', [view])
    for owner in owners:
        b.effect('owner.drop', [owner])
    compare = '''def compare(o:mutbuf, s:readbuf) -> u8:
    i = 0
    difference = 0
    while i < length(s):
        difference = difference | (byte(o, i) ^ byte(s, i))
        i = i + 1
    return difference
'''
    compare = render_assembly(document(compare, 'comparison')).split('\n', 1)[1]
    compare = compare.replace('fn f0(', 'fn compare_all(')
    packer = (ROOT / 'examples/hia_bootstrap/exec_release_packer.hepta').read_text()
    wrapper = ('hia-asm.v1 hepta.hia.program.v8 exec_release_packer_reference\n'
        'fn observe() -> (u32,u8) effects(alloc,read,write,trap) entry(b0)\nblock b0()\n'
        + b.text() + '  ret(' + size + ',' + mismatch + ')\nend\n'
        + compare + packer.split('\n', 1)[1])
    actual = execute_program(assemble_program(wrapper), 'observe', [], max_steps=4000000)
    if (actual['status'] != 'returned' or actual['values'] != [len(expected), 0]
            or actual['resources']['live_owners'] != 0 or actual['resources']['live_local_loans'] != 0):
        raise AssertionError(actual)
    return {'input_sha256': sha256(frame).hexdigest(), 'complete_output_sha256': sha256(expected).hexdigest(),
            'complete_output_bytes': len(expected), 'result': actual}


def main():
    import argparse
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--originals', type=Path, required=True)
    args = parser.parse_args()
    result = originals()
    with args.originals.open('x') as stream:
        json.dump(result, stream, sort_keys=True, separators=(',', ':'))
        stream.write('\n')


if __name__ == '__main__':
    main()
