"""Finite CFG worklist regressions, including the unchanged review witnesses.

The inputs exercise source order, graph joins and ordinary resource lifetimes.
They do not change the native child limits or establish an all-input theorem.
"""
from __future__ import annotations

import re
from tools.hia_selfhost_cases import HEADER
from tools.hia_selfhost_loans import INPUT, OUTPUT, loan_cases, reference_source


def reverse_source(*, loan=False):
    """The two retained independent reconstructions of review comment 4507258706."""
    if not loan:
        return (HEADER + '  jump b255()\n'
                'block b1()\n  v3:u32 = const() {"value":7}\n  ret(v3)\n'
                + ''.join(f'block b{i}()\n  jump b{i-1}()\n' for i in range(2, 256))
                + 'end\n').encode()
    return (HEADER + '  v3:readbuf = borrow.read(v0)\n  jump b255(v0,v3)\n'
            'block b1(v4:readbuf,v5:readbuf)\n  _ = loan.end(v5)\n'
            '  v6:u32 = const() {"value":7}\n  ret(v6)\n'
            + ''.join(f'block b{i}(v{2*i+3}:readbuf,v{2*i+4}:readbuf)\n'
                      f'  jump b{i-1}(v{2*i+3},v{2*i+4})\n' for i in range(2, 256))
            + 'end\n').encode()


def future_capability_source():
    return (HEADER + '''  v3:readbuf = borrow.read(v1)
  jump b2(v1,v3)
block b1(v4:mutbuf,v5:readbuf)
  v6:readbuf = borrow.read(v4)
  _ = loan.end(v5)
  _ = loan.end(v6)
  v7:mutbuf = borrow.mut(v4)
  _ = loan.end(v7)
  v8:u32 = const() {"value":7}
  ret(v8)
block b2(v9:mutbuf,v10:readbuf)
  jump b1(v9,v10)
end
''').encode()


def reorder_blocks(source, order):
    """Rename whole block labels simultaneously; preserve each operation byte."""
    header, tail = source.split('block b0(', 1)
    body, rest = ('block b0(' + tail).split('\nend\n', 1)
    blocks = re.split(r'(?=^block b[0-9]+\()', body, flags=re.M)[1:]
    assert len(order) == len(blocks) and set(order) == set(range(len(blocks))) and order[0] == 0
    renamed = {old: new for new, old in enumerate(order)}
    text = header + ''.join(blocks[i] if blocks[i].endswith('\n') else blocks[i] + '\n' for i in order)
    text = re.sub(r'\bb([0-9]+)\b', lambda m: 'b' + str(renamed[int(m.group(1))]), text)
    return (text + 'end\n' + rest).encode()


def late_join_source(*, parent=False, mismatch=False):
    if not parent:
        new_parent = 'v9' if mismatch else 'v8'
        body = '''  jump b4(v1,v2)
block b1(v3:mutbuf,v4:mutbuf,v5:readbuf)
  _ = loan.end(v5)
  v6:u32 = const() {"value":0}
  ret(v6)
block b2(v8:mutbuf,v9:mutbuf)
  v10:readbuf = borrow.read(PARENT)
  jump b1(v8,v9,v10)
block b3(v11:mutbuf,v12:mutbuf,v13:readbuf)
  _ = loan.end(v13)
  jump b2(v11,v12)
block b4(v14:mutbuf,v15:mutbuf)
  v16:readbuf = borrow.read(v14)
  v17:bool = const() {"value":true}
  branch v17 b1(v14,v15,v16) b3(v14,v15,v16)
end
'''
    else:
        new_parent = 'v8' if mismatch else 'v9'
        body = '''  jump b4(v1)
block b1(v3:mutbuf,v4:readbuf,v5:readbuf)
  _ = loan.end(v5)
  _ = loan.end(v4)
  v6:u32 = const() {"value":0}
  ret(v6)
block b2(v8:mutbuf,v9:readbuf)
  v10:readbuf = borrow.read(PARENT)
  jump b1(v8,v9,v10)
block b3(v11:mutbuf,v12:readbuf,v13:readbuf)
  _ = loan.end(v13)
  jump b2(v11,v12)
block b4(v14:mutbuf)
  v15:readbuf = borrow.read(v14)
  v16:readbuf = borrow.read(v15)
  v17:bool = const() {"value":true}
  branch v17 b1(v14,v15,v16) b3(v14,v15,v16)
end
'''
    return (HEADER + body.replace('PARENT', new_parent)).encode()


def owned_source(*, chain=False):
    header = HEADER.replace('v8 selfhost\n', 'v8 selfhost_elf\n').replace(
        'effects(read,write,trap)', 'effects(alloc,read,write,trap)')
    if chain:
        return (header + '''  v3:chain = chain.empty()
  jump b3(v3)
block b1(v4:chain)
  v5:chain = owner.move(v4)
  _ = owner.drop(v5)
  v6:u32 = const() {"value":7}
  ret(v6)
block b2(v7:chain)
  jump b1(v7)
block b3(v8:chain)
  jump b2(v8)
end
''').encode()
    return (header + '''  v3:usize = const() {"value":8}
  v4:buffer = buffer.new(v3)
  v5:mutbuf = borrow.mut(v4)
  jump b3(v4,v5)
block b1(v6:buffer,v7:mutbuf)
  _ = loan.end(v7)
  v8:buffer = owner.move(v6)
  _ = owner.drop(v8)
  v9:u32 = const() {"value":7}
  ret(v9)
block b2(v10:buffer,v11:mutbuf)
  v14:u8 = const() {"value":91}
  _ = buffer.fill(v11,v14)
  jump b1(v10,v11)
block b3(v12:buffer,v13:mutbuf)
  jump b2(v12,v13)
end
''').encode()


def cases():
    rows = []

    def add(name, source, result, output=OUTPUT, data=INPUT):
        rows.append({'id': name, 'source': source.decode(), 'expected_result': result,
                     'source_hex': data.hex(), 'initial_hex': OUTPUT.hex(),
                     'expected_hex': output.hex()})

    add('reverse-256-scalar', reverse_source(), 7)
    add('reverse-256-read', reverse_source(loan=True), 7)
    mutable = reverse_source(loan=True).replace(b'borrow.read(v0)', b'borrow.mut(v1)')
    mutable = mutable.replace(b'jump b255(v0,v3)', b'jump b255(v1,v3)')
    # Only the transferred root/child become mutable; f0's source remains readbuf.
    lines = mutable.decode().splitlines()
    lines = [line if line.startswith(('fn ', 'block b0(')) else line.replace(':readbuf', ':mutbuf') for line in lines]
    mutable = ('\n'.join(lines) + '\n').replace('  _ = loan.end(v5)\n',
        '  v600:u8 = const() {"value":231}\n  _ = buffer.fill(v5,v600)\n  _ = loan.end(v5)\n').encode()
    add('reverse-256-mut', mutable, 7, bytes([231]) * 8)
    one = reverse_source(loan=True).decode()
    total = one + ''.join(one.split('\n', 1)[1].replace('fn f0(', f'fn f{i}(', 1) for i in range(1, 6))
    add('reverse-1536-six-functions', total.encode(), 7)
    add('replay-discards-future-capabilities', future_capability_source(), 7)
    previous = {row['id']: row for row in loan_cases()}
    for old, new in (('loan-through-loop-backedge', 'reverse-loop-backedge'),
                     ('matching-join-arm-0', 'reverse-join-arm-0'),
                     ('matching-join-arm-1', 'reverse-join-arm-1')):
        row = previous[old]
        add(new, reorder_blocks(row['source'], [0, 3, 2, 1]), row['expected_result'],
            bytes.fromhex(row['expected_hex']), bytes.fromhex(row['source_hex']))
    add('late-matching-root-join', late_join_source(), 0)
    add('late-matching-parent-join', late_join_source(parent=True), 0)
    add('queued-owner-and-local-loan', owned_source(), 7)
    add('queued-chain-move-drop', owned_source(chain=True), 7)
    return rows


def refusals():
    source = future_capability_source()
    return {
        'queued-live-local-at-return': source.replace(b'  _ = loan.end(v7)\n', b''),
        'queued-double-end': source.replace(b'  _ = loan.end(v5)\n', b'  _ = loan.end(v5)\n  _ = loan.end(v5)\n'),
        'queued-use-ended-loan': source.replace(b'  _ = loan.end(v5)\n', b'  _ = loan.end(v5)\n  v90:usize = buffer.len(v5)\n'),
        'queued-suspended-parent-write': source.replace(b'  v6:readbuf', b'  v90:u8 = const() {"value":1}\n  _ = buffer.fill(v4,v90)\n  v6:readbuf'),
        'queued-duplicate-local-ssa': source.replace(b'v7', b'v6'),
        'queued-duplicate-cross-block-ssa': source.replace(b'v4', b'v1'),
        'queued-undefined-value': source.replace(b'borrow.read(v4)', b'borrow.read(v99)'),
        'queued-target-outside-function': source.replace(b'jump b2(v1,v3)', b'jump b255(v1,v3)'),
        'queued-entry-backedge': source.replace(b'jump b1(v9,v10)', b'jump b0(v9,v10)'),
        'queued-unreachable-block': source.replace(b'end\n', b'block b3(v11:mutbuf,v12:readbuf)\n  jump b1(v11,v12)\nend\n'),
        'late-inconsistent-root-join': late_join_source(mismatch=True),
        'late-inconsistent-parent-join': late_join_source(parent=True, mismatch=True),
        'queued-owner-consumed-with-live-child': owned_source().replace(b'  _ = loan.end(v7)\n', b''),
        'queued-chain-double-consume': owned_source(chain=True).replace(b'  _ = owner.drop(v5)\n', b'  _ = owner.drop(v5)\n  _ = owner.drop(v4)\n'),
    }


def independent_reference():
    from hepta.hia_agent_assembly import assemble_program
    from hepta.hia_program import HIAProgramRejected, execute_program
    from tools.hia_selfhost_capacity import count_nodes
    accepted, rejected = [], []
    for row in cases():
        checked = assemble_program(row['source'].encode())
        wrapper = reference_source(row)
        actual = execute_program(assemble_program(wrapper), 'reference_entry', [])
        expected = [row['expected_result'], *bytes.fromhex(row['expected_hex'])]
        if actual['status'] != 'returned' or actual['values'] != expected:
            raise AssertionError((row['id'], expected, actual))
        accepted.append({**row, 'core_sha256': checked.sha256, 'core_nodes': count_nodes(checked.as_dict()),
                         'reference_source': wrapper.decode(), 'reference_result': actual})
    for name, source in refusals().items():
        try:
            assemble_program(source)
        except HIAProgramRejected as error:
            rejected.append({'id': name, 'source': source.decode(), 'code': error.code, 'message': str(error)})
        else:
            raise AssertionError('independent Core accepted invalid CFG ' + name)
    return {'cases': accepted, 'refusals': rejected, 'before_B0': True,
            'scope': 'finite CFG scheduling, lifetime and node-accounting witnesses',
            'all_input_correctness_or_performance_proved': False}


def qualify(directory, compilers, checks, reference, *, prefix="cfg-worklist"):
    from tools.qualify_hia_selfhost import compile_stage, invoke, observe_native_tool, INVALID
    from tools.qualify_hia_selfhost_owned_elf import inspect_owned_object
    observations = []
    for label, compiler in compilers:
        for row in reference['cases']:
            name = label + '-' + prefix + '-' + row['id']
            source = row['source'].encode()
            owned = b'v8 selfhost_elf\n' in source
            artifact, build = compile_stage(directory, name + '-build', compiler, source,
                output_extension='.o' if owned else '.image.bin', workspace_fill=0x5a)
            inspection, linking = None, None
            if owned:
                inspection = inspect_owned_object(artifact.read_bytes())
                linked = directory / (name + '.so')
                linking = observe_native_tool(directory, name + '-link', 'ld', ['-m', 'elf_x86_64',
                    '-shared', '-z', 'defs', '-z', 'noexecstack', '-z', 'relro', '-z', 'now',
                    '--build-id=none', artifact, '-lc', '-o', linked])
                artifact = linked
            initial = bytes.fromhex(row['initial_hex'])
            result, output = invoke(directory, name + '-run', artifact, bytes.fromhex(row['source_hex']),
                image_format='linked-selfhost' if owned else 'flat-x86-64', capacity=len(initial),
                workspace_size=0, output_initial=initial, observe_trap_writes=True)
            checks[name] = bool(build['workspace_header']['248'] == row['core_nodes']
                and build['limits']['cpu_seconds'] == 10 and build['limits']['workspace_bytes'] == 1048576
                and result.get('status') == 'returned' and result.get('abi_status') == 0
                and result.get('core_u32') == row['expected_result'] and result.get('source_unchanged')
                and not result.get('forbidden_compiler_modules_loaded') and output.hex() == row['expected_hex'])
            observations.append({'case': name, 'build': build, 'inspection': inspection,
                                 'linking': linking, 'execution': result, 'output_hex': output.hex()})
        for row in reference['refusals']:
            name = label + '-' + prefix + '-reject-' + row['id']
            result, output = invoke(directory, name, compiler, row['source'].encode(),
                                    capacity=512, workspace_fill=0x5a)
            checks[name] = bool(result.get('status') == 'returned' and result.get('core_u32') == INVALID
                and result.get('source_unchanged') and result.get('output_unchanged')
                and output == bytes([0xa5]) * 512)
            observations.append(result)
    return observations
