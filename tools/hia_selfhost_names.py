"""HIA identifier validation and exact-byte function interning.

Hashes only filter the bounded symbol search. Length and every actual source
byte must also match; a hash never chooses an implementation or a source blob.
The first defined function retains the existing public borrowed-buffer ABI.
"""
from __future__ import annotations


def _reserved_source():
    text = "def reserved_function(s:readbuf, begin:u64, size:u64) -> u64:\n"
    for name in ("abort", "calloc", "malloc", "free", "memcpy", "memmove", "memset"):
        packed = int.from_bytes(name.encode(), "little")
        text += f"    if match(s, begin, size, {len(name)}, {packed}, 0, 0, 0) == 1:\n        return 1\n"
    return text + "    return 0\n"


SOURCE = r'''
def identifier(s:readbuf, w:mutbuf) -> u64:
    quoted = get(w, 32)
    begin = get(w, 24) + quoted
    size = get(w, 0) - quoted - begin
    if size == 0 or size > 128:
        return fail(w, 67)
    i = 0
    h = 5381
    c = 0
    good = 0
    while i < size:
        c = byte(s, begin + i)
        good = 0
        if (c >= 65 and c <= 90) or (c >= 97 and c <= 122) or c == 95:
            good = 1
        if i != 0 and c >= 48 and c <= 57:
            good = 1
        if good == 0:
            return fail(w, 67)
        h = ((h * 33) ^ c) & 4294967295
        i = i + 1
    if size >= 6:
        if match(s, begin, 6, 6, 104871984914271, 0, 0, 0) == 1:
            return fail(w, 67)
    put(w, 456, begin)
    put(w, 464, size)
    put(w, 472, h)
    return 0

def same_identifier(s:readbuf, w:mutbuf, base:u64) -> u64:
    size = get(w, 464)
    if size != get(w, base + 8):
        return 0
    begin = get(w, 456)
    other = get(w, base)
    i = 0
    while i < size:
        if byte(s, begin + i) != byte(s, other + i):
            return 0
        i = i + 1
    return 1

def lookup_identifier(s:readbuf, w:mutbuf, base:u64, stride:u64, count:u64) -> u64:
    i = 0
    record = 0
    while i < count:
        record = base + i * stride
        if get(w, record + 16) == get(w, 472):
            if same_identifier(s, w, record) == 1:
                return i
        i = i + 1
    return count

def read_function_name(s:readbuf, w:mutbuf, definition:u64) -> u64:
    if get(w, 32) != 1 - definition:
        return fail(w, 49)
    identifier(s, w)
    if get(w, 40) != 0:
        return 0
    if reserved_function(s, get(w, 456), get(w, 464)) == 1:
        return fail(w, 67)
    f = 0
    base = 0
    if definition == 1:
        f = get(w, 64)
        if f >= 128:
            return fail(w, 2)
        base = FBASE + f * FSTRIDE
        if get(w, 48) == 0 and get(w, 432) == 1:
            if lookup_identifier(s, w, FBASE + 240, FSTRIDE, f) != f:
                return fail(w, 67)
            put(w, base + 240, get(w, 456))
            put(w, base + 248, get(w, 464))
            put(w, base + 256, get(w, 472))
        else:
            if same_identifier(s, w, base + 240) != 1:
                return fail(w, 67)
    else:
        # All signatures and exact names are discovered before any semantic
        # admission. No placeholder call graph or self-tail identity is used.
        if get(w, 432) == 0:
            f = lookup_identifier(s, w, FBASE + 240, FSTRIDE, get(w, 1024))
            if f == get(w, 1024):
                return fail(w, 23)
    next_token(s, w)
    return f
''' + _reserved_source() + r'''

def read_value_name(s:readbuf, w:mutbuf, kind:u64) -> u64:
    quoted = 0
    if kind == 260:
        quoted = 1
    if get(w, 32) != quoted:
        return fail(w, 48)
    identifier(s, w)
    if get(w, 40) != 0:
        return 0
    slot = ((get(w, 472) * 2654435761) & 4294967295) >> 21
    probes = 0
    base = 0
    index = 0
    while probes < 2048:
        base = 955152 + slot * 24
        if get(w, base + 8) == 0:
            index = get(w, 480)
            if index >= 2048:
                return fail(w, 37)
            put(w, base, get(w, 456))
            put(w, base + 8, get(w, 464))
            put(w, base + 16, index)
            put(w, 480, index + 1)
            next_token(s, w)
            return index
        if same_identifier(s, w, base) == 1:
            index = get(w, base + 16)
            next_token(s, w)
            return index
        slot = (slot + 1) & 2047
        probes = probes + 1
    return fail(w, 37)

def instruction_ahead(s:readbuf, w:mutbuf) -> u64:
    # Distinguish contextual keyword SSA names from terminators without
    # consuming a token or speculatively reading past source length.
    pos = get(w, 0)
    while pos < length(s) and byte(s, pos) == 32:
        pos = pos + 1
    if pos < length(s):
        c = byte(s, pos)
        if c == 58 or c == 44:
            return 1
        if get(w, 8) == 95 and c == 61:
            return 2
    return 0

'''


SOURCE += r"""
def read_block_name(s:readbuf, w:mutbuf, definition:u64) -> u64:
    if get(w, 32) != 0:
        return fail(w, 48)
    identifier(s, w)
    if get(w, 40) != 0:
        return 0
    count = get(w, 488)
    index = lookup_identifier(s, w, 1004304, 24, count)
    if definition == 1:
        if index != count or count >= 256:
            return fail(w, 11)
        put(w, 1004304 + count * 24, get(w, 456))
        put(w, 1004304 + count * 24 + 8, get(w, 464))
        put(w, 1004304 + count * 24 + 16, get(w, 472))
        put(w, 488, count + 1)
    else:
        if index == count:
            return fail(w, 19)
    next_token(s, w)
    return index

def discover_blocks(s:readbuf, w:mutbuf) -> u64:
    # Lexical name discovery only. Every declaration, instruction and edge is
    # still admitted by the unchanged complete semantic passes afterwards.
    pos = get(w, 0)
    token = get(w, 8)
    value = get(w, 16)
    begin = get(w, 24)
    quoted = get(w, 32)
    previous = get(w, 120)
    put(w, 488, 0)
    # Opaque line skipping is discovery only, never language admission. The
    # normal parser still validates every byte, opcode and edge afterwards.
    # Avoid lexing all instruction operands an extra time just to find labels.
    first_line = 1
    scan = 0
    while (first_line == 1 or get(w, 8) != @end@ or instruction_ahead(s, w) != 0) and get(w, 40) == 0:
        if first_line == 0 and get(w, 8) == @block@ and instruction_ahead(s, w) == 0:
            next_token(s, w)
            read_block_name(s, w, 1)
        first_line = 0
        scan = get(w, 0)
        while scan < length(s) and byte(s, scan) != 10:
            scan = scan + 1
        if scan == length(s):
            return fail(w, 46)
        put(w, 0, scan + 1)
        next_token(s, w)
    put(w, 0, pos)
    put(w, 8, token)
    put(w, 16, value)
    put(w, 24, begin)
    put(w, 32, quoted)
    put(w, 120, previous)
    return 0
"""


def name_hash(name):
    value = 5381
    for byte in name.encode('ascii'):
        value = ((value * 33) ^ byte) & 0xffffffff
    return value


def renamed_source(source, mapping):
    """Author a name-only fixture, independently reverified as ordinary Core."""
    from hepta.hia_agent_assembly import assemble_program, render_assembly
    doc = assemble_program(source).as_dict()
    for fn in doc['functions']:
        fn['name'] = mapping[fn['name']]
        for block in fn['blocks']:
            for op in block['ops']:
                if op['op'] == 'call':
                    op['attrs']['function'] = mapping[op['attrs']['function']]
    result = render_assembly(doc).encode()
    assemble_program(result)
    return result


def renamed_values(source, spellings=None):
    """Rename every SSA definition/use/formal origin, then reverify real Core."""
    from hepta.hia_agent_assembly import assemble_program, render_assembly
    doc = assemble_program(source).as_dict()
    for fi, fn in enumerate(doc['functions']):
        definitions = dict.fromkeys(p['name'] for b in fn['blocks']
            for p in [*b['params'], *[p for op in b['ops'] for p in op['out']]])
        mapping = {old: (spellings[i] if spellings is not None and i < len(spellings)
                         else 'local_' + str(fi) + '_' + str(i))
                   for i, old in enumerate(definitions)}
        for p in fn['params']:
            p['name'] = mapping[p['name']]
        if 'return_loans' in fn:
            fn['return_loans'] = [None if x is None else mapping[x] for x in fn['return_loans']]
        for block in fn['blocks']:
            for p in block['params']:
                p['name'] = mapping[p['name']]
            for op in block['ops']:
                op['args'] = [mapping[x] for x in op['args']]
                for p in op['out']:
                    p['name'] = mapping[p['name']]
            term = block['term']
            if term['op'] == 'ret':
                term['values'] = [mapping[x] for x in term['values']]
            elif term['op'] == 'jump':
                term['args'] = [mapping[x] for x in term['args']]
            elif term['op'] == 'branch':
                term['cond'] = mapping[term['cond']]
                for arm in ('then', 'else'):
                    term[arm]['args'] = [mapping[x] for x in term[arm]['args']]
    result = render_assembly(doc).encode()
    assemble_program(result)
    return result


def renamed_blocks(source, spellings=None):
    """Reverify all label definitions, entry names and forward/backward edges."""
    from hepta.hia_agent_assembly import assemble_program, render_assembly
    doc = assemble_program(source).as_dict()
    for fi, fn in enumerate(doc['functions']):
        mapping = {block['id']: (spellings[i] if spellings is not None and i < len(spellings)
                                else 'node_' + str(fi) + '_' + str(i))
                   for i, block in enumerate(fn['blocks'])}
        fn['entry'] = mapping[fn['entry']]
        for block in fn['blocks']:
            block['id'] = mapping[block['id']]
            term = block['term']
            if term['op'] == 'jump':
                term['target'] = mapping[term['target']]
            elif term['op'] == 'branch':
                for arm in ('then', 'else'):
                    term[arm]['target'] = mapping[term[arm]['target']]
    result = render_assembly(doc).encode()
    assemble_program(result)
    return result


def reordered_blocks(source, position='last'):
    """Preserve the graph and every operation, placing each entry last."""
    from hepta.hia_agent_assembly import assemble_program, render_assembly
    doc = assemble_program(source).as_dict()
    for fn in doc['functions']:
        remaining = [b for b in fn['blocks'] if b['id'] != fn['entry']]
        entry = next(b for b in fn['blocks'] if b['id'] == fn['entry'])
        if position == 'last':
            at = len(remaining)
        elif position == 'middle':
            at = len(fn['blocks']) // 2
        elif type(position) is int and 0 <= position <= len(remaining):
            at = position
        else:
            raise ValueError('invalid entry declaration position')
        fn['blocks'] = remaining[:at] + [entry] + remaining[at:]
    result = render_assembly(doc).encode()
    assemble_program(result)
    return result


def nonfirst_entry_source():
    # Exact retained valid-Core v27 exclusion; its bytes are not repaired.
    return ('hia-asm.v1 hepta.hia.program.v8 selfhost\n'
        'fn f0(v0:readbuf,v1:mutbuf,v2:mutbuf) -> (u32) effects() entry(later)\n'
        'block earlier()\n  v3:u32 = const() {"value":7}\n  ret(v3)\n'
        'block later(v0:readbuf,v1:mutbuf,v2:mutbuf)\n  jump earlier()\nend\n')


def entry_order_cases():
    from tools.hia_selfhost_cfg_worklist import cases as cfg_cases
    from tools.hia_selfhost_returned_loans import cases as loan_cases
    from tools.hia_selfhost_tailcalls import scalar_tail_source, scalar_tail_expected
    rows = [{'id': 'block-nonfirst-entry-remains-profile-boundary',
        'program': 'retained-nonfirst-entry', 'source': nonfirst_entry_source(),
        'source_hex': '', 'initial_hex': 'a5', 'expected_hex': 'a5', 'expected_result': 7,
        'retained_former_profile_refusal': True}]
    for row in cfg_cases():
        if row['id'] not in {'queued-owner-and-local-loan', 'queued-chain-move-drop'}:
            rows.append({**row, 'id': 'entry-last-' + row['id'], 'program': 'entry-last-' + row['id'],
                         'source': reordered_blocks(row['source']).decode()})
        if row['id'] in {'reverse-256-mut', 'reverse-1536-six-functions'}:
            rows.append({**row, 'id': 'entry-middle-' + row['id'], 'program': 'entry-middle-' + row['id'],
                         'source': reordered_blocks(row['source'], 'middle').decode()})
    for row in loan_cases():
        if row['program'] in {'loan-read-tail', 'loan-mut-tail'}:
            rows.append({**row, 'id': 'entry-last-' + row['id'], 'program': 'entry-last-' + row['program'],
                         'source': reordered_blocks(row['source']).decode()})
    rows.append({'id': 'entry-last-parallel-scalar-tail', 'program': 'entry-last-parallel-scalar-tail',
        'source': reordered_blocks(scalar_tail_source()).decode(), 'source_hex': '',
        'initial_hex': 'a5', 'expected_hex': 'a5', 'expected_result': scalar_tail_expected(63)})
    return rows


def entry_order_refusals():
    source = nonfirst_entry_source()
    incoming = ('hia-asm.v1 hepta.hia.program.v8 selfhost\n'
        'fn f0(v0:readbuf,v1:mutbuf,v2:mutbuf) -> (u32) effects() entry(later)\n'
        'block earlier(v3:readbuf,v4:mutbuf,v5:mutbuf)\n  jump later(v3,v4,v5)\n'
        'block later(v0:readbuf,v1:mutbuf,v2:mutbuf)\n  jump earlier(v0,v1,v2)\nend\n')
    wrong_origin = ('hia-asm.v1 hepta.hia.program.v8 selfhost\n'
        'fn f0(s:readbuf,o:mutbuf,w:mutbuf) -> (u32) effects(read,write,trap) entry(start)\n'
        'block start(s:readbuf,o:mutbuf,w:mutbuf)\n  view:readbuf = call(s,s) {"function":"helper"}\n'
        '  _ = loan.end(view)\n  result:u32 = const() {"value":0}\n  ret(result)\nend\n'
        'fn helper(first:readbuf,second:readbuf) -> (readbuf) effects() entry(later) return_loans(["first"])\n'
        'block earlier(a:readbuf,b:readbuf)\n  ret(b)\n'
        'block later(first:readbuf,second:readbuf)\n  jump earlier(first,second)\nend\n')
    bad_join = ('hia-asm.v1 hepta.hia.program.v8 selfhost\n'
        'fn f0(s:readbuf,o:mutbuf,w:mutbuf) -> (u32) effects(read,write,trap) entry(later)\n'
        'block finish(a:mutbuf,b:mutbuf,c:readbuf)\n  _ = loan.end(c)\n'
        '  result:u32 = const() {"value":0}\n  ret(result)\n'
        'block left(a1:mutbuf,b1:mutbuf)\n  c1:readbuf = borrow.read(a1)\n  jump finish(a1,b1,c1)\n'
        'block right(a2:mutbuf,b2:mutbuf)\n  c2:readbuf = borrow.read(b2)\n  jump finish(a2,b2,c2)\n'
        'block later(s:readbuf,o:mutbuf,w:mutbuf)\n  at:usize = const() {"value":0}\n'
        '  byte:u8 = buffer.load(s,at)\n  zero:u8 = const() {"value":0}\n'
        '  choose:bool = compare.eq(byte,zero)\n  branch choose left(o,w) right(o,w)\nend\n')
    return [{'id': 'entry-later-wrong-formal-name', 'source': source.replace('block later(v0:', 'block later(other:'), 'general_core_expected': 'rejected'},
        {'id': 'entry-later-wrong-formal-type', 'source': source.replace('block later(v0:readbuf', 'block later(v0:u64'), 'general_core_expected': 'rejected'},
        {'id': 'entry-later-wrong-arity', 'source': source.replace('block later(v0:readbuf,v1:mutbuf,v2:mutbuf)', 'block later(v0:readbuf,v1:mutbuf)'), 'general_core_expected': 'rejected'},
        {'id': 'entry-later-incoming-edge', 'source': incoming, 'general_core_expected': 'rejected'},
        {'id': 'entry-later-wrong-return-origin', 'source': wrong_origin, 'general_core_expected': 'rejected'},
        {'id': 'entry-later-mismatched-join-roots', 'source': bad_join, 'general_core_expected': 'rejected'}]


def block_cases():
    from tools.hia_selfhost_bulk import Body
    from tools.hia_selfhost_cases import HEADER
    b = Body()
    index = b.const('usize', 0)
    byte = b.value('u8', 'buffer.load', ['v0', index])
    cond = b.value('bool', 'compare.eq', [byte, b.const('u8', 0)])
    source = HEADER + b.text() + '  branch ' + cond + ' b1(v1) b2(v1)\n'
    for i, amount in enumerate((17, 73)):
        parent = 'v' + str(19 + i * 20)
        b = Body(20 + i * 20)
        value = b.const('u8', amount)
        b.effect('buffer.store', [parent, b.const('usize', 0), value])
        result = b.const('u32', amount)
        source += 'block b' + str(i + 1) + '(' + parent + ':mutbuf)\n' + b.text() + '  ret(' + result + ')\n'
    source += 'end\n'
    # A typed end/block/ret name must not be a declaration or terminator during
    # discovery. The complete original parser still checks its real syntax.
    source = renamed_values(source.encode(), ['source', 'output', 'workspace', 'end', 'block', 'ret', 'branch'])
    rows = []
    for i, spellings in enumerate((['entry', 'aaB', 'aba'], ['block', 'end', 'ret'],
            ['_', 'b00', 'b18446744073709551615'], ['b', 'prefix', 'prefix_more'],
            ['n' * 128, 'N' * 128, 'tail_' + 'z' * 123])):
        changed = renamed_blocks(source, spellings)
        for data in (0, 73, 255):
            result = 17 if data == 0 else 73
            program = 'block-spellings-' + str(i)
            rows.append({'id': program + '-' + str(data), 'program': program, 'source': changed.decode(),
                'source_hex': bytes([data]).hex(), 'initial_hex': 'a5', 'expected_result': result,
                'expected_hex': bytes([result]).hex()})
    from tools.hia_selfhost_cfg_worklist import cases as cfg_cases
    selected = {'reverse-256-scalar', 'reverse-256-read', 'reverse-256-mut',
        'reverse-1536-six-functions', 'late-matching-root-join', 'late-matching-parent-join',
        'reverse-loop-backedge', 'reverse-join-arm-0', 'reverse-join-arm-1'}
    for row in cfg_cases():
        if row['id'] in selected:
            rows.append({**row, 'id': 'named-' + row['id'], 'program': 'named-' + row['id'],
                'source': renamed_blocks(renamed_values(row['source'].encode())).decode()})
    if len(rows) != 24:
        raise AssertionError('block-name reference inventory changed')
    return rows


def block_refusals():
    source = block_cases()[0]['source']
    rows = []
    for name in ['n' * 129, '__hia_block', 'bad.name', 'bad-name', '1bad', '汉字']:
        rows.append({'id': 'block-invalid-' + str(len(rows)),
            'source': source.replace('aaB', name), 'general_core_expected': 'rejected'})
    rows += [{'id': 'block-duplicate-name', 'source': source.replace('aaB', 'aba'), 'general_core_expected': 'rejected'},
        {'id': 'block-missing-target', 'source': source.replace(' aaB(', ' absent(', 1), 'general_core_expected': 'rejected'},
        {'id': 'block-incoming-entry', 'source': source.replace(' aaB(', ' entry(', 1), 'general_core_expected': 'rejected'}]
    return rows


def core_observed_case(name, source):
    """An independent ordinary Core VM oracle for a retained historical case.

    This never executes a successor or grants VerifiedProgram status itself.
    The fixture's initial borrowed buffers are the existing owned/chain corpus
    contract; zero owner/loan residue is mandatory, not inferred from success.
    """
    from hepta.hia_agent_assembly import assemble_program
    from hepta.hia_program_runtime import _Machine, _Owner, _View
    checked = assemble_program(source)
    machine = _Machine(checked, 10_000_000, 16 << 20, None, 256)
    roots = [_Owner(-1, bytearray()), _Owner(-2, bytearray(b'\xa5' * 8)), _Owner(-3, bytearray())]
    values = machine.invoke(checked.as_dict()['functions'][0],
                           [_View(roots[0], False), _View(roots[1], True), _View(roots[2], True)])
    if len(values) != 1 or machine.owners or machine.chains or machine.loans_started != machine.loans_ended:
        raise AssertionError('historical name control did not close its resources: ' + name)
    return {'id': name, 'source': source.decode() if isinstance(source, bytes) else source,
            'expected_result': values[0], 'expected_output_hex': roots[1].data.hex(),
            'retained_former_profile_refusal': True, 'core_sha256': checked.sha256}


def value_cases():
    base = [row for row in cases() if row['program'] == 'named-pair-0']
    spellings = [
        ['source', 'output', 'workspace', 'zero', 'byteValue', 'result'],
        ['fn', 'block', 'entry', 'ret', 'trap', 'end', 'branch', 'jump'],
        ['_', 'f01', 'v2048', 'v8192', 'v18446744073709551615', 'value', 'mode', 'function'],
        ['aaB', 'aba', 'collision_tail'],
        ['n' * 128, 'N' * 128, 'tail_' + 'z' * 123],
        ['prefix', 'prefix_more', '_prefix', '_prefix_more'],
    ]
    rows = []
    for index, names in enumerate(spellings):
        for row in base:
            program = 'ssa-spellings-' + str(index)
            rows.append({**row, 'id': program + '-' + row['source_hex'], 'program': program,
                         'source': renamed_values(row['source'].encode(), names).decode()})
    for row in cases():
        if row['program'].startswith('named-loan-'):
            rows.append({**row, 'id': 'ssa-' + row['id'], 'program': 'ssa-' + row['program'],
                         'source': renamed_values(row['source'].encode()).decode()})
    from tools.hia_selfhost_cases import HEADER
    full = (HEADER + ''.join('  v' + str(i) + ':u32 = const() {"value":0}\n'
                             for i in range(3, 2048)) + '  ret(v2047)\nend\n')
    rows.append({'id': 'ssa-intern-table-full-2048', 'program': 'ssa-intern-table-full-2048',
                 'source': full, 'source_hex': '', 'initial_hex': 'a5',
                 'expected_result': 0, 'expected_hex': 'a5'})
    return rows


def value_refusals():
    seed = value_cases()[-1]['source']
    overflow = seed.replace('  ret(v2047)', '  v2048:u32 = const() {"value":1}\n  ret(v2048)')
    rows = [{'id': 'ssa-intern-table-overfull-2049', 'source': overflow,
             'general_core_expected': 'accepted'}]
    from tools.hia_selfhost_cases import HEADER
    ordinary = HEADER + '  v3:u32 = const() {"value":7}\n  ret(v3)\nend\n'
    for name in ['n' * 129, '__hia_local', '汉字', 'bad.name', 'bad-name', '1bad']:
        rows.append({'id': 'ssa-invalid-' + str(len(rows)),
                     'source': ordinary.replace('v3', name), 'general_core_expected': 'rejected'})
    rows += [{'id': 'ssa-undefined-name', 'source': ordinary.replace('ret(v3)', 'ret(missing)'),
              'general_core_expected': 'rejected'},
             {'id': 'ssa-entry-name-mismatch', 'source': ordinary.replace('block b0(v0:', 'block b0(other:', 1),
              'general_core_expected': 'rejected'},
             {'id': 'ssa-duplicate-definition', 'source': ordinary.replace('  ret(v3)',
                '  v3:u32 = const() {"value":9}\n  ret(v3)'), 'general_core_expected': 'rejected'}]
    return rows


def cases():
    from tools.hia_selfhost_bulk import Body
    from tools.hia_selfhost_cases import HEADER, backward_chain_source
    from tools.hia_selfhost_returned_loans import cases as loan_cases
    rows = []
    def add(program, source, byte, result, initial, output):
        rows.append({'id': program + '-' + str(byte), 'program': program, 'source': source.decode(),
            'source_hex': bytes([byte]).hex(), 'initial_hex': initial.hex(),
            'expected_result': result, 'expected_hex': output.hex()})
    pairs = [('compile', 'value'), ('fn', 'mode'), ('_', 'function'),
        ('f01', 'v99999999999999999999999999'), ('f', 'ret'),
        ('n' + 'x' * 127, 'n' + 'y' * 127), ('prefix', 'prefix_more')]
    for index, (entry, callee) in enumerate(pairs):
        b = Body(); zero = b.const('usize', 0)
        value = b.value('u8', 'buffer.load', ['v0', zero])
        value = b.value('u32', 'int.cast', [value], {'mode': 'wrap'})
        value = b.value('u32', 'call', [value], {'function': 'f1'})
        value = b.value('u8', 'int.cast', [value], {'mode': 'wrap'})
        b.effect('buffer.store', ['v1', zero, value]); result = b.const('u32', 0)
        source = (HEADER + b.text() + '  ret(' + result + ')\nend\n'
            + 'fn f1(v0:u32) -> (u32) effects() entry(b0)\nblock b0(v0:u32)\n'
            + '  v1:u32 = const() {"value":17}\n  v2:u32 = int.add.wrap(v0,v1)\n  ret(v2)\nend\n').encode()
        source = renamed_source(source, {'f0': entry, 'f1': callee})
        for byte in (0, 73, 255):
            add('named-pair-' + str(index), source, byte, 0, b'\xa5', bytes([(byte + 17) & 255]))
    # Real equal-hash, equal-length names must still compare all source bytes.
    assert name_hash('aaB') == name_hash('aba') and 'aaB' != 'aba'
    b = Body(); zero = b.const('usize', 0)
    value = b.value('u8', 'buffer.load', ['v0', zero])
    value = b.value('u32', 'int.cast', [value], {'mode': 'wrap'})
    a = b.value('u32', 'call', [value], {'function': 'f1'})
    c = b.value('u32', 'call', [value], {'function': 'f2'})
    a = b.value('u32', 'int.mul.wrap', [a, b.const('u32', 3)])
    value = b.value('u32', 'int.add.wrap', [a, c])
    value = b.value('u8', 'int.cast', [value], {'mode': 'wrap'})
    b.effect('buffer.store', ['v1', zero, value]); result = b.const('u32', 0)
    source = HEADER + b.text() + '  ret(' + result + ')\nend\n'
    for fn, amount in ((1, 17), (2, 73)):
        source += (f'fn f{fn}(v0:u32) -> (u32) effects() entry(b0)\nblock b0(v0:u32)\n'
            + f'  v1:u32 = const() {{"value":{amount}}}\n'
            + '  v2:u32 = int.add.wrap(v0,v1)\n  ret(v2)\nend\n')
    source = renamed_source(source.encode(), {'f0': 'entry', 'f1': 'aaB', 'f2': 'aba'})
    for byte in (0, 73, 255):
        add('equal-hash-distinct-functions', source, byte, 0, b'\xa5', bytes([(4 * byte + 124) & 255]))
    for row in loan_cases():
        if row['program'] not in {'loan-read-forward', 'loan-mut-cfg', 'loan-mut-tail'}:
            continue
        from hepta.hia_agent_assembly import assemble_program
        mapping = {fn['name']: 'lease_' + str(i) for i, fn in enumerate(
            assemble_program(row['source'].encode()).as_dict()['functions'])}
        source = renamed_source(row['source'].encode(), mapping)
        rows.append({**row, 'id': 'named-' + row['id'], 'program': 'named-' + row['program'],
            'source': source.decode()})
    source = backward_chain_source()
    source = renamed_source(source, {'f' + str(i): 'chain_node_' + str(i) for i in range(128)})
    add('named-128-functions', source, 0, 127, b'\xa5', b'\xa5')
    return rows


def refusals():
    from tools.hia_selfhost_cases import HEADER
    seed = (HEADER + '  v3:u32 = const() {"value":7}\n  ret(v3)\nend\n')
    rows = []
    for name in ('abort', 'calloc', 'malloc', 'free', 'memcpy', 'memmove', 'memset',
            '__hia_private', 'x' * 129, 'bad.name', 'bad-name', '9bad', 'badé'):
        rows.append({'id': 'name-reject-' + str(len(rows)),
            'source': seed.replace('fn f0(', 'fn ' + name + '(', 1), 'general_core_expected': 'rejected'})
    duplicate = seed.replace('fn f0(', 'fn duplicate(', 1)
    duplicate += 'fn duplicate(v0:u32) -> (u32) effects() entry(b0)\nblock b0(v0:u32)\n  ret(v0)\nend\n'
    rows.append({'id': 'name-duplicate', 'source': duplicate, 'general_core_expected': 'rejected'})
    unresolved = (HEADER + '  v3:u32 = const() {"value":1}\n'
        + '  v4:u32 = call(v3) {"function":"prefix_other"}\n  ret(v4)\nend\n'
        + 'fn prefix(v0:u32) -> (u32) effects() entry(b0)\nblock b0(v0:u32)\n  ret(v0)\nend\n')
    rows.append({'id': 'name-no-prefix-match', 'source': unresolved, 'general_core_expected': 'rejected'})
    return rows


def independent_reference():
    from hepta.hia_agent_assembly import assemble_program
    from hepta.hia_program import HIAProgramRejected
    from hepta.hia_program_runtime import _Machine, _Owner, _View
    from tools.generate_hia_selfhost import document
    from tools.qualify_hia_selfhost import SOURCE as COMPILER, mutate_compiler
    rows = []
    for row in [*cases(), *value_cases(), *block_cases(), *entry_order_cases()]:
        checked = assemble_program(row['source'].encode())
        machine = _Machine(checked, 1_000_000, 16 << 20, None, 256)
        roots = [_Owner(-1, bytearray.fromhex(row['source_hex'])),
            _Owner(-2, bytearray.fromhex(row['initial_hex'])), _Owner(-3, bytearray())]
        entry = checked.as_dict()['functions'][0]
        values = machine.invoke(entry, [_View(roots[0], False), _View(roots[1], True), _View(roots[2], True)])
        result = machine.report(entry['name'], 'returned', values=values)
        if (values != [row['expected_result']] or roots[1].data.hex() != row['expected_hex']
                or roots[0].data.hex() != row['source_hex']
                or result['resources']['live_owners'] or result['resources']['live_local_loans']):
            raise AssertionError({'case': row['id'], 'reference': result, 'output_hex': roots[1].data.hex()})
        rows.append({**row, 'core_sha256': checked.sha256, 'reference': result})
    rejected = []
    for row in [*refusals(), *value_refusals(), *block_refusals(), *entry_order_refusals()]:
        try:
            assemble_program(row['source'].encode())
        except HIAProgramRejected as error:
            if row['general_core_expected'] != 'rejected':
                raise AssertionError('valid profile exclusion became a Core error: ' + row['id']) from error
            rejected.append({**row, 'reference': {'status': 'rejected', 'code': error.code}})
        else:
            if row['general_core_expected'] != 'accepted':
                raise AssertionError('invalid name was accepted by Core: ' + row['id'])
            rejected.append({**row, 'reference': {'status': 'accepted_general_core'}})
    _, names = document(); mapping = {number: name for name, number in names.items()}
    canonical = COMPILER.read_bytes()
    alpha = {}
    for label, source in (('original', canonical), ('modified', mutate_compiler(canonical))):
        renamed = renamed_blocks(renamed_values(renamed_source(source, mapping)))
        alpha[label] = {'source': renamed.decode(), 'core_sha256': assemble_program(renamed).sha256,
            'canonical_core_sha256': assemble_program(source).sha256}
    return {'before_B0': True, 'cases': rows, 'refusals': rejected, 'alpha_compiler': alpha,
        'equal_hash_control': {'names': ['aaB', 'aba'], 'hash': name_hash('aaB')},
        'all_input_correctness_proved': False, 'whole_stack_rewrite_complete': False}


def qualify(directory, compiler, checks, reference, label):
    from pathlib import Path
    from tools.qualify_hia_selfhost import compile_stage, invoke, observe_native_tool, INVALID, inspect_selfhost_object
    from tools.qualify_hia_selfhost_cli import execute, inspect_executable
    directory = Path(directory)
    observations, images = [], {}
    for row in reference['cases']:
        program = row['program']
        if program not in images:
            source = row['source'].encode()
            flat, build = compile_stage(directory, label + '-' + program + '-flat', compiler, source)
            observations.append(build)
            obj, build = compile_stage(directory, label + '-' + program + '-object', compiler,
                source.replace(b'v8 selfhost\n', b'v8 selfhost_elf\n', 1), output_extension='.o')
            observations.append({**build, 'inspection': inspect_selfhost_object(obj.read_bytes())})
            linked = directory / (label + '-' + program + '.so')
            linked_run = observe_native_tool(directory, label + '-' + program + '-link', 'ld',
                ['-m', 'elf_x86_64', '-shared', '-z', 'defs', '-z', 'noexecstack',
                 '-z', 'relro', '-z', 'now', '--build-id=none', obj, '-o', linked])
            if linked_run['returncode']:
                raise AssertionError(linked_run)
            observations.append(linked_run)
            images[program] = [('flat', flat, 'flat-x86-64'), ('elf', linked, 'linked-selfhost')]
        for kind, image, image_format in images[program]:
            receipt, output = invoke(directory, label + '-' + row['id'] + '-' + kind,
                image, bytes.fromhex(row['source_hex']), image_format=image_format,
                capacity=len(bytes.fromhex(row['initial_hex'])), workspace_size=0,
                output_initial=bytes.fromhex(row['initial_hex']))
            checks[label + '-' + row['id'] + '-' + kind] = bool(receipt.get('status') == 'returned'
                and receipt.get('abi_status') == 0 and receipt.get('core_u32') == row['expected_result']
                and receipt.get('source_unchanged') and output.hex() == row['expected_hex'])
            observations.append({'compiler': label, 'case': row['id'], 'format': kind,
                'native': receipt, 'output_hex': output.hex()})
    for row in reference['refusals']:
        receipt, output = invoke(directory, label + '-' + row['id'], compiler,
            row['source'].encode(), capacity=512)
        checks[label + '-' + row['id']] = bool(receipt.get('status') == 'returned'
            and receipt.get('core_u32') == INVALID and receipt.get('source_unchanged')
            and receipt.get('output_unchanged') and output == b'\xa5' * 512)
        observations.append({'compiler': label, 'case': row['id'], 'native': receipt})
    alpha = reference['alpha_compiler'][label]['source'].encode()
    previous = compiler
    for generation in (1, 2):
        image, build = compile_stage(directory, label + '-alpha-R' + str(generation), previous, alpha)
        checks[label + '-alpha-R' + str(generation)] = image.read_bytes() == compiler.read_bytes()
        observations.append(build); previous = image
    executable_source = alpha.replace(b'v8 selfhost\n', b'v8 selfhost_exec\n', 1)
    executable, build = compile_stage(directory, label + '-alpha-E1', compiler,
        executable_source, output_extension='.elf')
    observations.append({**build, 'inspection': inspect_executable(executable.read_bytes())})
    executable.chmod(0o700)
    receipt, output = execute(directory, label + '-alpha-E2-run', executable, executable_source)
    checks[label + '-alpha-executable-fixed-point'] = bool(receipt['status'] == 'OWNED_PROCESS_COMPLETED'
        and receipt['returncode'] == 0 and receipt['cleanup']['complete']
        and not receipt['stderr_hex'] and output == executable.read_bytes())
    observations.append({'compiler': label, 'case': 'alpha-E2', 'native': receipt})
    from tools.qualify_hia_selfhost import SOURCE as COMPILER, mutate_compiler
    canonical = COMPILER.read_bytes()
    if label == 'modified':
        canonical = mutate_compiler(canonical)
    module_source = canonical.replace(b'v8 selfhost\n',
        b'v8 ' + ('Compiler_' + label).encode() + b'\n', 1)
    previous = compiler
    for generation in (1, 2):
        image, build = compile_stage(directory, label + '-module-R' + str(generation),
                                     previous, module_source)
        checks[label + '-module-R' + str(generation)] = image.read_bytes() == compiler.read_bytes()
        observations.append(build)
        previous = image
    return observations


def qualify_entry_layout(directory, compilers):
    """Additional finite native gate; never replace the complete cold replay.

    Declaration permutations can change machine layout and dense SSA numbering.
    Compare generations of the SAME source, not a reordered image to a canonical
    image. Separately require each successor to reproduce its canonical compiler.
    The resource references and all permuted Core inputs are checked before any
    native compilation in this gate; these are not all-input refinement proofs.
    """
    from pathlib import Path
    from hepta.hia_agent_assembly import assemble_program
    from hepta.hia_program import execute_program
    from tools.hia_selfhost_capacity import count_nodes
    from tools.hia_selfhost_cfg_worklist import cases as cfg_cases, qualify as qualify_cfg
    from tools.hia_selfhost_loans import reference_source
    from tools.qualify_hia_selfhost import SOURCE as COMPILER, compile_stage, mutate_compiler
    from tools.qualify_hia_selfhost_cli import execute, inspect_executable
    directory = Path(directory)
    prepared = []
    for label, compiler in compilers:
        canonical = COMPILER.read_bytes()
        if label == 'modified':
            canonical = mutate_compiler(canonical)
        elif label != 'original':
            raise ValueError('unknown compiler identity')
        for position in ('last', 'middle'):
            source = reordered_blocks(canonical, position)
            checked = assemble_program(source)
            resources = []
            for row in cfg_cases():
                if row['id'] not in {'queued-owner-and-local-loan', 'queued-chain-move-drop'}:
                    continue
                row = {**row, 'source': reordered_blocks(row['source'], position).decode()}
                program = assemble_program(row['source'])
                reference = execute_program(assemble_program(reference_source(row)), 'reference_entry', [])
                if (reference['status'] != 'returned'
                        or reference['values'] != [row['expected_result'], *bytes.fromhex(row['expected_hex'])]
                        or reference['resources']['live_owners']
                        or reference['resources']['live_local_loans']):
                    raise AssertionError(reference)
                resources.append({**row, 'core_nodes': count_nodes(program.as_dict()),
                                  'core_sha256': program.sha256, 'reference': reference})
            prepared.append((label, compiler, position, canonical, source, checked.sha256, resources))
    checks, observations, references = {}, [], []
    for label, compiler, position, canonical, source, core_hash, resources in prepared:
        name = label + '-entry-' + position
        references.append({'compiler': label, 'position': position, 'core_sha256': core_hash,
                           'source': source.decode(), 'resource_cases': resources})
        first, receipt = compile_stage(directory, name + '-R1', compiler, source)
        observations.append(receipt)
        second, receipt = compile_stage(directory, name + '-R2', first, source)
        observations.append(receipt)
        checks[name + '-flat-fixed-point'] = first.read_bytes() == second.read_bytes()
        restored, receipt = compile_stage(directory, name + '-canonical', second, canonical)
        observations.append(receipt)
        checks[name + '-canonical-reproduction'] = restored.read_bytes() == Path(compiler).read_bytes()
        executable_source = source.replace(b'v8 selfhost\n', b'v8 selfhost_exec\n', 1)
        executable, receipt = compile_stage(directory, name + '-E1', second,
                                           executable_source, output_extension='.elf')
        observations.append({**receipt, 'inspection': inspect_executable(executable.read_bytes())})
        executable.chmod(0o700)
        receipt, output = execute(directory, name + '-E2-run', executable, executable_source)
        checks[name + '-executable-fixed-point'] = bool(receipt['status'] == 'OWNED_PROCESS_COMPLETED'
            and receipt['returncode'] == 0 and receipt['cleanup']['complete']
            and not receipt['stderr_hex'] and output == executable.read_bytes())
        observations.append(receipt)
        observations.extend(qualify_cfg(directory, [(name, second)], checks,
            {'cases': resources, 'refusals': []}, prefix='resource'))
    return {'checks': checks, 'observations': observations, 'references': references,
            'references_completed_before_native_compilation': True,
            'all_input_correctness_proved': False, 'whole_stack_rewrite_complete': False}
