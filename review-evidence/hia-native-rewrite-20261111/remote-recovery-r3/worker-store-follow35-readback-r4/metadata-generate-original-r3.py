"""Development authoring of the complete fixed public metadata contract in HIA.

The emitted HIA owns selection, constant expansion, SHA-256 and final bytes.
The ten documents are finite language/entry metadata, not program answers.
Catalog digests are deliberately excluded from the constant pool and are
computed by HIA from the exact selected canonical body on every invocation.
"""
from __future__ import annotations
import ast
from hashlib import sha256
import importlib.util
import json
from pathlib import Path
import sys

ROOT = Path(__file__).resolve().parents[1]
BASE = ROOT.parent
REFERENCE = BASE / 'Hepta-agent-edit-native'
sys.path.insert(0, str(REFERENCE))
from hepta.cli import agent_capabilities
from hepta.hia_opcodes import opcode_catalog
from hepta.hia_schema import PRIMITIVE_PROFILES, schema_registry
from hepta.hia_agent_assembly import render_assembly
from tools.generate_hia_sha256 import source_program as hash_source

spec = importlib.util.spec_from_file_location('metadata_authoring', BASE / 'native-edit-controller-next/tools/edit_authoring.py')
authoring = importlib.util.module_from_spec(spec)
spec.loader.exec_module(authoring)


def wire(value):
    return json.dumps(value, sort_keys=True, separators=(',', ':'), ensure_ascii=True, allow_nan=False).encode()


def compress(data):
    """Finite source-constant packing; the runtime decoder is emitted HIA."""
    history, out, literal = {}, bytearray(), bytearray()
    at = 0
    while at < len(data):
        best, position = 0, 0
        for previous in history.get(data[at:at + 4], ())[-48:]:
            count = 4
            while at + count < len(data) and data[previous + count] == data[at + count]:
                count += 1
            if count > best:
                best, position = count, previous
        if best >= 6:
            if literal:
                out.append(len(literal) - 1); out.extend(literal); literal.clear()
            if best <= 130:
                out.append(128 + best - 4)
            else:
                out.append(255); out.extend(best.to_bytes(4, 'little'))
            out.extend(position.to_bytes(4, 'little'))
            advance = best
        else:
            literal.append(data[at]); advance = 1
            if len(literal) == 128:
                out.append(127); out.extend(literal); literal.clear()
        for position in range(at, at + advance):
            key = data[position:position + 4]
            entries = history.setdefault(key, [])
            entries.append(position)
            if len(entries) > 64:
                del entries[:-64]
        at += advance
    if literal:
        out.append(len(literal) - 1); out.extend(literal)
    return bytes(out)


def decompress(data, size):
    at, result = 0, bytearray()
    while at < len(data):
        tag = data[at]; at += 1
        if tag < 128:
            count = tag + 1
            result.extend(data[at:at + count]); at += count
        else:
            count = tag - 128 + 4
            if tag == 255:
                count = int.from_bytes(data[at:at + 4], 'little'); at += 4
            start = int.from_bytes(data[at:at + 4], 'little'); at += 4
            assert start < len(result) and count <= size - len(result)
            for i in range(count):
                result.append(result[start + i])
    assert at == len(data) and len(result) == size
    return bytes(result)


def dataset():
    values = [('entry', agent_capabilities())]
    for schema in PRIMITIVE_PROFILES:
        value = opcode_catalog(schema)
        digest = value.pop('catalog_sha256')
        assert sha256(wire(value)).hexdigest() == digest
        values.append((schema, value))
    registry = schema_registry()
    registry['instruction_catalog']['catalog_sha256'] = '0' * 64
    values.append(('registry', registry))
    raw, rows = bytearray(), []
    for name, value in values:
        payload = wire(value)
        row = dict(name=name, start=len(raw), bytes=len(payload), sha256=sha256(payload).hexdigest())
        if name.startswith('hepta.hia.program.'):
            row['insert_at'] = payload.index(b'"conditional_effects":')
        elif name == 'registry':
            row['digest_at'] = payload.index(b'"catalog_sha256":"') + len(b'"catalog_sha256":"')
            assert payload[row['digest_at']:row['digest_at'] + 64] == b'0' * 64
        raw.extend(payload); rows.append(row)
    packed = compress(bytes(raw))
    assert decompress(packed, len(raw)) == raw
    return bytes(raw), packed, rows


BODY = r'''
def metadata(s:readbuf, r:readbuf, w:mutbuf) -> u32:
    if length(w) < 3072:
        return BAD
    if get(w, 2056) == 2 or get(w, 2056) == 3:
        return BAD
    if get(w, 2056) == 0:
        if length(r) != 96 or word(r, 0) != COMMAND or word(r, 8) != 1:
            return refuse(w, 1)
        if word(r, 16) == 0 or word(r, 24) == 0 or word(r, 48) != length(s):
            return refuse(w, 2)
        if word(r, 32) < 1 or word(r, 32) > 3 or word(r, 40) > 1:
            return refuse(w, 3)
        i = 56
        while i < 96:
            if word(r, i) != 0:
                return refuse(w, 4)
            i = i + 8
        i = 0
        while i < 3072:
            if byte(w, i) != 0:
                return refuse(w, 5)
            i = i + 1
        put(w, 2048, STATE)
        put(w, 2056, 1)
        put(w, 2064, word(r, 16))
        put(w, 2072, word(r, 24))
        put(w, 2080, word(r, 32))
        put(w, 2088, word(r, 40))
        put(w, 2096, length(s))
        if word(r, 32) != 2 and (word(r, 40) != 0 or length(s) != 0):
            return refuse(w, 6)
        version = 8
        if word(r, 32) == 2:
            if word(r, 40) == 0:
                if length(s) != 0:
                    return refuse(w, 7)
            else:
                version = schema_version(s)
                if version == 0:
                    error_text(w)
                    put(w, 2056, 2)
                    return event(w, 2, 2816, ERROR_BYTES, 1)
        put(w, 2104, version)
        copy_source(w, r, 2560, 0, 96)
        copy_source(w, s, 2688, 0, length(s))
    else:
        if get(w, 2048) != STATE or get(w, 2056) != 1:
            return refuse(w, 8)
        if length(r) != 96 or length(s) != get(w, 2096):
            return refuse(w, 9)
        if get(w, 2064) != word(r, 16) or get(w, 2072) != word(r, 24):
            return refuse(w, 14)
        if get(w, 2080) != word(r, 32) or get(w, 2088) != word(r, 40):
            return refuse(w, 15)
        expected = 8
        if word(r, 32) == 2 and word(r, 40) == 1:
            expected = schema_version(s)
        if expected == 0 or get(w, 2104) != expected:
            return refuse(w, 16)
        i = 0
        while i < 96:
            if byte(r, i) != byte(w, 2560 + i):
                return refuse(w, 10)
            i = i + 1
        i = 0
        while i < length(s):
            if byte(s, i) != byte(w, 2688 + i):
                return refuse(w, 11)
            i = i + 1
    if length(w) < REQUIRED:
        return event(w, 1, 0, 0, REQUIRED)
    constants(w)
    if expand(w) == 0:
        return refuse(w, 12)
    selected = get(w, 2104)
    if get(w, 2080) == 1:
        selected = 0
    if get(w, 2080) == 3:
        selected = 8
    select_span(w, selected)
    source = POOL + get(w, 2112)
    size = get(w, 2120)
    if selected != 0:
        if digest(w, source, size) != 32:
            return refuse(w, 13)
    if get(w, 2080) == 3:
        select_span(w, 9)
        source = POOL + get(w, 2112)
        size = get(w, 2120)
        copy_local(w, OUTPUT, source, size)
        hex_digest(w, OUTPUT + REGISTRY_DIGEST)
    else:
        if selected == 0:
            copy_local(w, OUTPUT, source, size)
        else:
            before = get(w, 2128)
            copy_local(w, OUTPUT, source, before)
            hash_field(w, OUTPUT + before)
            hex_digest(w, OUTPUT + before + 18)
            store(w, OUTPUT + before + 82, 34)
            store(w, OUTPUT + before + 83, 44)
            copy_local(w, OUTPUT + before + 84, source + before, size - before)
            size = size + 84
    put(w, 2056, 2)
    return event(w, 0, OUTPUT, size, 0)

def schema_version(s:readbuf) -> u64:
    if length(s) != 20:
        return 0
    if word(s, 0) != 7592917770926978408 or word(s, 8) != 7017844561981833545:
        return 0
    if byte(s, 16) != 109 or byte(s, 17) != 46 or byte(s, 18) != 118:
        return 0
    value = byte(s, 19)
    if value < 49 or value > 56:
        return 0
    return value - 48

def expand(w:mutbuf) -> u64:
    at = 0
    used = 0
    while at < PACKED_BYTES:
        tag = byte(w, PACKED + at)
        at = at + 1
        if tag < 128:
            count = tag + 1
            if count > PACKED_BYTES - at or count > POOL_BYTES - used:
                return 0
            i = 0
            while i < count:
                store(w, POOL + used + i, byte(w, PACKED + at + i))
                i = i + 1
            at = at + count
        else:
            count = tag - 128 + 4
            if tag == 255:
                if PACKED_BYTES - at < 4:
                    return 0
                count = low32(w, PACKED + at)
                at = at + 4
            if PACKED_BYTES - at < 4:
                return 0
            source = low32(w, PACKED + at)
            at = at + 4
            if source >= used or count == 0 or count > POOL_BYTES - used:
                return 0
            i = 0
            while i < count:
                store(w, POOL + used + i, byte(w, POOL + source + i))
                i = i + 1
        used = used + count
    if used != POOL_BYTES:
        return 0
    return 1

def low32(w:mutbuf, at:u64) -> u64:
    return byte(w, at) | (byte(w, at + 1) << 8) | (byte(w, at + 2) << 16) | (byte(w, at + 3) << 24)

def copy_local(w:mutbuf, target:u64, source:u64, count:u64) -> u64:
    i = 0
    while i < count:
        store(w, target + i, byte(w, source + i))
        i = i + 1
    return 0

def copy_source(w:mutbuf, s:readbuf, target:u64, source:u64, count:u64) -> u64:
    i = 0
    while i < count:
        store(w, target + i, byte(s, source + i))
        i = i + 1
    return 0

def word(s:readbuf, at:u64) -> u64:
    value = 0
    i = 0
    while i < 8:
        value = value | (byte(s, at + i) << (i * 8))
        i = i + 1
    return value

def event(w:mutbuf, action:u64, at:u64, count:u64, detail:u64) -> u32:
    i = 2304
    while i < 2432:
        store(w, i, 0)
        i = i + 1
    put(w, 2304, EVENT)
    put(w, 2312, action)
    put(w, 2320, get(w, 2064))
    put(w, 2328, get(w, 2072))
    put(w, 2336, get(w, 2080))
    put(w, 2344, at)
    put(w, 2352, count)
    put(w, 2360, detail)
    if action == 1:
        return GROW
    return 128

def refuse(w:mutbuf, reason:u64) -> u32:
    put(w, 2048, STATE)
    put(w, 2056, 3)
    event(w, 3, 0, 0, reason)
    return BAD

def hex_digest(w:mutbuf, at:u64) -> u64:
    i = 0
    while i < 32:
        value = byte(w, 1152 + i)
        store(w, at + i * 2, hex_digit(value >> 4))
        store(w, at + i * 2 + 1, hex_digit(value & 15))
        i = i + 1
    return 0

def hex_digit(value:u64) -> u64:
    if value < 10:
        return value + 48
    return value + 87
'''


def local_digest_source():
    """Only source delivery/output locations change from retained HIA SHA."""
    tree = ast.parse(hash_source())
    entry = tree.body[0]
    entry.name = 'digest'
    entry.returns = ast.Name(id='u64', ctx=ast.Load())
    entry.args = ast.parse('def f(w:mutbuf, start:u64, count:u64): pass').body[0].args
    # The service owns both disjoint input and SHA scratch regions in one buffer.
    entry.body[0] = ast.parse('if start < 4096 or start > length(w) or count > length(w) - start or count > 8388608: return 4294967293').body[0]
    padded = next(n for n in tree.body if n.name == 'padded_byte')
    padded.args = ast.parse('def f(w:mutbuf, start:u64, count:u64, index:u64, total:u64): pass').body[0].args
    class Adapt(ast.NodeTransformer):
        def visit_Call(self, node):
            if isinstance(node.func, ast.Name):
                if node.func.id == 'length' and isinstance(node.args[0], ast.Name) and node.args[0].id == 's':
                    return ast.copy_location(ast.Name(id='count', ctx=ast.Load()), node)
                if node.func.id == 'byte' and isinstance(node.args[0], ast.Name) and node.args[0].id == 's':
                    return ast.copy_location(ast.parse('byte(w, start + index)').body[0].value, node)
                if node.func.id == 'padded_byte':
                    node.args = [ast.Name(id='w', ctx=ast.Load()), ast.Name(id='start', ctx=ast.Load()), ast.Name(id='count', ctx=ast.Load())] + node.args[1:]
                if node.func.id == 'store' and isinstance(node.args[0], ast.Name) and node.args[0].id == 'o':
                    node.args[0] = ast.Name(id='w', ctx=ast.Load())
                    node.args[1] = ast.BinOp(left=ast.Constant(1152), op=ast.Add(), right=node.args[1])
            return self.generic_visit(node)
    tree = ast.fix_missing_locations(Adapt().visit(tree))
    return ast.unparse(tree) + '\n'


def store_text(name, text, destination):
    raw = text.encode()
    lines = [f'def {name}(w:mutbuf' + (', at:u64' if destination is None else '') + ') -> u64:']
    at = 'at' if destination is None else str(destination)
    for i in range(0, len(raw) // 8 * 8, 8):
        lines.append(f'    put(w, {at} + {i}, {int.from_bytes(raw[i:i + 8], "little")})')
    for i in range(len(raw) // 8 * 8, len(raw)):
        lines.append(f'    store(w, {at} + {i}, {raw[i]})')
    lines.append('    return 0')
    return '\n'.join(lines) + '\n'


def document():
    raw, packed, rows = dataset()
    pool = (4096 + len(packed) + 63) & ~63
    output = (pool + len(raw) + 63) & ~63
    required = output + max(row['bytes'] + 84 for row in rows)
    constants = dict(COMMAND=int.from_bytes(b'HIAPMC01', 'little'), STATE=int.from_bytes(b'HIAPMW01', 'little'),
                     EVENT=int.from_bytes(b'HIAPME01', 'little'), BAD=0xfffffffd, GROW=0xfffffffe,
                     PACKED=4096, PACKED_BYTES=len(packed), POOL=pool, POOL_BYTES=len(raw),
                     OUTPUT=output, REQUIRED=required, REGISTRY_DIGEST=rows[9]['digest_at'],
                     ERROR_BYTES=len('catalog requires an exact primitive schema'))
    source = BODY
    source += 'def select_span(w:mutbuf, selected:u64) -> u64:\n'
    for i, row in enumerate(rows):
        source += f'    if selected == {i}:\n        put(w, 2112, {row["start"]})\n        put(w, 2120, {row["bytes"]})\n        put(w, 2128, {row.get("insert_at", 0)})\n        return 0\n'
    source += '    return 1\n'
    source += store_text('hash_field', '"catalog_sha256":"', None)
    source += store_text('error_text', 'catalog requires an exact primitive schema', 2816)
    padded = packed + b'\0' * (-len(packed) % 8)
    pieces = [padded[i:i + 512] for i in range(0, len(padded), 512)]
    source += 'def constants(w:mutbuf) -> u64:\n'
    for i in range(len(pieces)):
        source += f'    constants_{i}(w)\n'
    source += '    return 0\n'
    for i, piece in enumerate(pieces):
        source += f'def constants_{i}(w:mutbuf) -> u64:\n'
        for j in range(0, len(piece), 8):
            source += f'    put(w, {4096 + i * 512 + j}, {int.from_bytes(piece[j:j + 8], "little")})\n'
        source += '    return 0\n'
    source += local_digest_source()
    # Derive the three exact prefix words, rather than transcribing magic numbers.
    source = source.replace('7592917770926978408', str(int.from_bytes(b'hepta.hi', 'little')))
    source = source.replace('7017844561981833545', str(int.from_bytes(b'a.progra', 'little')))
    expanded = authoring.source(source, constants, 'metadata')
    value = authoring.document(expanded, 'agent_program_metadata')
    # Retain the compiler's exact R/W/W flat entry. The second loan is read-only
    # inside the owner and the wrapper ends it before returning.
    for function in value['functions']:
        function['name'] = 'f' + str(int(function['name'][1:]) + 1)
        for block in function['blocks']:
            for operation in block['ops']:
                if operation['op'] == 'call':
                    name = operation['attrs']['function']
                    operation['attrs']['function'] = 'f' + str(int(name[1:]) + 1)
    params = [{'name':'v0', 'type':'readbuf'}, {'name':'v1', 'type':'mutbuf'}, {'name':'v2', 'type':'mutbuf'}]
    wrapper = dict(name='f0', params=params, returns=['u32'], effects=['read','write','trap'], entry='b0', blocks=[
        dict(id='b0', params=params, ops=[
            dict(op='borrow.read', args=['v1'], out=[{'name':'v3','type':'readbuf'}], attrs={}),
            dict(op='call', args=['v0','v3','v2'], out=[{'name':'v4','type':'u32'}], attrs={'function':'f1'}),
            dict(op='loan.end', args=['v3'], out=[], attrs={})], term={'op':'ret','values':['v4']})])
    value['functions'].insert(0, wrapper)
    profile = dict(functions=len(value['functions']), blocks=sum(len(f['blocks']) for f in value['functions']),
                   max_blocks=max(len(f['blocks']) for f in value['functions']),
                   instructions=sum(len(b['ops']) for f in value['functions'] for b in f['blocks']),
                   max_block_params=max(len(b['params']) for f in value['functions'] for b in f['blocks']))
    metadata = dict(schema='hia-native-fixed-metadata-source.v1', constants=constants, rows=rows,
                    packed_bytes=len(packed), packed_sha256=sha256(packed).hexdigest(),
                    expanded_bytes=len(raw), expanded_sha256=sha256(raw).hexdigest(),
                    source_bound_original_reference=True, catalog_hashes_embedded=False,
                    profile=profile, whole_stack_closed=False)
    return value, expanded, metadata


if __name__ == '__main__':
    value, expanded, metadata = document()
    target = ROOT / 'examples/hia_bootstrap/agent_program_metadata.hiaasm'
    target.parent.mkdir(parents=True, exist_ok=True)
    (ROOT / 'development').mkdir(exist_ok=True)
    target.write_text(render_assembly(value))
    (ROOT / 'development/metadata-authoring-r1.py').write_text(expanded)
    (ROOT / 'development/metadata-source-r1.json').write_text(json.dumps(metadata, indent=2, sort_keys=True) + '\n')
    print(json.dumps(dict(source_bytes=target.stat().st_size, **metadata), sort_keys=True), flush=True)
