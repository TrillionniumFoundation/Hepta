"""Author the native worker manifest framer and its independently pinned tables.

This module is an authoring/reference tool. The emitted HIA leaf consumes only
the HIAWMF01 frame; it has no Python, filesystem, JSON-library or compiler calls.
"""
from __future__ import annotations

import argparse
import ast
import copy
from dataclasses import dataclass, field
from hashlib import sha256
import importlib
import json
from pathlib import Path
import re
import struct

from tools.generate_hia_direct_load_plan import LinkerBuilder
from tools.generate_hia_selfhost import compact_authoring_cfg, total_scalar_functions
from tools.generate_hia_sha256_stream import source_program
from tools.generate_hia_sha256 import INITIAL, ROUND
from hepta.hia_agent_assembly import render_assembly

ROOT = Path(__file__).resolve().parents[1]
SOURCE_PATH = 'examples/hia_bootstrap/source_worker_manifest.hepta'
TABLE_PATH = 'examples/hia_bootstrap/worker_manifest_tables.hiastd'
MODEL_PATH = 'docs/HIA_WORKER_MANIFEST_RECORDS.json'
MASK = re.compile(r'__HIA_WMF_SLOT_([0-9]+)__')
SUBSTITUTION = re.compile(r'__HIA_WMF_SLOT_([0-9]+)__|__HIA_WMF_SOURCE_([0-9]+)_([0-9a-f]+)__')


@dataclass
class Recipe:
    mode: int
    role: int
    pieces: list[str]
    slots: list[tuple[int, int, bytes]] = field(default_factory=list)
    operations: list[tuple[int, object]] = field(default_factory=list)
    validators: list[tuple[int, int, int, int, bytes]] = field(default_factory=list)
    compiler_slot: int | None = None
    output_path: str = ''

    def slot(self, kind: int, piece: int, extra: bytes = b'') -> str:
        item = (kind, piece, extra)
        if item not in self.slots:
            self.slots.append(item)
        return '__HIA_WMF_SLOT_' + str(self.slots.index(item)) + '__'

    def digest(self, piece: int) -> str:
        return self.slot(1, piece)

    def raw_pin(self, piece: int) -> str:
        return self.slot(2, piece)

    def source_pin(self, piece: int, path: str) -> str:
        return self.slot(3, piece, path.encode('ascii'))

    def streamed_source_pin(self, piece: int, path: str) -> str:
        # The native authority can have more paths than the unchanged 512
        # temporary slots. Read each pin from the admitted inventory at render
        # time instead of storing another copy in a per-field temporary slot.
        return '__HIA_WMF_SOURCE_' + str(piece) + '_' + path.encode('ascii').hex() + '__'

    def bounds(self, piece: int, low: int, high: int) -> None:
        self.validators.append((1, piece, low, high, b''))

    def exact_digest(self, piece: int, digest: str) -> None:
        self.validators.append((2, piece, 0, 0, bytes.fromhex(digest)))

    def child(self, piece: int, mode: int, role: int) -> None:
        self.validators.append((3, piece, mode, role, b''))

    def same_compiler(self, first: int, second: int) -> None:
        self.validators.append((4, first, second, 0, b''))

    def child_exact_slot(self, piece: int, slot: int, digest: str) -> None:
        self.validators.append((5, piece, slot, 0, bytes.fromhex(digest)))

    def child_digest_slot(self, piece: int, slot: int, other: int) -> None:
        self.validators.append((6, piece, slot, other, b''))

    def json(self, value: dict) -> None:
        source = json.dumps(value, sort_keys=True, indent=2) + '\n'
        position = 0
        for match in SUBSTITUTION.finditer(source):
            if match.start() != position:
                self.operations.append((0, source[position:match.start()].encode()))
            if match[1] is not None:
                self.operations.append((1, int(match[1])))
            else:
                self.operations.append((4, struct.pack('<Q', int(match[2])) + bytes.fromhex(match[3])))
            position = match.end()
        if position != len(source):
            self.operations.append((0, source[position:].encode()))

    def encode(self) -> bytes:
        slots = b''.join(struct.pack('<3Q', kind, piece, len(extra)) + extra
                         for kind, piece, extra in self.slots)
        operations = b''
        for kind, value in self.operations:
            if kind in (0, 4):
                assert isinstance(value, bytes) and value
                operations += struct.pack('<2Q', kind, len(value)) + value
            else:
                operations += struct.pack('<2Q', kind, value)
        tests = b''.join(struct.pack('<5Q', tag, a, b, c, len(data)) + data
                         for tag, a, b, c, data in self.validators)
        body = slots + operations + tests
        flags = 0 if self.compiler_slot is None else self.compiler_slot + 1
        return struct.pack('<8Q', self.mode, self.role, len(self.pieces),
                           len(self.slots), len(self.operations), len(self.validators),
                           64 + len(body), flags) + body


def model(root: Path, native_source_authority=None) -> dict:
    from tools.build_hia_worker_release import INSTALLED_HELPERS, ADDITIONAL_HELPERS
    from tools.build_hia_json_preflight import CANDIDATES
    from hepta import hia_native_helpers as authority
    from hepta.hia_agent_contract import CONTINUATION_BUILD_FILES
    from hepta.hia_worker_scheduling_bundle import FAMILIES
    helpers = []
    for number, candidate in enumerate((*INSTALLED_HELPERS, *ADDITIONAL_HELPERS), 1):
        source, protocol = CANDIDATES.get(candidate, (candidate.replace('-', '_'), candidate))
        image = candidate + '.image.bin'
        if candidate in ('sha256-stream', 'native-build-admission'):
            image = candidate.replace('-', '_') + '.image.bin'
        schema = ('hepta.hia.native-build-admission.v1' if candidate == 'native-build-admission'
                  else 'hepta.hia.' + protocol + '-native.v' + ('2' if candidate == 'agent-journal' else '1'))
        helpers.append(dict(role=number, name=candidate,
            source='examples/hia_bootstrap/' + source + '.hepta', image_path=image,
            schema=schema, installed=number <= len(INSTALLED_HELPERS)))
    families = []
    ordinal = 1
    for number, (family, (module, _)) in enumerate(FAMILIES.items(), 1):
        selected = importlib.import_module('hepta.hia_' + module + '_selection')
        raw = (root / selected.ABI_SOURCE).read_bytes()
        abi = selected.checked_abi(raw)
        units = []
        for name in (module + '_pool', *abi['units']):
            units.append(dict(role=ordinal, name=name,
                source='examples/hia_bootstrap/' + name + '.hepta',
                image_path=name + '.image.bin', schema=selected.UNIT_SCHEMA))
            ordinal += 1
        families.append(dict(role=number, name=family, module=module,
            abi_source=selected.ABI_SOURCE, abi_sha256=sha256(raw).hexdigest(),
            schema=selected.SCHEMA, unit_schema=selected.UNIT_SCHEMA,
            units=units, abi=abi))
    result = dict(helpers=helpers, families=families,
        helpers_schema=authority.SCHEMA, target=authority.TARGET, abi=authority.ABI,
        continuation_resources=list(CONTINUATION_BUILD_FILES),
        continuation_runtime=['hepta/hia_native_continuation.py',
            'hepta/hia_native_continuation_selection.py',
            'hepta/hia_native_continuation_inprocess.py',
            'hepta/hia_native_helpers.py', 'hepta/hia_core_lowering_native.py'],
        runtime_files=sorted('hepta/' + p.name for p in (root / 'hepta').glob('*.py')))
    if native_source_authority is not None:
        from tools.hia_native_worker_source_authority import native_model
        return native_model(result, native_source_authority)
    return result


def image_recipe(mode: int, role: int, schema: str, image: str, output: str) -> Recipe:
    r = Recipe(mode, role, ['source', 'image', 'compiler'], output_path=output)
    for i in range(3):
        r.bounds(i, 1, 1 << 20)
    compiler, image_pin, source = r.digest(2), r.digest(1), r.digest(0)
    r.compiler_slot = 0
    r.json(dict(compiler_sha256=compiler, image_path=image, image_sha256=image_pin,
                schema=schema, source_sha256=source))
    return r


def recipes(m: dict) -> list[Recipe]:
    result = []
    for h in m['helpers']:
        result.append(image_recipe(1, h['role'], h['schema'], h['image_path'],
                                   h['name'] + '/manifest.json'))
    r = Recipe(2, 0, ['package_sha256_raw32', *[h['name'] + '_manifest' for h in m['helpers']]],
               output_path='helpers.json')
    r.bounds(0, 32, 32)
    package = r.raw_pin(0)
    helpers = []
    for i, h in enumerate(m['helpers'], 1):
        r.bounds(i, 1, 8192)
        r.child(i, 1, h['role'])
        if i != 1:
            r.same_compiler(i, 1)
        helpers.append(dict(selector='HEPTA_HIA_' + h['name'].replace('-', '_').upper() + '_MANIFEST',
            manifest_path=('store/' + package + '/' + h['name'] + '-manifest.json')
                if h['installed'] else h['name'] + '/manifest.json',
            manifest_sha256=r.digest(i)))
    r.json(dict(schema=m['helpers_schema'], target=m['target'], abi=m['abi'], helpers=helpers))
    result.append(r)

    reports = [('policy', 'worker-report'), ('wire', 'json-wire')]
    for i, (name, protocol) in enumerate(reports, 1):
        result.append(image_recipe(3, i, 'hepta.hia.' + protocol + '-native.v1',
                                   protocol + '.image.bin', 'report/' + name + '/manifest.json'))
    r = Recipe(4, 0, ['policy_manifest', 'wire_manifest'], output_path='report/manifest.json')
    for i in range(2):
        r.bounds(i, 1, 8192)
        r.child(i, 3, i + 1)
    r.same_compiler(0, 1)
    r.json(dict(schema='hepta.hia.worker-report-bundle.v1',
        policy_manifest='policy/manifest.json', policy_manifest_sha256=r.digest(0),
        wire_manifest='wire/manifest.json', wire_manifest_sha256=r.digest(1)))
    result.append(r)

    r = Recipe(5, 0, ['helpers_json', 'report_manifest'], output_path='report.json')
    r.bounds(0, 1, 1 << 20)
    r.bounds(1, 1, 8192)
    r.child(0, 2, 0)
    r.child(1, 4, 0)
    r.json(dict(schema='hepta.hia.native-helpers.v2', target=m['target'], abi=m['abi'],
        helpers_bundle='helpers.json', helpers_bundle_sha256=r.digest(0),
        report_bundle='report/manifest.json', report_bundle_sha256=r.digest(1)))
    result.append(r)

    for f in m['families']:
        for unit in f['units']:
            result.append(image_recipe(6, unit['role'], unit['schema'], unit['image_path'],
                f['name'] + '/policy/' + unit['name'] + '/manifest.json'))
        r = Recipe(7, f['role'], ['abi', 'compiler', *[u['name'] + '_manifest' for u in f['units']]],
            output_path=f['name'] + '/policy/manifest.json')
        r.bounds(0, 1, 1 << 20)
        r.bounds(1, 1, 1 << 20)
        r.exact_digest(0, f['abi_sha256'])
        for i, unit in enumerate(f['units'], 2):
            r.bounds(i, 1, 8192)
            r.child(i, 6, unit['role'])
            r.child_digest_slot(i, 0, 1)
        abi, compiler = r.digest(0), r.digest(1)
        r.compiler_slot = 1
        r.json(dict(schema=f['schema'], abi_sha256=abi, compiler_sha256=compiler,
            unit_manifests={u['name']: u['name'] + '/manifest.json' for u in f['units']}))
        result.append(r)

        r = Recipe(8, f['role'], ['policy_manifest', 'compiler', 'inprocess_image', 'source_inventory_HIASPI01'],
            output_path=f['name'] + '/inprocess-manifest.json')
        r.bounds(0, 1, 1 << 20)
        r.bounds(1, 1, 1 << 20)
        r.bounds(2, 177, 64 << 20)
        r.bounds(3, 16, 1 << 20)
        r.child(0, 7, f['role'])
        r.child_exact_slot(0, 0, f['abi_sha256'])
        r.child_digest_slot(0, 1, 1)
        r.validators.append((7, 2, 0, 0, b''))
        compiler, image, policy = r.digest(1), r.digest(2), r.digest(0)
        r.compiler_slot = 0
        r.json(dict(schema='hepta.hia.native-continuation-inprocess.v1', kind=f['name'],
            compiler_sha256=compiler, image_path='continuation.image.bin', image_sha256=image,
            policy_bundle='policy/manifest.json', policy_bundle_sha256=policy,
            resource_sha256={p: r.source_pin(3, p) for p in m['continuation_resources']},
            runtime_sha256={p: r.source_pin(3, p) for p in m['continuation_runtime']}))
        result.append(r)

    r = Recipe(9, 0, ['report_json', *[f['name'] + '_manifest' for f in m['families']], 'source_inventory_HIASPI01'],
        output_path='schedulers.json')
    for i in range(6):
        r.bounds(i, 1, 1 << 20)
    r.bounds(6, 16, 1 << 20)
    r.child(0, 5, 0)
    for i, f in enumerate(m['families'], 1):
        r.child(i, 8, f['role'])
        if i != 1:
            r.same_compiler(i, 1)
    value = dict(schema='hepta.hia.native-helpers.v3', target=m['target'], abi=m['abi'],
        base_bundle='report.json', base_bundle_sha256=r.digest(0),
        runtime_sha256={p: (r.streamed_source_pin(6, p) if 'native_source_authority' in m else r.source_pin(6, p)) for p in m['runtime_files']},
        schedulers=[dict(kind=f['name'], manifest_path=f['name'] + '/inprocess-manifest.json',
            manifest_sha256=r.digest(i)) for i, f in enumerate(m['families'], 1)])
    r.json(value)
    result.append(r)

    for f in m['families']:
        abi = f['abi']
        r = Recipe(10, f['role'], ['abi', 'continuation_policy', *[u['name'] + '_image' for u in f['units']]],
            output_path='HIACTPK1 aggregate frame')
        for i in range(len(r.pieces)):
            r.bounds(i, 1, 1 << 20)
        r.exact_digest(0, f['abi_sha256'])
        modes = sorted(abi['modes'].values(), key=lambda row: row['number'])
        r.operations.extend([(0, b'HIACTPK1'), (3, 1),
            (0, struct.pack('<6Q', len(f['units']) - 1, abi['workspace_bytes'], abi['output_bytes'],
                            abi['pool_bytes'], abi['literal_count'], len(modes))), (3, 2)])
        for i in range(3, len(r.pieces)):
            r.operations.append((3, i))
        r.operations.append((0, b''.join(struct.pack('<2Q', row['number'], row['arity']) for row in modes)))
        for i in range(1, len(r.pieces)):
            r.operations.append((2, i))
        result.append(r)
    assert len({(r.mode, r.role) for r in result}) == len(result)
    return result


def sha_source() -> str:
    nodes = [n for n in ast.parse(source_program()).body if n.name != 'stream']
    names = {n.name: 'sha_' + n.name for n in nodes}
    class RenameSHA(ast.NodeTransformer):
        def visit_FunctionDef(self, node):
            node = copy.deepcopy(node)
            node.name = names[node.name]
            return self.generic_visit(node)
        def visit_Call(self, node):
            node = self.generic_visit(node)
            if isinstance(node.func, ast.Name):
                name = node.func.id
                if name in ('byte', 'store', 'word_load') and isinstance(node.args[0], ast.Name) and node.args[0].id == 'w':
                    node.args[1] = ast.BinOp(left=ast.Constant(value=524288), op=ast.Add(), right=node.args[1])
                if name in names:
                    node.func.id = names[name]
            return node
    helpers = '\n\n'.join(ast.unparse(ast.fix_missing_locations(RenameSHA().visit(n))) for n in nodes)
    init = 'def digest_init(w:mutbuf) -> u64:\n'
    for i, value in enumerate(ROUND):
        init += f'    sha_put(w, {i * 8}, {value})\n'
    for i, value in enumerate(INITIAL):
        init += f'    sha_put(w, {1024 + i * 8}, {value})\n'
    init += '    return 0\n'
    return '\n' + helpers + '\n' + init + '''
def digest_feed(s:readbuf, w:mutbuf, start:u64, count:u64) -> u64:
    used = 0
    i = 0
    while i < count:
        store(w, 525400 + used, byte(s, start + i))
        used = used + 1
        if used == 64:
            sha_compress(w)
            used = 0
        i = i + 1
    return 0

def digest_finish(o:mutbuf, w:mutbuf, count:u64) -> u64:
    used = count & 63
    store(w, 525400 + used, 128)
    used = used + 1
    while used != 56:
        if used == 64:
            sha_compress(w)
            used = 0
        else:
            store(w, 525400 + used, 0)
            used = used + 1
    bits = count << 3
    i = 0
    while i < 8:
        store(w, 525456 + i, (bits >> ((7 - i) * 8)) & 255)
        i = i + 1
    sha_compress(w)
    i = 0
    while i < 8:
        value = sha_get(w, 1024 + i * 8)
        j = 0
        while j < 4:
            store(o, i * 4 + j, (value >> ((3 - j) * 8)) & 255)
            j = j + 1
        i = i + 1
    return 0

def digest(s:readbuf, o:mutbuf, w:mutbuf, start:u64, count:u64) -> u64:
    digest_init(w)
    digest_feed(s, w, start, count)
    return digest_finish(o, w, count)
'''


def native_source_policy(source: str) -> str:
    """Add an inventory-backed pin output operation without changing budgets.

    The existing child-manifest shape validator intentionally retains its
    original accepted operation set. The source-map stream is only the final
    mode-9 schedulers output, never an unvalidated child-manifest passthrough.
    """
    layout_old = '''        elif kind == 2 or kind == 3:
            if value >= uint(s, record + 16, 8):
                return 0
        else:
            return 0'''
    layout_new = '''        elif kind == 2 or kind == 3:
            if value >= uint(s, record + 16, 8):
                return 0
        elif kind == 4:
            if value < 9 or value > 4103 or value > limit - cursor:
                return 0
            if uint(s, cursor, 8) >= uint(s, record + 16, 8) or relative(s, cursor + 8, value - 8) == 0:
                return 0
            cursor = cursor + value
        else:
            return 0'''
    render_old = '''        elif kind == 2:
            n = piece_size(w, value)
            if n > length(o) - out:
                return 0
            copy(s, o, out, piece(w, value), n)
            out = out + n
        else:
            if 8 > length(o) - out:'''
    render_new = '''        elif kind == 2:
            n = piece_size(w, value)
            if n > length(o) - out:
                return 0
            copy(s, o, out, piece(w, value), n)
            out = out + n
        elif kind == 4:
            pin = source_pin(s, w, uint(s, cursor, 8), cursor + 8, value - 8)
            if pin == 0 or 64 > length(o) - out:
                return 0
            j = 0
            while j < 32:
                ch = byte(s, pin + j)
                store(o, out + j * 2, hex_digit(ch >> 4))
                store(o, out + j * 2 + 1, hex_digit(ch & 15))
                j = j + 1
            out = out + 64
            cursor = cursor + value
        else:
            if 8 > length(o) - out:'''
    for old, new in ((layout_old, layout_new), (render_old, render_new)):
        if source.count(old) != 1:
            raise ValueError('native source stream transformation does not match the frozen manifest owner')
        source = source.replace(old, new)
    return source


def current_model(root: Path, native_source_authority=None) -> dict:
    from tools.build_hia_worker_release import EXTENDED_INSTALLED_HELPERS
    from tools.build_hia_json_preflight import CANDIDATES, image_manifest_schema
    result = model(root)
    for _, candidate in EXTENDED_INSTALLED_HELPERS:
        source, protocol = CANDIDATES[candidate]
        result['helpers'].append(dict(
            role=len(result['helpers']) + 1, name=candidate,
            source='examples/hia_bootstrap/' + source + '.hepta',
            image_path=protocol + '.image.bin',
            schema=image_manifest_schema(candidate, protocol), installed=True))
    if native_source_authority is not None:
        from tools.hia_native_worker_source_authority import native_model
        return native_model(result, native_source_authority)
    return result


def render(root: Path, native_source_authority=None, *, helper_extensions=False):
    m = current_model(root, native_source_authority) if helper_extensions else model(root, native_source_authority)
    entries = recipes(m)
    if native_source_authority is not None:
        for recipe in entries:
            if (len(recipe.slots) > 512 or not 1 <= len(recipe.operations) <= 4096
                    or len(recipe.validators) > 512):
                raise ValueError('native source authority exceeds the unchanged manifest recipe budget')
    payload = b''.join(r.encode() for r in entries)
    table_magic = b'HIAWMT02' if helper_extensions else b'HIAWMT01'
    request_magic = b'HIAWMF02' if helper_extensions else b'HIAWMF01'
    table = struct.pack('<8s3Q', table_magic, 1, len(entries), 32 + len(payload)) + payload
    if len(table) > 1048576:
        raise ValueError('Worker manifest table exceeds the original 1 MiB budget')
    pin = sha256(table).digest()
    source = POLICY_SOURCE if native_source_authority is None else native_source_policy(POLICY_SOURCE)
    for name, value in dict(MAGIC_REQUEST=request_magic, MAGIC_TABLE=table_magic,
                            MAGIC_SPI=b'HIASPI01', MAGIC_INPROCESS=b'HIAINP01').items():
        source = source.replace(name, str(int.from_bytes(value, 'little')))
    source += '\ndef table_pin(o:mutbuf) -> u64:\n'
    for offset in range(0, 32, 8):
        source += f'    if get(o, {offset}) != {int.from_bytes(pin[offset:offset+8], "little")}:\n        return 0\n'
    source += '    return 1\n' + sha_source()
    nodes = ast.parse(source).body
    names = {node.name: 'f' + str(i) for i, node in enumerate(nodes)}
    assert len(names) == len(nodes)
    signatures = {n.name: ([a.annotation.id for a in n.args.args], n.returns.id) for n in nodes}
    total = total_scalar_functions(nodes)
    functions = []
    for node in nodes:
        b = LinkerBuilder(node, names, signatures, total)
        b.statements(node.body)
        functions.append(dict(name=names[node.name], params=[b.param(a) for a in b.params],
            returns=[b.returns], effects=['read', 'write', 'trap'], entry='b0', blocks=b.blocks))
    document = compact_authoring_cfg(dict(schema='hepta.hia.program.v9',
        module='source_worker_manifest_current' if helper_extensions else 'source_worker_manifest', functions=functions))
    assembly = render_assembly(document)
    spec = dict(schema='hepta.hia.worker-manifest-records.v2' if helper_extensions else 'hepta.hia.worker-manifest-records.v1', request=request_magic.decode('ascii'),
        table_path=TABLE_PATH, table_sha256=pin.hex(), table_bytes=len(table),
        source_path=SOURCE_PATH, source_sha256=sha256(assembly.encode()).hexdigest(),
        table_piece='Append the exact tables bytes as the last length-prefixed piece in every request.',
        sources=m, records=[dict(mode=r.mode, role=r.role, pieces=[*r.pieces, 'tables'],
            output=r.output_path, slot_count=len(r.slots), validator_count=len(r.validators)) for r in entries])
    stats = dict(functions=len(functions), blocks=sum(len(f['blocks']) for f in document['functions']),
        instructions=sum(len(b['ops']) for f in document['functions'] for b in f['blocks']),
        max_blocks=max(len(f['blocks']) for f in document['functions']),
        max_parameters=max(len(b['params']) for f in document['functions'] for b in f['blocks']),
        source_bytes=len(assembly.encode()), table_bytes=len(table), recipes=len(entries), table_sha256=pin.hex())
    return assembly, table, spec, stats


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--check', action='store_true')
    parser.add_argument('--native-source-authority', type=Path)
    args = parser.parse_args()
    source, table, spec, stats = render(ROOT, args.native_source_authority)
    products = {SOURCE_PATH: source.encode(), TABLE_PATH: table,
                MODEL_PATH: (json.dumps(spec, sort_keys=True, indent=2) + '\n').encode()}
    for name, data in products.items():
        path = ROOT / name
        if args.check:
            if not path.is_file() or path.read_bytes() != data:
                raise SystemExit('generated worker manifest source differs: ' + name)
        else:
            path.write_bytes(data)
    print(json.dumps(stats, sort_keys=True))


POLICY_SOURCE = r"""
def entry(s:readbuf, o:mutbuf, w:mutbuf) -> u32:
    if length(w) < 1114112 or length(o) < 1048576:
        return 17
    phase = get(w, 0)
    mode = get(w, 16)
    if phase == 0 and mode == 0:
        if length(s) != 21 or uint(s, 0, 8) != 1 or uint(s, 8, 8) != 5 or uint(s, 16, 5) != 431315580258:
            return 16
        put(w, 16, 1)
        return 0
    if phase == 2 and mode == 3:
        return 3
    if phase != 1 or mode != 1:
        return 16
    if request(s, o, w) == 0:
        return 16
    n = render(s, o, w)
    if n == 0:
        return 16
    put(w, 88, n)
    put(w, 16, 3)
    return 0

def request(s:readbuf, o:mutbuf, w:mutbuf) -> u64:
    if length(s) < 40 or length(s) > 67108864 or uint(s, 0, 8) != MAGIC_REQUEST:
        return 0
    count = uint(s, 24, 8)
    if count < 2 or count > 64:
        return 0
    put(w, 128, count - 1)
    cursor = 32
    i = 0
    while i < count:
        if cursor + 8 > length(s):
            return 0
        n = uint(s, cursor, 8)
        cursor = cursor + 8
        if n == 0 or n > length(s) - cursor:
            return 0
        put(w, 1024 + i * 16, cursor)
        put(w, 1032 + i * 16, n)
        put(w, 3072 + i * 8, 0)
        cursor = cursor + n
        i = i + 1
    if cursor != length(s):
        return 0
    table = piece(w, count - 1)
    size = piece_size(w, count - 1)
    if size < 32 or size > 1048576:
        return 0
    digest(s, o, w, table, size)
    if table_pin(o) == 0:
        return 0
    if uint(s, table, 8) != MAGIC_TABLE or uint(s, table + 8, 8) != 1 or uint(s, table + 24, 8) != size:
        return 0
    put(w, 136, table)
    put(w, 144, size)
    put(w, 232, 0)
    put(w, 248, 0)
    record = lookup(s, w, uint(s, 8, 8), uint(s, 16, 8))
    if record == 0 or uint(s, record + 16, 8) != count - 1:
        return 0
    put(w, 152, record)
    if layout(s, w, record, 512) == 0:
        return 0
    if validators(s, o, w) == 0:
        return 0
    return slots(s, o, w)

def lookup(s:readbuf, w:mutbuf, mode:u64, role:u64) -> u64:
    start = get(w, 136)
    limit = start + get(w, 144)
    count = uint(s, start + 16, 8)
    if count == 0 or count > 256:
        return 0
    cursor = start + 32
    i = 0
    while i < count:
        if cursor + 64 > limit:
            return 0
        n = uint(s, cursor + 48, 8)
        if n < 64 or n > limit - cursor:
            return 0
        if uint(s, cursor, 8) == mode and uint(s, cursor + 8, 8) == role:
            return cursor
        cursor = cursor + n
        i = i + 1
    return 0

def layout(s:readbuf, w:mutbuf, record:u64, base:u64) -> u64:
    slots_n = uint(s, record + 24, 8)
    ops_n = uint(s, record + 32, 8)
    tests_n = uint(s, record + 40, 8)
    limit = record + uint(s, record + 48, 8)
    if slots_n > 512 or ops_n == 0 or ops_n > 4096 or tests_n > 512:
        return 0
    cursor = record + 64
    put(w, base, cursor)
    put(w, base + 24, slots_n)
    put(w, base + 32, ops_n)
    put(w, base + 40, tests_n)
    put(w, base + 48, limit)
    put(w, base + 56, uint(s, record + 56, 8))
    i = 0
    while i < slots_n:
        if cursor + 24 > limit:
            return 0
        kind = uint(s, cursor, 8)
        n = uint(s, cursor + 16, 8)
        if kind < 1 or kind > 3 or n > 4095 or n > limit - cursor - 24:
            return 0
        if uint(s, cursor + 8, 8) >= uint(s, record + 16, 8):
            return 0
        if (kind == 3 and n == 0) or (kind != 3 and n != 0):
            return 0
        cursor = cursor + 24 + n
        i = i + 1
    put(w, base + 8, cursor)
    i = 0
    while i < ops_n:
        if cursor + 16 > limit:
            return 0
        kind = uint(s, cursor, 8)
        value = uint(s, cursor + 8, 8)
        cursor = cursor + 16
        if kind == 0:
            if value == 0 or value > limit - cursor:
                return 0
            cursor = cursor + value
        elif kind == 1:
            if value >= slots_n:
                return 0
        elif kind == 2 or kind == 3:
            if value >= uint(s, record + 16, 8):
                return 0
        else:
            return 0
        i = i + 1
    put(w, base + 16, cursor)
    i = 0
    while i < tests_n:
        if cursor + 40 > limit:
            return 0
        n = uint(s, cursor + 32, 8)
        if n > 4095 or n > limit - cursor - 40:
            return 0
        cursor = cursor + 40 + n
        i = i + 1
    return choose(cursor == limit, 1, 0)

def validators(s:readbuf, o:mutbuf, w:mutbuf) -> u64:
    cursor = get(w, 528)
    i = 0
    while i < get(w, 552):
        kind = uint(s, cursor, 8)
        a = uint(s, cursor + 8, 8)
        b = uint(s, cursor + 16, 8)
        c = uint(s, cursor + 24, 8)
        n = uint(s, cursor + 32, 8)
        if a >= get(w, 128):
            return 0
        if kind == 1:
            if n != 0 or piece_size(w, a) < b or piece_size(w, a) > c:
                return 0
        elif kind == 2:
            if n != 32:
                return 0
            digest(s, o, w, piece(w, a), piece_size(w, a))
            if equal_output(s, o, cursor + 40, 0, 32) == 0:
                return 0
        elif kind == 3:
            child = lookup(s, w, b, c)
            if n != 0 or child == 0 or shape(s, w, a, child) == 0:
                return 0
        elif kind == 4:
            if n != 0 or b >= get(w, 128):
                return 0
            left = get(w, 3072 + a * 8)
            right = get(w, 3072 + b * 8)
            if left == 0 or right == 0 or equal(s, left, right, 64) == 0:
                return 0
        elif kind == 5 or kind == 6:
            if get(w, 248) != a + 1 or b >= get(w, 256):
                return 0
            at = get(w, 24576 + b * 8)
            if at == 0:
                return 0
            if kind == 5:
                if n != 32 or equal_hex_source(s, at - 1, cursor + 40) == 0:
                    return 0
            else:
                if n != 0 or c >= get(w, 128):
                    return 0
                digest(s, o, w, piece(w, c), piece_size(w, c))
                if equal_hex_output(s, o, at - 1) == 0:
                    return 0
        elif kind == 7:
            if n != 0 or inprocess(s, w, a) == 0:
                return 0
        else:
            return 0
        cursor = cursor + 40 + n
        i = i + 1
    return 1

def shape(s:readbuf, w:mutbuf, part:u64, record:u64) -> u64:
    if layout(s, w, record, 640) == 0:
        return 0
    i = 0
    while i < get(w, 664):
        put(w, 24576 + i * 8, 0)
        i = i + 1
    start = piece(w, part)
    end = start + piece_size(w, part)
    at = start
    cursor = get(w, 648)
    i = 0
    while i < get(w, 672):
        kind = uint(s, cursor, 8)
        value = uint(s, cursor + 8, 8)
        cursor = cursor + 16
        if kind == 0:
            if value > end - at or equal(s, at, cursor, value) == 0:
                return 0
            at = at + value
            cursor = cursor + value
        elif kind == 1:
            if 64 > end - at or hex_string(s, at) == 0:
                return 0
            old = get(w, 24576 + value * 8)
            if old != 0 and equal(s, old - 1, at, 64) == 0:
                return 0
            put(w, 24576 + value * 8, at + 1)
            at = at + 64
        else:
            return 0
        i = i + 1
    if at != end:
        return 0
    compiler = get(w, 696) & 65535
    if compiler != 0:
        if compiler > get(w, 664):
            return 0
        position = get(w, 24576 + (compiler - 1) * 8)
        if position == 0:
            return 0
        put(w, 3072 + part * 8, position - 1)
    put(w, 248, part + 1)
    put(w, 256, get(w, 664))
    return 1

def inprocess(s:readbuf, w:mutbuf, part:u64) -> u64:
    start = piece(w, part)
    size = piece_size(w, part)
    if size <= 176 or size > 67108864:
        return 0
    i = 0
    while i < 176:
        value = 0
        if i < 8:
            value = (MAGIC_INPROCESS >> (i * 8)) & 255
        elif i == 8:
            value = 1
        elif i == 16:
            value = 176
        elif i >= 96 and i < 104:
            value = (size >> ((i - 96) * 8)) & 255
        elif i >= 104 and i < 112:
            value = (size >> ((i - 104) * 8)) & 255
        if byte(s, start + i) != value:
            return 0
        i = i + 1
    return 1

def slots(s:readbuf, o:mutbuf, w:mutbuf) -> u64:
    cursor = get(w, 512)
    i = 0
    while i < get(w, 536):
        kind = uint(s, cursor, 8)
        part = uint(s, cursor + 8, 8)
        n = uint(s, cursor + 16, 8)
        target = 4096 + i * 32
        if kind == 1:
            digest(s, o, w, piece(w, part), piece_size(w, part))
            j = 0
            while j < 32:
                store(w, target + j, byte(o, j))
                j = j + 1
        elif kind == 2:
            if piece_size(w, part) != 32:
                return 0
            copy(s, w, target, piece(w, part), 32)
        else:
            at = source_pin(s, w, part, cursor + 24, n)
            if at == 0:
                return 0
            copy(s, w, target, at, 32)
        cursor = cursor + 24 + n
        i = i + 1
    return 1

def source_pin(s:readbuf, w:mutbuf, part:u64, name:u64, n:u64) -> u64:
    if get(w, 232) != part + 1:
        if source_index(s, w, part) == 0:
            return 0
    low = 0
    high = get(w, 240)
    while low < high:
        middle = low + ((high - low) >> 1)
        row = 32768 + middle * 24
        order = compare(s, get(w, row), get(w, row + 8), name, n)
        if order == 1:
            low = middle + 1
        elif order == 2:
            high = middle
        else:
            return get(w, row + 16)
    return 0

def source_index(s:readbuf, w:mutbuf, part:u64) -> u64:
    start = piece(w, part)
    size = piece_size(w, part)
    if size < 16 or size > 1048576 or uint(s, start, 8) != MAGIC_SPI:
        return 0
    count = uint(s, start + 8, 8)
    if count == 0 or count > 4096:
        return 0
    cursor = start + 16
    end = start + size
    i = 0
    while i < count:
        if cursor + 40 > end:
            return 0
        n = uint(s, cursor, 8)
        if n == 0 or n > 4095 or n > end - cursor - 40:
            return 0
        path = cursor + 40
        if relative(s, path, n) == 0:
            return 0
        if i != 0:
            previous = 32768 + (i - 1) * 24
            if compare(s, get(w, previous), get(w, previous + 8), path, n) != 1:
                return 0
        row = 32768 + i * 24
        put(w, row, path)
        put(w, row + 8, n)
        put(w, row + 16, cursor + 8)
        cursor = path + n
        i = i + 1
    if cursor != end:
        return 0
    put(w, 232, part + 1)
    put(w, 240, count)
    return 1

def relative(s:readbuf, at:u64, n:u64) -> u64:
    i = 0
    start = 0
    while i <= n:
        ch = choose(i == n, 47, byte(s, at + choose(i == n, 0, i)))
        if ch == 47:
            width = i - start
            if width == 0 or (width == 1 and byte(s, at + start) == 46):
                return 0
            if width == 2 and byte(s, at + start) == 46 and byte(s, at + start + 1) == 46:
                return 0
            start = i + 1
        elif ch < 32 or ch > 126 or ch == 92:
            return 0
        i = i + 1
    return 1

def render(s:readbuf, o:mutbuf, w:mutbuf) -> u64:
    cursor = get(w, 520)
    i = 0
    out = 0
    while i < get(w, 544):
        kind = uint(s, cursor, 8)
        value = uint(s, cursor + 8, 8)
        cursor = cursor + 16
        if kind == 0:
            if value > length(o) - out:
                return 0
            copy(s, o, out, cursor, value)
            cursor = cursor + value
            out = out + value
        elif kind == 1:
            if 64 > length(o) - out:
                return 0
            j = 0
            while j < 32:
                ch = byte(w, 4096 + value * 32 + j)
                store(o, out + j * 2, hex_digit(ch >> 4))
                store(o, out + j * 2 + 1, hex_digit(ch & 15))
                j = j + 1
            out = out + 64
        elif kind == 2:
            n = piece_size(w, value)
            if n > length(o) - out:
                return 0
            copy(s, o, out, piece(w, value), n)
            out = out + n
        else:
            if 8 > length(o) - out:
                return 0
            put(o, out, piece_size(w, value))
            out = out + 8
        i = i + 1
    return out

def equal(s:readbuf, left:u64, right:u64, n:u64) -> u64:
    i = 0
    while i < n:
        if byte(s, left + i) != byte(s, right + i):
            return 0
        i = i + 1
    return 1

def equal_output(s:readbuf, o:mutbuf, left:u64, right:u64, n:u64) -> u64:
    i = 0
    while i < n:
        if byte(s, left + i) != byte(o, right + i):
            return 0
        i = i + 1
    return 1

def equal_hex_source(s:readbuf, text:u64, raw:u64) -> u64:
    i = 0
    while i < 32:
        ch = byte(s, raw + i)
        if byte(s, text + i * 2) != hex_digit(ch >> 4) or byte(s, text + i * 2 + 1) != hex_digit(ch & 15):
            return 0
        i = i + 1
    return 1

def equal_hex_output(s:readbuf, o:mutbuf, text:u64) -> u64:
    i = 0
    while i < 32:
        ch = byte(o, i)
        if byte(s, text + i * 2) != hex_digit(ch >> 4) or byte(s, text + i * 2 + 1) != hex_digit(ch & 15):
            return 0
        i = i + 1
    return 1

def hex_string(s:readbuf, at:u64) -> u64:
    i = 0
    while i < 64:
        ch = byte(s, at + i)
        if (ch < 48 or ch > 57) and (ch < 97 or ch > 102):
            return 0
        i = i + 1
    return 1

def hex_digit(n:u64) -> u64:
    return choose(n < 10, 48 + n, 87 + n)

def compare(s:readbuf, left:u64, ln:u64, right:u64, rn:u64) -> u64:
    i = 0
    while i < ln and i < rn:
        a = byte(s, left + i)
        b = byte(s, right + i)
        if a < b:
            return 1
        if a > b:
            return 2
        i = i + 1
    return choose(ln == rn, 0, choose(ln < rn, 1, 2))

def piece(w:mutbuf, index:u64) -> u64:
    return get(w, 1024 + index * 16)

def piece_size(w:mutbuf, index:u64) -> u64:
    return get(w, 1032 + index * 16)

def uint(s:readbuf, at:u64, n:u64) -> u64:
    i = 0
    value = 0
    while i < n:
        value = value | (byte(s, at + i) << (i * 8))
        i = i + 1
    return value

def get(w:mutbuf, at:u64) -> u64:
    return word_load(w, at)

def put(w:mutbuf, at:u64, value:u64) -> u64:
    i = 0
    while i < 8:
        store(w, at + i, (value >> (i * 8)) & 255)
        i = i + 1
    return 0

def copy(s:readbuf, o:mutbuf, at:u64, source:u64, n:u64) -> u64:
    i = 0
    while i < n:
        store(o, at + i, byte(s, source + i))
        i = i + 1
    return 0

"""


if __name__ == '__main__':
    main()
