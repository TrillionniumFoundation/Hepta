"""Agent data: independent complete VM arenas, actual native images and callers."""
from concurrent.futures import ThreadPoolExecutor
from hashlib import sha256
import json
import os
from pathlib import Path
import random
import struct
import subprocess
import sys
import tempfile
import unittest
from unittest.mock import patch

from hepta.hia_agent_data_json_native import (
    SOURCE, SCHEMA, MAGIC, SELECTOR, NativeAgentDataJson, materialize_data, installed_agent_data_json)
from hepta.hia_json_decode_native import arena_sizes, materialize, HEADER, RECORD
from tools.generate_hia_agent_data_json import document, source_program

ROOT = Path(__file__).resolve().parents[1]


def vm_arena(wire, nodes=32, depth=8):
    from hepta.hia_agent_assembly import assemble_program
    from hepta.hia_program_runtime import _Machine, _Owner, _View
    checked = assemble_program(SOURCE.read_bytes())
    output_size, workspace_size = arena_sizes(len(wire), nodes, depth)
    state = bytearray(workspace_size)
    struct.pack_into('<QQ', state, 48, nodes, depth)
    owners = [_Owner(-1, bytearray(wire)), _Owner(-2, bytearray(output_size)), _Owner(-3, state)]
    machine = _Machine(checked, 3000000, 32 << 20, None, 256)
    entry = next(fn for fn in checked.as_dict()['functions'] if fn['name'] == 'f0')
    status = machine.invoke(entry, [_View(owners[0], False), _View(owners[1], True), _View(owners[2], True)])[0]
    return status, bytes(owners[1].data[:status]) if status <= output_size else None


def typed(value):
    if type(value) is float:
        return ('float-binary64', struct.pack('<d', value).hex())
    if type(value) is list:
        return ('list', [typed(v) for v in value])
    if type(value) is dict:
        return ('dict', [(k, typed(v)) for k, v in value.items()])
    return (type(value).__name__, value)


GOOD = (b'null', b'true', b'false', b'[]', b'{}', b'""', b'0', b'-0', b'0.0', b'-0.0', b'1e0', b'-0e+1000',
        b'1.25e-3', b'[1.0,-2E+4]', b'{"ratio":1.25}', b'{"x":"\\ud83d\\ude00","n":1e2}',
        b'"1e400"', b'{"1e0":-0.0}')
BAD = (b'+1', b'.1', b'1.', b'01', b'00.1', b'-01e0', b'1e', b'1e+', b'1e-',
       b'1.e1', b'1e1.0', b'1e1e1', b'NaN', b'Infinity', b'-Infinity', b'[1e0,]',
       b'{"x":1e0,}', b'"\\ud800"', b'"\xc0\x80"')


def independent_witnesses():
    for wire in GOOD:
        status, arena = vm_arena(wire)
        assert status == len(arena) and typed(materialize_data(arena, wire)) == typed(json.loads(wire))
    for wire in BAD:
        assert vm_arena(wire)[0] == 0xffffffff, wire
    assert vm_arena(b'{"x":1.0,"\\u0078":2e1}')[0] == 0xfffffffc
    assert vm_arena(b'[1.0]', nodes=1)[0] == 0xfffffffe
    # Native grammar records the lexeme; finite binary64 refusal is explicitly
    # in the bridge, not claimed as a native floating point implementation.
    status, arena = vm_arena(b'1e400')
    assert status == len(arena)
    try: materialize_data(arena, b'1e400')
    except ValueError: pass
    else: raise AssertionError('nonfinite foreign value accepted')


class AgentDataJsonSourceTests(unittest.TestCase):
    def test_generated_source_and_unchanged_integer_support_algorithms(self):
        import ast
        from hepta.hia_agent_assembly import render_assembly, assemble_program
        from tools.generate_hia_json_decode import source_program as integer_source
        self.assertEqual(SOURCE.read_text(), render_assembly(document()))
        current = {n.name: ast.dump(n) for n in ast.parse(source_program()).body}
        previous = {n.name: ast.dump(n) for n in ast.parse(integer_source()).body}
        self.assertEqual(set(current), set(previous))
        for name in current.keys() - {'decode_json', 'atom'}:
            self.assertEqual(current[name], previous[name], name)
        self.assertEqual(len(assemble_program(SOURCE.read_bytes()).as_dict()['functions']), 15)

    def test_complete_independent_arenas_before_any_native_seed(self):
        independent_witnesses()

    def test_distinct_protocol_and_mandatory_tree_range_tag_checks(self):
        _, arena = vm_arena(b'[1.0,2]')
        with self.assertRaises(ValueError): materialize(arena, b'[1.0,2]')
        for offset, value in ((0, 0), (8, 1048577), (16, 0), (24, len(arena) + 1),
                              (48, 2), (64, 8), (120, 3), (128, 2), (144, 999999)):
            broken = bytearray(arena); struct.pack_into('<Q', broken, offset, value)
            with self.subTest(offset=offset), self.assertRaises(ValueError):
                materialize_data(bytes(broken), b'[1.0,2]')

    def test_incomplete_builder_cannot_create_output(self):
        from tools.build_hia_agent_data_json import build
        with tempfile.TemporaryDirectory(prefix='hia-data-json-invalid-cold-') as d:
            root = Path(d); compiler = root / 'compiler'; cold = root / 'cold'
            compiler.write_bytes(b'unqualified'); cold.write_text('{}')
            with self.assertRaisesRegex(ValueError, 'completed matching-source cold'):
                build(root / 'output', compiler, cold)
            self.assertFalse((root / 'output').exists())


class AgentDataJsonNativeTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        independent_witnesses()
        from tools.qualify_hia_selfhost import build_seed, compile_stage
        selected = os.environ.get('HEPTA_HIA_AGENT_DATA_JSON_EVIDENCE')
        cls.temporary = None
        if selected:
            cls.folder = Path(selected); cls.folder.mkdir(mode=0o700)
        else:
            cls.temporary = tempfile.TemporaryDirectory(prefix='hia-agent-data-json-')
            cls.folder = Path(cls.temporary.name)
        seed, _ = build_seed(cls.folder)
        source = (ROOT / 'examples/hia_bootstrap/selfhost.hiaasm').read_bytes()
        first, _ = compile_stage(cls.folder, 'B1', seed, source, image_format='seed-shared')
        second, _ = compile_stage(cls.folder, 'B2', first, source)
        assert first.read_bytes() == second.read_bytes()
        image, receipt = compile_stage(cls.folder, 'agent-data-json', second, SOURCE.read_bytes())
        raw = image.read_bytes(); cls.native = NativeAgentDataJson(raw, sha256(raw).hexdigest())
        cls.manifest = cls.folder / 'manifest.json'
        cls.metadata = dict(schema=SCHEMA, source_sha256=sha256(SOURCE.read_bytes()).hexdigest(),
            image_path=image.name, image_sha256=sha256(raw).hexdigest(), compiler_sha256=sha256(second.read_bytes()).hexdigest())
        cls.manifest.write_text(json.dumps(cls.metadata))
        (cls.folder / 'development-build.json').write_text(json.dumps(dict(status='DEVELOPMENT_NOT_COLD_QUALIFICATION',
            native_compile_receipt=receipt, manifest=cls.metadata, host_float_and_object_bridge=True)))

    @classmethod
    def tearDownClass(cls):
        if cls.temporary: cls.temporary.cleanup()

    def test_full_VM_arena_bytes_equal_actual_native_and_lexeme_tags(self):
        for wire in GOOD:
            with self.subTest(wire=wire):
                status, reference = vm_arena(wire)
                actual = self.native.arena(wire, max_nodes=32, max_depth=8)
                self.assertEqual(actual, reference)
                self.assertEqual(status, len(actual))
                self.assertEqual(HEADER.unpack_from(actual)[0], MAGIC)
        arena = self.native.arena(b'[0,0.0,1E0]', max_nodes=8, max_depth=2)
        self.assertEqual([RECORD.unpack_from(arena, 64 + i * 56)[0] for i in range(4)], [5, 3, 7, 7])

    def test_actual_ordinary_data_matches_reference_including_float_bits(self):
        from hepta.hia_agent_store import decode_data
        values = list(GOOD) + [b'5e-324', b'2.2250738585072014e-308', b'1.7976931348623157e308',
            b'0e99999', b'1e-99999', b'1234567890123456789012345678901234567890',
            b'{"a":[-0.0,{"b":4E-2}],"c":{"a":1.0}}']
        rng = random.Random(601106)
        for _ in range(256):
            values.append(('%s%d.%09de%+d' % ('-' if rng.getrandbits(1) else '',
                rng.randrange(100000), rng.randrange(10**9), rng.randrange(-330, 300))).encode())
        with patch.dict(os.environ, {SELECTOR: ''}):
            expected = [typed(decode_data(wire)) for wire in values]
        with patch('json.loads', side_effect=AssertionError('host JSON payload parser')):
            actual = [typed(self.native.decode(wire)) for wire in values]
        self.assertEqual(actual, expected)

    def test_selected_Agent_path_forbids_host_tokenizer_and_preserves_rejections(self):
        from hepta import hia_agent_store as store
        with patch.dict(os.environ, {SELECTOR: str(self.manifest)}), \
                patch('json.loads', side_effect=AssertionError('host JSON payload parser')), \
                patch.object(store.re, 'compile', side_effect=AssertionError('host numeric tokenizer')), \
                patch.object(store, 'preflight_hia_json', side_effect=AssertionError('host integer-mask preflight')):
            for wire in GOOD:
                self.assertEqual(typed(store.decode_data(wire)), typed(self.native.decode(wire)))
            for wire in (*BAD, b'1e400', b'-1e99999', b'1.7976931348623159e308'):
                with self.subTest(wire=wire), self.assertRaises(ValueError): store.decode_data(wire)
            with self.assertRaises(store.AgentRejected) as caught: store.decode_data(b'1e400')
            self.assertEqual(caught.exception.code, 'E_HIA_JSON')

    def test_duplicate_scope_unicode_budget_byte_ceiling_and_no_fallback(self):
        for wire in (b'{"x":1.0,"\\u0078":2e0}', b'{"\\ud83d\\ude00":0.0,"\xf0\x9f\x98\x80":1}'):
            with self.assertRaisesRegex(ValueError, 'duplicate'): self.native.decode(wire)
        self.assertEqual(self.native.decode(b'[{"x":1.0},{"x":2e0}]'), [{'x': 1.0}, {'x': 2.0}])
        for wire, nodes, depth in ((b'[1.0]', 1, 8), (b'[[1.0]]', 8, 1)):
            with self.assertRaises(ValueError): self.native.decode(wire, max_nodes=nodes, max_depth=depth)
        wire = b'0' + b' ' * ((8 << 20) - 1)
        self.assertEqual(self.native.decode(wire), 0)
        with self.assertRaises(ValueError): self.native.decode(wire + b' ')
        bad = self.folder / 'bad-manifest.json'; bad.write_text('{}')
        from hepta.hia_agent_store import decode_data
        with patch.dict(os.environ, {SELECTOR: str(bad)}):
            with self.assertRaises(ValueError): decode_data(b'1.0')
        copied = self.folder / 'source-copy.hiaasm'; copied.write_bytes(SOURCE.read_bytes())
        with patch('hepta.hia_agent_data_json_native.SOURCE', copied):
            self.assertEqual(installed_agent_data_json(str(self.manifest)).decode(b'1.0'), 1.0)
            copied.write_bytes(b'changed source')
            with self.assertRaisesRegex(ValueError, 'source identity'):
                installed_agent_data_json(str(self.manifest))

    def test_concurrent_calls_keep_private_arenas_and_exact_values(self):
        wires = [b'{"ratio":1.25e-3,"values":[-0.0,17]}' for _ in range(48)]
        with ThreadPoolExecutor(max_workers=8) as pool:
            observed = list(pool.map(self.native.decode, wires))
        expected = typed({'ratio': 1.25e-3, 'values': [-0.0, 17]})
        self.assertEqual([typed(value) for value in observed], [expected] * len(wires))

    def test_actual_full_Agent_node_profile_under_unchanged_child_address_cap(self):
        code = r'''
import gc,json,resource,sys
sys.path.insert(0,sys.argv[1])
from hepta.hia_agent_data_json_native import installed_agent_data_json
native=installed_agent_data_json(sys.argv[2])
resource.setrlimit(resource.RLIMIT_AS,(268435456,268435456))
resource.setrlimit(resource.RLIMIT_CPU,(10,10))
def forbidden(*a,**k):raise AssertionError('foreign payload JSON decoder')
json.loads=forbidden
wire=b'['+b'0.0,'*262142+b'0.0]'
value=native.decode(wire)
assert len(value)==262143 and all(type(v)is float and v.hex()=='0x0.0p+0' for v in value)
del value;gc.collect()
try:native.decode(b'['+b'0.0,'*262143+b'0.0]')
except ValueError:pass
else:raise AssertionError('one-past Agent node budget accepted')
print('actual262144nodesaccepted/262145refused;256MiB/10CPU;nohostJSONparser')
'''
        result = subprocess.run([sys.executable, '-I', '-S', '-B', '-c', code, str(ROOT), str(self.manifest)],
            capture_output=True, env={'PATH': '', 'LANG': 'C', 'LC_ALL': 'C'}, timeout=30)
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        self.assertIn(b'actual262144nodesaccepted/262145refused', result.stdout)


if __name__ == '__main__': unittest.main()
