"""Independent HIA VM, real native objects and loader observations for the linker."""
from __future__ import annotations

import ctypes
from hashlib import sha256
import json
from pathlib import Path
import struct
import subprocess
import tempfile
import unittest
from unittest.mock import patch

from hepta.hia_agent_assembly import assemble_program, render_assembly
from tools.generate_hia_elf_linker import SOURCE, MAGIC, LIMIT, WORKSPACE, document

ROOT = Path(__file__).resolve().parents[1]


def frame(*objects):
    return struct.pack('<QQ', MAGIC, len(objects)) + struct.pack('<' + 'Q' * len(objects), *map(len, objects)) + b''.join(objects)


def fixture(value=42, name=b'answer'):
    """Independent canonical object with a real mov-immediate/ret scalar body."""
    text = b'\xb8' + struct.pack('<I', value) + b'\xc3'
    names = b'\0.text\0.symtab\0.strtab\0.shstrtab\0.note.GNU-stack\0.rela.text\0'
    symbols_at = (64 + len(text) + 7) & ~7
    strings_at = symbols_at + 72
    strings = b'\0' + name + b'\0'
    names_at = strings_at + len(strings)
    headers_at = (names_at + len(names) + 7) & ~7
    result = bytearray(headers_at + 7 * 64)
    struct.pack_into('<16sHHIQQQIHHHHHH', result, 0, b'\x7fELF\x02\x01\x01' + bytes(9),
        1, 62, 1, 0, 0, headers_at, 0, 64, 0, 0, 64, 7, 4)
    result[64:64 + len(text)] = text
    struct.pack_into('<IBBHQQ', result, symbols_at + 24, 0, 3, 0, 1, 0, 0)
    struct.pack_into('<IBBHQQ', result, symbols_at + 48, 1, 18, 0, 1, 0, len(text))
    result[strings_at:strings_at + len(strings)] = strings
    result[names_at:names_at + len(names)] = names
    sections = [(1, 1, 6, 64, len(text), 0, 0, 16, 0),
        (7, 2, 0, symbols_at, 72, 3, 2, 8, 24),
        (15, 3, 0, strings_at, len(strings), 0, 0, 1, 0),
        (23, 3, 0, names_at, len(names), 0, 0, 1, 0),
        (33, 1, 0, names_at + len(names), 0, 0, 0, 1, 0),
        (49, 4, 0, headers_at, 0, 2, 1, 8, 24)]
    for i, (n, t, f, off, size, link, info, align, entry) in enumerate(sections, 1):
        struct.pack_into('<IIQQQQIIQQ', result, headers_at + i * 64, n, t, f, 0, off, size, link, info, align, entry)
    return bytes(result)


def vm(wire, capacity=12000, scratch=WORKSPACE, fill=0x5a):
    from hepta.hia_program_runtime import _Machine, _Owner, _View
    checked = assemble_program(SOURCE.read_bytes())
    machine = _Machine(checked, 8_000_000, 16 << 20, None, 256)
    source = _Owner(-1, bytearray(wire))
    output = _Owner(-2, bytearray([0xa5]) * capacity)
    workspace = _Owner(-3, bytearray([fill]) * scratch)
    entry = next(f for f in checked.as_dict()['functions'] if f['name'] == 'f0')
    result = machine.invoke(entry, [_View(source, False), _View(output, True), _View(workspace, True)])
    assert bytes(source.data) == wire
    return result[0], bytes(output.data)


def inspect(data, exports):
    from hepta.elf_shared_abi import inspect_owned_shared_elf
    report = inspect_owned_shared_elf(data, tuple(sorted(exports)))
    header = struct.unpack_from('<16sHHIQQQIHHHHHH', data)
    segments = [struct.unpack_from('<IIQQQQQQ', data, 64 + i * 56) for i in range(header[10])]
    assert not any(s[0] == 3 or s[1] == 7 for s in segments)
    loads = [s for s in segments if s[0] == 1]
    assert [s[1] for s in loads] == [5, 6]
    assert loads[0][3] + loads[0][6] <= loads[1][3]
    relro = [s for s in segments if s[0] == 0x6474e552]
    assert len(relro) == 1 and relro[0][3] == loads[1][3] and relro[0][6] == 4096
    return report


def preseed_reference():
    """The generic Core VM executes real HIA linking before B0 exists."""
    objects = [fixture(42, b'left'), fixture(59, b'right')]
    status, raw = vm(frame(*objects))
    assert 0 < status < 12000, status
    result = raw[:status]
    inspect(result, ['left', 'right'])
    assert result[352:358] == b'\xb8*\0\0\0\xc3'
    assert result[368:374] == b'\xb8;\0\0\0\xc3'
    assert raw[status:] == b'\xa5' * (len(raw) - status)
    for wire, expected in [(frame(objects[0], objects[0]), 0xffffffff),
                           (frame(fixture(name=b'calloc')), 0xffffffff),
                           (frame(objects[0])[:-1], 0xffffffff),
                           (frame(objects[0]) + b'x', 0xffffffff)]:
        actual, output = vm(wire)
        assert actual == expected and output == b'\xa5' * len(output), actual
    actual, output = vm(frame(objects[0]), capacity=100)
    assert actual == 0xfffffffe and output == b'\xa5' * 100
    return result


class HiaElfLinkerSourceTests(unittest.TestCase):
    def test_checked_in_HIA_source_and_independent_VM(self):
        self.assertEqual(SOURCE.read_text(), render_assembly(document()))
        preseed_reference()

    def test_builder_rejects_missing_cold_qualification(self):
        from tools.build_hia_elf_linker import build
        with tempfile.TemporaryDirectory(prefix='hia-linker-unqualified-') as tmp:
            folder = Path(tmp)
            compiler, cold = folder / 'compiler', folder / 'cold.json'
            compiler.write_bytes(b'unqualified')
            for value in ({}, {'status': 'FAIL'}, {'status': 'COLD_SELFHOST_REPLAY_PASS'}):
                cold.write_text(json.dumps(value))
                with self.assertRaises(ValueError):
                    build(folder / 'output', compiler, cold)
                self.assertFalse((folder / 'output').exists())

    def test_builder_rejects_unbound_source_and_actual_compiler_substitution(self):
        from tools.build_hia_elf_linker import build
        with tempfile.TemporaryDirectory(prefix='hia-linker-build-custody-') as tmp:
            folder = Path(tmp); compiler = folder / 'compiler'; cold = folder / 'cold.json'
            compiler.write_bytes(b'fixture compiler, never executed')
            checks = {'export_manifest_matches_qualification', 'isolated_python_without_site',
                'nested_full_qualification_pass', 'nested_process_exit_zero', 'no_ancestor_git_identity',
                'no_bytecode_cache_created', 'no_inherited_home_or_python_cache',
                'no_inherited_seed_or_successor_images', 'origin_hashes_preserved',
                'owned_process_tree_cleanup_confirmed', 'source_export_hashes_preserved'}
            fixture_report = {'schema': 'hepta.hia.selfhost-cold-replay.v1', 'status': 'COLD_SELFHOST_REPLAY_PASS',
                'returncode': 0, 'checks': dict.fromkeys(checks, True),
                'generation_sha256': [sha256(compiler.read_bytes()).hexdigest()] * 3, 'source_manifest': {}}
            cold.write_text(json.dumps(fixture_report))
            with self.assertRaisesRegex(ValueError, 'source inventory'):
                build(folder / 'missing-source', compiler, cold)
            names = ['examples/hia_bootstrap/elf_linker.hiaasm', 'tools/generate_hia_elf_linker.py',
                'tools/build_hia_elf_linker.py', 'tools/link_hia_elf.py']
            fixture_report['source_manifest'] = {name: sha256((ROOT / name).read_bytes()).hexdigest() for name in names}
            cold.write_text(json.dumps(fixture_report))
            def substituted_compiler(output, label, actual_compiler, source, **kwargs):
                image = output / 'substituted.bin'; image.write_bytes(b'fixture output, never executed')
                return image, {'artifact_sha256': sha256(b'different actual compiler').hexdigest(),
                    'input_sha256': sha256(source).hexdigest(), 'source_sha256': sha256(source).hexdigest(),
                    'produced_sha256': sha256(image.read_bytes()).hexdigest()}
            with patch('tools.qualify_hia_selfhost.compile_stage', side_effect=substituted_compiler):
                with self.assertRaisesRegex(ValueError, 'identity mismatch'):
                    build(folder / 'substitution', compiler, cold)
            self.assertFalse((folder / 'substitution' / 'manifest.json').exists())
            original_read = Path.read_bytes
            reads = 0
            def source_aba(path):
                nonlocal reads
                if path == SOURCE:
                    reads += 1
                    if reads == 1:
                        return b'other source temporarily present during first capture'
                return original_read(path)
            with patch.object(Path, 'read_bytes', source_aba), patch('tools.qualify_hia_selfhost.compile_stage') as stage:
                with self.assertRaisesRegex(ValueError, 'source inventory'):
                    build(folder / 'source-aba', compiler, cold)
            stage.assert_not_called()
            self.assertFalse((folder / 'source-aba').exists())

    def test_failed_output_sync_never_publishes_partial_final_artifact(self):
        from tools.link_hia_elf import _publish
        with tempfile.TemporaryDirectory(prefix='hia-linker-publication-') as tmp:
            directory = Path(tmp); output = directory / 'library.so'
            with patch('tools.link_hia_elf.os.fsync', side_effect=OSError('simulated disk failure')):
                with self.assertRaises(OSError):
                    _publish(output, b'complete candidate')
            self.assertFalse(output.exists())
            self.assertEqual(list(directory.iterdir()), [])
            _publish(output, b'complete candidate')
            with self.assertRaises(FileExistsError):
                _publish(output, b'replacement')
            self.assertEqual(output.read_bytes(), b'complete candidate')
            self.assertEqual(list(directory.iterdir()), [output])


class HiaElfLinkerNativeTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.vm_bytes = preseed_reference()
        from tests.test_hia_core_json_cli import independent_export_pair
        from tools.qualify_hia_selfhost_exports import independent_reference
        cls.export_documents, cls.export_reference = independent_export_pair()
        cls.all_exports_reference = independent_reference()
        from tools.hia_selfhost_owned_elf_cases import cases, reference
        cls.owned_cases = cases()
        cls.owned_references = [reference(case) for case in cls.owned_cases]
        from tools.qualify_hia_selfhost import build_seed, compile_stage
        from hepta.hia_json_preflight_native import NativeHiaJsonImage
        cls.temporary = tempfile.TemporaryDirectory(prefix='hia-native-linker-')
        cls.folder = Path(cls.temporary.name)
        source = (ROOT / 'examples/hia_bootstrap/selfhost.hiaasm').read_bytes()
        seed, _ = build_seed(cls.folder)
        first, _ = compile_stage(cls.folder, 'B1', seed, source, image_format='seed-shared')
        cls.compiler, _ = compile_stage(cls.folder, 'B2', first, source)
        assert first.read_bytes() == cls.compiler.read_bytes()
        image, cls.receipt = compile_stage(cls.folder, 'linker', cls.compiler, SOURCE.read_bytes())
        cls.native = NativeHiaJsonImage(image.read_bytes(), sha256(image.read_bytes()).hexdigest())
        # The existing compiler's native syscall filter makes this algorithm a
        # standalone linker. No Python input parser, linker or child at runtime.
        cli_source = SOURCE.read_bytes().replace(b'hepta.hia.program.v8 elf_linker\n', b'hepta.hia.program.v8 selfhost_exec\n', 1)
        cls.executable, _ = compile_stage(cls.folder, 'hia-link', cls.compiler, cli_source, output_extension='.elf')
        cls.executable.chmod(0o700)
        cls.selected_manifest = cls.folder / 'linker-manifest.json'
        cls.write_development_manifest(cls.selected_manifest, cls.executable)

    @classmethod
    def tearDownClass(cls):
        cls.temporary.cleanup()

    @classmethod
    def write_development_manifest(cls, path, executable):
        """Explicit local test selection, not a cold qualification/publication."""
        from tools.build_hia_elf_linker import SCHEMA
        names = ['examples/hia_bootstrap/elf_linker.hiaasm', 'tools/generate_hia_elf_linker.py',
            'tools/build_hia_elf_linker.py', 'tools/link_hia_elf.py']
        value = {'schema': SCHEMA, 'source_files': {name: sha256((ROOT / name).read_bytes()).hexdigest() for name in names},
            'executable_path': executable.name, 'executable_sha256': sha256(executable.read_bytes()).hexdigest(),
            'compiler_sha256': sha256(cls.compiler.read_bytes()).hexdigest()}
        path.write_text(json.dumps(value))
        return value

    def native_link(self, wire, capacity=LIMIT, scratch=WORKSPACE, fill=0x5a):
        source = ctypes.create_string_buffer(wire, max(1, len(wire)))
        output = ctypes.create_string_buffer(b'\xa5' * (capacity + 8), capacity + 8)
        workspace = ctypes.create_string_buffer(bytes([fill]) * (scratch + 8), scratch + 8)
        status = self.native._entry(source, len(wire), output, capacity, workspace, scratch)
        self.assertEqual(source.raw[:len(wire)], wire)
        self.assertEqual(output.raw[capacity:], b'\xa5' * 8)
        self.assertEqual(workspace.raw[scratch:], bytes([fill]) * 8)
        if status >= 0xfffffffe:
            self.assertEqual(output.raw, b'\xa5' * (capacity + 8))
            return status, b''
        self.assertGreater(status, 0)
        self.assertLessEqual(status, capacity)
        self.assertEqual(output.raw[status:], b'\xa5' * (capacity + 8 - status))
        return status, output.raw[:status]

    def run_cli(self, wire, code=0, args=()):
        result = subprocess.run([str(self.executable), *args], input=wire, capture_output=True,
            timeout=10, cwd=self.folder, env={'PATH': '/nonexistent', 'HOME': '/nonexistent', 'LANG': 'C'})
        self.assertEqual(result.returncode, code, result.stderr)
        self.assertEqual(result.stderr, b'')
        if code:
            self.assertEqual(result.stdout, b'')
        return result.stdout

    def test_native_matches_every_VM_byte_and_standalone(self):
        wire = frame(fixture(42, b'left'), fixture(59, b'right'))
        _, output = self.native_link(wire)
        self.assertEqual(output, self.vm_bytes)
        self.assertEqual(self.run_cli(wire), output)
        path = self.folder / 'fixture.so'
        path.write_bytes(output)
        library = ctypes.CDLL(str(path))
        self.assertEqual(library.left(), 42)
        self.assertEqual(library.right(), 59)
        address = ctypes.cast(library.left, ctypes.c_void_p).value
        base = address - 352
        got = struct.unpack_from('<Q', output, 120 + 16)[0]
        mappings = []
        for row in Path('/proc/self/maps').read_text().splitlines():
            extent, permissions, *_ = row.split()
            low, high = (int(x, 16) for x in extent.split('-'))
            mappings.append((low, high, permissions))
        code_permission = next(p for a, b, p in mappings if a <= address < b)
        got_permission = next(p for a, b, p in mappings if a <= base + got < b)
        self.assertEqual(code_permission[:3], 'r-x')
        self.assertEqual(got_permission[:3], 'r--')

    def test_actual_native_compiler_scalar_and_allocator_objects(self):
        from tools.qualify_hia_selfhost import compile_stage
        documents, expected = self.export_documents, self.export_reference
        objects = []
        for i, doc in enumerate(documents):
            path, _ = compile_stage(self.folder, 'object-' + str(i), self.compiler,
                render_assembly(doc).encode(), output_extension='.o')
            objects.append(path.read_bytes())
        _, data = self.native_link(frame(*objects))
        self.assertEqual(data, self.run_cli(frame(*objects)))
        report = inspect(data, sum([d['exports'] for d in documents], []))
        path = self.folder / 'combined.so'
        path.write_bytes(data)
        library = ctypes.CDLL(str(path))
        for prefix in ('cli_left_', 'cli_right_'):
            for fn in ('via_private', 'allocated_size', 'identity_i8', 'identity_bool'):
                f = getattr(library, prefix + fn)
                args = []
                f.restype = ctypes.c_uint64
                if fn == 'allocated_size': f.argtypes = [ctypes.c_size_t]; args = [37]
                if fn == 'identity_i8': f.argtypes = [ctypes.c_int8]; f.restype = ctypes.c_int8; args = [-120]
                if fn == 'identity_bool': f.argtypes = [ctypes.c_bool]; f.restype = ctypes.c_bool; args = [True]
                self.assertEqual(f(*args), expected[prefix + fn])
        self.assertEqual(self.native_link(frame(objects[0], objects[0]))[0], 0xffffffff)

    def test_all_existing_scalar_export_qualification_calls(self):
        from tools.qualify_hia_selfhost import compile_stage
        for row in self.all_exports_reference['programs']:
            with self.subTest(profile=row['name']):
                obj, _ = compile_stage(self.folder, 'matrix-' + row['name'], self.compiler,
                    row['source'].encode(), output_extension='.o')
                _, data = self.native_link(frame(obj.read_bytes()))
                inspect(data, row['exports'])
                shared = self.folder / ('matrix-' + row['name'] + '.so')
                shared.write_bytes(data)
                request = {'schema': 'hepta.hia.scalar-export-observation.v1',
                    'image': str(shared), 'image_sha256': sha256(data).hexdigest(),
                    'calls': [{key: call[key] for key in ('function', 'arguments', 'return_type')} for call in row['calls']]}
                raw = json.dumps(request, sort_keys=True).encode()
                path = self.folder / ('matrix-' + row['name'] + '.json')
                path.write_bytes(raw)
                import sys
                observed = subprocess.run([sys.executable, '-I', '-S', '-B',
                    str(ROOT / 'tools/hia_selfhost_exports_child.py'), '--request', str(path),
                    '--sha256', sha256(raw).hexdigest()], capture_output=True, timeout=15)
                self.assertEqual(observed.returncode, 0, observed.stderr)
                actual = json.loads(observed.stdout)
                self.assertEqual(actual['forbidden_compiler_modules_loaded'], [])
                self.assertEqual(actual['observations'], [{'function': call['function'],
                    'value': call['expected']} for call in row['calls']])

    def test_legacy_borrowed_entry_and_six_section_object(self):
        from tools.qualify_hia_selfhost import compile_stage
        raw = (ROOT / 'examples/hia_bootstrap/bytesum.hiaasm').read_bytes()
        raw = raw.replace(b'v8 selfhost\n', b'v8 selfhost_elf\n', 1)
        obj, _ = compile_stage(self.folder, 'legacy-abi', self.compiler, raw, output_extension='.o')
        self.assertEqual(struct.unpack_from('<H', obj.read_bytes(), 60)[0], 6)
        _, data = self.native_link(frame(obj.read_bytes()))
        inspect(data, ['f0'])
        shared = self.folder / 'legacy.so'
        shared.write_bytes(data)
        lib = ctypes.CDLL(str(shared)); function = lib.f0
        function.argtypes = [ctypes.c_void_p, ctypes.c_uint64] * 3
        function.restype = ctypes.c_uint64
        source = ctypes.create_string_buffer(bytes(range(16)))
        output = ctypes.create_string_buffer(64)
        workspace = ctypes.create_string_buffer(64)
        expected = 5381
        for value in range(16):
            expected = ((expected * 33) ^ value) & 0xffffffff
        self.assertEqual(function(source, 16, output, 64, workspace, 64), expected)
        self.assertEqual(output.raw[0], expected & 255)
        self.assertEqual(workspace.raw[0], expected & 255)

    def test_existing_owned_elf_allocations_loans_and_trap_effects(self):
        from tools.qualify_hia_selfhost import compile_stage, invoke
        for case in self.owned_cases:
            with self.subTest(case=case['id']):
                obj, _ = compile_stage(self.folder, 'owned-' + case['id'], self.compiler,
                    case['source'].encode(), output_extension='.o')
                _, data = self.native_link(frame(obj.read_bytes()))
                shared = self.folder / ('owned-' + case['id'] + '.so')
                shared.write_bytes(data)
                inspect(data, ['f0'])
                observation, output = invoke(self.folder, 'owned-observe-' + case['id'], shared,
                    b'', image_format='linked-selfhost', capacity=8, workspace_size=0,
                    output_initial=b'\xa5' * 8, observe_trap_writes=True)
                self.assertEqual(output.hex(), case['expected_output_hex'])
                if 'expected_trap' in case:
                    self.assertEqual(observation.get('status'), 'child_failed')
                    self.assertEqual(observation.get('returncode'), -4)
                else:
                    self.assertEqual(observation.get('status'), 'returned')
                    self.assertEqual(observation.get('core_u32'), case['expected_result'])

    def test_object_counts_and_exports_capacity(self):
        objects = [fixture(i, ('entry_' + str(i)).encode()) for i in range(16)]
        _, data = self.native_link(frame(*objects))
        inspect(data, ['entry_' + str(i) for i in range(16)])
        self.assertEqual(self.native_link(frame(*objects, fixture(name=b'extra')))[0], 0xffffffff)

    def test_relocation_and_symbol_mutations_refuse_without_output(self):
        from tools.qualify_hia_selfhost import compile_stage
        from tools.hia_selfhost_exports_cases import allocated_document
        obj, _ = compile_stage(self.folder, 'mutations-owned', self.compiler,
            render_assembly(allocated_document()).encode(), output_extension='.o')
        raw = obj.read_bytes(); headers = struct.unpack_from('<Q', raw, 40)[0]
        symbols = struct.unpack_from('<Q', raw, headers + 2 * 64 + 24)[0]
        relocations = struct.unpack_from('<Q', raw, headers + 6 * 64 + 24)[0]
        mutations = [(relocations, '<Q', 0), (relocations, '<Q', 2**64 - 1),
            (relocations + 8, '<Q', 4), (relocations + 8, '<Q', (4 << 32) | 1),
            (relocations + 16, '<Q', 0), (symbols + 48 + 8, '<Q', 2**64 - 1),
            (symbols + 48 + 16, '<Q', 0), (headers + 64 + 8, '<Q', 7)]
        for offset, fmt, value in mutations:
            changed = bytearray(raw); struct.pack_into(fmt, changed, offset, value)
            with self.subTest(offset=offset, value=value):
                self.assertEqual(self.native_link(frame(bytes(changed)))[0], 0xffffffff)
        for size in range(0, len(raw), max(1, len(raw) // 30)):
            self.assertEqual(self.native_link(frame(raw[:size]))[0], 0xffffffff)

    def test_input_capacity_mutations_and_private_buffer_canaries(self):
        source = fixture()
        bad = [b'', bytes(24), frame(), frame(source)[:-1], frame(source) + b'x',
            frame(fixture(name=b'_init')), frame(fixture(name=b'malloc'))]
        for offset in (0, 4, 5, 6, 7, 8, 16, 18, 20, 24, 32, 40, 48, 52, 54, 56, 58, 60, 62):
            changed = bytearray(source); changed[offset] ^= 128; bad.append(frame(bytes(changed)))
        for wire in bad:
            with self.subTest(size=len(wire), prefix=wire[:24]):
                self.assertEqual(self.native_link(wire)[0], 0xffffffff)
                self.run_cli(wire, 2)
        self.assertEqual(self.native_link(frame(source), capacity=100)[0], 0xfffffffe)
        self.assertEqual(self.native_link(frame(source), scratch=WORKSPACE - 1)[0], 0xfffffffe)
        self.run_cli(frame(source), 64, ('unexpected',))

    def test_host_custody_executes_captured_bytes_and_no_fallback(self):
        from tools.link_hia_elf import link
        from tools.hia_selfhost_native_observer import execute
        folder = self.folder / 'custody'; folder.mkdir()
        executable = folder / 'hia-link'; raw = self.executable.read_bytes()
        executable.write_bytes(raw)
        obj = folder / 'input.o'; obj.write_bytes(fixture())
        manifest = folder / 'manifest.json'
        self.write_development_manifest(manifest, executable)
        def replace_path_after_capture(captured, request, **kwargs):
            self.assertEqual(captured, raw)
            executable.write_bytes(b'temporary unrelated executable')
            try:
                return execute(captured, request, **kwargs)
            finally:
                executable.write_bytes(raw)
        with patch('tools.hia_selfhost_native_observer.execute', side_effect=replace_path_after_capture):
            receipt = link([obj], manifest, folder / 'linked.so')
        self.assertEqual(receipt['executable_sha256'], sha256(raw).hexdigest())
        self.assertEqual(receipt['output_sha256'], sha256((folder / 'linked.so').read_bytes()).hexdigest())
        inspect((folder / 'linked.so').read_bytes(), ['answer'])
        with self.assertRaises(FileExistsError):
            link([obj], manifest, folder / 'linked.so')
        executable.write_bytes(b'wrong')
        with self.assertRaises(ValueError):
            link([obj], manifest, folder / 'wrong.so')
        self.assertFalse((folder / 'wrong.so').exists())

    def test_existing_qualifiers_select_native_linker_without_fallback(self):
        from tools.qualify_hia_selfhost_exports import qualify as exports
        from tools.qualify_hia_selfhost_owned_elf import qualify as owned
        from tools.qualify_hia_selfhost import observe_native_tool
        exports_dir = self.folder / 'exports-selected'; exports_dir.mkdir()
        checks = {}
        # No external linker is available to the selected export route. Its
        # existing native calls, refusal assertions and independent VM remain.
        with patch('tools.qualify_hia_selfhost.observe_native_tool', side_effect=AssertionError('unexpected host tool')):
            observations = exports(exports_dir, self.compiler, checks, self.all_exports_reference,
                'native', linker_manifest=self.selected_manifest)
        self.assertTrue(checks and all(checks.values()))
        links = [row['link'] for row in observations if 'link' in row]
        self.assertEqual(len(links), 4)
        self.assertTrue(all(row['status'] == 'NATIVE_HIA_LINK_RETURNED' for row in links))
        def inspection_only(directory, label, tool, arguments):
            self.assertEqual(tool, 'readelf')
            return observe_native_tool(directory, label, tool, arguments)
        with patch('tools.qualify_hia_selfhost.observe_native_tool', side_effect=inspection_only):
            report = owned(self.folder / 'owned-selected', self.compiler, linker_manifest=self.selected_manifest)
        self.assertEqual(report['status'], 'PASS_SCOPED_OWNED_BUFFER_ELF')
        self.assertTrue(report['cases'] and all(row['pass'] for row in report['cases']))
        self.assertTrue(report['refusals'] and all(row['pass'] for row in report['refusals']))
        self.assertTrue(all(row['tools'][1]['status'] == 'NATIVE_HIA_LINK_RETURNED' for row in report['cases']))
        failing = self.folder / 'failing-native-selection'; failing.mkdir()
        with patch('tools.link_hia_elf.link', side_effect=ValueError('selected native linker failure')), patch(
                'tools.qualify_hia_selfhost.observe_native_tool', side_effect=AssertionError('fallback linker')):
            with self.assertRaisesRegex(ValueError, 'selected native linker failure'):
                exports(failing, self.compiler, {}, self.all_exports_reference, 'refused',
                    linker_manifest=self.selected_manifest)


if __name__ == '__main__':
    unittest.main()
