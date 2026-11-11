"""Independent HIA VM controls and real standalone source-bundle rebuilding."""
from __future__ import annotations

from hashlib import sha256
import json
import os
from pathlib import Path
import re
import selectors
import shutil
import signal
import struct
import subprocess
import tempfile
import time
import unittest

from hepta.hia_agent_assembly import assemble_program, render_assembly
from hepta.hia_program import execute_program
from tools.generate_hia_artifact_publication import document
from tools.generate_hia_source_build import (
    BUNDLE_MAGIC, PACK_MAGIC, IMAGE_AT, IMAGE_LIMIT, WIRE_LIMIT,
    POLICY_WORK_BYTES, COMPILER_WORK_BYTES, ROLE_NAMES, LAYOUT,
    policy_source, packer_source, template,
)
from tools.hia_selfhost_bulk import Body

ROOT = Path(__file__).resolve().parents[1]
POLICY = ROOT / 'examples/hia_bootstrap/source_build_policy.hepta'
PACKER = ROOT / 'examples/hia_bootstrap/source_build_packer.hepta'
PINNED_FILES = ('examples/hia_bootstrap/selfhost.hepta',
                'examples/hia_bootstrap/source_build_policy.hepta',
                'examples/hia_bootstrap/source_build_packer.hepta',
                'tools/generate_hia_source_build.py', 'tools/hia_source_build_syscalls.S')
SMALL = b'''hia-asm.v1 hepta.hia.program.v8 source_build_constant
fn f0(v0:readbuf,v1:mutbuf,v2:mutbuf) -> (u32) effects(read,write,trap) entry(b0)
block b0(v0:readbuf,v1:mutbuf,v2:mutbuf)
  v3:u32 = const() {"value":7}
  ret(v3)
end
'''


def bundle(files):
    result = bytearray(struct.pack('<3Q', BUNDLE_MAGIC, len(files), 0))
    for name, mode, data in files:
        name = name.encode('ascii') if isinstance(name, str) else name
        result += struct.pack('<3Q', len(name), mode, len(data)) + name + data
    return bytes(result)


def unpack(raw):
    """An independent HIAREL01 output oracle, never part of the native runtime."""
    import io
    stream = io.BytesIO(raw)
    header = stream.read(24)
    if len(raw) > WIRE_LIMIT or len(header) != 24:
        raise ValueError('wire extent')
    magic, count, reserved = struct.unpack('<3Q', header)
    if magic != BUNDLE_MAGIC or reserved or not 1 <= count <= 256:
        raise ValueError('header')
    result = {}
    for _ in range(count):
        fields = stream.read(24)
        if len(fields) != 24:
            raise ValueError('entry header')
        n, mode, size = struct.unpack('<3Q', fields)
        if not 1 <= n <= 127 or mode != 0o400 or not 1 <= size <= IMAGE_LIMIT:
            raise ValueError('entry limits')
        name = stream.read(n)
        if len(name) != n or re.fullmatch(rb'[A-Za-z0-9][A-Za-z0-9._-]*', name) is None or name in result:
            raise ValueError('name')
        data = stream.read(size)
        if len(data) != size:
            raise ValueError('payload')
        result[name] = data
    if stream.read():
        raise ValueError('trailing bytes')
    return result


def expected_elf(images):
    prefix, holes = template()
    policy, compiler, packer = images
    result = bytearray(prefix + policy + compiler + packer)
    struct.pack_into('<Q', result, 96, len(result))
    struct.pack_into('<Q', result, 104, len(result))
    for name, at in holes.items():
        offset = len(prefix)
        if name in ('compiler_hole', 'packer_hole'):
            offset += len(policy)
        if name == 'packer_hole':
            offset += len(compiler)
        struct.pack_into('<i', result, at, offset - at - 4)
    return bytes(result)


def workspace(**words):
    raw = bytearray(IMAGE_AT + 1)
    for name, value in words.items():
        struct.pack_into('<Q', raw, int(name[1:]), value)
    return raw


def observe_policy(wire, work, *, output=b'', output_size=64, offsets=(), work_offsets=()):
    body, owners, views = Body(0), [], []
    for data, extent in ((wire, len(wire)), (output, output_size), (work, POLICY_WORK_BYTES)):
        owner = body.value('buffer', 'buffer.new', [body.const('usize', extent)])
        owners.append(owner)
        view = body.value('mutbuf', 'borrow.mut', [owner])
        for at, value in enumerate(data):
            if value:
                body.effect('buffer.store', [view, body.const('usize', at), body.const('u8', value)])
        if not views:
            body.effect('loan.end', [view])
            view = body.value('readbuf', 'borrow.read', [owner])
        views.append(view)
    status = body.value('u32', 'call', views, {'function': 'f0'})
    values = [body.value('u8', 'buffer.load', [views[1], body.const('usize', at)]) for at in offsets]
    values += [body.value('u8', 'buffer.load', [views[2], body.const('usize', at)]) for at in work_offsets]
    for view in views:
        body.effect('loan.end', [view])
    for owner in owners:
        body.effect('owner.drop', [owner])
    wrapper = ('hia-asm.v1 hepta.hia.program.v8 source_build_reference\n'
               'fn observe() -> (' + ','.join(['u32'] + ['u8'] * len(values)) +
               ') effects(alloc,read,write,trap) entry(b0)\nblock b0()\n' + body.text() +
               '  ret(' + ','.join([status, *values]) + ')\nend\n' + POLICY.read_text().split('\n', 1)[1])
    actual = execute_program(assemble_program(wrapper), 'observe', [], max_steps=4000000)
    assert actual['status'] == 'returned', actual
    return actual['values'][0], bytes(actual['values'][1:])


def vm_packer():
    images = (b'\xc3', b'\x90\xc3', b'\x90\x90\xc3')
    wire = struct.pack('<4Q', PACK_MAGIC, *map(len, images)) + b''.join(images)
    expected = expected_elf(images)
    b, owners, views = Body(0), [], []
    for data, extent in ((wire, len(wire)), (b'', len(expected)), (b'', 1), (expected, len(expected))):
        owner = b.value('buffer', 'buffer.new', [b.const('usize', extent)])
        owners.append(owner)
        view = b.value('mutbuf', 'borrow.mut', [owner])
        for at, value in enumerate(data):
            if value:
                b.effect('buffer.store', [view, b.const('usize', at), b.const('u8', value)])
        if len(views) in (0, 3):
            b.effect('loan.end', [view])
            view = b.value('readbuf', 'borrow.read', [owner])
        views.append(view)
    size = b.value('u32', 'call', views[:3], {'function': 'f0'})
    difference = b.value('u8', 'call', [views[1], views[3]], {'function': 'compare_all'})
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
    compare = render_assembly(document(compare, 'comparison')).split('\n', 1)[1].replace('fn f0(', 'fn compare_all(')
    source = ('hia-asm.v1 hepta.hia.program.v8 source_packer_reference\n'
              'fn observe() -> (u32,u8) effects(alloc,read,write,trap) entry(b0)\nblock b0()\n' +
              b.text() + '  ret(' + size + ',' + difference + ')\nend\n' + compare + PACKER.read_text().split('\n', 1)[1])
    actual = execute_program(assemble_program(source), 'observe', [], max_steps=4000000)
    assert actual['status'] == 'returned' and actual['values'] == [len(expected), 0], actual


class SourceBuilderSourceTests(unittest.TestCase):
    def test_complete_generated_sources_and_disjoint_fixed_layout(self):
        from tools.qualify_hia_selfhost import CAPACITY
        self.assertEqual(POLICY.read_text(), render_assembly(document(policy_source(), 'source_build_policy')))
        self.assertEqual(PACKER.read_text(), render_assembly(document(packer_source(), 'source_build_packer')))
        self.assertEqual(IMAGE_LIMIT, CAPACITY)
        self.assertEqual(COMPILER_WORK_BYTES, CAPACITY)
        regions = [(LAYOUT['ARGS'], 4096), (LAYOUT['WORK'], POLICY_WORK_BYTES),
                   (LAYOUT['COMPWORK'], COMPILER_WORK_BYTES), (LAYOUT['FRAME'], LAYOUT['FRAME_CAP']),
                   (LAYOUT['OUT'], WIRE_LIMIT), (LAYOUT['WIRE'], LAYOUT['WIRE_CAP'])]
        for (start, size), (following, _) in zip(regions, regions[1:]):
            self.assertEqual(start + size, following)
            self.assertEqual(start % 4096, 0)
        self.assertEqual(regions[-1][0] + regions[-1][1], LAYOUT['MAPSIZE'])

    def test_independent_vm_arguments_and_permanent_protocol_poison(self):
        args = struct.pack('<2Q', 1, 5) + b'build'
        self.assertEqual(observe_policy(args, workspace(), work_offsets=(8, 16)), (0, b'\x01\x01'))
        for changed in (args[:-1], struct.pack('<2Q', 2, 5) + b'build', struct.pack('<2Q', 1, 3) + b'bad'):
            self.assertEqual(observe_policy(changed, workspace(), work_offsets=(16,)), (16, b'\xff'))
        self.assertEqual(observe_policy(args, workspace(p16=255), work_offsets=(16,)), (16, b'\xff'))
        self.assertEqual(observe_policy(b'', workspace(p0=3, p16=0), work_offsets=(16,)), (16, b'\xff'))

    def test_independent_vm_admission_preflight_and_no_partial_capacity_write(self):
        wire = bundle([('a.hepta', 0o400, b'x')])
        initial = bytes([0xa5]) * 64
        self.assertEqual(observe_policy(wire, workspace(p0=1, p8=1, p16=1), work_offsets=(16, 24)), (0, b'\x02\x01'))
        for malformed in (wire + b'x', wire[:-1], bundle([('../x.hepta', 0o400, b'x')]),
                          bundle([('a.hepta', 0o400, b'x'), ('a.hepta', 0o400, b'y')])):
            code, output = observe_policy(malformed, workspace(p0=1, p8=1, p16=1), output=initial, offsets=range(64))
            self.assertEqual((code, output), (16, initial))
        w = workspace(p0=3, p8=1, p16=3, p24=1, p40=len(wire), p48=24, p72=1,
                      p4096=48, p4104=7, p4112=55, p4120=1)
        w[IMAGE_AT] = 195
        code, output = observe_policy(wire, w, output=initial, offsets=range(64))
        self.assertEqual((code, output), (17, initial))
        self.assertEqual(observe_policy(b'', workspace(p0=3, p16=3, p72=0xffffffff))[0], 18)

    def test_independent_vm_elf_complete_byte_oracle(self):
        vm_packer()

    def test_strict_receipt_identity_and_integer_size_fields(self):
        from tools.build_hia_source_build import _check_compile_receipt
        compiler, source, produced = b'compiler', b'source', b'image'
        good = {'status': 'returned', 'abi_status': 0, 'core_u32': len(produced),
                'artifact_sha256': sha256(compiler).hexdigest(), 'image_sha256': sha256(compiler).hexdigest(),
                'input_sha256': sha256(source).hexdigest(), 'source_sha256': sha256(source).hexdigest(),
                'input_bytes': len(source), 'source_unchanged': True, 'forbidden_compiler_modules_loaded': [],
                'produced_bytes': len(produced), 'produced_sha256': sha256(produced).hexdigest()}
        _check_compile_receipt(good, compiler=compiler, source=source, produced=produced)
        for field, wrong in [('artifact_sha256', '0' * 64), ('image_sha256', '0' * 64),
                             ('abi_status', False), ('core_u32', True), ('input_bytes', True), ('produced_bytes', True),
                             ('input_sha256', '0' * 64), ('source_sha256', '0' * 64),
                             ('source_unchanged', False), ('forbidden_compiler_modules_loaded', None),
                             ('produced_sha256', '0' * 64), ('status', 'failed')]:
            with self.subTest(field=field), self.assertRaises(ValueError):
                _check_compile_receipt({**good, field: wrong}, compiler=compiler, source=source, produced=produced)

    def test_cold_admission_precedes_output_and_never_falls_back_to_development(self):
        from tools.build_hia_source_build import build
        with tempfile.TemporaryDirectory(prefix='hia-source-build-refusal-') as directory:
            base = Path(directory)
            (base / 'compiler').write_bytes(b'not executed')
            (base / 'cold.json').write_text('{}')
            with self.assertRaisesRegex(ValueError, 'cold qualification'):
                build(base / 'absent', base / 'compiler', base / 'cold.json')
            self.assertFalse((base / 'absent').exists())


class SourceBuilderNativeTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        from tools.qualify_hia_selfhost import build_seed, compile_stage, invoke
        cls.temporary = None
        out = os.environ.get('HEPTA_HIA_SOURCE_BUILD_OBSERVATIONS')
        if out:
            cls.folder = Path(out)
            cls.folder.mkdir(mode=0o700)
        else:
            cls.temporary = tempfile.TemporaryDirectory(prefix='hia-source-build-native-')
            cls.folder = Path(cls.temporary.name)
        cls.observations = []
        cls.serial = 0
        cls.sources = [(name, 0o400, (ROOT / 'examples/hia_bootstrap' / name).read_bytes()) for name in ROLE_NAMES]
        cls.input_bundle = bundle(cls.sources)
        cold = os.environ.get('HEPTA_HIA_SOURCE_BUILD_COLD_REPORT')
        development = os.environ.get('HEPTA_HIA_SOURCE_BUILD_DEVELOPMENT_MANIFEST')
        cls.generations = []
        if cold:
            from tools.build_hia_source_build import build
            outer = json.loads(Path(cold).read_bytes())
            nested = json.loads(Path(outer['nested_report']).read_bytes())
            cls.compiler = Path(nested['generations'][-1]['produced_image'])
            cls.app = build(cls.folder / 'cold-build', cls.compiler, Path(cold))
            cls.policy_image = (cls.app.parent / 'policy.image.bin').read_bytes()
            cls.packer_image = (cls.app.parent / 'packer.image.bin').read_bytes()
            cls.generations = list(outer['generation_sha256'])
            cls.evidence_scope = 'current complete cold contract through the actual strict builder'
        elif development:
            record = json.loads(Path(development).read_bytes())
            expected_sources = {name: sha256((ROOT / name).read_bytes()).hexdigest() for name in PINNED_FILES}
            if record.get('development_only') is not True or record.get('sources') != expected_sources:
                raise ValueError('development source identity differs from the current checked sources')
            cls.compiler = Path(record['compiler'])
            cls.app = Path(record['app'])
            cls.policy_image = Path(record['images']['source_build_policy']).read_bytes()
            cls.packer_image = Path(record['images']['source_build_packer']).read_bytes()
            if sha256(cls.app.read_bytes()).hexdigest() != record['app_sha256']:
                raise ValueError('development executable image drift')
            cls.evidence_scope = 'explicit development artifact; no cold qualification claim'
        else:
            # This independent VM witness runs before the Python seed boundary.
            vm_packer()
            seed, _ = build_seed(cls.folder)
            source = cls.sources[1][2]
            first, _ = compile_stage(cls.folder, 'B1', seed, source, image_format='seed-shared')
            second, _ = compile_stage(cls.folder, 'B2', first, source)
            cls.compiler, _ = compile_stage(cls.folder, 'B3', second, source)
            cls.generations = [sha256(p.read_bytes()).hexdigest() for p in (first, second, cls.compiler)]
            if len(set(cls.generations)) != 1:
                raise AssertionError('B1/B2/B3 do not have identical bytes')
            policy, _ = compile_stage(cls.folder, 'policy', cls.compiler, POLICY.read_bytes())
            packer, _ = compile_stage(cls.folder, 'packer', cls.compiler, PACKER.read_bytes())
            cls.policy_image, cls.packer_image = policy.read_bytes(), packer.read_bytes()
            compiler_image = cls.compiler.read_bytes()
            wire = struct.pack('<4Q', PACK_MAGIC, len(cls.policy_image), len(compiler_image), len(cls.packer_image))
            wire += cls.policy_image + compiler_image + cls.packer_image
            receipt, raw = invoke(cls.folder, 'bootstrap-pack', packer, wire)
            if receipt.get('status') != 'returned' or not 0 < receipt['core_u32'] <= len(raw):
                raise AssertionError(receipt)
            cls.app = cls.folder / 'hia-source-build'
            cls.app.write_bytes(raw[:receipt['core_u32']])
            cls.app.chmod(0o500)
            cls.evidence_scope = 'fresh independent VM and B0/B1/B2/B3 development evidence'
        cls.compiler_image = cls.compiler.read_bytes()
        if cls.app.read_bytes() != expected_elf((cls.policy_image, cls.compiler_image, cls.packer_image)):
            raise ValueError('standalone ELF does not contain the exact selected images and transport')
        cls.original_app = cls.app.read_bytes()

    @classmethod
    def tearDownClass(cls):
        report = {'schema': 'hepta.hia.source-build-observations.v1', 'scope': cls.evidence_scope,
                  'cold_report': os.environ.get('HEPTA_HIA_SOURCE_BUILD_COLD_REPORT'),
                  'generations': cls.generations, 'executable_sha256': sha256(cls.original_app).hexdigest(),
                  'compiler_sha256': sha256(cls.compiler_image).hexdigest(),
                  'sources': {name: sha256((ROOT / name).read_bytes()).hexdigest() for name in PINNED_FILES},
                  'observations': cls.observations, 'memory_layout': LAYOUT,
                  'whole_native_delivery_qualified': False}
        (cls.folder / 'observations.json').write_text(json.dumps(report, indent=2, sort_keys=True) + '\n')
        if cls.temporary is not None:
            cls.temporary.cleanup()

    def setUp(self):
        type(self).serial += 1
        self.case = self.folder / ('case-' + str(self.serial))
        self.case.mkdir(mode=0o700)

    def run_app(self, wire, operation='build', *, code=0, app=None, args=None, timeout=120):
        target = Path(app or self.app)
        before = target.read_bytes()
        result = subprocess.run([str(target), *(args if args is not None else [operation])], input=wire,
                                capture_output=True, env={'PATH': ''}, cwd=self.case, timeout=timeout)
        self.observations.append({'case': self.id(), 'operation': operation,
                                  'input_sha256': sha256(wire).hexdigest(), 'input_bytes': len(wire),
                                  'executable_sha256': sha256(before).hexdigest(),
                                  'returncode': result.returncode, 'output_bytes': len(result.stdout),
                                  'output_sha256': sha256(result.stdout).hexdigest(),
                                  'stderr_sha256': sha256(result.stderr).hexdigest()})
        self.assertEqual(target.read_bytes(), before)
        self.assertEqual(result.returncode, code, result.stderr)
        self.assertEqual(result.stderr, b'')
        if code:
            self.assertEqual(result.stdout, b'')
        return result.stdout

    def test_actual_native_compilation_and_modified_source_effect(self):
        from tools.qualify_hia_selfhost import invoke
        changed = SMALL.replace(b'"value":7', b'"value":19')
        built = unpack(self.run_app(bundle([('first.hepta', 0o400, SMALL), ('second.hepta', 0o400, changed)])))
        self.assertEqual(built[b'first.hepta'], SMALL)
        self.assertEqual(built[b'second.hepta'], changed)
        self.assertNotEqual(built[b'first.hepta.bin'], built[b'second.hepta.bin'])
        for name, value in (('first', 7), ('second', 19)):
            image = self.case / (name + '.image.bin')
            image.write_bytes(built[(name + '.hepta.bin').encode()])
            receipt, _ = invoke(self.case, name, image, b'', capacity=0, workspace_size=0)
            self.assertEqual((receipt['status'], receipt['core_u32']), ('returned', value))

    def test_complete_sourcekit_and_two_native_self_rebuilds(self):
        previous = self.original_app
        app = self.app
        for generation in (1, 2):
            kit = self.run_app(self.input_bundle, app=app)
            parsed = unpack(kit)
            self.assertEqual(set(parsed), {n.encode() for n in (*ROLE_NAMES, *(s + '.bin' for s in ROLE_NAMES))})
            for name, _, source in self.sources:
                self.assertEqual(parsed[name.encode()], source)
            for name, image in zip(ROLE_NAMES, (self.policy_image, self.compiler_image, self.packer_image)):
                self.assertEqual(parsed[(name + '.bin').encode()], image)
            rebuilt = self.run_app(kit, 'pack', app=app)
            self.assertEqual(rebuilt, previous)
            app = self.case / ('generation-' + str(generation))
            app.write_bytes(rebuilt)
            app.chmod(0o500)
            previous = rebuilt

    def test_actual_compiler_swap_restored_before_receipt_check_is_rejected(self):
        from tools.build_hia_source_build import _check_compile_receipt
        from tools.qualify_hia_selfhost import compile_stage, mutate_compiler
        changed = mutate_compiler(self.sources[1][2])
        actual = unpack(self.run_app(bundle([('selfhost.hepta', 0o400, changed)])))[b'selfhost.hepta.bin']
        self.assertNotEqual(actual, self.compiler_image)
        path = self.case / 'temporarily-replaced-compiler.image.bin'
        path.write_bytes(actual)
        try:
            produced, receipt = compile_stage(self.case, 'actual-temporary-compiler', path, SMALL)
        finally:
            path.write_bytes(self.compiler_image)
        self.assertEqual(path.read_bytes(), self.compiler_image)
        self.assertEqual(receipt['artifact_sha256'], sha256(actual).hexdigest())
        with self.assertRaisesRegex(ValueError, 'actual native call identity'):
            _check_compile_receipt(receipt, compiler=self.compiler_image, source=SMALL, produced=produced.read_bytes())
        self.observations.append({'actual_temporary_compiler_swap_refused': True,
                                  'expected_compiler_sha256': sha256(self.compiler_image).hexdigest(),
                                  'actual_compile_receipt': receipt})

    def test_actual_sealed_bootstrap_descriptor_build_and_pack(self):
        from tools.build_hia_source_build import _run_captured
        built = _run_captured(self.original_app, 'build', self.input_bundle, self.case)
        self.assertEqual((built.returncode, built.stderr), (0, b''))
        self.assertEqual(len(unpack(built.stdout)), 6)
        packed = _run_captured(self.original_app, 'pack', built.stdout, self.case)
        self.assertEqual((packed.returncode, packed.stderr, packed.stdout), (0, b'', self.original_app))

    def test_final_publication_uses_anonymous_descriptor_under_real_path_replacement(self):
        from tools.build_hia_source_build import _publish_captured
        from unittest.mock import patch
        decoy = self.case / 'bootstrap-private'
        decoy.write_bytes(self.original_app)
        original_link = os.link
        entered = []
        def replace_old_path_then_link(source, target, **kwargs):
            decoy.replace(self.case / 'retained-original-decoy')
            decoy.write_bytes(b'wrong image substituted at the publication syscall')
            self.assertTrue(source.startswith('/proc/self/fd/'))
            fd = int(source.rsplit('/', 1)[1])
            self.assertEqual(os.fstat(fd).st_nlink, 0)
            self.assertEqual(os.pread(fd, len(self.original_app) + 1, 0), self.original_app)
            self.assertIs(kwargs['follow_symlinks'], True)
            self.assertIsInstance(kwargs['dst_dir_fd'], int)
            entered.append((os.fstat(fd).st_dev, os.fstat(fd).st_ino))
            return original_link(source, target, **kwargs)
        with patch('tools.build_hia_source_build.os.link', side_effect=replace_old_path_then_link):
            binding = _publish_captured(self.case, self.original_app, {'status': 'test publication'})
        actual = self.case / 'hia-source-build'
        self.assertEqual(actual.read_bytes(), self.original_app)
        self.assertNotEqual(actual.read_bytes(), decoy.read_bytes())
        self.assertEqual(entered, [(actual.stat().st_dev, actual.stat().st_ino)])
        self.assertEqual(json.loads((self.case / 'build.json').read_bytes())['publication'], binding)
        self.assertEqual(binding['sha256'], sha256(actual.read_bytes()).hexdigest())
        self.assertEqual(binding['inode'], actual.stat().st_ino)
        self.observations.append({'actual_path_replacement_cannot_change_published_inode': True,
                                  'publication': binding})

    def test_final_publication_never_replaces_and_rolls_back_on_receipt_conflict(self):
        from tools.build_hia_source_build import _publish_captured
        for existing in ('hia-source-build', 'build.json'):
            directory = self.case / existing.replace('.', '-')
            directory.mkdir()
            prior = directory / existing
            prior.write_bytes(b'preexisting bytes must survive')
            with self.assertRaises(FileExistsError):
                _publish_captured(directory, self.original_app, {'status': 'test publication'})
            self.assertEqual(prior.read_bytes(), b'preexisting bytes must survive')
            self.assertEqual({p.name for p in directory.iterdir()}, {existing})

    def test_normal_sourcekit_and_executable_publication_bind_actual_files(self):
        from tools.build_hia_source_build import _publish_captured
        import stat
        sourcekit = self.run_app(self.input_bundle)
        binding = _publish_captured(self.case, self.original_app,
                                    {'status': 'test publication'}, sourcekit=sourcekit)
        report = json.loads((self.case / 'build.json').read_bytes())
        self.assertEqual(report['publication'], binding)
        self.assertEqual(report['sourcekit_path'], 'sourcekit.bin')
        for name, key, data, mode in (('hia-source-build', 'publication', self.original_app, 0o500),
                                      ('sourcekit.bin', 'sourcekit_publication', sourcekit, 0o400)):
            path = self.case / name
            info = path.stat()
            actual = report[key]
            self.assertEqual(path.read_bytes(), data)
            self.assertEqual((actual['device'], actual['inode']), (info.st_dev, info.st_ino))
            self.assertEqual((actual['size'], actual['mode']), (len(data), mode))
            self.assertEqual(stat.S_IMODE(info.st_mode), mode)
            self.assertEqual(actual['sha256'], sha256(data).hexdigest())
            self.assertEqual(actual['source'], 'O_TMPFILE retained descriptor')
            self.assertIs(actual['no_replace'], True)
        self.assertEqual(report['sourcekit_sha256'], sha256(sourcekit).hexdigest())
        self.assertEqual(self.run_app((self.case / 'sourcekit.bin').read_bytes(), 'pack',
                                      app=self.case / 'hia-source-build'), self.original_app)
        self.observations.append({'normal_captured_output_publications': {
            name: report[name] for name in ('publication', 'sourcekit_publication')},
            'actual_published_sourcekit_native_repack_equal': True})

    def test_modified_compiler_M1_differs_M2_equals_M3(self):
        from tools.qualify_hia_selfhost import mutate_compiler
        # The existing qualified mutation changes emitted wrapper stack space
        # from 64 to 80 bytes, retaining its alignment and language profile.
        modified = [(name, mode, mutate_compiler(source) if name == 'selfhost.hepta' else source)
                    for name, mode, source in self.sources]
        assemble_program(modified[1][2])
        wire = bundle(modified)
        compilers, executables = [], []
        app = self.app
        for generation in (1, 2, 3):
            kit = self.run_app(wire, app=app)
            compilers.append(unpack(kit)[b'selfhost.hepta.bin'])
            executable = self.run_app(kit, 'pack', app=app)
            executables.append(executable)
            app = self.case / ('M' + str(generation))
            app.write_bytes(executable)
            app.chmod(0o500)
        self.assertNotEqual(compilers[0], compilers[1])
        self.assertEqual(compilers[1], compilers[2])
        self.assertEqual(executables[1], executables[2])
        self.assertNotEqual(compilers[2], self.compiler_image)
        self.assertEqual(compilers[0][:8], bytes.fromhex('554889e54883ec40'))
        self.assertEqual(compilers[2][:8], bytes.fromhex('554889e54883ec50'))
        self.observations.append({'causality': 'changed compiler source',
                                  **{'M' + str(i): sha256(raw).hexdigest()
                                     for i, raw in enumerate(compilers, 1)}})

    def test_exact_pack_roles_and_source_image_identity_without_input_execution(self):
        # UD2 inputs remain opaque bytes: packing them must not execute them.
        images = [(name + '.bin', 0o400, b'\x0f\x0b') for name in ROLE_NAMES]
        self.assertEqual(self.run_app(bundle(images[::-1]), 'pack'), expected_elf((b'\x0f\x0b',) * 3))
        kit = unpack(self.run_app(self.input_bundle))
        correct = [(name.decode(), 0o400, data) for name, data in kit.items()]
        for index in (1, 3, 5):
            bad = list(correct)
            name, mode, raw = bad[index]
            bad[index] = name, mode, raw[:-1] + bytes([raw[-1] ^ 1])
            self.run_app(bundle(bad), 'pack', code=19)
        self.run_app(bundle(images + [('extra.hepta', 0o400, SMALL)]), 'pack', code=16)
        self.run_app(bundle([('wrong.bin', 0o400, b'\x0f\x0b'), *images[1:]]), 'pack', code=16)

    def test_complete_input_preflight_and_late_compile_failure_publish_nothing(self):
        good = bundle([('a.hepta', 0o400, SMALL)])
        malformed = [good[:-1], good + b'x', b'', good[:23],
                     bytes([good[0] ^ 1]) + good[1:], good[:16] + struct.pack('<Q', 1) + good[24:]]
        for name in ('../a.hepta', '.a.hepta', 'a/b.hepta', 'a.hia', 'a.HEPTA', '', 'a' * 118 + '.hepta'):
            malformed.append(bundle([(name, 0o400, SMALL)]))
        malformed += [bundle([(b'\xff.hepta', 0o400, SMALL)]), bundle([('a.hepta', 0o500, SMALL)]),
                      bundle([('a.hepta', 0o400, b'')]),
                      bundle([('a.hepta', 0o400, SMALL), ('a.hepta', 0o400, SMALL)])]
        for wire in malformed:
            self.run_app(wire, code=16)
        self.run_app(bundle([('first.hepta', 0o400, SMALL), ('later.hepta', 0o400, b'not HIA assembly')]), code=18)
        self.assertEqual(list(self.case.iterdir()), [])
        for args in ([], ['bad'], ['build', 'extra'], ['build\n'], ['b' * 17]):
            self.run_app(good, code=16, args=args)

    def test_real_valid_JSON_hepta_stays_outside_retained_assembly_profile(self):
        from hepta.hia_program import verify_program
        raw = (ROOT / 'tests/fixtures/hia_artifact_session/byte_sum.core.hepta').read_bytes()
        verify_program(raw)
        wire = bundle([('first.hepta', 0o400, SMALL), ('byte_sum.core.hepta', 0o400, raw)])
        self.run_app(wire, code=18)
        self.assertEqual(list(self.case.iterdir()), [])

    def test_exact_name_source_and_member_limits(self):
        name = 'a' * 117 + '.hepta'
        parsed = unpack(self.run_app(bundle([(name, 0o400, SMALL)])))
        self.assertEqual(parsed[name.encode()], SMALL)
        self.assertEqual(len((name + '.bin').encode()), 127)
        # Blank-line padding is intentionally outside the retained compiler's
        # canonical assembly syntax. Exactly 1 MiB must reach that compiler
        # refusal (18); one extra byte must fail bundle admission instead (16).
        source = SMALL + b'\n' * (IMAGE_LIMIT - len(SMALL))
        self.run_app(bundle([(name, 0o400, source)]), code=18)
        self.run_app(bundle([(name, 0o400, source + b'\n')]), code=16)
        many = [(f'f{i}.hepta', 0o400, SMALL) for i in range(128)]
        self.assertEqual(len(unpack(self.run_app(bundle(many)))), 256)
        self.run_app(bundle(many + [('overflow.hepta', 0o400, SMALL)]), code=16)

    def test_large_pack_and_real_final_output_capacity_refusal(self):
        opaque = bytes([0x5a]) * IMAGE_LIMIT
        files = [(n + '.bin', 0o400, opaque) for n in ROLE_NAMES]
        packed = self.run_app(bundle(files), 'pack')
        self.assertEqual(packed, expected_elf((opaque,) * 3))
        # Every source is valid and really compiled. Failure occurs only when
        # the next successful image would exceed the 64 MiB result budget.
        compiler_source = self.sources[1][2]
        count = WIRE_LIMIT // (len(compiler_source) + len(self.compiler_image) + 52 + 2 * len('unit000.hepta')) + 1
        self.assertLessEqual(count, 128)
        wire = bundle([(f'unit{i:03}.hepta', 0o400, compiler_source) for i in range(count)])
        self.assertLessEqual(len(wire), WIRE_LIMIT)
        self.run_app(wire, code=17, timeout=180)
        self.assertEqual(list(self.case.iterdir()), [])

    def test_wire_limit_and_kernel_io_failures(self):
        self.run_app(bytes(WIRE_LIMIT), code=16)
        self.run_app(bytes(WIRE_LIMIT + 1), code=17)
        fd = os.open(self.case, os.O_RDONLY | os.O_DIRECTORY)
        try:
            process = subprocess.run([str(self.app), 'build'], stdin=fd, capture_output=True,
                                     env={'PATH': ''}, cwd=self.case, timeout=120)
        finally:
            os.close(fd)
        self.assertEqual((process.returncode, process.stdout, process.stderr), (15, b'', b''))
        wire = bundle([('a.hepta', 0o400, SMALL)])
        with open('/dev/full', 'wb') as full:
            process = subprocess.run([str(self.app), 'build'], input=wire, stdout=full,
                                     stderr=subprocess.PIPE, env={'PATH': ''}, cwd=self.case, timeout=120)
        self.assertEqual((process.returncode, process.stderr), (15, b''))

    def test_real_EPIPE_after_a_written_prefix_exits_with_io_status(self):
        strace = shutil.which('strace')
        self.assertIsNotNone(strace)
        opaque = bytes([0x5a]) * IMAGE_LIMIT
        wire = bundle([(name + '.bin', 0o400, opaque) for name in ROLE_NAMES])
        input_path, log = self.case / 'input.bin', self.case / 'write-syscalls.log'
        input_path.write_bytes(wire)
        with input_path.open('rb') as source:
            process = subprocess.Popen([strace, '-o', str(log), '-e', 'trace=write', str(self.app), 'pack'],
                                       stdin=source, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                                       env={'PATH': ''}, cwd=self.case, start_new_session=True)
            completed = False
            deadline = time.monotonic() + 30
            try:
                prefix = bytearray()
                descriptor = process.stdout.fileno()
                os.set_blocking(descriptor, False)
                with selectors.DefaultSelector() as selector:
                    selector.register(descriptor, selectors.EVENT_READ)
                    while len(prefix) < 4096:
                        remaining = deadline - time.monotonic()
                        if remaining <= 0 or not selector.select(remaining):
                            raise TimeoutError('native EPIPE control did not publish a prefix before its deadline')
                        try:
                            chunk = os.read(descriptor, 4096 - len(prefix))
                        except BlockingIOError:
                            continue
                        if not chunk:
                            break
                        prefix += chunk
                self.assertEqual(len(prefix), 4096)
                process.stdout.close()
                process.stdout = None
                _, error = process.communicate(timeout=max(0.001, deadline - time.monotonic()))
                code = process.returncode
                completed = True
            finally:
                try:
                    if not completed:
                        # Popen created this invocation's own session/group.
                        # Kill both tracer and tracee before reaping the leader.
                        try:
                            os.killpg(process.pid, signal.SIGKILL)
                        except ProcessLookupError:
                            pass
                        process.wait(timeout=10)
                finally:
                    if process.stdout is not None:
                        process.stdout.close()
                    process.stderr.close()
        self.assertEqual((code, error), (15, b''))
        self.assertEqual(prefix, expected_elf((opaque,) * 3)[:4096])
        trace = log.read_text()
        self.assertIn('EPIPE', trace)
        self.assertRegex(trace, r'write\(1,.*\)\s+= [1-9][0-9]*')
        self.observations.append({'kernel_write_failure': 'EPIPE', 'prefix_bytes': len(prefix),
                                  'returncode': code, 'syscall_trace_sha256': sha256(log.read_bytes()).hexdigest()})

    def test_copied_executable_empty_PATH_and_no_external_runtime(self):
        copied = self.case / 'arbitrary-name'
        copied.write_bytes(self.original_app)
        copied.chmod(0o500)
        wire = bundle([('a.hepta', 0o400, SMALL)])
        expected = self.run_app(wire, app=copied)
        strace = shutil.which('strace')
        self.assertIsNotNone(strace, 'the existing native qualification prerequisite strace is required')
        log = self.case / 'syscalls.log'
        process = subprocess.run([strace, '-f', '-o', str(log), '-e', 'trace=process,file,memory',
                                  str(copied), 'build'], input=wire, capture_output=True,
                                 env={'PATH': ''}, cwd=self.case, timeout=120)
        self.assertEqual((process.returncode, process.stdout, process.stderr), (0, expected, b''))
        trace = log.read_text()
        self.assertEqual(len(re.findall(r'\bexecve\(', trace)), 1, trace)
        self.assertNotRegex(trace, r'\b(?:execveat|clone|clone3|fork|vfork|open|openat|openat2|creat)\(')
        self.assertNotIn('PROT_WRITE|PROT_EXEC', trace)
        self.assertIn(str(LAYOUT['MAPSIZE']), trace)


if __name__ == '__main__':
    unittest.main()
