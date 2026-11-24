"""Real no-selector candidate installation, default worker custody and callers."""
from __future__ import annotations

from hashlib import sha256
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest
from unittest.mock import patch
import zipfile

ROOT = Path(__file__).resolve().parents[1]
COLD = 'HEPTA_HIA_DEFAULT_RELEASE_COLD_REPORT'
DEVELOPMENT = 'HEPTA_HIA_DEFAULT_RELEASE_DEVELOPMENT_COMPILER'
EVIDENCE = 'HEPTA_HIA_DEFAULT_RELEASE_EVIDENCE'


def clean_environment():
    return {**{key: value for key, value in os.environ.items()
               if key not in ('PYTHONPATH', 'PYTHONHOME') and not key.startswith('HEPTA_HIA_')},
            'PYTHONDONTWRITEBYTECODE': '1'}


class DefaultReleaseSourceTests(unittest.TestCase):
    def test_cpython_3123_package_selection_preserves_scopes_and_translations(self):
        import argparse
        from hepta import hia_default_native as default
        from hepta.hia_native_helpers import native_helpers_scope
        with (patch('hepta.hia_cli_native.native_cli_profile', return_value=3123),
              patch.object(default, '_package_cli', return_value='ordinary') as package,
              patch('gettext.find', return_value=None)):
            self.assertEqual(default.default_cli(), 'ordinary')
            with native_helpers_scope():
                self.assertIsNone(default.default_cli())
            with patch('gettext.find', return_value='/catalog/messages.mo'):
                self.assertIsNone(default.default_cli())
            with patch.object(argparse, '_', side_effect=lambda text: 'local ' + text):
                self.assertIsNone(default.default_cli())
            package.assert_called_once_with()

    def test_cpython_3123_implicit_python_argv_keeps_host_object_protocol(self):
        from hepta.hia_cli_native import NativeCli, SELECTOR
        from hepta import cli
        class Argument(str):
            pass
        argv = [Argument('catalog'), object()]
        owner = NativeCli(None, None)
        environment = {key: value for key, value in os.environ.items() if key != SELECTOR}
        with (patch.dict(os.environ, environment, clear=True),
              patch('hepta.hia_cli_native.native_cli_profile', return_value=3123),
              patch.object(cli, '_reference_hia_main', return_value=17) as reference):
            self.assertEqual(owner.run(iter(argv), cli), 17)
            received = reference.call_args.args[0]
            self.assertIs(received[0], argv[0])
            self.assertIs(received[1], argv[1])
            reference.assert_called_once_with(argv, package_discovery=True)

    def test_portable_pin_retains_original_api_on_other_host_observations(self):
        from hepta.hia_default_native import capture_default_bundle, render_pin
        from hepta.hia_full_cost_gate import assess_full_cost
        from tests.test_hia_full_cost_native import fixture, wire, original
        self.assertEqual((ROOT / 'hepta/hia_default_native_pin.py').read_bytes(), render_pin(None))
        with patch.dict(os.environ, clean_environment(), clear=True), \
             patch('hepta.hia_native_helpers.NativeHelpersBinding', side_effect=AssertionError('native binding')):
            for system, machine in (('Windows', 'AMD64'), ('Darwin', 'arm64'), ('Linux', 'aarch64')):
                with patch('platform.system', return_value=system), patch('platform.machine', return_value=machine):
                    self.assertIsNone(capture_default_bundle())
                    self.assertEqual(assess_full_cost(wire(fixture())), original()(wire(fixture())))

    def test_portable_worker_scope_is_still_unselected(self):
        from hepta.hia_native_helpers import native_helpers_scope, native_helpers_identity
        with patch.dict(os.environ, clean_environment(), clear=True), native_helpers_scope() as selected:
            self.assertIsNone(selected)
            self.assertEqual(native_helpers_identity(), {})

    def test_invalid_cold_or_missing_choice_cannot_create_candidate_output(self):
        from tools.build_hia_default_release import build
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            compiler, cold = root / 'compiler', root / 'cold.json'
            compiler.write_bytes(b'not a compiler')
            cold.write_text('{}')
            for arguments in ({}, {'cold_report': cold}, {'cold_report': cold, 'development': True}):
                with self.subTest(arguments=arguments), self.assertRaises(ValueError):
                    build(root / 'must-not-exist', compiler, **arguments)
                self.assertFalse((root / 'must-not-exist').exists())

    def test_pin_value_cannot_change_without_its_captured_declaration(self):
        from hepta import hia_default_native_pin
        from hepta.hia_default_native import capture_default_bundle, PIN_SCHEMA, TARGET, BUNDLE_RESOURCE
        candidate = (PIN_SCHEMA, TARGET, BUNDLE_RESOURCE, 'a' * 64,
                     'DEVELOPMENT_COMPONENT', '-', 'b' * 64)
        with patch.object(hia_default_native_pin, 'RELEASE_PIN', candidate), \
             patch('hepta.hia_native_helpers.NativeHelpersBinding', side_effect=AssertionError('native binding')):
            with self.assertRaisesRegex(ValueError, 'pin'):
                capture_default_bundle()


PRELUDE = r'''
import importlib.abc, json, os, sys
from pathlib import Path
from unittest.mock import patch
installed = Path(sys.argv[1]).resolve()
sys.path.insert(0, str(installed))
assert not [key for key in os.environ if key.startswith('HEPTA_HIA_') and key.endswith('_MANIFEST')]
class NoAuthoringImports(importlib.abc.MetaPathFinder):
    def find_spec(self, fullname, path=None, target=None):
        if fullname == 'tools' or fullname.startswith('tools.'):
            raise AssertionError('installed runtime imported authoring: ' + fullname)
sys.meta_path.insert(0, NoAuthoringImports())
from hepta import hia_full_cost_gate as owner
from hepta import hia_full_cost_native as native
from hepta import hia_default_native as defaults
from hepta import hia_native_helpers as helpers
assert Path(owner.__file__).resolve().is_relative_to(installed)
assert Path(native.__file__).resolve().is_relative_to(installed)
assert native.SOURCE.resolve().is_relative_to(installed)
raw = Path(sys.argv[2]).read_bytes()
def forbidden(*args, **kwargs):
    raise AssertionError('retained arithmetic or unpinned loader entered')
owner._reference_arm = owner._reference_decision = forbidden
'''


class DefaultReleaseNativeTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        from tools.build_hia_default_release import build
        from tools.build_hia_patch_impact import build as build_patch
        from tests.test_hia_full_cost_native import original, threshold_cases, wire, interpreted
        from hepta.hia_agent_assembly import assemble_program
        from hepta import hia_full_cost_native as native
        cold, development = os.environ.get(COLD), os.environ.get(DEVELOPMENT)
        if ((cold is None) == (development is None) or cold == '' or development == ''):
            raise ValueError('default-release tests require one current cold report or explicit development compiler')
        evidence = os.environ.get(EVIDENCE)
        if evidence is not None:
            if not evidence:
                raise ValueError('default-release evidence directory must not be empty')
            cls.root = Path(evidence).absolute()
            cls.root.mkdir(mode=0o700, exist_ok=False)
        else:
            cls.temporary = tempfile.TemporaryDirectory(prefix='hia-default-release-')
            cls.root = Path(cls.temporary.name)
            cls.addClassCleanup(cls.temporary.cleanup)
        if cold:
            report = json.loads(Path(cold).read_bytes())
            nested = json.loads(Path(report['nested_report']).read_bytes())
            compiler = Path(nested['generations'][-1]['produced_image'])
        else:
            compiler = Path(development)
        # Observe both unchanged arithmetic protocols in the independent VM
        # before constructing any package image. Detailed numerical coverage
        # remains in the retained full-cost component and original caller suites.
        document = threshold_cases()[0]
        expected = original()(wire(document))
        program = assemble_program(native.SOURCE.read_bytes())
        arm = document['arms'][0]
        requests = (native.arm_packet(arm['one_time_ns'], arm['observations']),
                    native.decision_packet(expected['arm_total_ns'], expected['arm_observed_limits'],
                        expected['unknown_costs'], {a['observer_digest'] for a in document['arms']}, document))
        for request in requests:
            code, result = interpreted(program, request)
            if code != native.OUTPUT_BYTES or len(result) != native.OUTPUT_BYTES:
                raise AssertionError('independent full-cost VM did not admit the original protocol')
        cls.wheel = build(cls.root / 'build', compiler, cold, development=not bool(cold))
        cls.report = json.loads((cls.root / 'build/build.json').read_bytes())
        cls.patch_manifest = build_patch(cls.root / 'other-owner', compiler, cold, development=not bool(cold))
        cls.installed = cls.root / 'installed'
        cls.environment = clean_environment()
        cls.input = cls.root / 'input.json'
        cls.input.write_bytes(wire(threshold_cases()[0]))
        cls.expected = original()(cls.input.read_bytes())
        cls._run(['-m', 'pip', 'install', '--no-deps', '--no-index', '--no-compile',
                  '--target', cls.installed, cls.wheel])
        cls.initial_files = cls.inventory()

    @classmethod
    def tearDownClass(cls):
        from tools.build_hia_json_preflight import current_sources
        from tools.build_hia_default_release import encoded
        record = {'schema': 'hepta.hia.default-native-release-test-custody.v1',
            'scope': cls.report['scope'], 'source_manifest_before': cls.report['source_manifest'],
            'source_manifest_after': current_sources(), 'compiler_sha256': cls.report['compiler_sha256'],
            'cold_report_sha256': cls.report['cold_report_sha256'], 'wheel': str(cls.wheel),
            'wheel_sha256': sha256(cls.wheel.read_bytes()).hexdigest(),
            'package_build_sha256': sha256((cls.root / 'build/build.json').read_bytes()).hexdigest(),
            'default_bundle_sha256': cls.report['default_bundle_sha256'],
            'installed_files_before': cls.initial_files, 'installed_files_after': cls.inventory(),
            'source_and_installation_unchanged': (current_sources() == cls.report['source_manifest']
                and cls.inventory() == cls.initial_files),
            'independent_VM_both_protocols_before_image_construction': True,
            'retained_reference_bodies_removed': False, 'whole_native_delivery_qualified': False}
        (cls.root / 'component-custody.json').write_bytes(encoded(record))
        if not record['source_and_installation_unchanged']:
            raise ValueError('default-release source or installation changed during execution')

    @classmethod
    def _run(cls, arguments, *, env=None, input=None):
        result = subprocess.run([sys.executable, '-B', *map(str, arguments)], cwd=cls.root,
            env=env or cls.environment, input=input, capture_output=True, text=True, timeout=60)
        if result.returncode:
            raise AssertionError(result.stdout + result.stderr)
        return result

    @classmethod
    def child(cls, body, *arguments, env=None):
        return cls._run(['-I', '-c', PRELUDE + body, cls.installed, cls.input, *arguments], env=env)

    @classmethod
    def inventory(cls):
        return {str(p.relative_to(cls.installed)): sha256(p.read_bytes()).hexdigest()
                for p in sorted(cls.installed.rglob('*')) if p.is_file()}

    def tearDown(self):
        self.assertEqual(self.inventory(), self.initial_files)

    def test_wheel_record_rows_and_incremental_hashes_match_original_wheel_protocol(self):
        import base64
        import csv
        import io
        from hepta.hia_json_preflight_native import NativeHiaJsonImage
        from hepta.hia_sha256_stream_native import MAX_CHUNK, NativeSha256Stream
        from tools.build_hia_default_release import _wheel_record_row

        images = self.root / 'build' / 'wheel-record'
        def load(name, image_type):
            image = (images / (name + '.image.bin')).read_bytes()
            receipt = json.loads((images / (name + '.receipt.json')).read_bytes())
            return image_type(image, receipt['produced_sha256'])

        encoder = load('wheel_record_row', NativeHiaJsonImage)
        hasher = load('sha256_stream', NativeSha256Stream)
        content = b'wheel' * (MAX_CHUNK // 5 + 1)
        expected = sha256(content).digest()
        self.assertEqual(hasher.digest(content), expected)
        for name, size, digest in (('目录/"quoted",file\r\n', (1 << 64) - 1, expected),
                                   ('x' * 65535, 0, sha256(b'').digest()), ('w.dist-info/RECORD', 0, None)):
            with self.subTest(length=len(name), size=size):
                writer = io.StringIO(newline='')
                checksum = 'sha256=' + base64.urlsafe_b64encode(digest).decode().rstrip('=') if digest else ''
                csv.writer(writer, lineterminator='\n').writerow((name, checksum, size if digest else ''))
                self.assertEqual(_wheel_record_row(encoder, name, size, digest), writer.getvalue().encode())
        with self.assertRaises(ValueError):
            _wheel_record_row(encoder, 'x' * 65536, 0, expected)
        with self.assertRaises(ValueError):
            _wheel_record_row(encoder, 'w.dist-info/RECORD', 1)

    def test_hia_zip_writes_seekable_deflate_and_preserves_executable_mode(self):
        import io
        from hepta.hia_json_preflight_native import NativeHiaJsonImage
        from tools.build_hia_default_release import _write_zip

        images = self.root / 'build' / 'wheel-record'
        image = (images / 'wheel_zip_directory.image.bin').read_bytes()
        receipt = json.loads((images / 'wheel_zip_directory.receipt.json').read_bytes())
        encoder = NativeHiaJsonImage(image, receipt['produced_sha256'])
        package = 'hia_core-1'
        program = package + '.data/scripts/hia'
        members = {program: b'\x7fELF' + b'x' * (1 << 20), '资料/é': b'payload', 'empty': b''}
        members[package + '.data/scripts/text'] = b'not an ELF'
        actual = io.BytesIO()
        _write_zip(actual, members, package + '.dist-info', encoder)
        original = io.BytesIO()
        with zipfile.ZipFile(original, 'w') as archive:
            for name, contents in sorted(members.items()):
                member = zipfile.ZipInfo(name, (1980, 1, 1, 0, 0, 0))
                member.create_system = 3
                member.external_attr = (0o100755 if name == program else 0o100644) << 16
                member.compress_type = zipfile.ZIP_DEFLATED
                archive.writestr(member, contents)
        self.assertEqual(actual.getvalue(), original.getvalue())
        with zipfile.ZipFile(actual) as archive:
            self.assertIsNone(archive.testzip())
            self.assertEqual(archive.getinfo(program).external_attr >> 16, 0o100755)

    def test_hia_inflater_admits_extent_before_allocating(self):
        import ctypes
        import zlib
        from hepta.hia_json_preflight_native import NativeHiaJsonImage
        from tools.build_hia_default_release import _inflate_wheel_member

        folder = self.root / 'build' / 'wheel-record'
        raw = (folder / 'wheel_inflate.image.bin').read_bytes()
        receipt = json.loads((folder / 'wheel_inflate.receipt.json').read_bytes())
        image = NativeHiaJsonImage(raw, receipt['produced_sha256'])
        content = b'wheel' * 18432
        for level, strategy in ((0, zlib.Z_DEFAULT_STRATEGY), (6, zlib.Z_FIXED), (9, zlib.Z_DEFAULT_STRATEGY)):
            compressor = zlib.compressobj(level, zlib.DEFLATED, -15, zlib.DEF_MEM_LEVEL, strategy)
            encoded = compressor.compress(content) + compressor.flush()
            self.assertEqual(_inflate_wheel_member(image, encoded, len(content)), content)
            for damaged in (encoded[:-1], encoded + b'X'):
                with self.assertRaises(zipfile.BadZipFile):
                    _inflate_wheel_member(image, damaged, len(content))
        allocate = ctypes.create_string_buffer
        def bounded(value, *args):
            if isinstance(value, int) and value > 4112:
                self.fail('allocation preceded validation of the declared uncompressed extent')
            return allocate(value, *args)
        with patch.object(ctypes, 'create_string_buffer', bounded), self.assertRaises(zipfile.BadZipFile):
            _inflate_wheel_member(image, encoded, 1 << 44)

    def test_stored_and_deflated_members_use_checked_local_hia_extent(self):
        import ctypes
        import io
        from hepta.hia_json_preflight_native import NativeHiaJsonImage
        from tools.build_hia_default_release import _wheel_member

        folder = self.root / 'build' / 'wheel-record'
        def image(name):
            raw = (folder / (name + '.image.bin')).read_bytes()
            digest = json.loads((folder / (name + '.receipt.json')).read_bytes())['produced_sha256']
            return NativeHiaJsonImage(raw, digest)
        images = (None, None, image('wheel_zip_directory'), image('wheel_inflate'), image('wheel_zip_local'))
        workspace = ctypes.create_string_buffer(2048)
        wire = io.BytesIO()
        expected = {'payload/é': b'example' * 1024, 'empty': b''}
        with zipfile.ZipFile(wire, 'w') as archive:
            archive.writestr('payload/é', expected['payload/é'], compress_type=zipfile.ZIP_DEFLATED)
            archive.writestr('empty', b'', compress_type=zipfile.ZIP_STORED)
        with zipfile.ZipFile(wire) as archive, patch.object(zipfile.ZipFile, 'open', side_effect=AssertionError):
            for name, raw in expected.items():
                self.assertEqual(_wheel_member(archive, name, images, workspace), raw)
        damaged = bytearray(wire.getvalue())
        damaged[30] ^= 1
        with zipfile.ZipFile(io.BytesIO(damaged)) as archive, self.assertRaises(zipfile.BadZipFile):
            _wheel_member(archive, 'payload/é', images, workspace)

    def test_wheel_is_platform_specific_and_only_pin_is_derived_runtime_source(self):
        import csv
        import io
        import base64
        from hepta.hia_default_native import PIN_RESOURCE, render_pin, render_pin_data
        from tools.build_hia_default_release import SLOT_RECEIPT, WHEEL_TAG
        base, = (self.root / 'build/base-wheel').glob('*.whl')
        with zipfile.ZipFile(self.wheel) as archive, zipfile.ZipFile(base) as original:
            names = archive.namelist()
            metadata, = [name for name in names if name.endswith('.dist-info/WHEEL')]
            self.assertIn(b'Root-Is-Purelib: false\n', archive.read(metadata))
            if SLOT_RECEIPT in original.namelist():
                tag = '-'.join(base.stem.rsplit('-', 3)[-3:])
                receipt = original.read(SLOT_RECEIPT)
                binary = 'hepta/' + json.loads(receipt)['binary']['name']
                self.assertEqual(archive.read(SLOT_RECEIPT), receipt)
                self.assertEqual(archive.read(binary), original.read(binary))
                self.assertEqual((self.installed / binary).read_bytes(), original.read(binary))
            else:
                tag = WHEEL_TAG
            self.assertIn(('Tag: ' + tag + '\n').encode(), archive.read(metadata))
            self.assertEqual(self.report['wheel_tag'], tag)
            self.assertEqual(archive.read('hepta/hia_default_native_pin.py'), render_pin(None))
            self.assertEqual(archive.read('hepta/' + PIN_RESOURCE), render_pin_data(self.report['pin']))
            for name in names:
                if name.startswith('hepta/') and name.endswith('.py') and '/_data/' not in name:
                    self.assertEqual(archive.read(name), (ROOT / name).read_bytes(), name)
            record, = [name for name in names if name.endswith('.dist-info/RECORD')]
            rows = list(csv.reader(io.StringIO(archive.read(record).decode())))
            self.assertEqual({row[0] for row in rows}, set(names))
            for name, digest, length in rows:
                if name != record:
                    expected = base64.urlsafe_b64encode(sha256(archive.read(name)).digest()).rstrip(b'=').decode()
                    self.assertEqual(digest, 'sha256=' + expected)
                    self.assertEqual(int(length), len(archive.read(name)))
        self.assertEqual(self.report['ordinary_source_default_changed'], self.report['matching_source_cold_component'])
        self.assertFalse(self.report['retained_reference_bodies_removed'])

    def test_ordinary_installed_API_needs_no_selector_or_authoring_imports(self):
        body = r'''
counts = [0, 0]
arm, decide = native.NativeFullCost.arm, native.NativeFullCost.decide
def seen_arm(image, *args):
    assert getattr(image, '_default_package_binding', None) is not None
    counts[0] += 1
    return arm(image, *args)
def seen_decide(image, *args):
    counts[1] += 1
    return decide(image, *args)
with patch.object(native.NativeFullCost, 'arm', seen_arm), \
     patch.object(native.NativeFullCost, 'decide', seen_decide), \
     patch('hepta.hia_json_preflight_native._load_manifest', forbidden):
    answer = owner.assess_full_cost(raw)
assert counts == [4, 1], counts
assert not [k for k in os.environ if k.startswith('HEPTA_HIA_') and k.endswith('_MANIFEST')]
print(json.dumps(answer, sort_keys=True))
'''
        self.assertEqual(json.loads(self.child(body).stdout), self.expected)

    def test_installed_assembly_parser_and_public_checker_preserve_real_diagnostics(self):
        if self.report['scope'] == 'DEVELOPMENT_COMPONENT':
            self.skipTest('the parser and diagnostic reporter are linked into the cold public tool')
        from tests.test_hia_agent_assembly import SOURCE
        body = r'''
import contextlib, io, subprocess
from hashlib import sha256
from hepta import cli, hia_agent_assembly as asm
from hepta.hia_native_helpers import native_helpers_scope
valid = sys.argv[3]
attributes = valid.replace('{"mode":"wrap"}', '{"a":[' + ','.join('0' for _ in range(2050)) + ']}', 1)
loan = ' return_loans(' + ('[' * 17 + '0' + ']' * 17) + ')'
loans = valid.replace('v6', 'v8').replace('effects() entry(entry)', 'effects() entry(entry)' + loan)
obsolete = valid.replace('effects() entry(entry)', 'effects() entry(entry) return_loans([null])')
cases = [valid, valid.encode(), b'', b'no header', b'\xff', valid + 'end', attributes, loans, obsolete,
         valid.replace('ret(answer)', 'ret(unknown)'), valid.replace('exports(total)', 'exports(twice)')]
def outcome(source):
    try:
        return 'ok', asm.assemble_program(source).canonical_bytes
    except asm.HIAAssemblyRejected as exc:
        return 'error', exc.code, exc.line, exc.phase, str(exc), type(exc.__cause__).__name__, str(exc.__cause__)
with patch.object(defaults, 'default_assembly_document', return_value=None):
    expected = [outcome(source) for source in cases]
    reports = [asm.diagnose_assembly(text) for text in (attributes, loans, obsolete)]
observed = []
run = asm._native_assembly_document
def capture(syntax, presenter, source):
    observed.append((syntax.image_sha256, presenter.image_sha256))
    return run(syntax, presenter, source)
resources = [installed / 'hepta' / path for path in (defaults.ASSEMBLY_SYNTAX_RESOURCE, defaults.ASSEMBLY_DIAGNOSTIC_RESOURCE)]
pair = tuple(sha256(resource.read_bytes()).hexdigest() for resource in resources)
with patch.object(asm, '_native_assembly_document', capture), patch.object(asm, '_parse_assembly_document', forbidden), patch.object(asm, '_source', forbidden):
    assert [outcome(source) for source in cases] == expected
    for field, bound, detail in (('MAX_FUNCTIONS', 0, 'function inventory'), ('MAX_BLOCKS', 0, 'block inventory'),
                                 ('MAX_OPERATIONS', 1, 'operation inventory')):
        with patch.object(asm, field, bound):
            blocked = outcome(valid)
            assert blocked[1] == 'E_HIA_ASSEMBLY_LIMIT' and detail in blocked[4]
    from tempfile import TemporaryDirectory
    with TemporaryDirectory() as temporary:
        assembly = Path(temporary) / 'example.hia'
        assembly.write_text(valid)
        output = io.StringIO()
        with contextlib.redirect_stdout(output):
            assert cli.hia_main(['import-assembly', str(assembly)]) == 0
        assert json.loads(output.getvalue())['module'] == 'sums'
assert observed == [pair] * (len(cases) + 4)
role = installed / 'bin' / 'hia-import-assembly'
assert all(role.read_bytes().count(path.read_bytes()) == 1 for path in resources)
for text, expected in zip((attributes, loans, obsolete), reports, strict=True):
    result = subprocess.run(['hia-check-assembly-accepted'], executable=role, input=text.encode(), capture_output=True)
    assert result.returncode == 1 and not result.stderr and json.loads(result.stdout) == expected
with native_helpers_scope(), patch.object(asm, '_native_assembly_document', forbidden):
    assert asm.assemble_program(valid).canonical_bytes
print('PACKAGE_HIA_ASSEMBLY_SYNTAX')
'''
        self.assertEqual(self.child(body, SOURCE).stdout.strip(), 'PACKAGE_HIA_ASSEMBLY_SYNTAX')

    def test_installed_public_api_and_cli_share_the_authenticated_assembly_renderer(self):
        if self.report['scope'] == 'DEVELOPMENT_COMPONENT':
            self.skipTest('the public renderer comes from the matching cold CLI link')
        from tests.test_hia_agent_assembly import SOURCE
        body = r'''
from hashlib import sha256
from hepta import cli, hia_agent_assembly as assembly
from hepta.hia_agent_assembly import assemble_program, render_assembly
from hepta.hia_native_helpers import native_helpers_scope
import contextlib, io
text = sys.argv[3]
checked = assemble_program(text)
renderer = installed / 'hepta' / defaults.ASSEMBLY_RENDER_RESOURCE
digest = sha256(renderer.read_bytes()).hexdigest()
role = installed / 'bin' / 'hia-render-assembly'
assert role.read_bytes().count(renderer.read_bytes()) == 1
observed = []
original = assembly._native_assembly_text
def consume(image, core):
    observed.append((image.image_sha256, sha256(core).hexdigest()))
    return original(image, core)
with patch.object(assembly, '_native_assembly_text', consume), patch.object(assembly, '_render_assembly_document', forbidden):
    assert render_assembly(checked) == text
    from tempfile import TemporaryDirectory
    with TemporaryDirectory() as temporary:
        source = Path(temporary) / 'program.json'
        source.write_bytes(checked.canonical_bytes)
        output = io.StringIO()
        with contextlib.redirect_stdout(output):
            assert cli.hia_main(['render-assembly', str(source)]) == 0
        assert output.getvalue() == text
assert observed == [(digest, checked.sha256)] * 2
with native_helpers_scope(), patch.object(assembly, '_native_assembly_text', forbidden):
    assert render_assembly(checked) == text
original_image = renderer.read_bytes()
try:
    renderer.write_bytes(original_image[:-1])
    with patch.object(assembly, '_render_assembly_document', forbidden), patch.object(assembly, '_native_assembly_text', forbidden):
        try:
            render_assembly(checked)
        except ValueError as error:
            assert defaults.ASSEMBLY_RENDER_RESOURCE in str(error)
        else:
            raise AssertionError('damaged package renderer reached the public API')
finally:
    renderer.write_bytes(original_image)
print('PACKAGE_HIA_ASSEMBLY_RENDER')
'''
        self.assertEqual(self.child(body, SOURCE).stdout.strip(), 'PACKAGE_HIA_ASSEMBLY_RENDER')

    def test_installed_cli_uses_package_control_without_argparse_or_selectors(self):
        from hepta.hia_cli_native import native_cli_profile

        if self.report['scope'] == 'DEVELOPMENT_COMPONENT' or native_cli_profile() is None:
            self.skipTest('requires a matching-cold wheel on an admitted CLI presentation profile')
        body = r'''
import argparse
import contextlib
import io
from hepta import cli
from hepta.hia_default_native import CLI_BUNDLE_RESOURCE
from hepta.hia_schema import PRIMITIVE_PROFILES

def observe(owner, arguments):
    out, err = io.StringIO(), io.StringIO()
    with contextlib.redirect_stdout(out), contextlib.redirect_stderr(err):
        try:
            status = owner(arguments)
        except SystemExit as error:
            status = error.code
    return status, out.getvalue(), err.getvalue()

cases = (['--help'], ['--version'], ['capabilities'], ['build', 'missing.hepta'],
         *(['catalog', '--schema', schema] for schema in PRIMITIVE_PROFILES))
expected = [observe(cli._reference_hia_main, arguments) for arguments in cases]
assert 'HEPTA_HIA_CLI_MANIFEST' not in os.environ
with patch.object(cli, '_reference_hia_main', forbidden), \
     patch.object(argparse, 'ArgumentParser', forbidden), \
     patch.object(cli, 'agent_capabilities', forbidden), \
     patch('hepta.hia_opcodes.opcode_catalog', forbidden):
    assert [observe(cli.hia_main, arguments) for arguments in cases] == expected
    with patch.dict(os.environ, {'HEPTA_HIA_CLI_DISCOVERY_JSON_MANIFEST': ''}):
        status, output, _ = observe(cli.hia_main, ['capabilities'])
        assert status == 2 and 'selected CLI discovery JSON manifest must not be empty' in output
    bundle = installed / 'hepta' / CLI_BUNDLE_RESOURCE
    original = bundle.read_bytes()
    try:
        bundle.write_bytes(original + b' ')
        try:
            cli.hia_main(['capabilities'])
        except ValueError as error:
            assert str(error) in ('native CLI bundle identity mismatch',
                                  'native-default pin differs from package resource ' + CLI_BUNDLE_RESOURCE)
        else:
            raise AssertionError('changed package CLI bundle reached the command')
    finally:
        bundle.write_bytes(original)
print('PACKAGE_HIA_CLI_CONTROL')
'''
        self.assertEqual(self.child(body).stdout.strip(), 'PACKAGE_HIA_CLI_CONTROL')

    def test_hosted_parser_uses_the_installed_discovery_image_after_admission(self):
        if self.report['scope'] == 'DEVELOPMENT_COMPONENT':
            self.skipTest('the cold wheel supplies the immutable discovery owner')
        body = r'''
import contextlib
import io
from hepta import cli, hia_default_native as default
from hepta.hia_schema import PRIMITIVE_PROFILES

def observe(owner, arguments):
    out, err = io.StringIO(), io.StringIO()
    with contextlib.redirect_stdout(out), contextlib.redirect_stderr(err):
        try:
            status = ('return', owner(iter(arguments)))
        except SystemExit as error:
            status = ('exit', error.code)
    return status, out.getvalue(), err.getvalue()

valid = (['capabilities'], ['catalog'], *(['catalog', '--schema', value] for value in PRIMITIVE_PROFILES))
parser = (['--help'], ['--version'], ['catalog', '--schema', 'invalid'], ['capabilities', '--unexpected'])
expected = [observe(cli._reference_hia_main, args) for args in valid]
presentations = [observe(cli._reference_hia_main, args) for args in parser]
with patch('hepta.hia_cli_native.native_cli_profile', return_value=None):
    with patch.object(cli, 'agent_capabilities', forbidden), patch('hepta.hia_opcodes.opcode_catalog', forbidden):
        assert [observe(cli.hia_main, args) for args in valid] == expected
    with patch.object(default, 'default_cli_discovery', forbidden):
        assert [observe(cli.hia_main, args) for args in parser] == presentations
        with patch.dict(os.environ, {'HEPTA_HIA_CLI_DISCOVERY_JSON_MANIFEST': ''}):
            status, output, _ = observe(cli.hia_main, ['catalog'])
            assert status == ('return', 2) and 'must not be empty' in output
    with patch.object(cli, 'agent_capabilities', return_value={'oracle': True}):
        assert json.loads(observe(cli._reference_hia_main, ['capabilities'])[1]) == {'oracle': True}
print('PACKAGE_DISCOVERY_HOSTED_PARSER')
'''
        self.assertEqual(self.child(body).stdout.strip(), 'PACKAGE_DISCOVERY_HOSTED_PARSER')

    def test_matching_cold_wheel_builds_direct_shared_without_manual_selectors(self):
        from tests.test_hia_program_tools import scalar_program

        if self.report['scope'] == 'DEVELOPMENT_COMPONENT':
            self.skipTest('only the matching-source cold wheel ships Core ELF defaults')
        source = self.root / 'packaged-shared.hepta'
        source.write_text(json.dumps(scalar_program()))
        output = self.root / 'packaged-shared.so'
        body = r'''
import ctypes
from hepta import cli
from hepta import elf_shared_abi
from hepta import hia_program_native
assert not [key for key in os.environ
            if key.startswith('HEPTA_HIA_') and key.endswith('_MANIFEST')]
os.environ['PATH'] = ''
source, output = sys.argv[3:5]
with patch.object(elf_shared_abi, '_reference_owned_shared_symbols', forbidden), \
     patch.object(hia_program_native.shutil, 'which', forbidden):
    assert cli.hia_main(['build', source, '--backend', 'native', '--kind', 'shared', '-o', output]) == 0
library = ctypes.CDLL(output)
library.increment.argtypes = [ctypes.c_uint32]
library.increment.restype = ctypes.c_uint32
assert library.increment(41) == 42
'''
        result = json.loads(self.child(body, source, output).stdout)
        self.assertEqual(result['toolchain']['mode'], 'hia')
        self.assertEqual(result['binary_inventory']['dynamic_exports'], ['increment'])
        self.assertFalse(result['claims']['external_linker_used'])
        self.assertEqual(result['artifact_sha256'], sha256(output.read_bytes()).hexdigest())

    def test_matching_cold_wheel_keeps_final_verification_with_no_external_linker(self):
        from hepta.hia_verified_simd import simd_kernel_program
        from tests.test_hia_program_tools import scalar_program
        from tests.test_hia_safe_core import read_byte

        if self.report['scope'] == 'DEVELOPMENT_COMPONENT':
            self.skipTest('only the matching-source cold wheel ships Core ELF defaults')
        inputs = self.root / 'verified-shared-inputs'
        inputs.mkdir()
        for name, program in (
            ('scalar', scalar_program()), ('checked', read_byte()),
            ('simd', simd_kernel_program('copy_u8').as_dict()),
        ):
            (inputs / (name + '.hepta')).write_text(json.dumps(program))
        body = r'''
import ctypes
from hashlib import sha256
from hepta import cli, hia_program_native, hia_verified_kernel, hia_verified_scalar
from hepta.hia_elf_verified_linker_native import NativeVerifiedLinker, selected_verified_linker
from hepta.hia_safe_core import build_safe_core
from hepta.hia_verified_image import VerifiedImageRejected

inputs = Path(sys.argv[3])
def read(name):
    return json.loads((inputs / (name + '.hepta')).read_bytes())

def check(report, output, export):
    toolchain = report.get('toolchain') or report['compilation']['toolchain']
    assert (toolchain['mode'], toolchain['path'], toolchain['sha256']) == ('hia', None, image.image_sha256)
    assert report['validation']['complete'] and report['validation']['ok']
    assert report['artifact_sha256'] == sha256(output.read_bytes()).hexdigest()
    return getattr(ctypes.CDLL(str(output), mode=os.RTLD_NOW), export)

image = selected_verified_linker()
assert image._default_package_binding is not None
os.environ['PATH'] = ''
with patch.object(hia_program_native.shutil, 'which', forbidden):
    output = inputs / 'scalar.so'
    with patch.object(cli, 'output_json') as published:
        assert cli.hia_main(['build', str(inputs / 'scalar.hepta'), '--backend', 'auto',
                             '--kind', 'shared', '-o', str(output)]) == 0
    increment = check(published.call_args.args[0], output, 'increment')
    increment.argtypes = [ctypes.c_uint32]
    increment.restype = ctypes.c_uint32
    assert increment(41) == 42
    checked = inputs / 'checked.so'
    check(build_safe_core(read('checked'), checked, foreign_extent=8), checked, 'read_byte')
    simd = inputs / 'simd.so'
    check(hia_verified_kernel.build_verified_kernel(read('simd'), simd, strategy='simd',
                                                    simd_unroll=1), simd, 'calculate')
    refused = inputs / 'unverified.so'
    def malformed(_self, _object, destination):
        destination.write_bytes(b'bad')
    with patch.object(NativeVerifiedLinker, 'link', malformed):
        try:
            hia_verified_scalar.build_verified_scalar(read('scalar'), refused)
        except hia_verified_scalar.VerifiedScalarRejected as error:
            assert isinstance(error.__cause__, VerifiedImageRejected), error
        else:
            raise AssertionError('malformed linked output was accepted without verification')
    assert not refused.exists()
print('PACKAGED_HIA_LINKAGE_STILL_REQUIRES_FINAL_PROOF')
'''
        self.assertEqual(self.child(body, inputs).stdout.strip(),
                         'PACKAGED_HIA_LINKAGE_STILL_REQUIRES_FINAL_PROOF')

    def test_cold_wheel_proves_signed_safe_core_with_its_scoped_hia_pair(self):
        from tests.test_hia_safe_core_signed import core_operation

        if self.report['scope'] == 'DEVELOPMENT_COMPONENT':
            self.skipTest('only the matching-source cold wheel ships the proof pair')
        source = self.root / 'signed-checked-multiply.hepta'
        source.write_text(json.dumps(core_operation('int.mul.checked', 'i8')))
        output = self.root / 'signed-checked-multiply.so'
        body = r'''
from unittest.mock import patch
from hepta.hia_cnf_native import selected_cnf
from hepta.hia_default_native import BINDER_RESOURCE, PROOF_BUNDLE_RESOURCE, default_safe_core_pair
from hepta.hia_safe_core import build_safe_core

assert selected_cnf() is None
os.environ['PATH'] = ''
document = json.loads(Path(sys.argv[3]).read_bytes())
destination = Path(sys.argv[4])
with (patch('hepta.hia_cnf_native._graph_packet', side_effect=AssertionError('host Core proof packing entered')),
      patch('hepta.hia_safe_core._scalar_caller_contract', side_effect=AssertionError('host obligations entered')),
      patch('hepta.hia_cnf_native.NativeCnf.bind_artifact_circuits',
            side_effect=AssertionError('host machine and Core binding entered')),
      patch('hepta.hia_safe_core_x64_decode_native.NativeSafeCoreX64Decode._legacy_decode_workspace',
            side_effect=AssertionError('host relocation projection entered')),
      patch('hepta.hia_safe_core_elf.bind_final_image',
            side_effect=AssertionError('host ELF program orchestration entered')),
      patch('hepta.hia_safe_core_elf_inventory_native.NativeSafeCoreElfInventory._function_link_header',
            side_effect=AssertionError('host function link framing entered')),
      patch('hepta.hia_safe_core_elf_inventory_native.NativeSafeCoreElfInventory.verify_object_inventory',
            side_effect=AssertionError('host object relocation framing entered')),
      patch('hepta.hia_cnf_native.NativeCnf.solve_circuit', side_effect=AssertionError('host circuit added'))):
    report = build_safe_core(document, destination, profile_version=6)['validation']
assert report['complete'] and report['ok']
assert [row['result'] for row in report['obligations']] == ['sat'] + ['unsat'] * 4
assert all('native_cnf' in row for row in report['obligations'])
semantics = report['obligations'][-1]['native_cnf']
assert semantics['method'] == 'native_hia_exhaustive_word_table'
assert semantics['assignments_checked'] == 65_536
assert len(semantics['word_table_sha256']) == 64
checker = report['checker']
identity = checker['source_identity']
mapped = {row['mapped_image_sha256'] for row in checker['input_execution']['native_helpers']}
assert identity['native_x64_decoder_image_sha256'] in mapped
assert identity['native_cnf_image_sha256'] in mapped
assert identity['native_core_proof_wire_image_sha256'] in mapped
assert selected_cnf() is None

from hashlib import sha256
executable = installed / 'hepta' / BINDER_RESOURCE
native_code = executable.read_bytes()
assert sha256(native_code).hexdigest() == identity['native_elf_binder_image_sha256']
try:
    executable.write_bytes(native_code[:-1] + bytes([native_code[-1] ^ 1]))
    try:
        default_safe_core_pair()
    except ValueError as error:
        assert 'binder identity mismatch' in str(error)
    else:
        raise AssertionError('the scoped proof accepted a changed binder')
finally:
    executable.write_bytes(native_code)

bundle = installed / 'hepta' / PROOF_BUNDLE_RESOURCE
original = bundle.read_bytes()
try:
    bundle.write_bytes(original + b' ')
    try:
        default_safe_core_pair()
    except ValueError as error:
        assert 'bundle identity mismatch' in str(error)
    else:
        raise AssertionError('the scoped proof accepted changed package bytes')
finally:
    bundle.write_bytes(original)
print('SCOPED_HIA_SAFE_CORE_PROOF')
'''
        self.assertEqual(self.child(body, source, output).stdout.strip(), 'SCOPED_HIA_SAFE_CORE_PROOF')

    def test_default_worker_scope_and_real_restarted_service_bind_packaged_bundle(self):
        body = r'''
import contextlib, io
from hepta import hia_agent_worker as worker
def invoke(arguments, request=None):
    old_in, old_out = sys.stdin, sys.stdout
    source = io.TextIOWrapper(io.BytesIO(b'' if request is None else json.dumps(request,
        sort_keys=True, separators=(',', ':'), ensure_ascii=False).encode()), encoding='utf-8')
    output = io.TextIOWrapper(io.BytesIO(), encoding='utf-8')
    sys.stdin, sys.stdout = source, output
    try:
        code = worker.main(arguments)
        output.flush()
        payload = output.buffer.getvalue()
    finally:
        sys.stdin, sys.stdout = old_in, old_out
    assert code == 0, (code, payload)
    assert not [key for key in os.environ if key.startswith('HEPTA_HIA_') and key.endswith('_MANIFEST')]
    assert helpers._SCOPE_OWNER is None and helpers._ACTIVE is None
    return json.loads(payload)
pins = invoke(['--installation-manifest'])
assert pins['native_helpers_sha256'] == sys.argv[3]
from hashlib import sha256
packet = {'schema': 'hia-agent-worker-request-v1', 'tool': 'hia_describe',
    'arguments': {'section': 'manifest'}, 'profile_sha256': 'a' * 64,
    'catalog_sha256': pins['catalog_sha256']}
packet['request_sha256'] = sha256(json.dumps(packet, sort_keys=True,
    separators=(',', ':'), ensure_ascii=False).encode()).hexdigest()
state = str(Path(sys.argv[4]))
for _ in range(2):
    report = invoke(['--state-root', state, '--request-json-stdin'], packet)
    assert report['native_helpers_sha256'] == sys.argv[3]
    assert report['request_sha256'] == packet['request_sha256'] and report['complete'] is True
    assert report['response']['status'] == 'completed', report
print('DEFAULT_WORKER_AND_RESTARTED_SERVICE_BOUND')
'''
        run = self.child(body, self.report['default_bundle_sha256'], self.root / 'worker-state')
        self.assertEqual(run.stdout.strip(), 'DEFAULT_WORKER_AND_RESTARTED_SERVICE_BOUND')

    def test_explicit_administrator_bundle_uses_only_its_captured_images(self):
        body = r'''
import shutil
from hashlib import sha256
bundle, expected, _ = defaults.capture_default_bundle()
external = Path(sys.argv[3]); external.mkdir(exist_ok=True)
shutil.copyfile(bundle, external / 'bundle.json')
for entry in json.loads(bundle.read_bytes())['helpers']:
    name = Path(entry['manifest_path'])
    (external / name).parent.mkdir(parents=True, exist_ok=True)
    shutil.copyfile(bundle.parent / name, external / name)
    image = name.parent / json.loads((bundle.parent / name).read_bytes())['image_path']
    shutil.copyfile(bundle.parent / image, external / image)
saved = bundle.read_bytes()
bundle.write_bytes(saved + b' ')
try:
    with helpers.native_helpers_scope(str(external / 'bundle.json'), expected):
        with patch('hepta.hia_json_preflight_native._load_manifest', forbidden), \
             patch.object(defaults, 'capture_default_bundle', forbidden):
            answer = owner.assess_full_cost(raw)
            assert helpers.native_helpers_identity()['native_helpers_sha256'] == expected
finally:
    bundle.write_bytes(saved)
assert not [k for k in os.environ if k.startswith('HEPTA_HIA_') and k.endswith('_MANIFEST')]
print(json.dumps(answer, sort_keys=True))
'''
        self.assertEqual(json.loads(self.child(body, self.root / 'explicit-cost-bundle').stdout), self.expected)

    def test_valid_admin_bundle_missing_cost_cannot_borrow_packaged_code(self):
        from hepta.hia_native_helpers import ABI, SCHEMA, TARGET
        other = self.root / 'other-bundle.json'
        payload = {'schema': SCHEMA, 'target': TARGET, 'abi': ABI, 'helpers': [{
            'selector': 'HEPTA_HIA_PATCH_IMPACT_MANIFEST', 'manifest_path': str(self.patch_manifest),
            'manifest_sha256': sha256(self.patch_manifest.read_bytes()).hexdigest()}]}
        other.write_text(json.dumps(payload, sort_keys=True, separators=(',', ':')))
        body = r'''
with helpers.native_helpers_scope(sys.argv[3], sys.argv[4]):
    with patch.object(native.NativeFullCost, '__init__', forbidden), \
         patch('hepta.hia_json_preflight_native._load_manifest', forbidden):
        try:
            owner.assess_full_cost(raw)
        except ValueError as error:
            assert 'absent from the active worker bundle' in str(error), str(error)
        else:
            raise AssertionError('administrator bundle was supplemented from package defaults')
print('INCOMPLETE_ADMIN_BUNDLE_REFUSED')
'''
        self.assertEqual(self.child(body, other, sha256(other.read_bytes()).hexdigest()).stdout.strip(),
                         'INCOMPLETE_ADMIN_BUNDLE_REFUSED')

    def test_default_worker_rejects_ambient_selection_before_state(self):
        body = r'''
from hepta import hia_agent_worker as worker
state = Path(sys.argv[3])
os.environ[native.SELECTOR] = 'caller-may-not-select-this'
try:
    with patch('sqlite3.connect', forbidden):
        result = worker.main(['--state-root', str(state), '--request-json-stdin'])
    assert result == 2 and not state.exists()
    assert os.environ[native.SELECTOR] == 'caller-may-not-select-this'
finally:
    del os.environ[native.SELECTOR]
assert helpers._SCOPE_OWNER is None and helpers._ACTIVE is None
print('AMBIENT_SELECTION_REFUSED_BEFORE_STATE')
'''
        self.assertEqual(self.child(body, self.root / 'no-ambient-state').stdout.strip(),
                         'AMBIENT_SELECTION_REFUSED_BEFORE_STATE')

    def test_missing_and_warm_changed_package_inputs_never_fall_back(self):
        body = r'''
bundle, _digest, _pin = defaults.capture_default_bundle()
manifest = json.loads((bundle.parent / 'manifest.json').read_bytes())
paths = [bundle, bundle.parent / 'manifest.json', bundle.parent / manifest['image_path'],
         native.SOURCE, installed / 'hepta/hia_default_native_pin.py', installed / 'hepta' / defaults.PIN_RESOURCE,
         next(installed.glob('hia_core-*.dist-info/RECORD'))]
data = json.loads(raw)
for path in paths:
    captured = defaults.default_image(native.SELECTOR)
    original = path.read_bytes()
    try:
        path.write_bytes(original + b' ')
        with patch.object(native.NativeFullCost, '__init__', forbidden):
            try:
                owner.assess_full_cost(raw)
            except (ValueError, OSError):
                pass
            else:
                raise AssertionError('changed package input accepted: ' + str(path))
        with patch.object(captured, '_entry', forbidden):
            try:
                captured.arm(data['arms'][0]['one_time_ns'], data['arms'][0]['observations'])
            except (ValueError, OSError):
                pass
            else:
                raise AssertionError('warm package binding ignored changed input: ' + str(path))
    finally:
        path.write_bytes(original)
for path in paths:
    held = path.with_name(path.name + '.held')
    path.rename(held)
    try:
        try:
            owner.assess_full_cost(raw)
        except (ValueError, OSError):
            pass
        else:
            raise AssertionError('missing package input silently disabled default: ' + str(path))
    finally:
        held.rename(path)
print('ALL_COLD_AND_WARM_PACKAGE_INPUTS_REFUSED')
'''
        self.assertEqual(self.child(body).stdout.strip(), 'ALL_COLD_AND_WARM_PACKAGE_INPUTS_REFUSED')

    def test_fresh_process_cannot_downgrade_candidate_pin_to_portable_none(self):
        body = r'''
pin = installed / 'hepta' / defaults.PIN_RESOURCE
saved = pin.read_bytes()
assert 'hepta.hia_default_native_pin' not in sys.modules
try:
    pin.unlink()
    try:
        owner.assess_full_cost(raw)
    except ValueError as error:
        assert 'wheel RECORD' in str(error), str(error)
    else:
        raise AssertionError('rewriting the pin to portable None disabled the installed native default')
finally:
    pin.write_bytes(saved)
print('COLD_PORTABLE_DOWNGRADE_REFUSED')
'''
        self.assertEqual(self.child(body).stdout.strip(), 'COLD_PORTABLE_DOWNGRADE_REFUSED')

    def test_repeated_defaults_release_images_immediately_with_cyclic_GC_disabled(self):
        body = r'''
import gc, weakref
observed = []
original = native.NativeFullCost.arm
def track(image, *args):
    observed.append(weakref.ref(image))
    assert image._default_package_binding.images == {}
    return original(image, *args)
enabled = gc.isenabled()
gc.disable()
try:
    with patch.object(native.NativeFullCost, 'arm', track):
        for _ in range(32):
            owner.assess_full_cost(raw)
            assert all(item() is None for item in observed), 'default mapping retained until cyclic GC'
finally:
    if enabled:
        gc.enable()
assert len(observed) == 128
print('ALL_DEFAULT_IMAGES_RELEASED_WITHOUT_CYCLIC_GC')
'''
        self.assertEqual(self.child(body).stdout.strip(), 'ALL_DEFAULT_IMAGES_RELEASED_WITHOUT_CYCLIC_GC')

    def test_concurrent_public_calls_capture_their_own_package_custody(self):
        body = r'''
from concurrent.futures import ThreadPoolExecutor
with ThreadPoolExecutor(max_workers=2) as pool:
    observed = list(pool.map(lambda _: owner.assess_full_cost(raw), range(4)))
assert all(item == observed[0] for item in observed)
print(json.dumps(observed[0], sort_keys=True))
'''
        self.assertEqual(json.loads(self.child(body).stdout), self.expected)

    def test_all_original_38_callers_use_actual_installed_default(self):
        from tools.qualify_hia_default_release_callers import qualify
        result = qualify(self.root / 'build/build.json', self.root / 'original-callers')
        self.assertEqual(result['status'], 'PASS', result)
        self.assertEqual(result['actual_tests'], 38)
        self.assertEqual(result['started'], result['stopped'])
        self.assertEqual(result['planned'], result['started'])
        self.assertTrue(result['no_native_selector_environment'])
        self.assertTrue(result['source_wheel_and_installation_unchanged'])

    def test_ordinary_portable_wheel_still_has_no_default_image(self):
        base, = (self.root / 'build/base-wheel').glob('*.whl')
        portable = self.root / 'portable-installed'
        self._run(['-m', 'pip', 'install', '--no-deps', '--no-index', '--no-compile', '--target', portable, base])
        script = r'''
import json, sys
from pathlib import Path
from unittest.mock import patch
sys.path.insert(0, sys.argv[1])
from hepta.hia_default_native import capture_default_bundle
from hepta.hia_full_cost_gate import assess_full_cost
assert capture_default_bundle() is None
with patch('platform.system', return_value='Darwin'), patch('platform.machine', return_value='arm64'), \
     patch('hepta.hia_native_helpers.NativeHelpersBinding', side_effect=AssertionError('native entered')):
    answer = assess_full_cost(Path(sys.argv[2]).read_bytes())
print(json.dumps(answer, sort_keys=True))
'''
        result = self._run(['-I', '-c', script, portable, self.input])
        self.assertEqual(json.loads(result.stdout), self.expected)
