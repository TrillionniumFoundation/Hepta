"""Original ordinary-inspect results compared with a complete native owner."""
from __future__ import annotations
from concurrent.futures import ThreadPoolExecutor
from contextlib import contextmanager, redirect_stdout
from copy import deepcopy
import ctypes
from hashlib import sha256
import io
import json
import os
from pathlib import Path
import shutil
import struct
import subprocess
import sys
import tempfile
import unittest
from unittest.mock import patch

from hepta.hia_cli_inspect_native import (
    SOURCE, SCHEMA, SELECTOR, MAGIC, RESULT_MAGIC, NativeCliInspect,
    capture_request, storage_sizes, installed_cli_inspect)
from hepta.hia_program import VerifiedProgram, verify_program
from hepta import hia_program_tools as ordinary
from tools.generate_hia_cli_inspect import document
from tests.test_hia_returned_loan_interfaces import scalar, choose_loan

ROOT = Path(__file__).resolve().parents[1]
COLD = 'HEPTA_HIA_CLI_INSPECT_COLD_REPORT'
DEVELOPMENT = 'HEPTA_HIA_CLI_INSPECT_DEVELOPMENT_COMPILER'
EVIDENCE = 'HEPTA_HIA_CLI_INSPECT_EVIDENCE'


def clean_environment():
    return {key: value for key, value in os.environ.items()
            if not key.startswith(('HEPTA_', 'HIA_'))}


def reference(value):
    with patch.dict(os.environ, clean_environment(), clear=True):
        return ordinary.inspect_program(value)


def record(path, value):
    path.write_text(json.dumps(value, sort_keys=True, indent=2) + '\n')


@contextmanager
def observe(native):
    calls = []
    actual = native._entry
    def entry(source, source_size, output, output_size, work, work_size):
        before = ctypes.string_at(source, source_size)
        result = actual(source, source_size, output, output_size, work, work_size)
        calls.append({'request': before, 'after': ctypes.string_at(source, source_size),
                      'status': result, 'output_size': output_size,
                      'workspace_size': work_size,
                      'published': ctypes.string_at(output, result) if 64 < result <= output_size else b''})
        return result
    native._entry = entry
    try:
        yield calls
    finally:
        native._entry = actual


class CliInspectSourceTests(unittest.TestCase):
    def test_original_generator_roundtrip_and_fixed_entry_ABI(self):
        from hepta.hia_agent_assembly import render_assembly, assemble_program
        doc = document()
        raw = SOURCE.read_bytes()
        self.assertEqual(raw, render_assembly(doc).encode())
        self.assertEqual(assemble_program(raw).as_dict(), doc)
        self.assertEqual([p['type'] for p in doc['functions'][0]['params']], ['readbuf', 'mutbuf', 'mutbuf'])
        self.assertEqual(doc['functions'][0]['returns'], ['u32'])

    def test_unqualified_builder_refuses_before_any_output(self):
        from tools.build_hia_cli_inspect import build
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            compiler, cold = root / 'compiler', root / 'cold.json'
            compiler.write_bytes(b'not qualified')
            cold.write_text('{}')
            with self.assertRaisesRegex(ValueError, 'a completed matching native cold qualification is required'):
                build(root / 'out', compiler, cold)
            self.assertFalse((root / 'out').exists())

    def test_resource_and_helper_have_the_real_installed_owner(self):
        from hepta.hia_agent_contract import NATIVE_SOURCE_FILES
        from hepta.hia_native_helpers import HELPERS
        self.assertEqual(NATIVE_SOURCE_FILES.count('examples/hia_bootstrap/cli_inspect.hepta'), 1)
        self.assertEqual(HELPERS[SELECTOR], ('hia_cli_inspect_native', 'NativeCliInspect'))
        self.assertIn('include examples/hia_bootstrap/cli_inspect.hepta',
                      (ROOT / 'MANIFEST.in').read_text())


class CliInspectNativeTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        from tools.qualify_hia_selfhost import compile_stage
        from tools.build_hia_cli_inspect import build
        selected = os.environ.get(EVIDENCE)
        cls.temporary = None
        if selected:
            cls.folder = Path(selected)
            cls.folder.mkdir(mode=0o700)
        else:
            cls.temporary = tempfile.TemporaryDirectory(prefix='hia-cli-inspect-')
            cls.folder = Path(cls.temporary.name)
            cls.addClassCleanup(cls.temporary.cleanup)
        cold, development = os.environ.get(COLD), os.environ.get(DEVELOPMENT)
        if (COLD in os.environ and not cold) or (DEVELOPMENT in os.environ and not development):
            raise ValueError('empty inspect qualification selector')
        if bool(cold) == bool(development):
            raise ValueError('inspect tests require exactly one matching-cold or explicit development compiler')
        if cold:
            report = json.loads(Path(cold).read_bytes())
            # Matching builds retain the production strict source admission.
            nested = json.loads(Path(report['nested_report']).read_bytes())
            compiler = Path(nested['generations'][-1]['produced_image']).resolve(strict=True)
            cls.manifest = build(cls.folder / 'build', compiler, Path(cold))
            manifest = json.loads(cls.manifest.read_bytes())
            cls.image = cls.manifest.parent / manifest['image_path']
        else:
            compiler = Path(development)
            cls.image, receipt = compile_stage(cls.folder, 'cli-inspect', compiler, SOURCE.read_bytes())
            cls.manifest = cls.folder / 'manifest.json'
            record(cls.manifest, {'schema': SCHEMA, 'source_sha256': sha256(SOURCE.read_bytes()).hexdigest(),
                'image_path': cls.image.name, 'image_sha256': sha256(cls.image.read_bytes()).hexdigest(),
                'compiler_sha256': sha256(compiler.read_bytes()).hexdigest()})
            record(cls.folder / 'development-compile.json', {
                'compiler': str(compiler), 'receipt': receipt, 'current_source_cold_qualified': False})
        raw = cls.image.read_bytes()
        cls.native = NativeCliInspect(raw, sha256(raw).hexdigest())

    def selected(self, value):
        from hepta import hia_cli_inspect_native as adapter
        with patch.dict(os.environ, {SELECTOR: str(self.manifest)}), \
                patch.object(adapter, 'installed_cli_inspect', return_value=self.native):
            return ordinary.inspect_program(value)

    def test_all_primitive_versions_match_complete_original_report(self):
        for version in range(1, 9):
            value = scalar(version)
            expected = reference(value)
            with self.subTest(version=version), observe(self.native) as calls:
                actual = self.selected(value)
            self.assertEqual(actual, expected)
            self.assertEqual(len(calls), 1)
            self.assertEqual(calls[0]['request'], calls[0]['after'])
            self.assertFalse(actual['claims']['native_executed'])
            self.assertFalse(actual['claims']['whole_language_soundness_proved'])

    def test_all_structured_versions_keep_original_input_and_core_identity(self):
        from tests.test_hia_program_composite import stored_loan_program, enum_owner_program
        for version in range(1, 5):
            for factory in (stored_loan_program, enum_owner_program):
                value = factory()
                value['schema'] = 'hepta.hia.composite.v' + str(version)
                expected = reference(value)
                with self.subTest(version=version, fixture=factory.__name__):
                    actual = self.selected(value)
                    self.assertEqual(actual, expected)
                    self.assertTrue(actual['normalization']['structured_elaboration_rechecked'])
                    self.assertEqual(actual['normalization']['input_schema'], value['schema'])
                    self.assertNotEqual(actual['input_sha256'], actual['program_sha256'])

    def test_complete_return_loans_operations_and_explicit_exports(self):
        value = choose_loan()
        expected = reference(value)
        actual = self.selected(value)
        self.assertEqual(actual, expected)
        self.assertEqual([fn['return_loans'] for fn in actual['functions']], [[None], ['left']])
        self.assertEqual(actual['normalization']['public_scalar_entrypoints'], ['entrypoint'])
        for fn in actual['functions']:
            for block in fn['blocks']:
                self.assertEqual([op['index'] for op in block['operations']], list(range(len(block['operations']))))
        actual['functions'][1]['return_loans'][0] = 'right'
        self.assertEqual(value['functions'][1]['return_loans'], ['left'])
        self.assertEqual(self.selected(value), expected)

    def test_original_maximum_function_domain_and_sorted_public_names(self):
        value = scalar()
        template = value['functions'][0]
        value['functions'] = []
        for index in reversed(range(1024)):
            fn = deepcopy(template)
            fn['name'] = 'function_' + str(index).zfill(4) + '_' + 'x' * 110
            value['functions'].append(fn)
        expected = reference(value)
        actual = self.selected(value)
        self.assertEqual(actual, expected)
        self.assertEqual(len(actual['functions']), 1024)
        self.assertEqual(actual['normalization']['public_scalar_entrypoints'],
                         sorted(fn['name'] for fn in value['functions']))

    def test_selected_owner_never_uses_host_report_digest_or_signature(self):
        value = choose_loan()
        expected = reference(value)
        def absent(*args, **kwargs):
            raise AssertionError('foreign inspect report owner')
        with patch.object(ordinary, 'function_signature', side_effect=absent), \
                patch.object(VerifiedProgram, 'normalization_report', property(absent)), \
                patch.object(VerifiedProgram, 'sha256', property(absent)), \
                patch.object(VerifiedProgram, 'input_sha256', property(absent)):
            self.assertEqual(self.selected(value), expected)

    def test_actual_cli_keeps_output_and_original_first_refusals(self):
        from hepta.cli import hia_main
        path = self.folder / 'cli-input.json'
        path.write_text(json.dumps(choose_loan()))
        old, new = io.StringIO(), io.StringIO()
        with patch.dict(os.environ, clean_environment(), clear=True), redirect_stdout(old):
            old_rc = hia_main(['inspect', str(path)])
        with patch.dict(os.environ, {SELECTOR: str(self.manifest)}), redirect_stdout(new):
            new_rc = hia_main(['inspect', str(path)])
        self.assertEqual((new_rc, new.getvalue()), (old_rc, old.getvalue()))
        self.assertEqual(new_rc, 0)
        for wire in (b'{"schema":', b'{"schema":"unknown","module":"bad","functions":[]}', b'\xff'):
            path.write_bytes(wire)
            outcomes = []
            for environment in (clean_environment(), {**clean_environment(), SELECTOR: str(self.manifest)}):
                output = io.StringIO()
                with patch.dict(os.environ, environment, clear=True), redirect_stdout(output):
                    code = hia_main(['inspect', str(path)])
                outcomes.append((code, output.getvalue()))
            self.assertEqual(outcomes[0], outcomes[1])
            self.assertNotEqual(outcomes[0][0], 0)

    def test_private_frames_and_capacity_cannot_publish_partial_reports(self):
        request = capture_request(verify_program(scalar()))
        output_size, workspace_size = storage_sizes(*struct.unpack_from('<2Q', request, 16))
        for change in ('magic', 'reserved', 'short-output', 'short-workspace'):
            wire = bytearray(request)
            actual_output, actual_workspace = output_size, workspace_size
            if change == 'magic':
                struct.pack_into('<Q', wire, 0, 0)
            elif change == 'reserved':
                struct.pack_into('<Q', wire, 40, 1)
            elif change == 'short-output':
                actual_output = 31
            else:
                actual_workspace = 31
            source = ctypes.create_string_buffer(bytes(wire), len(wire))
            output = ctypes.create_string_buffer(b'\xa5' * (output_size + 32), output_size + 32)
            work = ctypes.create_string_buffer(b'\x93' * (workspace_size + 32), workspace_size + 32)
            status = self.native._entry(source, len(wire), ctypes.byref(output, 16), actual_output,
                                       ctypes.byref(work, 16), actual_workspace)
            self.assertEqual(status, 0xfffffffd)
            self.assertEqual(source.raw, bytes(wire))
            self.assertEqual(output.raw, b'\xa5' * (output_size + 32))
            self.assertEqual(work.raw, b'\x93' * (workspace_size + 32))

    def test_captured_bytes_and_concurrent_calls_are_private(self):
        value = choose_loan()
        expected = reference(value)
        checked = verify_program(value)
        captured = capture_request(checked)
        value['functions'].clear()
        first = self.native.transition(captured)
        self.assertEqual(json.loads(first.payload_wire), expected)
        with ThreadPoolExecutor(max_workers=6) as pool:
            results = list(pool.map(self.native.transition, [captured] * 18))
        self.assertEqual([row.payload_wire for row in results], [first.payload_wire] * 18)
        self.assertEqual(first.functions, len(expected['functions']))
        self.assertEqual(first.blocks, sum(len(fn['blocks']) for fn in expected['functions']))
        self.assertEqual(first.operations, sum(len(block['operations']) for fn in expected['functions'] for block in fn['blocks']))
        record(self.folder / 'private-capture.json', {
            'captured_bytes': len(captured), 'request_sha256': sha256(captured).hexdigest(),
            'complete_output_sha256': sha256(first.payload_wire).hexdigest(),
            'actual_parallel_calls': 18, 'caller_mutation_after_capture': True})

    def test_independent_Core_VM_reproduces_complete_native_payload(self):
        from hepta.hia_agent_assembly import assemble_program
        from hepta.hia_program_runtime import _Machine, _Owner, _View
        checked = verify_program(scalar())
        request = capture_request(checked)
        output_size, workspace_size = storage_sizes(len(checked.canonical_bytes), 0)
        program = assemble_program(SOURCE.read_bytes())
        owners = [_Owner(-1, bytearray(request)), _Owner(-2, bytearray(output_size)),
                  _Owner(-3, bytearray(workspace_size))]
        machine = _Machine(program, 3000000, 64 << 20, None, 128)
        entry = next(fn for fn in program.as_dict()['functions'] if fn['name'] == 'f0')
        status = machine.invoke(entry, [_View(owners[0], False), _View(owners[1], True), _View(owners[2], True)])[0]
        receipt = self.native.transition(request)
        self.assertEqual(status, 64 + len(receipt.payload_wire))
        self.assertEqual(bytes(owners[1].data[:status]), receipt.header + receipt.payload_wire)
        self.assertEqual(json.loads(receipt.payload_wire), reference(checked))
        self.assertEqual(bytes(owners[0].data), request)

    def test_warm_source_identity_and_empty_selector_never_fall_back(self):
        with patch.dict(os.environ, {SELECTOR: ''}):
            with self.assertRaisesRegex(ValueError, 'must not be empty'):
                ordinary.inspect_program(scalar())
        from hepta import hia_cli_inspect_native as adapter
        with tempfile.TemporaryDirectory() as temporary:
            altered = Path(temporary) / 'source.hepta'
            altered.write_bytes(SOURCE.read_bytes())
            with patch.object(adapter, 'SOURCE', altered):
                image = installed_cli_inspect(str(self.manifest))
                self.assertEqual(image.inspect_checked(verify_program(scalar())), reference(scalar()))
                altered.write_bytes(altered.read_bytes() + b'\n')
                with self.assertRaisesRegex(ValueError, 'source identity mismatch'):
                    installed_cli_inspect(str(self.manifest))

    def test_real_sdist_wheel_installed_cli_uses_package_owned_source(self):
        from hepta.hia_agent_contract import (
            DISCOVERY_FILES, NATIVE_SOURCE_FILES, SOURCE_BUILD_FILES, COMPILER_BUILD_FILES, PUBLICATION_BUILD_FILES)
        root = self.folder / 'installed'
        root.mkdir()
        source = root / 'source'
        source.mkdir()
        shutil.copytree(ROOT / 'hepta', source / 'hepta', ignore=shutil.ignore_patterns('__pycache__', '*.pyc'))
        resources = tuple('docs/' + name for name in DISCOVERY_FILES) + NATIVE_SOURCE_FILES + \
            SOURCE_BUILD_FILES + COMPILER_BUILD_FILES + PUBLICATION_BUILD_FILES
        for name in (*resources, 'pyproject.toml', 'setup.py', 'MANIFEST.in',
                     'tests/fixtures/hia_compiler_rename_reference.json.gz'):
            target = source / name
            target.parent.mkdir(parents=True, exist_ok=True)
            shutil.copyfile(ROOT / name, target)
        environment = clean_environment()
        def run(argv, cwd=None, timeout=90):
            result = subprocess.run(argv, cwd=cwd, env=environment, capture_output=True, timeout=timeout)
            self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
            return result
        run([sys.executable, '-B', 'setup.py', 'sdist', '--formats=gztar'], source)
        archives = list((source / 'dist').glob('*.tar.gz'))
        self.assertEqual(len(archives), 1)
        wheels = root / 'wheels'
        run([sys.executable, '-m', 'pip', 'wheel', '--no-deps', '--no-build-isolation',
             str(archives[0]), '-w', str(wheels)])
        built = list(wheels.glob('*.whl'))
        self.assertEqual(len(built), 1)
        installed = root / 'site'
        run([sys.executable, '-m', 'pip', 'install', '--no-deps', '--no-compile',
             '--target', str(installed), str(built[0])], timeout=60)
        self.assertEqual((installed / 'hepta/_data/examples/hia_bootstrap/cli_inspect.hepta').read_bytes(), SOURCE.read_bytes())
        self.assertFalse((installed / 'hepta/_data/tests/fixtures/hia_compiler_rename_reference.json.gz').exists())
        input_path, expected_path = root / 'input.json', root / 'expected.txt'
        input_path.write_text(json.dumps(choose_loan()))
        expected_path.write_text(json.dumps(reference(choose_loan()), ensure_ascii=False, indent=2, sort_keys=True) + '\n')
        code = r'''
import contextlib,io,json,os,pathlib,sys
from unittest.mock import patch
sys.path.insert(0,sys.argv[1])
from hepta import hia_cli_inspect_native as adapter,hia_program_tools as ordinary
from hepta.cli import hia_main
assert pathlib.Path(adapter.__file__).is_relative_to(pathlib.Path(sys.argv[1]))
assert adapter.SOURCE==pathlib.Path(sys.argv[1])/'hepta/_data/examples/hia_bootstrap/cli_inspect.hepta'
os.environ[adapter.SELECTOR]=sys.argv[2]
native=adapter.installed_cli_inspect(sys.argv[2])
actual=native._entry
calls=[]
def entry(*args):
    calls.append(1)
    return actual(*args)
native._entry=entry
def absent(*args,**kwargs):raise AssertionError('host inspect report fallback')
output=io.StringIO()
with patch.object(ordinary,'function_signature',side_effect=absent),contextlib.redirect_stdout(output):
    status=hia_main(['inspect',sys.argv[3]])
assert status==0 and output.getvalue()==pathlib.Path(sys.argv[4]).read_text()
assert calls==[1]
old=adapter.SOURCE.read_bytes()
adapter.SOURCE.write_bytes(old+b'\n')
try:adapter.installed_cli_inspect(sys.argv[2])
except ValueError as error:assert 'source identity mismatch' in str(error)
else:raise AssertionError('installed resource drift was hidden')
print(json.dumps({'installed_actual_native_entries':len(calls),'resource_owned':True,'installation_resource_tamper_rejected':True}))
'''
        result = run([sys.executable, '-I', '-B', '-c', code, str(installed), str(self.manifest),
                      str(input_path), str(expected_path)], timeout=90)
        self.assertEqual(json.loads(result.stdout)['installed_actual_native_entries'], 1)
        record(root / 'installed-result.json', json.loads(result.stdout))
