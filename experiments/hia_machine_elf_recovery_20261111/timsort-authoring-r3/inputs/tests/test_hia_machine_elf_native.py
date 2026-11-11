"""Whole ELF-owner development controls; cold selection is explicit.

The retained complete Python writer is an independent oracle. These controls
do not prove arbitrary foreign CPython sorting schedules equivalent.
"""
from __future__ import annotations
from collections import Counter
from contextlib import ExitStack
from dataclasses import fields
from hashlib import sha256
import ast
import ctypes
import json
import os
from pathlib import Path
import shutil
import struct
import subprocess
import sys
import tempfile
import types
import unittest
from unittest.mock import patch

from hepta import hia_machine_elf as public
from hepta import hia_machine_elf_native as bridge
from hepta.hia_machine_elf_native import (
    ACK, REQUEST, SEQUENCE, ElfSession, SOURCE, installed_machine_elf,
)

ROOT = Path(__file__).resolve().parents[1]
SELECTOR = 'HEPTA_HIA_MACHINE_ELF_MANIFEST'
DEVELOPMENT = 'HEPTA_HIA_MACHINE_ELF_DEVELOPMENT_MANIFEST'
COLD = 'HEPTA_HIA_MACHINE_ELF_COLD_REPORT'
EVIDENCE = 'HEPTA_HIA_MACHINE_ELF_FIXTURE_EVIDENCE'
ORACLE_SHA = 'c77cc453d33058ccbeea9e056191001982892a3e59386958090122ccf487c101'
CASE_SHA = 'c6cc16625a76a3912c539107a9cf1ceac6689e6dc73889c583500d8f1633465d'
_ORACLE = public._reference_write_elf_object


def _write_json(path, value):
    with Path(path).open('x') as stream:
        json.dump(value, stream, indent=2, sort_keys=True)
        stream.write('\n')


def _decode(value):
    if type(value) is list:
        return [_decode(item) for item in value]
    if type(value) is dict:
        kind = value.get('@type')
        if kind == 'bytes':
            return bytes.fromhex(value['hex'])
        if kind == 'bytearray':
            return bytearray.fromhex(value['hex'])
        if kind == 'tuple':
            return tuple(_decode(item) for item in value['items'])
        if kind == 'float':
            return float(value['value'])
        if kind == 'repeat':
            return [_decode(value['value']) for _ in range(value['count'])]
        if kind is not None:
            raise ValueError('unknown declared ELF fixture value')
        return {key: _decode(item) for key, item in value.items()}
    return value


def _outcome(writer, spec):
    args = _decode(spec)
    try:
        value = writer(args['code'], args['symbols'], args['relocations'],
                       text_alignment=args['alignment'])
        return ('bytes', value)
    except BaseException as exc:
        return ('exception', type(exc).__qualname__, exc.args)


def _encoded(value):
    if type(value) is bytes:
        return {'bytes': len(value), 'sha256': sha256(value).hexdigest(), 'hex': value.hex()}
    if type(value) in (tuple, list):
        return [_encoded(item) for item in value]
    if type(value) is dict:
        return {key: _encoded(item) for key, item in value.items()}
    return value


def _machine(value):
    return {item.name: _encoded(getattr(value, item.name)) for item in fields(value)}


class ForeignStop(BaseException):
    pass


def pending_lookup(image, session_type=ElfSession):
    """Reach an actual HIA-issued dict lookup without performing that effect."""
    ledger = []
    control = {'exception': None}

    class Key:
        def __init__(self, name):
            self.name = name

        def __hash__(self):
            ledger.append(('hash', self.name))
            return hash(self.name)

        def __eq__(self, other):
            ledger.append(('eq', self.name, other if type(other) is str else type(other).__name__))
            if control['exception'] is not None:
                raise control['exception']
            return self.name == other

    row = {Key(name): value for name, value in (
        ('name', 'entry'), ('offset', 0), ('size', 1), ('global', True))}
    session = session_type(image, b'\xc3', [row], [], 16)
    for _ in range(256):
        if session.step() != 1:
            session.close()
            raise AssertionError('real ELF policy finished before dict observation')
        if session.word(REQUEST) == 6:
            return session, ledger, control
        session.observe()
    session.close()
    raise AssertionError('real ELF policy did not reach its issued dict lookup')


class MachineElfSourceTests(unittest.TestCase):
    def test_complete_original_writer_prefix_and_reconstructed_inputs(self):
        raw = (ROOT / 'hepta/hia_machine_elf.py').read_bytes()
        prefix = raw.split(b'\n\n# The complete original writer above', 1)[0]
        self.assertEqual(sha256(prefix).hexdigest(), ORACLE_SHA)
        document = json.loads((ROOT / 'tests/hia_machine_elf_cases.json').read_bytes())
        self.assertEqual(sha256((ROOT / 'tests/hia_machine_elf_cases.json').read_bytes()).hexdigest(), CASE_SHA)
        self.assertEqual(document['revision'], 'RECONSTRUCTED_NEW_55_NOT_RECOVERED_OLD_CONTROL')
        self.assertEqual(len(document['cases']), 55)
        self.assertEqual(len({row['id'] for row in document['cases']}), 55)
        self.assertEqual(sum(row['expected_kind'] == 'bytes' for row in document['cases']), 6)

    def test_generated_hia_roundtrips_with_original_limits(self):
        from tools.generate_hia_machine_elf import document
        from hepta.hia_agent_assembly import assemble_program, render_assembly
        value = document()
        self.assertEqual(render_assembly(value).encode(), SOURCE.read_bytes())
        self.assertEqual(assemble_program(SOURCE.read_bytes()).as_dict(), value)
        self.assertEqual(len(value['functions']), 62)
        self.assertLessEqual(len(SOURCE.read_bytes()), 1 << 20)

    def test_declared_installed_source_resource(self):
        from hepta.hia_agent_contract import NATIVE_SOURCE_FILES
        self.assertEqual(NATIVE_SOURCE_FILES.count('examples/hia_bootstrap/machine_elf.hiaasm'), 1)
        self.assertIn('include examples/hia_bootstrap/machine_elf.hiaasm',
                      (ROOT / 'MANIFEST.in').read_text().splitlines())

    def test_incomplete_cold_report_refuses_before_creating_output(self):
        from tools import build_hia_machine_elf as builder
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            compiler, cold = root / 'compiler', root / 'cold.json'
            compiler.write_bytes(b'not-a-qualified-compiler')
            cold.write_text('{}')
            with patch.object(builder, 'compile_stage',
                              side_effect=AssertionError('rejected input reached native compilation')):
                with self.assertRaises(ValueError):
                    builder.build(root / 'absent-parent' / 'output', compiler, cold)
            self.assertFalse((root / 'absent-parent').exists())

    def test_original_api_unselected_and_explicit_missing_refuses(self):
        code = b'\xc3'
        rows = [{'name': 'entry', 'offset': 0, 'size': 1, 'global': True}]
        with patch.dict(os.environ, {}, clear=False):
            os.environ.pop(SELECTOR, None)
            self.assertEqual(public.native_implementation_identity(), b'')
            self.assertEqual(public.write_elf_object(code, rows, []), _ORACLE(code, rows, []))
        with patch.dict(os.environ, {SELECTOR: '/missing/explicit-machine-elf-manifest'}):
            with self.assertRaises(FileNotFoundError):
                public.write_elf_object(code, rows, [])


class _Fixture:
    @classmethod
    def setUpClass(cls):
        development, cold = os.environ.get(DEVELOPMENT), os.environ.get(COLD)
        if development is not None and cold is not None:
            raise AssertionError('development manifest cannot override a requested cold report')
        if development is None and cold is None:
            raise unittest.SkipTest('requires explicit current cold report or development manifest')
        base = os.environ.get(EVIDENCE)
        if base is None:
            cls.temporary = tempfile.TemporaryDirectory(prefix='hia-machine-elf-native-')
            cls.addClassCleanup(cls.temporary.cleanup)
            cls.folder = Path(cls.temporary.name)
        else:
            base = Path(base).resolve()
            base.mkdir(parents=True, exist_ok=True)
            cls.folder = base / cls.__name__
            cls.folder.mkdir(mode=0o700)
        if cold is not None:
            from tools.build_hia_machine_elf import build
            outer = json.loads(Path(cold).read_bytes())
            nested = json.loads(Path(outer['nested_report']).read_bytes())
            compiler = Path(nested['generations'][-1]['produced_image'])
            cls.manifest = build(cls.folder / 'qualified', compiler, Path(cold))
            cls.scope = 'MATCHING_SOURCE_COLD_BUILD'
        else:
            cls.manifest = Path(development).resolve(strict=True)
            cls.scope = 'EXPLICIT_DEVELOPMENT_ONLY'
        cls.native = installed_machine_elf(str(cls.manifest))

    def selected(self):
        stack = ExitStack()
        stack.enter_context(patch.dict(os.environ, {SELECTOR: str(self.manifest)}))
        stack.enter_context(patch.object(public, '_reference_write_elf_object',
            side_effect=AssertionError('retained ELF writer entered explicit native selection')))
        return stack


class MachineElfNativeTests(_Fixture, unittest.TestCase):
    def test_complete_reconstructed_55_input_denominator(self):
        definitions = json.loads((ROOT / 'tests/hia_machine_elf_cases.json').read_bytes())
        self.assertEqual(len(definitions['cases']), 55)
        results = []
        before = self.native.calls.copy()
        with self.selected():
            for row in definitions['cases']:
                expected = _outcome(_ORACLE, row['arguments'])
                actual = _outcome(public.write_elf_object, row['arguments'])
                results.append({'id': row['id'], 'original': _encoded(expected),
                                'native': _encoded(actual), 'equal': expected == actual})
                with self.subTest(case=row['id']):
                    self.assertEqual(expected[0], row['expected_kind'])
                    self.assertEqual(expected, actual)
        _write_json(self.folder / 'complete-55.json', {
            'revision': definitions['revision'], 'cases': results,
            'loaded': 55, 'executed': len(results),
            'native_operation_counts': dict(self.native.calls - before),
        })
        self.assertTrue(self.native.calls - before)

    def test_pending_step_refusal_permanently_revokes_real_effect(self):
        session, ledger, _ = pending_lookup(self.native)
        try:
            before = list(ledger)
            with self.assertRaisesRegex(RuntimeError, 'not ready'):
                session.step()
            self.assertTrue(session.finished)
            self.assertFalse(session.pending)
            with self.assertRaisesRegex(RuntimeError, 'not pending'):
                session.observe()
            self.assertEqual(ledger, before)
        finally:
            session.close()

    def test_repeated_observe_and_unissued_observe_are_terminal(self):
        session, ledger, _ = pending_lookup(self.native)
        try:
            session.observe()
            after = list(ledger)
            with self.assertRaisesRegex(RuntimeError, 'not pending'):
                session.observe()
            with self.assertRaisesRegex(RuntimeError, 'not ready'):
                session.step()
            self.assertTrue(session.finished)
            self.assertFalse(session.pending)
            self.assertEqual(ledger, after)
        finally:
            session.close()
        fresh = ElfSession(self.native, b'\xc3',
            [{'name': 'entry', 'offset': 0, 'size': 1, 'global': True}], [], 16)
        try:
            with self.assertRaisesRegex(RuntimeError, 'not pending'):
                fresh.observe()
            with self.assertRaisesRegex(RuntimeError, 'not ready'):
                fresh.step()
            self.assertTrue(fresh.finished)
        finally:
            fresh.close()

    def test_malformed_ack_reaches_real_native_refusal_then_closes(self):
        session, ledger, _ = pending_lookup(self.native)
        try:
            before = list(ledger)
            session.pending = False
            session.put(ACK, session.word(SEQUENCE) + 1)
            with self.assertRaises(RuntimeError):
                session.step()
            self.assertTrue(session.finished)
            with self.assertRaises(RuntimeError):
                session.observe()
            self.assertEqual(ledger, before)
        finally:
            session.close()

    def test_foreign_baseexception_retains_object_traceback_and_context(self):
        session, ledger, control = pending_lookup(self.native)
        stop = ForeignStop('foreign-key-stop')
        try:
            try:
                raise OSError('ambient-original')
            except OSError as ambient:
                control['exception'] = stop
                try:
                    session.observe()
                except BaseException as caught:
                    self.assertIs(caught, stop)
                    original_tb = caught.__traceback__
                    self.assertIs(caught.__context__, ambient)
                    names = []
                    while original_tb is not None:
                        names.append(original_tb.tb_frame.f_code.co_name)
                        original_tb = original_tb.tb_next
                    self.assertEqual(names[-1], '__eq__')
                    original_tb = caught.__traceback__
                else:
                    self.fail('issued foreign exception was swallowed')
                after = list(ledger)
                with self.assertRaises(RuntimeError):
                    session.observe()
                self.assertIs(stop.__traceback__, original_tb)
                self.assertIs(stop.__context__, ambient)
                self.assertEqual(ledger, after)
                self.assertTrue(session.finished)
                self.assertFalse(session.pending)
        finally:
            session.close()

    def test_post_native_entry_and_counter_baseexceptions_are_terminal(self):
        actual_entry = self.native._entry
        returns = []
        stop = ForeignStop('after-real-native-entry')
        def after_entry(*args):
            returns.append(actual_entry(*args))
            raise stop
        session = ElfSession(self.native, b'\xc3',
            [{'name': 'entry', 'offset': 0, 'size': 1, 'global': True}], [], 16)
        try:
            with patch.object(self.native, '_entry', after_entry):
                with self.assertRaises(ForeignStop) as caught:
                    session.step()
            self.assertIs(caught.exception, stop)
            self.assertEqual(len(returns), 1)
            self.assertTrue(session.finished)
            self.assertFalse(session.pending)
        finally:
            session.close()
        session, ledger, _ = pending_lookup(self.native)
        class ExplodingCounter(Counter):
            def __getitem__(self, key):
                raise stop
        try:
            session.calls = ExplodingCounter()
            before = list(ledger)
            with self.assertRaises(ForeignStop) as caught:
                session.observe()
            self.assertIs(caught.exception, stop)
            self.assertTrue(session.finished)
            with self.assertRaises(RuntimeError):
                session.observe()
            self.assertEqual(ledger, before)
        finally:
            session.close()

    def test_success_and_explicit_close_cannot_replay_effects(self):
        session = ElfSession(self.native, b'\xc3',
            [{'name': 'entry', 'offset': 0, 'size': 1, 'global': True}], [], 16)
        try:
            while session.step():
                session.observe()
            self.assertTrue(session.finished)
            with self.assertRaises(RuntimeError):
                session.observe()
            with self.assertRaises(RuntimeError):
                session.step()
        finally:
            session.close()
        session, ledger, _ = pending_lookup(self.native)
        before = list(ledger)
        session.close()
        with self.assertRaises(RuntimeError):
            session.observe()
        with self.assertRaises(RuntimeError):
            session.step()
        self.assertEqual(ledger, before)

    def test_backend_full_return_identity_and_mid_emit_selection(self):
        from hepta import hia_program_native as backend
        from hepta.hia_program import verify_program
        from tests.test_hia_program_native import minimal_document
        program = verify_program(minimal_document())
        with patch.dict(os.environ, {}, clear=False):
            os.environ.pop(SELECTOR, None)
            original = backend.emit_program_machine(program)
        with self.selected():
            selected = backend.emit_program_machine(program)
            expected_identity = backend._implementation_hash()
            self.assertEqual(selected.implementation_sha256, expected_identity)
            with patch.object(backend, 'write_elf_object', _ORACLE):
                same_identity_oracle = backend.emit_program_machine(program)
            self.assertEqual(_machine(selected), _machine(same_identity_oracle))
        self.assertNotEqual(original.implementation_sha256, selected.implementation_sha256)
        self.assertEqual(original.object_bytes, selected.object_bytes)
        render = backend._Emitter.render
        def changed_inside_render(emitter):
            os.environ[SELECTOR] = '/missing/changed-after-owner-capture'
            return render(emitter)
        with self.selected(), patch.object(backend._Emitter, 'render', changed_inside_render):
            frozen = backend.emit_program_machine(program)
        self.assertEqual(_machine(frozen), _machine(selected))
        _write_json(self.folder / 'complete-return-object.json', {
            'original': _machine(original), 'selected': _machine(selected),
            'same_identity_oracle': _machine(same_identity_oracle), 'frozen': _machine(frozen),
        })

    def test_pinned_owner_refuses_source_drift_before_first_identity(self):
        directory = self.folder / 'pinned-source-window'
        directory.mkdir()
        source = directory / 'machine_elf.hiaasm'
        original = SOURCE.read_bytes()
        source.write_bytes(original)
        with patch.object(bridge, 'SOURCE', source), self.selected():
            with public.native_elf_scope():
                before = self.native.calls.copy()
                self.assertEqual(self.native.admitted_source_sha256, sha256(original).hexdigest())
                source.write_bytes(original + b'\n')
                try:
                    with self.assertRaisesRegex(ValueError, 'changed after admission'):
                        public.native_implementation_identity()
                    from hepta import hia_program_native as backend
                    with self.assertRaisesRegex(ValueError, 'changed after admission'):
                        backend._implementation_hash()
                    self.assertEqual(self.native.calls, before)
                finally:
                    source.write_bytes(original)
                self.assertEqual(public.native_implementation_identity(),
                    (sha256(original).hexdigest() + ':' + self.native.image_sha256).encode())

    def test_cached_image_rebinds_installed_source_and_forged_manifest(self):
        directory = self.folder / 'source-binding'
        directory.mkdir()
        source = directory / 'machine_elf.hiaasm'
        source.write_bytes(SOURCE.read_bytes())
        with patch.object(bridge, 'SOURCE', source):
            self.assertIs(installed_machine_elf(str(self.manifest)), self.native)
            source.write_bytes(source.read_bytes() + b'\n')
            with self.assertRaisesRegex(ValueError, 'source identity mismatch'):
                installed_machine_elf(str(self.manifest))
            source.unlink()
            with self.assertRaises(FileNotFoundError):
                installed_machine_elf(str(self.manifest))
        value = json.loads(self.manifest.read_bytes())
        value['source_sha256'] = '0' * 64
        forged = directory / 'forged.json'
        forged.write_text(json.dumps(value))
        with self.assertRaisesRegex(ValueError, 'source identity mismatch'):
            installed_machine_elf(str(forged))
        warmed = directory / 'warm'
        warmed.mkdir()
        manifest_value = json.loads(self.manifest.read_bytes())
        image_name = manifest_value['image_path']
        image_path = warmed / 'image.bin'
        image_raw = (self.manifest.parent / image_name).read_bytes()
        image_path.write_bytes(image_raw)
        manifest_value['image_path'] = image_path.name
        warm_manifest = warmed / 'manifest.json'
        warm_manifest.write_text(json.dumps(manifest_value))
        mapped = installed_machine_elf(str(warm_manifest))
        image_path.write_bytes(image_raw[:-1] + bytes([image_raw[-1] ^ 1]))
        self.assertIs(installed_machine_elf(str(warm_manifest)), mapped)
        result = mapped.write(b'\xc3',
            [{'name': 'entry', 'offset': 0, 'size': 1, 'global': True}], [])
        self.assertEqual(result, _ORACLE(b'\xc3',
            [{'name': 'entry', 'offset': 0, 'size': 1, 'global': True}], []))
        image_path.write_bytes(image_raw)

    def test_real_installed_wheel_isolated_empty_path_without_old_writer(self):
        from hepta.hia_agent_contract import (
            DISCOVERY_FILES, NATIVE_SOURCE_FILES, PUBLICATION_BUILD_FILES,
        )
        from hepta.hia_program import verify_program
        from hepta import hia_program_native as backend
        from tests.test_hia_program_native import minimal_document
        case = self.folder / 'installed-wheel'
        case.mkdir()
        source, wheels, installed = case / 'source', case / 'wheels', case / 'installed'
        source.mkdir()
        shutil.copytree(ROOT / 'hepta', source / 'hepta',
                        ignore=shutil.ignore_patterns('__pycache__'))
        resources = tuple('docs/' + name for name in DISCOVERY_FILES) + \
                    NATIVE_SOURCE_FILES + PUBLICATION_BUILD_FILES
        for name in (*resources, 'setup.py', 'pyproject.toml', 'MANIFEST.in'):
            target = source / name
            target.parent.mkdir(parents=True, exist_ok=True)
            shutil.copyfile(ROOT / name, target)
        python = os.environ.get('HEPTA_HIA_TEST_PACKAGING_PYTHON', sys.executable)
        processes = []
        def command(argv, label, environment=None):
            out, err = case / (label + '.stdout'), case / (label + '.stderr')
            with out.open('xb') as stdout, err.open('xb') as stderr:
                result = subprocess.run(argv, cwd=case, env=environment,
                    stdin=subprocess.DEVNULL, stdout=stdout, stderr=stderr, timeout=120)
            processes.append({
                'argv': argv, 'returncode': result.returncode,
                'stdout_sha256': sha256(out.read_bytes()).hexdigest(),
                'stderr_sha256': sha256(err.read_bytes()).hexdigest(),
            })
            _write_json(case / (label + '.process.json'), processes[-1])
            self.assertEqual(result.returncode, 0, err.read_bytes()[-16384:])
            return out.read_bytes()
        command([python, '-B', '-m', 'pip', 'wheel', '--no-cache-dir', '--no-deps',
                 '--no-index', '--no-build-isolation', '--wheel-dir', str(wheels),
                 str(source)], 'build')
        wheel, = wheels.glob('*.whl')
        command([python, '-B', '-m', 'pip', 'install', '--no-cache-dir', '--no-deps',
                 '--no-index', '--target', str(installed), str(wheel)], 'install')
        document = minimal_document()
        with self.selected(), patch.object(backend, 'write_elf_object', _ORACLE):
            expected = backend.emit_program_machine(verify_program(document))
        inputs = case / 'inputs.json'
        _write_json(inputs, {'document': document, 'expected': _machine(expected)})
        script = case / 'installed.py'
        script.write_text(INSTALLED_CONTROL)
        environment = {key: value for key, value in os.environ.items()
                       if not key.startswith('HEPTA_HIA_')}
        environment.update(PATH='', PYTHONPATH='')
        raw = command([sys.executable, '-I', '-S', '-B', str(script), str(installed),
                       str(self.manifest), str(inputs)], 'execution', environment)
        value = json.loads(raw)
        self.assertEqual(value['status'], 'INSTALLED_NATIVE_ELF_PASS')
        self.assertTrue(value['isolated_without_site'] and value['empty_PATH'])
        self.assertTrue(value['full_return_object_equal'])
        self.assertGreater(sum(value['native_operation_counts'].values()), 0)
        _write_json(case / 'processes.json', processes)


INSTALLED_CONTROL = r"""import importlib.abc,json,os,sys
from dataclasses import fields
from hashlib import sha256
from pathlib import Path
sys.path.insert(0,sys.argv[1])
class NoAuthoring(importlib.abc.MetaPathFinder):
    def find_spec(self,fullname,path=None,target=None):
        if fullname=='tools' or fullname.startswith('tools.'):
            raise AssertionError('installed ELF execution imported authoring tools')
sys.meta_path.insert(0,NoAuthoring())
from hepta import hia_machine_elf as public
from hepta.hia_machine_elf_native import SOURCE,installed_machine_elf
from hepta.hia_program import verify_program
from hepta.hia_program_native import emit_program_machine
assert Path(sys.argv[1]) in SOURCE.parents
def forbidden(*args,**kwargs):
    raise AssertionError('installed ELF execution entered the retained writer')
public._reference_write_elf_object=forbidden
os.environ['HEPTA_HIA_MACHINE_ELF_MANIFEST']=sys.argv[2]
def encoded(value):
    if type(value)is bytes:
        return {'bytes':len(value),'sha256':sha256(value).hexdigest(),'hex':value.hex()}
    if type(value)in(tuple,list):return [encoded(item)for item in value]
    if type(value)is dict:return {key:encoded(item)for key,item in value.items()}
    return value
inputs=json.loads(Path(sys.argv[3]).read_bytes())
machine=emit_program_machine(verify_program(inputs['document']))
actual={field.name:encoded(getattr(machine,field.name))for field in fields(machine)}
assert actual==inputs['expected']
native=installed_machine_elf(sys.argv[2])
assert sum(native.calls.values())>0
original=SOURCE.read_bytes()
SOURCE.write_bytes(original+b'\n')
try:installed_machine_elf(sys.argv[2])
except ValueError:pass
else:raise AssertionError('warm installed native image hid changed source')
SOURCE.write_bytes(original)
SOURCE.unlink()
try:installed_machine_elf(sys.argv[2])
except FileNotFoundError:pass
else:raise AssertionError('installed native image fell back to another source tree')
SOURCE.write_bytes(original)
assert SOURCE.read_bytes()==original
print(json.dumps({'status':'INSTALLED_NATIVE_ELF_PASS',
 'source_sha256':sha256(original).hexdigest(),'image_sha256':native.image_sha256,
 'full_return_object_equal':True,'actual':actual,
 'isolated_without_site':bool(sys.flags.isolated and sys.flags.no_site),
 'empty_PATH':os.environ['PATH']=='','native_operation_counts':dict(native.calls)}))
"""


class MachineElfBoundaryTests(_Fixture, unittest.TestCase):
    def _compare(self, label, code, symbols, relocations, *, alignment=16):
        import gzip
        result = {'case': label, 'code_bytes': len(code), 'symbols': len(symbols),
                  'relocations': len(relocations), 'alignment': alignment}
        def call(fn):
            try:
                return ('bytes', fn(code, symbols, relocations, text_alignment=alignment))
            except BaseException as exc:
                return ('exception', type(exc).__qualname__, exc.args)
        expected = call(_ORACLE)
        before = self.native.calls.copy()
        with self.selected():
            actual = call(public.write_elf_object)
        equal = expected == actual
        for name, observation in (('original', expected), ('native', actual)):
            if observation[0] == 'bytes':
                raw = observation[1]
                path = self.folder / (label + '-' + name + '.elf.gz')
                with path.open('xb') as stream:
                    with gzip.GzipFile(filename='', mode='wb', fileobj=stream, mtime=0) as encoded:
                        encoded.write(raw)
                # Verify the complete archived output, including its decoded
                # length and bytes, rather than trusting the compression call.
                with gzip.open(path, 'rb') as stream:
                    restored = stream.read()
                self.assertTrue(restored == raw, 'complete boundary artifact retention differs')
                result[name] = {
                    'kind': 'bytes', 'bytes': len(raw), 'sha256': sha256(raw).hexdigest(),
                    'archive': path.name, 'archive_sha256': sha256(path.read_bytes()).hexdigest(),
                }
                del restored
            else:
                result[name] = {'kind': 'exception', 'type': observation[1],
                                'args': observation[2]}
        result['equal'] = equal
        result['native_operation_counts'] = dict(self.native.calls - before)
        _write_json(self.folder / (label + '.json'), result)
        self.assertTrue(equal, label + ': actual complete oracle/native outcome differs')
        self.assertTrue(result['native_operation_counts'])
        return result

    def test_actual_64mib_code_and_final_object_boundary(self):
        limit = public.MAX_OBJECT_BYTES
        # This exact-size fixture is calculated from the complete retained ELF
        # structure, then checked against its actual output; it is not an
        # implementation shortcut supplied to the HIA owner.
        largest_code = limit - 656
        row = lambda size: [{'name': 'entry', 'offset': 0, 'size': size, 'global': True}]
        exact = self._compare('object-exact-64mib', b'\xc3' * largest_code,
                              row(largest_code), [])
        self.assertEqual(exact['original']['bytes'], limit)
        above = self._compare('object-over-64mib', b'\xc3' * (largest_code + 1),
                              row(largest_code + 1), [])
        self.assertEqual(above['original']['args'], ('ELF object exceeds byte budget',))
        code_at = self._compare('code-exact-64mib', b'\xc3' * limit, row(limit), [])
        self.assertEqual(code_at['original']['args'], ('ELF object exceeds byte budget',))
        code_over = self._compare('code-over-64mib', b'\xc3' * (limit + 1), row(limit + 1), [])
        self.assertEqual(code_over['original']['args'],
                         ('nonempty bounded immutable machine bytes required',))

    def test_actual_65536_symbol_inventory_boundary(self):
        count = public.MAX_SYMBOLS - 2
        rows = [{'name': 'f' + str(index).zfill(5), 'offset': index,
                 'size': 1, 'global': bool(index & 1)} for index in range(count + 1)]
        exact = self._compare('symbol-table-exact-65536', b'\xc3' * count,
                              rows[:count], [])
        self.assertEqual(exact['original']['kind'], 'bytes')
        above = self._compare('symbol-table-over-65536', b'\xc3' * (count + 1),
                              rows, [])
        self.assertEqual(above['original']['args'], ('ELF symbol inventory exceeds limit',))

    def test_actual_imported_symbol_inventory_boundary(self):
        count = public.MAX_SYMBOLS - 3
        rows = [{'name': 'f' + str(index).zfill(5), 'offset': index + 5,
                 'size': 1, 'global': bool(index & 1)} for index in range(count + 1)]
        relocation = [{'offset': 1, 'symbol': 'outside', 'type': 4, 'addend': -4}]
        exact = self._compare('import-table-exact-65536',
                              b'\xe8\0\0\0\0' + b'\xc3' * count, rows[:count], relocation)
        self.assertEqual(exact['original']['kind'], 'bytes')
        above = self._compare('import-table-over-65536',
                              b'\xe8\0\0\0\0' + b'\xc3' * (count + 1), rows, relocation)
        self.assertEqual(above['original']['args'], ('ELF symbol inventory exceeds limit',))

    def test_full_name_and_alignment_with_adjacent_calls(self):
        code = b'\xe8\0\0\0\0\xe8\0\0\0\0\xc3'
        symbols = [{'name': 'x' * 192, 'offset': 0, 'size': len(code), 'global': False}]
        relocations = [{'offset': 6, 'symbol': 'z' * 192, 'type': 4, 'addend': -4},
                       {'offset': 1, 'symbol': 'a' * 192, 'type': 4, 'addend': -4}]
        for alignment in (16, 32, 64):
            result = self._compare('names-192-alignment-' + str(alignment),
                                   code, symbols, relocations, alignment=alignment)
            self.assertEqual(result['original']['kind'], 'bytes')


if __name__ == '__main__':
    unittest.main()
