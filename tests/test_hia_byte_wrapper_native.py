"""Independent original policy, HIA VM and real native borrowed-byte tests."""
from __future__ import annotations

import ast
from contextlib import ExitStack
import ctypes
from hashlib import sha256
import inspect
import json
import os
from pathlib import Path
import shutil
import subprocess
import sys
import tempfile
import types
import unittest
from unittest.mock import patch

from hepta import hia_native_byte_abi as byte_abi, hia_program_native as backend
from hepta.hia_byte_wrapper_native import NativeByteWrapper
from hepta.hia_byte_wrapper_selection import (
    SELECTOR, ABI_SOURCE, checked_abi, source_names, installed_byte_wrapper,
    native_byte_wrapper_scope, active_byte_wrapper)
from hepta.hia_core_lowering_native import ABI, LoweringSession
from tests.test_hia_core_lowering_native import recorded, comparable

ROOT = Path(__file__).resolve().parents[1]
DEVELOPMENT = 'HEPTA_HIA_BYTE_WRAPPER_DEVELOPMENT_MANIFEST'
COLD = 'HEPTA_HIA_BYTE_WRAPPER_COLD_REPORT'
EVIDENCE = 'HEPTA_HIA_BYTE_WRAPPER_FIXTURE_EVIDENCE'


def selected_guard(manifest):
    stack = ExitStack()
    stack.enter_context(patch.dict(os.environ, {SELECTOR: str(manifest)}))
    for name in ('normalize_exports', 'emit_wrapper'):
        stack.enter_context(patch.object(byte_abi, '_reference_' + name,
            side_effect=AssertionError('retained byte-wrapper control entered: ' + name)))
    return stack


class ByteWrapperSourceTests(unittest.TestCase):
    def test_exact_original_policy_nested_closure_and_packet_caps(self):
        fixture = ROOT / 'tests/fixtures/hia_native_byte_abi_bbfa.py.txt'
        self.assertEqual(sha256(fixture.read_bytes()).hexdigest(), '0bb40a17f76c27146a48a6d3d229228c9a89bfd96d4b9d65b3b9c70215a3edd6')
        original = [n for n in ast.parse(fixture.read_bytes()).body if isinstance(n, ast.FunctionDef)]
        policy = [n for n in ast.parse((ROOT / 'tools/hia_byte_wrapper_policy.py').read_bytes()).body
                  if isinstance(n, ast.FunctionDef)]
        self.assertEqual([ast.dump(n) for n in original], [ast.dump(n) for n in policy])
        current = ast.parse(inspect.getsource(byte_abi))
        for before in original:
            retained = next(n for n in current.body if isinstance(n, ast.FunctionDef)
                            and n.name == '_reference_' + before.name)
            retained.name = before.name
            self.assertEqual(ast.dump(before), ast.dump(retained))
        from tools.hia_byte_wrapper_ir import compile_policy
        _, functions, entries, _ = compile_policy((ROOT / 'tools/hia_byte_wrapper_policy.py').read_text())
        self.assertEqual(tuple(entries), ('normalize_exports', 'emit_wrapper', 'emit_wrapper.load'))
        self.assertTrue(all(len(fn.parameters) <= 4 for fn in functions))
        self.assertEqual(entries['emit_wrapper.load']['parameters'], ['c', 'input_slot', 'word', 'register'])
        with self.assertRaises(ValueError):
            compile_policy('def unknown(): pass\n')

    def test_typed_sources_keep_caps_and_VM_manifest_policy(self):
        from hepta.hia_agent_assembly import assemble_program, render_assembly
        from hepta.hia_agent_contract import BYTE_WRAPPER_BUILD_FILES
        from hepta.hia_program_runtime import _Machine, _Owner, _View
        from hepta.hia_program import verify_program
        from tests.test_hia_native_byte_abi import byte_program
        abi = checked_abi((ROOT / ABI_SOURCE).read_bytes())
        self.assertEqual(BYTE_WRAPPER_BUILD_FILES, (ABI_SOURCE, *source_names(abi)))
        self.assertEqual(len(source_names(abi)), 9)
        programs = []
        for name in source_names(abi):
            raw = (ROOT / name).read_bytes()
            self.assertLessEqual(len(raw), 1 << 20)
            self.assertLessEqual(len(raw.splitlines()), 16384)
            program = assemble_program(raw)
            self.assertEqual(render_assembly(program.as_dict()).encode(), raw)
            functions = program.as_dict()['functions']
            blocks = [b for fn in functions for b in fn['blocks']]
            self.assertLessEqual(len(functions), 128)
            self.assertLessEqual(len(blocks), 1536)
            self.assertLessEqual(sum(len(b['ops']) + 1 for b in blocks), 8192)
            self.assertTrue(all(len(fn['blocks']) <= 256 and len(fn['params']) <= 16 for fn in functions))
            programs.append(program)
        observations = []
        class VMImage:
            def __init__(self, program):
                self.program = program
            def _entry(self, source, size, output, output_size, workspace, workspace_size):
                packet = ctypes.string_at(source, size)
                owners = [_Owner(-1, bytearray(packet)),
                    _Owner(-2, bytearray(ctypes.string_at(output, output_size))),
                    _Owner(-3, bytearray(ctypes.string_at(workspace, workspace_size)))]
                machine = _Machine(self.program, 4_000_000, 16 << 20, None, 128)
                result = machine.invoke(self.program.as_dict()['functions'][0],
                    [_View(owners[0], False), _View(owners[1], True), _View(owners[2], True)])[0]
                if bytes(owners[0].data) != packet:
                    raise AssertionError('byte-wrapper wrote read-only packet')
                for pointer, owner in ((output, owners[1]), (workspace, owners[2])):
                    ctypes.memmove(pointer, bytes(owner.data), len(owner.data))
                observations.append(machine.resources())
                return result
        owner = NativeByteWrapper([VMImage(p) for p in programs[1:]], VMImage(programs[0]), abi, vars(byte_abi))
        program = verify_program(byte_program())
        for exports in ((), [], (('copy_bytes', 32),), (('missing', 1),), (('copy_bytes', True),)):
            self.assertEqual(recorded(owner.invoke, 'normalize_exports', (exports, program)),
                             recorded(byte_abi._reference_normalize_exports, exports, program))
        self.assertTrue(observations)
        self.assertTrue(all(o['live_owners'] == o['live_local_loans'] == 0 for o in observations))

    def test_unqualified_cold_refuses_without_mutation_and_unselected_stays_original(self):
        from tools.build_hia_byte_wrapper import build
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            compiler, cold = root / 'compiler', root / 'cold'
            compiler.write_bytes(b'not a qualified compiler')
            cold.write_text('{"status":"DEVELOPMENT_ONLY"}')
            with self.assertRaisesRegex(ValueError, 'completed matching native cold'):
                build(root / 'must-not-create' / 'bundle', compiler, cold)
            self.assertFalse((root / 'must-not-create').exists())
        with patch.dict(os.environ, {SELECTOR: ''}):
            self.assertEqual(byte_abi.normalize_exports((), None), ())
        with patch.dict(os.environ, {SELECTOR: '/missing/explicit-byte-wrapper'}):
            with self.assertRaises(FileNotFoundError):
                byte_abi.normalize_exports((), None)

    def test_multiple_import_opcodes_keep_original_fromlist_and_global_namespace(self):
        import builtins
        from hepta.hia_host_import import members_importer
        real_import = builtins.__import__
        cases = [('IMPORTS', '_LOADER_HOOKS', '_reject'),
                 ('MAX_FRAME_BYTES', '_ARG_REGS', '_normalize', '_prologue', '_reject')]
        for members in cases:
            events = []
            def imported(name, globals=None, locals=None, fromlist=(), level=0):
                if name == 'hia_program_native':
                    events.append((name, globals is vars(byte_abi), locals, fromlist, level))
                return real_import(name, globals, locals, fromlist, level)
            with patch.object(builtins, '__import__', imported):
                values = members_importer(vars(byte_abi), 'hia_program_native', members)()
            self.assertEqual(events, [('hia_program_native', True, None, members, 1)])
            self.assertEqual(values, tuple(getattr(backend, name) for name in members))


class ByteWrapperNativeTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        development, cold = os.environ.get(DEVELOPMENT), os.environ.get(COLD)
        if development and cold:
            raise AssertionError('development cannot override byte-wrapper cold')
        evidence = os.environ.get(EVIDENCE)
        if evidence:
            cls.folder = Path(evidence).resolve()
            cls.folder.mkdir(parents=True, exist_ok=False)
        else:
            temporary = tempfile.TemporaryDirectory(prefix='hia-byte-wrapper-')
            cls.addClassCleanup(temporary.cleanup)
            cls.folder = Path(temporary.name)
        if cold:
            from tools.build_hia_byte_wrapper import build
            report = json.loads(Path(cold).read_bytes())
            nested = json.loads(Path(report['nested_report']).read_bytes())
            cls.manifest = build(cls.folder / 'qualified', Path(nested['generations'][-1]['produced_image']), Path(cold))
            cls.scope = 'MATCHING_SOURCE_COLD_BUILD'
        elif development:
            cls.manifest = Path(development).resolve(strict=True)
            cls.scope = 'EXPLICIT_DEVELOPMENT_ONLY'
        else:
            raise unittest.SkipTest('requires matching byte-wrapper cold or explicit development bundle')
        cls.owner = installed_byte_wrapper(str(cls.manifest), vars(byte_abi))

    def test_ordinary_backend_manifest_wrapper_and_metadata_without_retained_policy(self):
        from hepta.hia_program import verify_program
        from tests.test_hia_native_byte_abi import byte_program
        program = verify_program(byte_program())
        for exports in ((('copy_bytes', 4096),), (('readonly', 8), ('mixed', 64)), (('echo_status', 32),)):
            with patch.dict(os.environ, {SELECTOR: ''}):
                wanted = backend.emit_program_machine(program, foreign_buffer_exports=exports)
            with selected_guard(self.manifest):
                actual = backend.emit_program_machine(program, foreign_buffer_exports=exports)
            self.assertEqual(comparable(actual), comparable(wanted))
            self.assertNotEqual(actual.implementation_sha256, wanted.implementation_sha256)

    def test_foreign_program_observations_and_normalization_errors_are_unchanged(self):
        def observe(native):
            events = []
            class Program:
                def as_dict(self):
                    events.append('as_dict')
                    return {'functions': []}
                @property
                def structured_bytes(self):
                    events.append('structured_bytes')
                    raise LookupError('original program observation')
            result = recorded(self.owner.invoke, 'normalize_exports', ((('x', 1),), Program())) if native else recorded(
                byte_abi._reference_normalize_exports, (('x', 1),), Program())
            return result, events
        self.assertEqual(observe(True), observe(False))

    def test_private_native_load_closure_observes_bound_method_before_word_arithmetic(self):
        def observe(native):
            events = []
            class Code:
                def __getattribute__(self, name):
                    if name == 'load': events.append('bind-load')
                    return object.__getattribute__(self, name)
                def load(self, *args):
                    events.append(('old-load', args))
            code = Code()
            class Word:
                def __mul__(self, value):
                    events.append(('multiply', value))
                    code.load = lambda *a: events.append(('new-load', a))
                    return 8
            if native:
                fn = self.owner.global_value('_hia_byte_closure')('emit_wrapper.load', (code, -32))
            else:
                def fn(word, register):
                    code.load(register, 'rbp', -32 + word * 8)
            result = recorded(fn, Word(), 'rax')
            return result, events
        self.assertEqual(observe(True), observe(False))

    def test_captured_selection_and_warm_source_drift_are_not_ignored(self):
        import hepta.hia_byte_wrapper_selection as selection
        with patch.dict(os.environ, {SELECTOR: str(self.manifest)}):
            with native_byte_wrapper_scope(vars(byte_abi)):
                with patch.dict(os.environ, {SELECTOR: '/changed/after/capture'}):
                    self.assertIs(active_byte_wrapper(), self.owner)
        with tempfile.TemporaryDirectory() as temporary:
            drift = Path(temporary) / 'drift'
            drift.write_bytes(b'not the admitted native source')
            name = source_names(checked_abi((ROOT / ABI_SOURCE).read_bytes()))[-1]
            original = selection._source_resource_path
            with patch.object(selection, '_source_resource_path', lambda path: drift if path == name else original(path)):
                with self.assertRaises(ValueError):
                    installed_byte_wrapper(str(self.manifest), vars(byte_abi))

    def test_packet_reserved_bytes_refuse_before_buffer_effects(self):
        session = LoweringSession(self.owner, self.owner.modes['normalize_exports']['number'], ((), None))
        packet = bytearray(session.initial)
        packet[72] = 1
        source = ctypes.create_string_buffer(bytes(packet))
        output = ctypes.create_string_buffer(b'\xa5' * (self.owner.output_bytes + 32))
        work = ctypes.create_string_buffer(b'\0' * (self.owner.workspace_bytes + 32))
        result = self.owner.images[0]._entry(source, len(packet), ctypes.byref(output, 16),
            self.owner.output_bytes, ctypes.byref(work, 16), self.owner.workspace_bytes)
        self.assertEqual(result, ABI)
        self.assertEqual(bytes(output)[:16], b'\xa5' * 16)
        self.assertEqual(bytes(output)[-17:-1], b'\xa5' * 16)
        with self.assertRaises(RuntimeError):
            session.observe()

    def test_actual_installed_wheel_uses_complete_bundle_without_authoring(self):
        from hepta.hia_agent_contract import DISCOVERY_FILES, NATIVE_SOURCE_FILES, PUBLICATION_BUILD_FILES, SOURCE_BUILD_FILES, COMPILER_BUILD_FILES, BACKEND_BUILD_FILES, EMITTER_BUILD_FILES, BYTE_WRAPPER_BUILD_FILES
        from tests.test_hia_native_byte_abi import byte_program
        case = self.folder / 'installed-control'
        case.mkdir()
        source = case / 'source'
        source.mkdir()
        shutil.copytree(ROOT / 'hepta', source / 'hepta', ignore=shutil.ignore_patterns('__pycache__'))
        resources = (tuple('docs/' + n for n in DISCOVERY_FILES) + NATIVE_SOURCE_FILES + PUBLICATION_BUILD_FILES + SOURCE_BUILD_FILES + COMPILER_BUILD_FILES) + BACKEND_BUILD_FILES + EMITTER_BUILD_FILES + BYTE_WRAPPER_BUILD_FILES
        for name in (*resources, 'setup.py', 'pyproject.toml', 'MANIFEST.in'):
            target = source / name
            target.parent.mkdir(parents=True, exist_ok=True)
            shutil.copyfile(ROOT / name, target)
        expected = {'python': {p.relative_to(ROOT).as_posix(): sha256(p.read_bytes()).hexdigest()
                              for p in sorted((ROOT / 'hepta').rglob('*.py')) if '_data' not in p.parts},
                    'resources': {name: sha256((ROOT / name).read_bytes()).hexdigest() for name in resources},
                    'document': byte_program()}
        request = case / 'expected.json'
        request.write_text(json.dumps(expected, sort_keys=True))
        packaging = os.environ.get('HEPTA_HIA_TEST_PACKAGING_PYTHON', sys.executable)
        wheels, installed = case / 'wheels', case / 'installed'
        processes = []
        def run(arguments, label, env=None):
            result = subprocess.run(arguments, cwd=case, env=env, capture_output=True, timeout=120)
            (case / (label + '.stdout')).write_bytes(result.stdout)
            (case / (label + '.stderr')).write_bytes(result.stderr)
            processes.append({'argv': arguments, 'returncode': result.returncode,
                              'stdout_sha256': sha256(result.stdout).hexdigest(),
                              'stderr_sha256': sha256(result.stderr).hexdigest()})
            (case / 'processes.json').write_text(json.dumps(processes, indent=2) + '\n')
            self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
            return result
        run([packaging, '-B', '-m', 'pip', 'wheel', '--no-cache-dir', '--no-deps', '--no-index',
             '--no-build-isolation', '--wheel-dir', str(wheels), str(source)], 'wheel-build')
        wheel, = wheels.glob('*.whl')
        run([packaging, '-B', '-m', 'pip', 'install', '--no-cache-dir', '--no-deps', '--no-index',
             '--target', str(installed), str(wheel)], 'wheel-install')
        script = case / 'installed-child.py'
        script.write_text(INSTALLED_CHILD)
        env = {k: v for k, v in os.environ.items() if not k.startswith('HEPTA_HIA_') and k != 'PYTHONPATH'}
        env['PATH'] = ''
        result = run([sys.executable, '-I', '-S', '-B', str(script), str(installed),
                      str(self.manifest), str(request)], 'installed-execution', env)
        observed = json.loads(result.stdout)
        self.assertEqual(observed['status'], 'INSTALLED_BYTE_WRAPPER_PASS')
        self.assertEqual(observed['units'], 9)
        (case / 'report.json').write_text(json.dumps(observed, indent=2, sort_keys=True) + '\n')


INSTALLED_CHILD = "\nimport importlib.abc,inspect,json,os,sys\nfrom pathlib import Path\nfrom hashlib import sha256\nsys.path.insert(0,sys.argv[1])\nclass NoTools(importlib.abc.MetaPathFinder):\n    def find_spec(self,fullname,path=None,target=None):\n        if fullname=='tools' or fullname.startswith('tools.'):\n            raise AssertionError('installed lowering imported authoring tools')\nsys.meta_path.insert(0,NoTools())\nroot=Path(sys.argv[1])\nexpected=json.loads(Path(sys.argv[3]).read_bytes())\nfor name,identity in expected['python'].items():\n    assert sha256((root/name).read_bytes()).hexdigest()==identity\nactual={p.relative_to(root).as_posix() for p in (root/'hepta').rglob('*.py') if '_data' not in p.parts}\nassert actual==set(expected['python'])\nfrom hepta.hia_json_preflight_native import _source_resource_path\nfor name,identity in expected['resources'].items():\n    path=_source_resource_path(name)\n    assert root in path.parents and sha256(path.read_bytes()).hexdigest()==identity\nfrom hepta import hia_program_native as backend, hia_native_byte_abi as byte_abi\nfrom hepta.hia_program import verify_program\nfrom hepta.hia_byte_wrapper_selection import SELECTOR,ABI_SOURCE,installed_byte_wrapper\nfrom hepta.hia_core_lowering_native import LoweringSession\nentries=[]\nreal=LoweringSession.step\ndef step(session,packet):\n    value=real(session,packet);entries.append(value);return value\nLoweringSession.step=step\ndef forbidden(*args,**kwargs):\n    raise AssertionError('retained byte-wrapper control entered installed child')\nfor name in ('normalize_exports','emit_wrapper'):\n    setattr(byte_abi,'_reference_'+name,forbidden)\nos.environ[SELECTOR]=sys.argv[2]\nowner=installed_byte_wrapper(sys.argv[2],vars(byte_abi))\nmachine=backend.emit_program_machine(verify_program(expected['document']),foreign_buffer_exports=(('copy_bytes',4096),))\nassert machine.object_bytes.startswith(b'\\x7fELF')\nassert entries and 0 in entries and 1 in entries and 2 in entries\nabi=_source_resource_path(ABI_SOURCE)\nraw=abi.read_bytes()\nabi.write_bytes(raw+b'\\n')\ntry:installed_byte_wrapper(sys.argv[2],vars(byte_abi))\nexcept ValueError:pass\nelse:raise AssertionError('warm ABI source change was ignored')\nabi.write_bytes(raw);abi.unlink()\ntry:installed_byte_wrapper(sys.argv[2],vars(byte_abi))\nexcept FileNotFoundError:pass\nelse:raise AssertionError('missing installed ABI fell back to checkout')\nabi.write_bytes(raw)\nassert sys.flags.isolated and sys.flags.no_site and os.environ['PATH']==''\nprint(json.dumps({'status':'INSTALLED_BYTE_WRAPPER_PASS','units':len(owner._admitted_bundle.images),\n 'source_sha256':dict(owner._admitted_bundle.source_hashes),'abi_sha256':owner._admitted_bundle.abi_sha256,\n 'image_sha256':[im.image_sha256 for im in owner._admitted_bundle.images],\n 'object_sha256':machine.sha256,'python_files':len(expected['python']),\n 'resource_files':len(expected['resources']),'actual_native_steps':len(entries),\n 'retained_byte_wrapper_forbidden':True,'authoring_forbidden':True,'isolated_without_site':True,'empty_PATH':True}))\n"

if __name__ == '__main__':
    unittest.main()
