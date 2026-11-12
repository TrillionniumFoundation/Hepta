"""Independent complete-policy, foreign-observation and real native Emitter tests."""
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

from hepta import hia_program_native as backend
from hepta.hia_core_emitter_native import NativeCoreEmitter, _project_items, _unpack_four
from hepta.hia_core_emitter_selection import (
    SELECTOR, ABI_SOURCE, checked_abi, source_names, installed_core_emitter,
    native_core_emitter_scope)
from hepta.hia_core_lowering_native import ABI, FRAME, LoweringSession
from tests.test_hia_core_lowering_native import original_nodes, recorded, comparable

ROOT = Path(__file__).resolve().parents[1]
DEVELOPMENT = 'HEPTA_HIA_CORE_EMITTER_DEVELOPMENT_MANIFEST'
COLD = 'HEPTA_HIA_CORE_EMITTER_COLD_REPORT'
EVIDENCE = 'HEPTA_HIA_CORE_EMITTER_FIXTURE_EVIDENCE'


def selected_guard(manifest):
    stack = ExitStack()
    stack.enter_context(patch.dict(os.environ, {SELECTOR: str(manifest)}))
    for name, method in backend._Emitter.__dict__.items():
        if inspect.isfunction(method) and name != '__new__':
            stack.enter_context(patch.object(backend._Emitter, name,
                side_effect=AssertionError('retained Emitter control entered: ' + name)))
    return stack


class CoreEmitterSourceTests(unittest.TestCase):
    def test_complete_original_Emitter_AST_and_constructor_transport(self):
        original = next(n for n in original_nodes().body
                        if isinstance(n, ast.ClassDef) and n.name == '_Emitter')
        policy = ast.parse((ROOT / 'tools/hia_core_emitter_policy.py').read_text()).body[-1]
        self.assertEqual(ast.dump(original), ast.dump(policy))
        current = next(n for n in ast.parse(inspect.getsource(backend)).body
                       if isinstance(n, ast.ClassDef) and n.name == '_Emitter')
        current.body = [n for n in current.body if getattr(n, 'name', None) != '__new__']
        self.assertEqual(ast.dump(original), ast.dump(current))
        from tools.hia_core_emitter_ir import transported_constructor, compile_policy
        constructor = original.body[0]
        transported = transported_constructor(constructor)
        self.assertEqual(ast.dump(ast.Module(body=transported.body[5:], type_ignores=[])),
                         ast.dump(ast.Module(body=constructor.body, type_ignores=[])))
        _, functions, entries, _ = compile_policy((ROOT / 'tools/hia_core_emitter_policy.py').read_text())
        self.assertEqual(len(functions), 6)
        self.assertTrue(all(len(f.parameters) <= 4 for f in functions))
        self.assertEqual(entries['_Emitter.__init__']['parameters'], ['self', '_hia_emitter_args'])
        with self.assertRaises(ValueError):
            compile_policy('class _Emitter:\n def unknown(self): pass\n')

    def test_lazy_projection_preserves_partial_extend_and_unpack_errors(self):
        def observe(native):
            events = []
            class Row:
                def __getitem__(self, key):
                    events.append(key)
                    if len(events) == 2:
                        raise LookupError('after one real write')
                    return 'u64'
            rows, output = [Row(), Row()], []
            try:
                output.extend(_project_items(rows, 'type') if native else (p['type'] for p in rows))
            except BaseException as exc:
                return output, events, type(exc), exc.args
            self.fail('missing deliberate projection error')
        self.assertEqual(observe(True), observe(False))
        self.assertEqual(observe(True)[0], ['u64'])
        for value in ((), (1, 2, 3), (1, 2, 3, 4), (1, 2, 3, 4, 5)):
            def reference(value):
                a, b, c, d = value
                return a, b, c, d
            self.assertEqual(recorded(_unpack_four, value), recorded(reference, value))

    def test_unselected_subclass_and_unqualified_cold_do_not_activate(self):
        from hepta.hia_program import verify_program
        from tests.test_hia_program_native import minimal_document
        from tools.build_hia_core_emitter import build
        document = minimal_document()
        with patch.dict(os.environ, {SELECTOR: ''}):
            self.assertIs(type(backend._Emitter(document, {'run'})), backend._Emitter)
        class Foreign(backend._Emitter):
            def __init__(self, document, allowed_exports, **kwargs):
                self.marker = document
        with patch.dict(os.environ, {SELECTOR: '/does/not/exist/emitter'}):
            self.assertEqual(Foreign('marker', set()).marker, 'marker')
            with self.assertRaisesRegex(backend.HIAProgramNativeRejected, 'E_HIA_PROGRAM_TARGET'):
                backend.emit_program_machine(verify_program(document), target='not-supported')
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            compiler, cold = root / 'compiler', root / 'cold'
            compiler.write_bytes(b'not-a-qualified-compiler')
            cold.write_text('{"status":"DEVELOPMENT_ONLY"}')
            with self.assertRaisesRegex(ValueError, 'completed matching native cold'):
                build(root / 'must-not-create' / 'bundle', compiler, cold)
            self.assertFalse((root / 'must-not-create').exists())

    def test_source_caps_typed_ABI_and_independent_VM_constructor(self):
        from hepta.hia_agent_assembly import assemble_program, render_assembly
        from hepta.hia_agent_contract import EMITTER_BUILD_FILES, BYTE_WRAPPER_BUILD_FILES, MACHINE_OBJECT_BUILD_FILES, EXECUTION_OBSERVATION_BUILD_FILES
        from hepta.hia_program_runtime import _Machine, _Owner, _View
        from tests.test_hia_program_native import minimal_document
        abi = checked_abi((ROOT / ABI_SOURCE).read_bytes())
        self.assertEqual(EMITTER_BUILD_FILES, (ABI_SOURCE, *source_names(abi)))
        self.assertEqual(len(source_names(abi)), 9)
        programs = []
        for name in source_names(abi):
            raw = (ROOT / name).read_bytes()
            self.assertLessEqual(len(raw), 1 << 20)
            self.assertLessEqual(len(raw.splitlines()), 16384)
            program = assemble_program(raw)
            self.assertEqual(render_assembly(program.as_dict()).encode(), raw)
            functions = program.as_dict()['functions']
            blocks = [b for f in functions for b in f['blocks']]
            self.assertLessEqual(len(functions), 128)
            self.assertLessEqual(len(blocks), 1536)
            self.assertLessEqual(sum(len(b['ops']) + 1 for b in blocks), 8192)
            for function in functions:
                self.assertLessEqual(len(function['blocks']), 256)
                self.assertLessEqual(len(function['params']), 16)
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
                    raise AssertionError('Emitter wrote its read-only packet')
                for pointer, owner in ((output, owners[1]), (workspace, owners[2])):
                    ctypes.memmove(pointer, bytes(owner.data), len(owner.data))
                observations.append(machine.resources())
                return result
        owner = NativeCoreEmitter([VMImage(p) for p in programs[1:]], VMImage(programs[0]), abi, vars(backend))
        receiver = types.SimpleNamespace()
        owner.invoke('_Emitter.__init__', (receiver, (minimal_document(), {'run'}, None, (), None)))
        self.assertEqual(receiver.serial, 0)
        self.assertEqual(owner.invoke('_Emitter.label', (receiver, 'block')), 'block_1')
        self.assertTrue(observations)
        self.assertTrue(all(o['live_owners'] == o['live_local_loans'] == 0 for o in observations))


class CoreEmitterNativeTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        development, cold = os.environ.get(DEVELOPMENT), os.environ.get(COLD)
        if development and cold:
            raise AssertionError('Emitter development cannot override requested cold')
        evidence = os.environ.get(EVIDENCE)
        if evidence:
            cls.folder = Path(evidence).resolve()
            cls.folder.mkdir(parents=True, exist_ok=False)
        else:
            temporary = tempfile.TemporaryDirectory(prefix='hia-core-emitter-')
            cls.addClassCleanup(temporary.cleanup)
            cls.folder = Path(temporary.name)
        if cold:
            from tools.build_hia_core_emitter import build
            report = json.loads(Path(cold).read_bytes())
            nested = json.loads(Path(report['nested_report']).read_bytes())
            cls.manifest = build(cls.folder / 'qualified', Path(nested['generations'][-1]['produced_image']), Path(cold))
            cls.scope = 'MATCHING_SOURCE_COLD_BUILD'
        elif development:
            cls.manifest = Path(development).resolve(strict=True)
            cls.scope = 'EXPLICIT_DEVELOPMENT_ONLY'
        else:
            raise unittest.SkipTest('requires current cold or explicit Emitter development bundle')
        cls.owner = installed_core_emitter(str(cls.manifest), vars(backend))

    def test_ordinary_emission_matches_all_metadata_with_retained_Emitter_forbidden(self):
        from hepta.hia_program import verify_program
        from tests.test_hia_program_native import minimal_document
        from tests.test_hia_program_native_review import _empty_memory_program
        from tools.qualify_hia_program import qualification_program
        documents = (minimal_document(), _empty_memory_program(), qualification_program())
        for document in documents:
            program = verify_program(document)
            with patch.dict(os.environ, {SELECTOR: ''}):
                wanted = backend.emit_program_machine(program)
            with selected_guard(self.manifest):
                actual = backend.emit_program_machine(program)
            self.assertEqual(comparable(actual), comparable(wanted))
            self.assertNotEqual(actual.implementation_sha256, wanted.implementation_sha256)

    def test_original_import_hook_globals_fromlist_level_and_refusal_are_preserved(self):
        import builtins
        from tests.test_hia_program_native import minimal_document
        real_import = builtins.__import__
        def observe(native, refusal):
            events = []
            def imported(name, globals=None, locals=None, fromlist=(), level=0):
                if name == 'hia_machine_plan':
                    events.append((name, globals is vars(backend), locals, fromlist, level))
                    if refusal:
                        raise ImportError('deliberate original import hook refusal')
                return real_import(name, globals, locals, fromlist, level)
            with patch.object(builtins, '__import__', imported):
                if native:
                    receiver = types.SimpleNamespace()
                    result = recorded(self.owner.invoke, '_Emitter.__init__',
                        (receiver, (minimal_document(), {'run'}, None, (), None)))
                else:
                    receiver = types.SimpleNamespace()
                    result = recorded(backend._Emitter.__init__, receiver,
                        minimal_document(), {'run'}, None, (), None)
            self.assertTrue(events)
            return result, events
        for refusal in (False, True):
            self.assertEqual(observe(True, refusal), observe(False, refusal))

    def test_import_from_attribute_fallback_and_ImportError_match_original_opcodes(self):
        import builtins
        real_import = builtins.__import__
        def observe(native, missing):
            events = []
            class ForeignModule:
                __name__ = 'foreign_import_witness'
                __file__ = '/witness/foreign_import_witness.py'
                def __getattribute__(self, name):
                    events.append(name)
                    if name == 'code_options' and not missing:
                        return {'marker': 'native import result'}
                    return object.__getattribute__(self, name)
            foreign = ForeignModule()
            def imported(name, globals=None, locals=None, fromlist=(), level=0):
                if name == 'hia_machine_plan':
                    return foreign
                return real_import(name, globals, locals, fromlist, level)
            with patch.object(builtins, '__import__', imported):
                if native:
                    result = recorded(self.owner.global_value('_hia_emitter_import_member'),
                                      'hia_machine_plan', 'code_options')
                else:
                    from types import FunctionType
                    def original_site():
                        from .hia_machine_plan import code_options
                        return code_options
                    result = recorded(FunctionType(original_site.__code__, vars(backend)))
            return result, events
        for missing in (False, True):
            self.assertEqual(observe(True, missing), observe(False, missing))

    def test_layout_lookups_errors_and_foreign_iadd_keep_exact_order(self):
        for order in (None, ['b', 'a'], ['missing']):
            fn = {'name': 'run', 'blocks': [{'id': 'a'}, {'id': 'b'}]}
            receiver = types.SimpleNamespace(block_order={} if order is None else {'run': order})
            self.assertEqual(recorded(self.owner.invoke, '_Emitter.ordered_blocks', (receiver, fn)),
                             recorded(backend._Emitter.ordered_blocks, receiver, fn))
        def observe(native):
            events = []
            class Serial:
                def __iadd__(self, value):
                    events.append(('iadd', value))
                    return 9
            class Suffix:
                def __add__(self, other):
                    events.append(('add', other))
                    return 'prefix'
            receiver = types.SimpleNamespace(serial=Serial())
            value = self.owner.invoke('_Emitter.label', (receiver, Suffix())) if native else backend._Emitter.label(receiver, Suffix())
            return value, receiver.serial, events
        self.assertEqual(observe(True), observe(False))
        receiver = types.SimpleNamespace(indices={'run': 17})
        self.assertEqual(self.owner.invoke('_Emitter.function_symbol', (receiver, 'run')), '__hia_native_fn_17')

    def test_protocol_reserved_bytes_refuse_without_overwriting_canaries(self):
        mode = self.owner.modes['_Emitter.label']['number']
        session = LoweringSession(self.owner, mode, (types.SimpleNamespace(serial=0), 'b'))
        packet = bytearray(session.initial)
        packet[72] = 1
        source = ctypes.create_string_buffer(bytes(packet))
        out = ctypes.create_string_buffer(b'\xa5' * (self.owner.output_bytes + 32))
        work = ctypes.create_string_buffer(b'\0' * (self.owner.workspace_bytes + 32))
        result = self.owner.images[0]._entry(source, len(packet), ctypes.byref(out, 16),
            self.owner.output_bytes, ctypes.byref(work, 16), self.owner.workspace_bytes)
        self.assertEqual(result, ABI)
        self.assertEqual(bytes(source)[:len(packet)], bytes(packet))
        self.assertEqual(bytes(out)[:16], b'\xa5' * 16)
        self.assertEqual(bytes(out)[-17:-1], b'\xa5' * 16)
        with self.assertRaises(RuntimeError):
            session.observe()

    def test_selected_scope_is_captured_and_warm_source_drift_refuses(self):
        from hepta.hia_core_emitter_selection import selected_core_emitter
        import hepta.hia_core_emitter_selection as selection
        with patch.dict(os.environ, {SELECTOR: str(self.manifest)}):
            with native_core_emitter_scope(vars(backend)):
                with patch.dict(os.environ, {SELECTOR: '/missing/changed-after-capture'}):
                    self.assertIs(selected_core_emitter(vars(backend)), self.owner)
            with patch.dict(os.environ, {SELECTOR: '/missing/changed-after-capture'}):
                with self.assertRaises(FileNotFoundError):
                    selected_core_emitter(vars(backend))
        with tempfile.TemporaryDirectory() as temporary:
            drift = Path(temporary) / 'drift.hepta'
            drift.write_bytes(b'not the source admitted by the warm bundle')
            source = source_names(checked_abi((ROOT / ABI_SOURCE).read_bytes()))[-1]
            original = selection._source_resource_path
            with patch.object(selection, '_source_resource_path', lambda name: drift if name == source else original(name)):
                with self.assertRaises(ValueError):
                    installed_core_emitter(str(self.manifest), vars(backend))


    def test_actual_installed_wheel_uses_complete_bundle_without_authoring(self):
        from hepta.hia_agent_contract import DISCOVERY_FILES, NATIVE_SOURCE_FILES, PUBLICATION_BUILD_FILES, SOURCE_BUILD_FILES, COMPILER_BUILD_FILES, BACKEND_BUILD_FILES, EMITTER_BUILD_FILES, BYTE_WRAPPER_BUILD_FILES, MACHINE_OBJECT_BUILD_FILES, EXECUTION_OBSERVATION_BUILD_FILES
        from tests.test_hia_program_native import minimal_document
        case = self.folder / 'installed-control'
        case.mkdir()
        source = case / 'source'
        source.mkdir()
        shutil.copytree(ROOT / 'hepta', source / 'hepta', ignore=shutil.ignore_patterns('__pycache__'))
        resources = (tuple('docs/' + n for n in DISCOVERY_FILES) + NATIVE_SOURCE_FILES + PUBLICATION_BUILD_FILES + SOURCE_BUILD_FILES + COMPILER_BUILD_FILES) + BACKEND_BUILD_FILES + EMITTER_BUILD_FILES + BYTE_WRAPPER_BUILD_FILES + MACHINE_OBJECT_BUILD_FILES + EXECUTION_OBSERVATION_BUILD_FILES
        for name in (*resources, 'setup.py', 'pyproject.toml', 'MANIFEST.in'):
            target = source / name
            target.parent.mkdir(parents=True, exist_ok=True)
            shutil.copyfile(ROOT / name, target)
        expected = {'python': {p.relative_to(ROOT).as_posix(): sha256(p.read_bytes()).hexdigest()
                              for p in sorted((ROOT / 'hepta').rglob('*.py')) if '_data' not in p.parts},
                    'resources': {name: sha256((ROOT / name).read_bytes()).hexdigest() for name in resources},
                    'document': minimal_document()}
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
        self.assertEqual(observed['status'], 'INSTALLED_CORE_EMITTER_PASS')
        self.assertEqual(observed['units'], 9)
        (case / 'report.json').write_text(json.dumps(observed, indent=2, sort_keys=True) + '\n')


INSTALLED_CHILD = "\nimport importlib.abc,inspect,json,os,sys\nfrom pathlib import Path\nfrom hashlib import sha256\nsys.path.insert(0,sys.argv[1])\nclass NoTools(importlib.abc.MetaPathFinder):\n    def find_spec(self,fullname,path=None,target=None):\n        if fullname=='tools' or fullname.startswith('tools.'):\n            raise AssertionError('installed lowering imported authoring tools')\nsys.meta_path.insert(0,NoTools())\nroot=Path(sys.argv[1])\nexpected=json.loads(Path(sys.argv[3]).read_bytes())\nfor name,identity in expected['python'].items():\n    assert sha256((root/name).read_bytes()).hexdigest()==identity\nactual={p.relative_to(root).as_posix() for p in (root/'hepta').rglob('*.py') if '_data' not in p.parts}\nassert actual==set(expected['python'])\nfrom hepta.hia_json_preflight_native import _source_resource_path\nfor name,identity in expected['resources'].items():\n    path=_source_resource_path(name)\n    assert root in path.parents and sha256(path.read_bytes()).hexdigest()==identity\nfrom hepta import hia_program_native as backend\nfrom hepta.hia_program import verify_program\nfrom hepta.hia_core_emitter_selection import SELECTOR,ABI_SOURCE,installed_core_emitter\nfrom hepta.hia_core_lowering_native import LoweringSession\nentries=[]\nreal=LoweringSession.step\ndef step(session,packet):\n    value=real(session,packet);entries.append(value);return value\nLoweringSession.step=step\ndef forbidden(*args,**kwargs):\n    raise AssertionError('retained Emitter control entered installed child')\nfor name,method in tuple(backend._Emitter.__dict__.items()):\n    if inspect.isfunction(method) and name!='__new__':\n        setattr(backend._Emitter,name,forbidden)\nos.environ[SELECTOR]=sys.argv[2]\nowner=installed_core_emitter(sys.argv[2],vars(backend))\nmachine=backend.emit_program_machine(verify_program(expected['document']))\nassert machine.object_bytes.startswith(b'\\x7fELF')\nassert entries and 0 in entries and 1 in entries and 2 in entries\nabi=_source_resource_path(ABI_SOURCE)\nraw=abi.read_bytes()\nabi.write_bytes(raw+b'\\n')\ntry:installed_core_emitter(sys.argv[2],vars(backend))\nexcept ValueError:pass\nelse:raise AssertionError('warm ABI source change was ignored')\nabi.write_bytes(raw);abi.unlink()\ntry:installed_core_emitter(sys.argv[2],vars(backend))\nexcept FileNotFoundError:pass\nelse:raise AssertionError('missing installed ABI fell back to checkout')\nabi.write_bytes(raw)\nassert sys.flags.isolated and sys.flags.no_site and os.environ['PATH']==''\nprint(json.dumps({'status':'INSTALLED_CORE_EMITTER_PASS','units':len(owner._admitted_bundle.images),\n 'source_sha256':dict(owner._admitted_bundle.source_hashes),'abi_sha256':owner._admitted_bundle.abi_sha256,\n 'image_sha256':[im.image_sha256 for im in owner._admitted_bundle.images],\n 'object_sha256':machine.sha256,'python_files':len(expected['python']),\n 'resource_files':len(expected['resources']),'actual_native_steps':len(entries),\n 'retained_emitter_forbidden':True,'authoring_forbidden':True,'isolated_without_site':True,'empty_PATH':True}))\n"

if __name__ == '__main__':
    unittest.main()
