"""Original ELF policy, independent HIA VM and source-bound native controls."""
from __future__ import annotations

import ast
import ctypes
from hashlib import sha256
import inspect
import shutil
import subprocess
import sys
from contextlib import ExitStack
import json
import os
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

from hepta import hia_machine_elf as elf, hia_program_native as backend
from hepta.hia_machine_object_native import NativeMachineObject
from hepta.hia_machine_object_selection import (
    ABI_SOURCE, SELECTOR, checked_abi, source_names, installed_machine_object,
    native_machine_object_scope, active_machine_object)
from tests.test_hia_core_lowering_native import recorded, comparable
from hepta.hia_core_lowering_native import ABI, LoweringSession

ROOT = Path(__file__).resolve().parents[1]


class MachineObjectSourceTests(unittest.TestCase):
    def test_all_original_function_ASTs_and_explicit_caps_preserved(self):
        fixture = (ROOT / 'tests/fixtures/hia_machine_elf_0e96229.py.txt').read_bytes()
        self.assertEqual(sha256(fixture).hexdigest(), 'c77cc453d33058ccbeea9e056191001982892a3e59386958090122ccf487c101')
        original = [n for n in ast.parse(fixture).body if isinstance(n, ast.FunctionDef)]
        policy = [n for n in ast.parse((ROOT / 'tools/hia_machine_object_policy.py').read_bytes()).body
                  if isinstance(n, ast.FunctionDef)]
        self.assertEqual([ast.dump(n) for n in policy], [ast.dump(n) for n in original])
        current = ast.parse(inspect.getsource(elf))
        for node in original:
            name = '_reference' + node.name if node.name.startswith('_') else '_reference_' + node.name
            retained = next(n for n in current.body if isinstance(n, ast.FunctionDef) and n.name == name)
            retained.name = node.name
            self.assertEqual(ast.dump(node), ast.dump(retained))
        from tools.hia_machine_object_ir import compile_policy
        _, functions, modes, _ = compile_policy((ROOT / 'tools/hia_machine_object_policy.py').read_text())
        self.assertEqual(len(modes), 10)
        self.assertTrue(all(len(n.parameters) <= 4 for n in functions))
        with self.assertRaises(ValueError):
            compile_policy('def unknown(): pass\n')

    def test_all_sources_roundtrip_and_original_packet_limits(self):
        from hepta.hia_agent_assembly import assemble_program, render_assembly
        abi = checked_abi((ROOT / ABI_SOURCE).read_bytes())
        self.assertEqual(len(source_names(abi)), 13)
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
            self.assertTrue(all(len(f['params']) <= 16 and len(f['blocks']) <= 256 for f in functions))

    def test_independent_VM_emits_exact_ELF_and_original_rejections(self):
        from hepta.hia_agent_assembly import assemble_program
        from hepta.hia_program_runtime import _Machine, _Owner, _View
        abi = checked_abi((ROOT / ABI_SOURCE).read_bytes())
        programs = [assemble_program((ROOT / n).read_bytes()) for n in source_names(abi)]
        observations = []
        class VMImage:
            def __init__(self, program): self.program = program
            def _entry(self, source, size, output, output_size, workspace, workspace_size):
                packet = ctypes.string_at(source, size)
                owners = [_Owner(-1, bytearray(packet)),
                    _Owner(-2, bytearray(ctypes.string_at(output, output_size))),
                    _Owner(-3, bytearray(ctypes.string_at(workspace, workspace_size)))]
                machine = _Machine(self.program, 4_000_000, 16 << 20, None, 128)
                # The fresh machine already decoded these immutable bytes.
                # Use that exact entry; do not decode the same graph twice.
                result = machine.invoke(next(iter(machine.functions.values())),
                    [_View(owners[0], False), _View(owners[1], True), _View(owners[2], True)])[0]
                if bytes(owners[0].data) != packet: raise AssertionError('read-only packet changed')
                for pointer, value in ((output, owners[1]), (workspace, owners[2])):
                    ctypes.memmove(pointer, bytes(value.data), len(value.data))
                observations.append(machine.resources())
                return result
        native = NativeMachineObject([VMImage(p) for p in programs[1:]], VMImage(programs[0]), abi, vars(elf))
        code = b'\xe8\0\0\0\0\xc3'
        symbols = [dict(name='entry', offset=0, size=6, **{'global':True})]
        relocations = [dict(offset=1, symbol='external', type=4, addend=-4)]
        for args in ((code,symbols,relocations,16), (code,symbols,relocations,64),
                     (b'',symbols,[],16), (code,[],[],16), (code,symbols,relocations,17),
                     (code,symbols,[dict(offset=1,symbol='external',type=4,addend=0)],16)):
            expected = recorded(lambda: elf._reference_write_elf_object(*args[:3], text_alignment=args[3]))
            actual = recorded(native.invoke, 'write_elf_object', args)
            self.assertEqual(actual, expected)
        self.assertTrue(observations)
        self.assertTrue(all(o['live_owners'] == o['live_local_loans'] == 0 for o in observations))

    def test_literal_identity_indexes_are_readonly_and_each_session_is_private(self):
        from types import MappingProxyType, SimpleNamespace
        original = (None, False, True, 'original-literal')
        indexes = MappingProxyType({id(v):i for i,v in enumerate(original,1)})
        owner = SimpleNamespace(literals=original, _literal_index_values=original,
            _literal_indexes=indexes, workspace_bytes=1024, output_bytes=128)
        first = LoweringSession(owner,1,('first-argument',))
        second = LoweringSession(owner,1,('second-argument',))
        self.assertIsNot(first.handles,second.handles)
        self.assertIsNot(first.values,second.values)
        first.handles.clear()
        self.assertEqual(second.handles[id(True)],3)
        self.assertEqual(dict(indexes),{id(v):i for i,v in enumerate(original,1)})
        with self.assertRaises(TypeError): indexes[id(True)]=99
        replacement=(None,False,True,'new-literal')
        owner.literals=replacement
        third=LoweringSession(owner,1,())
        self.assertEqual(third.handles,{id(v):i for i,v in enumerate(replacement,1)})
        self.assertIs(third.value(third.handles[id(replacement[-1])]),replacement[-1])

    def test_unqualified_build_refuses_before_output_and_default_is_retained(self):
        from tools.build_hia_machine_object import build
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            compiler, cold = root/'compiler', root/'cold'
            compiler.write_bytes(b'not a qualified compiler')
            cold.write_text('{"status":"DEVELOPMENT_ONLY"}')
            with self.assertRaisesRegex(ValueError, 'completed matching native cold'):
                build(root/'must-not-create'/'bundle', compiler, cold)
            self.assertFalse((root/'must-not-create').exists())
        with patch.dict(os.environ, {SELECTOR:''}):
            self.assertEqual(recorded(elf.write_elf_object,b'',[],[]),
                             recorded(elf._reference_write_elf_object,b'',[],[]))
        with patch.dict(os.environ, {SELECTOR:'/missing/explicit-ELF-bundle'}):
            with self.assertRaises(FileNotFoundError): elf.write_elf_object(b'\xc3',[],[])


DEVELOPMENT = "HEPTA_HIA_MACHINE_OBJECT_DEVELOPMENT_MANIFEST"
COLD = "HEPTA_HIA_MACHINE_OBJECT_COLD_REPORT"
EVIDENCE = "HEPTA_HIA_MACHINE_OBJECT_FIXTURE_EVIDENCE"


def selected_guard(manifest):
    stack = ExitStack()
    stack.enter_context(patch.dict(os.environ, {SELECTOR:str(manifest)}))
    for name in ("_reference_name", "_reference_exact_int", "_reference_write_elf_object"):
        stack.enter_context(patch.object(elf,name,side_effect=AssertionError("retained ELF owner entered: "+name)))
    return stack


class MachineObjectNativeTests(unittest.TestCase):

    def test_ordinary_backend_scalar_and_byte_outputs_forbid_retained_writer(self):
        from hepta.hia_program import verify_program
        from tests.test_hia_native_byte_abi import byte_program
        from tests.test_hia_program_native import minimal_document
        for document, exports in ((minimal_document(),()), (byte_program(),(('copy_bytes',4096),))):
            program = verify_program(document)
            with patch.dict(os.environ, {SELECTOR:''}):
                expected = backend.emit_program_machine(program, foreign_buffer_exports=exports)
            with selected_guard(self.manifest):
                actual = backend.emit_program_machine(program, foreign_buffer_exports=exports)
            self.assertEqual(comparable(actual), comparable(expected))
            self.assertNotEqual(actual.implementation_sha256, expected.implementation_sha256)

    def test_real_native_original_55_reconstructed_inputs_and_all_modes(self):
        raw = (ROOT/'tests/fixtures/hia_machine_object_cases_04ba.json').read_bytes()
        self.assertEqual(sha256(raw).hexdigest(), 'c6cc16625a76a3912c539107a9cf1ceac6689e6dc73889c583500d8f1633465d')
        document = json.loads(raw)
        self.assertEqual(document['revision'], 'RECONSTRUCTED_NEW_55_NOT_RECOVERED_OLD_CONTROL')
        self.assertEqual(len(document['cases']),55)
        def decode(value):
            if type(value) is list: return [decode(v) for v in value]
            if type(value) is dict:
                kind = value.get('@type')
                if kind=='bytes': return bytes.fromhex(value['hex'])
                if kind=='bytearray': return bytearray.fromhex(value['hex'])
                if kind=='tuple': return tuple(decode(v) for v in value['items'])
                if kind=='float': return float(value['value'])
                if kind=='repeat': return [decode(value['value']) for _ in range(value['count'])]
                if kind is not None: raise ValueError('unknown fixture encoding')
                return {k:decode(v) for k,v in value.items()}
            return value
        entries=[]
        original = self.owner.invoke
        def invoke(mode, arguments):
            entries.append(mode)
            return original(mode, arguments)
        with patch.object(self.owner,'invoke',invoke):
            for mode, args in (('_name',('entry',)),('_name',('bad-name',)),
                               ('_exact_int',(0,0,1)),('_exact_int',(True,0,1)),
                               ('_exact_int',(1,0,1))):
                reference=elf._reference_name if mode=='_name' else elf._reference_exact_int
                self.assertEqual(recorded(self.owner.invoke,mode,args),recorded(reference,*args))
            for row in document['cases']:
                values=decode(row['arguments'])
                args=(values['code'],values['symbols'],values['relocations'],values['alignment'])
                with self.subTest(case=row['id']):
                    expected=recorded(lambda:elf._reference_write_elf_object(*args[:3],text_alignment=args[3]))
                    actual=recorded(self.owner.invoke,'write_elf_object',args)
                    self.assertEqual(actual,expected)
        self.assertEqual(set(entries),set(self.owner.modes))

    def test_foreign_key_callbacks_keep_original_sort_schedule_and_exception_identity(self):
        def observe(native,fail_at):
            events=[]
            class Stop(BaseException): pass
            stop=Stop('original foreign callback')
            class Key:
                def __init__(self,name):self.name=name
                def __hash__(self):return hash(self.name)
                def __eq__(self,other):
                    events.append((self.name,other if type(other) is str else type(other).__name__))
                    if len(events)==fail_at:raise stop
                    return self.name==other
            symbols=[{Key(k):v for k,v in (('name',name),('offset',i*2),('size',1),('global',bool(i%2)))}
                     for i,name in enumerate(('zeta','alpha','gamma','beta'))]
            events.clear()
            try:
                raise OSError('ambient original context')
            except OSError as ambient:
                try:
                    result=(self.owner.invoke('write_elf_object',(b'\xc3'*8,symbols,[],16)) if native else
                            elf._reference_write_elf_object(b'\xc3'*8,symbols,[]))
                    outcome=('bytes',result)
                except BaseException as caught:
                    self.assertIs(caught,stop)
                    self.assertIs(caught.__context__,ambient)
                    outcome=('same foreign exception',caught.args)
            return outcome,events
        for fail_at in (1,9,37,100000):
            with self.subTest(fail_at=fail_at):self.assertEqual(observe(True,fail_at),observe(False,fail_at))

    @classmethod
    def setUpClass(cls):
            development, cold = os.environ.get(DEVELOPMENT), os.environ.get(COLD)
            if development and cold:
                raise AssertionError('development cannot override machine-object cold')
            evidence = os.environ.get(EVIDENCE)
            if evidence:
                cls.folder = Path(evidence).resolve()
                cls.folder.mkdir(parents=True, exist_ok=False)
            else:
                temporary = tempfile.TemporaryDirectory(prefix='hia-machine-object-')
                cls.addClassCleanup(temporary.cleanup)
                cls.folder = Path(temporary.name)
            if cold:
                from tools.build_hia_machine_object import build
                report = json.loads(Path(cold).read_bytes())
                nested = json.loads(Path(report['nested_report']).read_bytes())
                cls.manifest = build(cls.folder / 'qualified', Path(nested['generations'][-1]['produced_image']), Path(cold))
                cls.scope = 'MATCHING_SOURCE_COLD_BUILD'
            elif development:
                cls.manifest = Path(development).resolve(strict=True)
                cls.scope = 'EXPLICIT_DEVELOPMENT_ONLY'
            else:
                raise unittest.SkipTest('requires matching machine-object cold or explicit development bundle')
            cls.owner = installed_machine_object(str(cls.manifest), vars(elf))

    def test_captured_selection_and_warm_source_drift_are_not_ignored(self):
            import hepta.hia_machine_object_selection as selection
            with patch.dict(os.environ, {SELECTOR: str(self.manifest)}):
                with native_machine_object_scope(vars(elf)):
                    with patch.dict(os.environ, {SELECTOR: '/changed/after/capture'}):
                        self.assertIs(active_machine_object(), self.owner)
            with tempfile.TemporaryDirectory() as temporary:
                drift = Path(temporary) / 'drift'
                drift.write_bytes(b'not the admitted native source')
                name = source_names(checked_abi((ROOT / ABI_SOURCE).read_bytes()))[-1]
                original = selection._source_resource_path
                with patch.object(selection, '_source_resource_path', lambda path: drift if path == name else original(path)):
                    with self.assertRaises(ValueError):
                        installed_machine_object(str(self.manifest), vars(elf))

    def test_packet_reserved_bytes_refuse_before_buffer_effects(self):
            session = LoweringSession(self.owner, self.owner.modes['_name']['number'], ('entry',))
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
            from hepta.hia_agent_contract import DISCOVERY_FILES, NATIVE_SOURCE_FILES, PUBLICATION_BUILD_FILES, SOURCE_BUILD_FILES, COMPILER_BUILD_FILES, BACKEND_BUILD_FILES, EMITTER_BUILD_FILES, BYTE_WRAPPER_BUILD_FILES, MACHINE_OBJECT_BUILD_FILES, EXECUTION_OBSERVATION_BUILD_FILES, CONTINUATION_BUILD_FILES, ENTRY_BUILD_FILES
            from tests.test_hia_native_byte_abi import byte_program
            case = self.folder / 'installed-control'
            case.mkdir()
            source = case / 'source'
            source.mkdir()
            shutil.copytree(ROOT / 'hepta', source / 'hepta', ignore=shutil.ignore_patterns('__pycache__'))
            resources = (tuple('docs/' + n for n in DISCOVERY_FILES) + NATIVE_SOURCE_FILES + PUBLICATION_BUILD_FILES + SOURCE_BUILD_FILES + COMPILER_BUILD_FILES) + BACKEND_BUILD_FILES + EMITTER_BUILD_FILES + BYTE_WRAPPER_BUILD_FILES + MACHINE_OBJECT_BUILD_FILES + EXECUTION_OBSERVATION_BUILD_FILES + CONTINUATION_BUILD_FILES + ENTRY_BUILD_FILES
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
            self.assertEqual(observed['status'], 'INSTALLED_MACHINE_OBJECT_PASS')
            self.assertEqual(observed['units'], 13)
            (case / 'report.json').write_text(json.dumps(observed, indent=2, sort_keys=True) + '\n')


INSTALLED_CHILD = "\nimport importlib.abc,inspect,json,os,sys\nfrom pathlib import Path\nfrom hashlib import sha256\nsys.path.insert(0,sys.argv[1])\nclass NoTools(importlib.abc.MetaPathFinder):\n    def find_spec(self,fullname,path=None,target=None):\n        if fullname=='tools' or fullname.startswith('tools.'):\n            raise AssertionError('installed lowering imported authoring tools')\nsys.meta_path.insert(0,NoTools())\nroot=Path(sys.argv[1])\nexpected=json.loads(Path(sys.argv[3]).read_bytes())\nfor name,identity in expected['python'].items():\n    assert sha256((root/name).read_bytes()).hexdigest()==identity\nactual={p.relative_to(root).as_posix() for p in (root/'hepta').rglob('*.py') if '_data' not in p.parts}\nassert actual==set(expected['python'])\nfrom hepta.hia_json_preflight_native import _source_resource_path\nfor name,identity in expected['resources'].items():\n    path=_source_resource_path(name)\n    assert root in path.parents and sha256(path.read_bytes()).hexdigest()==identity\nfrom hepta import hia_program_native as backend, hia_machine_elf as elf\nfrom hepta.hia_program import verify_program\nfrom hepta.hia_machine_object_selection import SELECTOR,ABI_SOURCE,installed_machine_object\nfrom hepta.hia_core_lowering_native import LoweringSession\nentries=[]\nreal=LoweringSession.step\ndef step(session,packet):\n    value=real(session,packet);entries.append(value);return value\nLoweringSession.step=step\ndef forbidden(*args,**kwargs):\n    raise AssertionError('retained machine-object control entered installed child')\nfor name in ('_reference_name','_reference_exact_int','_reference_write_elf_object'):\n    setattr(elf,name,forbidden)\nos.environ[SELECTOR]=sys.argv[2]\nowner=installed_machine_object(sys.argv[2],vars(elf))\nmachine=backend.emit_program_machine(verify_program(expected['document']),foreign_buffer_exports=(('copy_bytes',4096),))\nassert machine.object_bytes.startswith(b'\\x7fELF')\nassert entries and 0 in entries and 1 in entries and 2 in entries\nabi=_source_resource_path(ABI_SOURCE)\nraw=abi.read_bytes()\nabi.write_bytes(raw+b'\\n')\ntry:installed_machine_object(sys.argv[2],vars(elf))\nexcept ValueError:pass\nelse:raise AssertionError('warm ABI source change was ignored')\nabi.write_bytes(raw);abi.unlink()\ntry:installed_machine_object(sys.argv[2],vars(elf))\nexcept FileNotFoundError:pass\nelse:raise AssertionError('missing installed ABI fell back to checkout')\nabi.write_bytes(raw)\nassert sys.flags.isolated and sys.flags.no_site and os.environ['PATH']==''\nprint(json.dumps({'status':'INSTALLED_MACHINE_OBJECT_PASS','units':len(owner._admitted_bundle.images),\n 'source_sha256':dict(owner._admitted_bundle.source_hashes),'abi_sha256':owner._admitted_bundle.abi_sha256,\n 'image_sha256':[im.image_sha256 for im in owner._admitted_bundle.images],\n 'object_sha256':machine.sha256,'python_files':len(expected['python']),\n 'resource_files':len(expected['resources']),'actual_native_steps':len(entries),\n 'retained_machine_object_forbidden':True,'authoring_forbidden':True,'isolated_without_site':True,'empty_PATH':True}))\n"
