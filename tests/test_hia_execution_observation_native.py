"""Exact retained observation policy, independent Core VM and native witnesses."""
from __future__ import annotations

import ast
import ctypes
from hashlib import sha256
import inspect
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

from hepta import hia_opcodes as original
from hepta.hia_execution_observation_native import NativeExecutionObservation
from hepta.hia_execution_observation_selection import (
    ABI_SOURCE, SELECTOR, checked_abi, source_names, installed_execution_observation)

ROOT = Path(__file__).resolve().parents[1]


def outcome(operation):
    try:
        return ('returned', operation())
    except BaseException as error:
        return ('raised', type(error), error.args)


def cases():
    empty = dict.fromkeys(original.EXECUTION_RESOURCE_FIELDS, 0)
    common = dict(steps=1, max_steps=10, max_heap_bytes=64)
    yield 'returned', empty, common
    for field in sorted(empty):
        for value in (-1, True, 1 << 64, 1):
            yield 'returned', {**empty, field:value}, common
    for status, code in (('trapped','bounds'), ('budget_exceeded','heap'),
                         ('budget_exceeded','calls'), ('trapped','steps'),
                         ('returned','bounds'), ('bad','bounds')):
        yield status, empty, {**common, 'error_code':code}
    for options in ({'steps':11,'error_code':'steps'},
                    {'steps':10,'error_code':'steps'},
                    {'steps':1,'error_code':'host_memory'},
                    {'steps':1,'error_code':'host_memory','allow_host_memory':True}):
        yield 'budget_exceeded',empty,{**common,**options}
    for options in ({'max_steps':True}, {'steps':False}, {'max_heap_bytes':-1},
                    {'with_chains':1}, {'allow_host_memory':0},
                    {'live_external_roots':-1}, {'live_external_roots':True},
                    {'live_external_roots':1<<64}):
        yield 'returned',empty,{**common,**options}
    chain={**empty,**dict.fromkeys(original.EXECUTION_CHAIN_FIELDS,0)}
    yield 'returned',chain,{**common,'with_chains':True}
    for field in sorted(original.EXECUTION_CHAIN_FIELDS):
        yield 'returned',{**chain,field:1},{**common,'with_chains':True}
    live={**empty,'allocation_attempts':1,'allocations':1,'owners_created':1,
          'live_owners':1,'live_bytes':4,'peak_bytes':4,'loans_started':1,'live_local_loans':1}
    yield 'trapped',live,{**common,'error_code':'bounds'}
    external={**empty,'loans_started':1,'live_local_loans':1}
    yield 'trapped',external,{**common,'error_code':'bounds'}
    yield 'trapped',external,{**common,'error_code':'bounds','live_external_roots':1}
    for ledger in (None,[],{**empty,'extra':0},{k:v for k,v in empty.items() if k!='frees'}):
        yield 'returned',ledger,common


def invoke(owner,status,ledger,options):
    return owner.invoke('validate_execution_observation',(status,ledger,(
        options['steps'],options['max_steps'],options['max_heap_bytes'],
        options.get('error_code'),options.get('with_chains',False),
        options.get('allow_host_memory',False),options.get('live_external_roots',0))))


class ExecutionObservationSourceTests(unittest.TestCase):
    def test_installed_publisher_binds_every_observation_resource(self):
        from hepta import hia_agent_contract as contract
        from hepta.artifact_publication import PublicationRejected
        from hepta.artifact_publication_native import _installed_source_custody
        import hepta.hia_json_preflight_native as resources
        # This is a test-owned installed-source contract, not a forged cold
        # qualification or executable manifest. No image is selected or run.
        assets=(tuple('docs/'+n for n in contract.DISCOVERY_FILES)
            +contract.NATIVE_SOURCE_FILES+contract.SOURCE_BUILD_FILES
            +contract.COMPILER_BUILD_FILES+contract.PUBLICATION_BUILD_FILES
            +contract.BACKEND_BUILD_FILES+contract.EMITTER_BUILD_FILES
            +contract.BYTE_WRAPPER_BUILD_FILES+contract.MACHINE_OBJECT_BUILD_FILES
            +contract.EXECUTION_OBSERVATION_BUILD_FILES+contract.CONTINUATION_BUILD_FILES + contract.ENTRY_BUILD_FILES)
        with tempfile.TemporaryDirectory() as directory:
            root=Path(directory)/'installed';root.mkdir()
            shutil.copytree(ROOT/'hepta',root/'hepta',ignore=shutil.ignore_patterns('__pycache__'))
            for name in assets:
                target=root/name;target.parent.mkdir(parents=True,exist_ok=True)
                shutil.copyfile(ROOT/name,target)
            names=[p.relative_to(root).as_posix() for p in (root/'hepta').rglob('*.py')]
            identities={name:sha256((root/name).read_bytes()).hexdigest() for name in [*names,*assets]}
            installed_contract={'schema':'hepta.hia.selfhost-core-support.v1',
                'profile':'test-owned-installed-source-custody-not-cold',
                'source_identity':{'files':identities}}
            (root/'docs/HIA_SELFHOST_CORE_SUPPORT.json').write_text(json.dumps(installed_contract))
            with patch.object(resources,'_source_resource_path',lambda name:root/name):
                _,observed=_installed_source_custody(root)
                for name in (*contract.EXECUTION_OBSERVATION_BUILD_FILES,*contract.CONTINUATION_BUILD_FILES):
                    self.assertEqual(observed[name],identities[name])
                    target=root/name;raw=target.read_bytes();target.write_bytes(raw+b'changed')
                    try:
                        with self.assertRaises(PublicationRejected):_installed_source_custody(root)
                    finally:target.write_bytes(raw)
                    target.unlink()
                    try:
                        with self.assertRaises(FileNotFoundError):_installed_source_custody(root)
                    finally:target.write_bytes(raw)

    def test_original_complete_AST_and_generated_caps(self):
        raw=(ROOT/'tests/fixtures/hia_opcodes_99d6567.py.txt').read_bytes()
        self.assertEqual(sha256(raw).hexdigest(),'7c3e1a531b790883da2f74ca0e06e37b18073a594063afb9aeb07be9bd34fd65')
        before=next(n for n in ast.parse(raw).body if isinstance(n,ast.FunctionDef)
                    and n.name=='validate_execution_observation')
        policy=ast.parse((ROOT/'tools/hia_execution_observation_policy.py').read_bytes()).body[0]
        self.assertEqual(ast.dump(before),ast.dump(policy))
        retained=ast.parse(inspect.getsource(original._reference_validate_execution_observation)).body[0]
        retained.name=before.name
        self.assertEqual(ast.dump(before),ast.dump(retained))
        from tools.hia_execution_observation_ir import compile_policy
        _,functions,modes,_=compile_policy((ROOT/'tools/hia_execution_observation_policy.py').read_text())
        self.assertEqual(len(modes),3)
        self.assertTrue(all(len(f.parameters)<=4 for f in functions))
        abi=checked_abi((ROOT/ABI_SOURCE).read_bytes())
        from hepta.hia_agent_assembly import assemble_program,render_assembly
        for name in source_names(abi):
            raw=(ROOT/name).read_bytes()
            self.assertLessEqual(len(raw),1<<20)
            self.assertLessEqual(len(raw.splitlines()),16384)
            self.assertEqual(render_assembly(assemble_program(raw).as_dict()).encode(),raw)

    def test_independent_Core_VM_exact_ledger_outcomes(self):
        from hepta.hia_agent_assembly import assemble_program
        from hepta.hia_program_runtime import _Machine,_Owner,_View
        abi=checked_abi((ROOT/ABI_SOURCE).read_bytes())
        programs=[assemble_program((ROOT/n).read_bytes()) for n in source_names(abi)]
        observations=[]
        class VMImage:
            def __init__(self,p):self.p=p
            def _entry(self,source,size,output,output_size,workspace,workspace_size):
                raw=ctypes.string_at(source,size)
                owners=[_Owner(-1,bytearray(raw)),_Owner(-2,bytearray(ctypes.string_at(output,output_size))),
                        _Owner(-3,bytearray(ctypes.string_at(workspace,workspace_size)))]
                machine=_Machine(self.p,4_000_000,16<<20,None,128)
                value=machine.invoke(next(iter(machine.functions.values())),
                    [_View(owners[0],False),_View(owners[1],True),_View(owners[2],True)])[0]
                if bytes(owners[0].data)!=raw:raise AssertionError('read-only input changed')
                for pointer,owner in ((output,owners[1]),(workspace,owners[2])):
                    ctypes.memmove(pointer,bytes(owner.data),len(owner.data))
                observations.append(machine.resources())
                return value
        owner=NativeExecutionObservation([VMImage(p) for p in programs[1:]],VMImage(programs[0]),abi,vars(original))
        # The independent VM is deliberately bounded to representative causal
        # witnesses; all mutations run against real native images separately.
        examples=list(cases())
        for status,ledger,options in [examples[0],examples[1],examples[4],*examples[-5:]]:
            with self.subTest(status=status,options=options,ledger=ledger):
                expected=outcome(lambda:original._reference_validate_execution_observation(status,ledger,**options))
                self.assertEqual(outcome(lambda:invoke(owner,status,ledger,options)),expected)
        self.assertTrue(observations)
        self.assertTrue(all(r['live_owners']==r['live_local_loans']==0 for r in observations))

    def test_unqualified_build_and_default_no_silent_refusal(self):
        from tools.build_hia_execution_observation import build
        with tempfile.TemporaryDirectory() as directory:
            root=Path(directory);(root/'compiler').write_bytes(b'not qualified');(root/'cold').write_text('{}')
            with self.assertRaises(ValueError):build(root/'must-not-create',root/'compiler',root/'cold')
            self.assertFalse((root/'must-not-create').exists())
        with patch.dict(os.environ,{SELECTOR:''}):
            with self.assertRaises(ValueError):original.validate_execution_observation('returned',{},steps=1,max_steps=10,max_heap_bytes=0)


class ExecutionObservationNativeTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        path=os.environ.get('HEPTA_HIA_EXECUTION_OBSERVATION_DEVELOPMENT_MANIFEST')
        cold=os.environ.get('HEPTA_HIA_EXECUTION_OBSERVATION_COLD_REPORT')
        if path and cold:raise AssertionError('development cannot override matching-source cold')
        evidence=os.environ.get('HEPTA_HIA_EXECUTION_OBSERVATION_FIXTURE_EVIDENCE')
        if evidence:
            cls.folder=Path(evidence).resolve();cls.folder.mkdir(parents=True,exist_ok=False)
        else:
            temporary=tempfile.TemporaryDirectory(prefix='hia-execution-observation-')
            cls.addClassCleanup(temporary.cleanup);cls.folder=Path(temporary.name)
        if cold:
            from tools.build_hia_execution_observation import build
            report=json.loads(Path(cold).read_bytes())
            nested=json.loads(Path(report['nested_report']).read_bytes())
            path=build(cls.folder/'qualified',Path(nested['generations'][-1]['produced_image']),Path(cold))
        if not path:raise unittest.SkipTest('requires own cold or explicit development image')
        cls.manifest=Path(path).resolve(strict=True)
        cls.owner=installed_execution_observation(str(cls.manifest),vars(original))

    def test_all_generated_ledger_mutations_use_actual_native_modes(self):
        count=0
        for status,ledger,options in cases():
            with self.subTest(status=status,ledger=ledger,options=options):
                expected=outcome(lambda:original._reference_validate_execution_observation(status,ledger,**options))
                self.assertEqual(outcome(lambda:invoke(self.owner,status,ledger,options)),expected)
                count+=1
        self.assertGreater(count,70)

    def test_real_runtime_and_external_roots_callers_forbid_retained_policy(self):
        # Existing test functions retain their original assertions and resource
        # budgets. Loading occurs before selection, so no source VM test is
        # recursively made dependent on the native observer being tested.
        suite=unittest.TestSuite(unittest.defaultTestLoader.loadTestsFromName(name)
            for name in ('tests.test_hia_execution_contract','tests.test_hia_agent_external_roots'))
        expected=suite.countTestCases()
        self.assertGreater(expected,5)
        import io
        from hepta.hia_core_lowering_native import LoweringSession
        entries=[];step=LoweringSession.step
        def observed(session,packet):
            status=step(session,packet)
            if session.owner is self.owner:entries.append((struct.unpack_from('<Q',session.initial,24)[0],status))
            return status
        with patch.dict(os.environ,{SELECTOR:str(self.manifest)}),patch.object(
                original,'_reference_validate_execution_observation',side_effect=AssertionError('retained ledger policy called')),patch.object(
                LoweringSession,'step',observed):
            stream=io.StringIO();result=unittest.TextTestRunner(stream=stream,verbosity=2).run(suite)
        self.assertEqual(result.testsRun,expected,stream.getvalue())
        self.assertTrue(result.wasSuccessful(),stream.getvalue())
        for name in ('errors','failures','skipped','expectedFailures','unexpectedSuccesses'):
            self.assertFalse(getattr(result,name),stream.getvalue())
        self.assertTrue(entries)
        self.assertTrue({0,1,2}.issubset({status for _,status in entries}))
        self.assertEqual({mode for mode,_ in entries},{row['number'] for row in self.owner.modes.values()})
        (self.folder/'original-runtime-callers.json').write_text(json.dumps({
            'status':'PASS','actual_tests':expected,'actual_entries':entries,
            'retained_ledger_policy_forbidden':True,'whole_runtime_native':False},indent=2)+'\n')

    def test_reserved_frame_and_terminal_session_refuse_without_canary_damage(self):
        from hepta.hia_core_lowering_native import ABI,LoweringSession
        session=LoweringSession(self.owner,self.owner.modes['validate_execution_observation']['number'],
            ('returned',{},(1,10,64,None,False,False,0)))
        raw=bytearray(session.initial);raw[72]=1
        source=ctypes.create_string_buffer(bytes(raw))
        output=ctypes.create_string_buffer(b'\xa5'*(self.owner.output_bytes+32))
        state=ctypes.create_string_buffer(b'\0'*(self.owner.workspace_bytes+32))
        result=self.owner.images[0]._entry(source,128,ctypes.byref(output,16),self.owner.output_bytes,
            ctypes.byref(state,16),self.owner.workspace_bytes)
        self.assertEqual(result,ABI)
        self.assertEqual(bytes(output)[:16],b'\xa5'*16)
        self.assertEqual(bytes(output)[-17:-1],b'\xa5'*16)
        session._close()
        with self.assertRaises(RuntimeError):session.observe()

    def test_warm_source_and_missing_source_never_fall_back(self):
        import hepta.hia_execution_observation_selection as selection
        actual=selection._source_resource_path
        with tempfile.TemporaryDirectory() as directory:
            source=Path(directory)/'source';source.write_bytes(b'not admitted source')
            with patch.object(selection,'_source_resource_path',lambda name:source if name==ABI_SOURCE else actual(name)):
                with self.assertRaises((ValueError,json.JSONDecodeError)):
                    installed_execution_observation(str(self.manifest),vars(original))
            source.unlink()
            with patch.object(selection,'_source_resource_path',lambda name:source if name==ABI_SOURCE else actual(name)):
                with self.assertRaises(FileNotFoundError):
                    installed_execution_observation(str(self.manifest),vars(original))


    def test_actual_installed_wheel_uses_complete_bundle_without_authoring(self):
            from hepta.hia_agent_contract import DISCOVERY_FILES, NATIVE_SOURCE_FILES, PUBLICATION_BUILD_FILES, SOURCE_BUILD_FILES, COMPILER_BUILD_FILES, BACKEND_BUILD_FILES, EMITTER_BUILD_FILES, BYTE_WRAPPER_BUILD_FILES, MACHINE_OBJECT_BUILD_FILES, EXECUTION_OBSERVATION_BUILD_FILES, CONTINUATION_BUILD_FILES, ENTRY_BUILD_FILES
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
                        'document': None}
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
            script.write_text(INSTALLED_OBSERVATION_CHILD)
            env = {k: v for k, v in os.environ.items() if not k.startswith('HEPTA_HIA_') and k != 'PYTHONPATH'}
            env['PATH'] = ''
            result = run([sys.executable, '-I', '-S', '-B', str(script), str(installed),
                          str(self.manifest), str(request)], 'installed-execution', env)
            observed = json.loads(result.stdout)
            self.assertEqual(observed['status'], 'INSTALLED_EXECUTION_OBSERVATION_PASS')
            self.assertEqual(observed['units'], 8)
            (case / 'report.json').write_text(json.dumps(observed, indent=2, sort_keys=True) + '\n')

INSTALLED_OBSERVATION_CHILD = "import importlib.abc,json,os,sys\nfrom pathlib import Path\nfrom hashlib import sha256\nsys.path.insert(0,sys.argv[1])\nclass NoTools(importlib.abc.MetaPathFinder):\n def find_spec(self,fullname,path=None,target=None):\n  if fullname=='tools' or fullname.startswith('tools.'):raise AssertionError('installed observer imported authoring tools')\nsys.meta_path.insert(0,NoTools())\nroot=Path(sys.argv[1]);expected=json.loads(Path(sys.argv[3]).read_bytes())\nfor name,identity in expected['python'].items():assert sha256((root/name).read_bytes()).hexdigest()==identity\nactual={p.relative_to(root).as_posix() for p in (root/'hepta').rglob('*.py') if '_data' not in p.parts};assert actual==set(expected['python'])\nfrom hepta.hia_json_preflight_native import _source_resource_path\nfor name,identity in expected['resources'].items():\n p=_source_resource_path(name);assert root in p.parents and sha256(p.read_bytes()).hexdigest()==identity\nfrom hepta import hia_opcodes as op\nfrom hepta.hia_execution_observation_selection import SELECTOR,ABI_SOURCE,installed_execution_observation\nfrom hepta.hia_core_lowering_native import LoweringSession\nentries=[];step=LoweringSession.step\ndef observed(session,packet):\n status=step(session,packet);entries.append(status);return status\nLoweringSession.step=observed\ndef forbidden(*args,**kwargs):raise AssertionError('retained execution policy entered installed wheel')\nop._reference_validate_execution_observation=forbidden\nos.environ[SELECTOR]=sys.argv[2]\nowner=installed_execution_observation(sys.argv[2],vars(op))\nledger=dict.fromkeys(op.EXECUTION_RESOURCE_FIELDS,0)\nop.validate_execution_observation('returned',ledger,steps=1,max_steps=10,max_heap_bytes=64)\ntry:op.validate_execution_observation('returned',{**ledger,'loans_started':1,'live_local_loans':1},steps=1,max_steps=10,max_heap_bytes=64)\nexcept op.ExecutionObservationRejected:pass\nelse:raise AssertionError('orphan loan was admitted')\nassert {0,1,2}.issubset(set(entries))\nabi=_source_resource_path(ABI_SOURCE);raw=abi.read_bytes();abi.write_bytes(raw+b'\\n')\ntry:installed_execution_observation(sys.argv[2],vars(op))\nexcept ValueError:pass\nelse:raise AssertionError('warm ABI drift ignored')\nabi.write_bytes(raw);abi.unlink()\ntry:installed_execution_observation(sys.argv[2],vars(op))\nexcept FileNotFoundError:pass\nelse:raise AssertionError('missing source fell back')\nabi.write_bytes(raw)\nassert sys.flags.isolated and sys.flags.no_site and os.environ['PATH']==''\nprint(json.dumps({'status':'INSTALLED_EXECUTION_OBSERVATION_PASS','units':len(owner._admitted_bundle.images),\n 'python_files':len(expected['python']),'resource_files':len(expected['resources']),'actual_native_steps':len(entries),\n 'retained_policy_forbidden':True,'authoring_forbidden':True,'isolated_without_site':True,'empty_PATH':True}))\n"

if __name__=='__main__':unittest.main()
