"""Original policy, effect, lifetime, and custody controls for native build."""
from __future__ import annotations
import ast
from collections import Counter
from contextlib import ExitStack
import ctypes
import gc
from hashlib import sha256
import importlib
import inspect
import json
import os
from pathlib import Path
import shutil
import stat
import struct
import subprocess
import sys
import tempfile
import threading
import traceback
import types
import unittest
from unittest.mock import patch

from hepta import hia_program_native as backend
from hepta import hia_native_build_selection as selection
from hepta.hia_native_build_native import NativeBuild, NativeBuildFrame, NativeBuildUnknown, SOURCE, SCHEMA, SELECTOR, ARITIES
from hepta import hia_native_build_native as adapter
from hepta import hia_machine_plan_control_native as protocol

ROOT=Path(__file__).resolve().parents[1]
FIXTURE=ROOT/'tests/fixtures/hia_native_build_before_selection.py.txt'
FIXTURE_SHA='b33b56bff030225b65fb7e7c8b490e1d865a83577793fee110df3b3fa580e785'
COLD='HEPTA_HIA_NATIVE_BUILD_COLD_REPORT'
DEVELOPMENT='HEPTA_HIA_NATIVE_BUILD_DEVELOPMENT_COMPILER'
EVIDENCE='HEPTA_HIA_NATIVE_BUILD_EVIDENCE'
ENTRIES=tuple(ARITIES)[:-1]
_BUILT=None


def original(name):
    return getattr(backend,'_reference_'+name.lstrip('_'))


def outcome(function,*args,**kwargs):
    try:return ('value',function(*args,**kwargs))
    except BaseException as error:return ('error',type(error),error.args)


def inputs():
    from tools.build_hia_native_build import DEVELOPMENT_INPUT_NAMES
    return {name:(ROOT/name).read_bytes() for name in DEVELOPMENT_INPUT_NAMES}


def program():
    from hepta.hia_program import verify_program
    from tests.test_hia_program import b,c,f,ret
    return verify_program({'schema':'hepta.hia.program.v1','module':'native_build_controls',
        'functions':[f('answer',[],['i64'],[],[b('entry',[],[c('value','i64',42)],ret('value'))])]})


class _Fixture:
    @classmethod
    def setUpClass(cls):
        global _BUILT
        cold,development=os.environ.get(COLD),os.environ.get(DEVELOPMENT)
        if cold and development:raise ValueError('native-build cold and development authority conflict')
        if not cold and not development:raise unittest.SkipTest('explicit current cold or retained development compiler required')
        current=inputs();key=(cold,development,os.environ.get(EVIDENCE))
        if _BUILT is None:
            temporary=None
            if os.environ.get(EVIDENCE):
                folder=Path(os.environ[EVIDENCE]).resolve();folder.mkdir(parents=True,exist_ok=True)
            else:
                temporary=tempfile.TemporaryDirectory(prefix='hia-native-build-');folder=Path(temporary.name)
            from tools.build_hia_native_build import build,build_development
            if cold:
                cold_path=Path(cold).resolve();raw=cold_path.read_bytes();outer=json.loads(raw)
                nested=json.loads(Path(outer['nested_report']).read_bytes())
                compiler=Path(nested['generations'][-1]['produced_image']).resolve()
                manifest=build(folder/'image',compiler,cold_path)
                authority={cold_path:raw,compiler:compiler.read_bytes()};scope='MATCHING_CURRENT_SOURCE_COLD'
            else:
                compiler=Path(development).resolve();authority={compiler:compiler.read_bytes()}
                manifest=build_development(folder/'image',compiler);scope='RETAINED_COMPILER_DEVELOPMENT_ONLY'
            record=json.loads(manifest.read_bytes());image=manifest.parent/record['image_path']
            authority.update({manifest:manifest.read_bytes(),image:image.read_bytes()})
            _BUILT=(key,current,folder,manifest,authority,temporary,scope)
        if _BUILT[0]!=key or _BUILT[1]!=current:raise AssertionError('native-build fixture source or authority changed')
        cls.folder=_BUILT[2]/cls.__name__;cls.folder.mkdir()
        cls.manifest,cls.authority,cls.scope=_BUILT[3],_BUILT[4],_BUILT[6]
        cls.inputs=current;cls.native=selection.installed_native_build(cls.manifest)

    @classmethod
    def tearDownClass(cls):
        if inputs()!=cls.inputs:raise AssertionError('native-build source bytes changed')
        for path,raw in cls.authority.items():
            if path.read_bytes()!=raw:raise AssertionError('native-build held authority changed: '+str(path))
        if os.environ.get(COLD):
            from tools.build_hia_json_preflight import admit_cold_build,current_sources
            cold_path=Path(os.environ[COLD]).resolve()
            compiler=next(p for p in cls.authority if p not in (cold_path,cls.manifest)
                and p.suffix=='.bin' and p.parent!=cls.manifest.parent)
            if current_sources()!=admit_cold_build(cls.authority[compiler],cls.authority[cold_path]):
                raise AssertionError('native-build complete cold source changed')


class NativeBuildSourceTests(unittest.TestCase):
    def test_complete_original_eight_bodies_signatures_and_identity_extension_are_retained(self):
        raw=FIXTURE.read_bytes();self.assertEqual(sha256(raw).hexdigest(),FIXTURE_SHA)
        before={n.name:n for n in ast.parse(raw).body if isinstance(n,ast.FunctionDef)}
        after={n.name:n for n in ast.parse((ROOT/'hepta/hia_program_native.py').read_text()).body if isinstance(n,ast.FunctionDef)}
        for name in ENTRIES:
            with self.subTest(entry=name):
                expected=before[name];actual=after['_reference_'+name.lstrip('_')]
                self.assertEqual(ast.dump(expected.args),ast.dump(actual.args))
                self.assertEqual([ast.dump(n) for n in expected.decorator_list],[ast.dump(n) for n in actual.decorator_list])
                if name!='_implementation_hash':
                    self.assertEqual([ast.dump(n) for n in expected.body],[ast.dump(n) for n in actual.body])
        retained=ast.unparse(after['_reference_implementation_hash'])
        for name in ('hia_native_build_native.py','hia_native_build_selection.py','hia_native_build_foreign.py'):
            self.assertIn(repr(name),retained)
        self.assertIn('native-build-coordinator',retained)
        policy={n.name:n for n in ast.parse((ROOT/'tools/hia_native_build_policy.py').read_text()).body if isinstance(n,ast.FunctionDef)}
        self.assertEqual(tuple(policy),(*ENTRIES,'_reject'))
        for name in ENTRIES:
            self.assertEqual(ast.dump(policy[name].args),ast.dump(after['_reference_'+name.lstrip('_')].args))
            self.assertEqual([ast.dump(n) for n in policy[name].body],[ast.dump(n) for n in after['_reference_'+name.lstrip('_')].body])

    def test_runtime_has_no_authoring_or_original_coordinator_callback(self):
        for name in ('hia_native_build_native.py','hia_native_build_selection.py','hia_native_build_foreign.py'):
            raw=(ROOT/'hepta'/name).read_text();tree=ast.parse(raw)
            self.assertNotIn('_reference_',raw)
            for node in ast.walk(tree):
                if isinstance(node,ast.ImportFrom):self.assertFalse((node.module or '').startswith('tools'))
                if isinstance(node,ast.Import):self.assertFalse(any(n.name.startswith('tools') for n in node.names))
        from hepta.hia_agent_contract import NATIVE_SOURCE_FILES
        from hepta.hia_checker_identity import CORE_SOURCE_FILES,MECHANISM_SOURCE_FILES,NATIVE_OWNERS,CAPTURED_NATIVE_OWNERS
        from hepta.hia_native_helpers import HELPERS
        self.assertIn('examples/hia_bootstrap/native_build.hiaasm',NATIVE_SOURCE_FILES)
        self.assertIn('hia_native_build_foreign.py',MECHANISM_SOURCE_FILES)
        self.assertNotIn('hia_native_build_foreign.py',CORE_SOURCE_FILES)
        self.assertIn(SELECTOR,NATIVE_OWNERS);self.assertIn(SELECTOR,CAPTURED_NATIVE_OWNERS)
        self.assertIn(SELECTOR,HELPERS)

    def test_source_generator_retains_original_compiler_limits_and_complete_policy(self):
        from tools.generate_hia_native_build import document
        from hepta.hia_agent_assembly import assemble_program,render_assembly
        from hepta.hia_program import verify_program
        doc=document();checked=verify_program(doc)
        self.assertEqual(SOURCE.read_bytes(),render_assembly(doc).encode())
        self.assertEqual(checked.as_dict(),assemble_program(SOURCE.read_bytes()).as_dict())
        functions=doc['functions'];blocks=[b for f in functions for b in f['blocks']]
        operations=[op for b in blocks for op in b['ops']]
        self.assertLessEqual(len(functions),128);self.assertLessEqual(len(blocks),1536)
        self.assertLessEqual(len(operations)+len(blocks),8192)
        self.assertLessEqual(max(len(b['params']) for b in blocks),16)
        self.assertLessEqual(len(SOURCE.read_bytes()),1<<20)
        self.assertLessEqual(len(SOURCE.read_bytes().splitlines()),16384)
        for function in functions:
            self.assertLessEqual(len(function['blocks']),256)
            self.assertLessEqual(len(function['params']),16)
            names={p['name'] for p in function['params']}
            for block in function['blocks']:
                names.update(p['name'] for p in block['params'])
                for operation in block['ops']:
                    names.update(p['name'] for p in operation['out'])
                    self.assertLessEqual(len(operation.get('args',())),16)
            self.assertLessEqual(len(names),2048)
        from tools.hia_native_build_control import compile_policy
        compiled=compile_policy((ROOT/'tools/hia_native_build_policy.py').read_text())
        self.assertEqual(tuple(compiled.by_name),(*ENTRIES,'_reject'))
        self.assertGreater(len(compiled.functions),len(ENTRIES))
        self.assertTrue(any(f.kind=='with_region' for f in compiled.functions))

    def test_only_fixed_import_groups_and_original_context_manager_protocol_are_ports(self):
        from tools.hia_native_build_control import compile_policy,WITH_REGION
        from hepta.hia_native_build_foreign import IMPORT_NAMES,import_ports
        compiled=compile_policy((ROOT/'tools/hia_native_build_policy.py').read_text())
        expected={(node.module,tuple(alias.name for alias in node.names)) for node in ast.walk(compiled.tree)
                  if isinstance(node,ast.ImportFrom)}
        self.assertEqual(set(IMPORT_NAMES),{name for _,names in expected for name in names})
        self.assertEqual(set(import_ports(vars(backend))[0]),expected)
        raw=(ROOT/'hepta/hia_native_build_native.py').read_text()
        self.assertIn('context manager suppressed an unconfirmed HIA body',raw)
        self.assertIn('returned=True',raw)
        self.assertNotIn('frame.close(release=sys.exc_info()',raw)

    def test_incomplete_cold_refuses_without_creating_output(self):
        from tools.build_hia_native_build import build
        with tempfile.TemporaryDirectory() as directory:
            root=Path(directory);compiler=root/'compiler.bin';cold=root/'cold.json';out=root/'output'
            compiler.write_bytes(b'not a current-source compiler');cold.write_text('{}')
            with self.assertRaises((KeyError,ValueError,TypeError)):build(out,compiler,cold)
            self.assertFalse(out.exists())

    def test_unselected_public_entry_keeps_original_early_error_and_signature(self):
        with patch.dict(os.environ,{SELECTOR:''}):
            self.assertEqual(outcome(backend.emit_program_machine,None,target='unsupported'),
                             outcome(original('emit_program_machine'),None,target='unsupported'))
        for name in ENTRIES:self.assertEqual(inspect.signature(getattr(backend,name)),inspect.signature(original(name)))


class NativeBuildCallerSourceTests(unittest.TestCase):
    def test_complete_original_114_discovery_and_exact_module_bytes(self):
        from tools import qualify_hia_native_build as qualification
        from tools.build_hia_native_build import REQUIRED_SOURCE_NAMES
        loader=unittest.TestLoader()
        suite=loader.loadTestsFromNames(qualification.MODULES)
        loaded=[test.id() for test in qualification.flatten(suite)]
        qualification.admit_original_discovery(loaded,loader.errors)
        self.assertEqual(len(loaded),114)
        self.assertEqual(len(qualification.MODULES),11)
        self.assertEqual({name:sha256((ROOT/name).read_bytes()).hexdigest()
                          for name in qualification.MODULE_SOURCE_PINS},qualification.MODULE_SOURCE_PINS)
        self.assertTrue(set(qualification.MODULE_SOURCE_PINS)<=set(REQUIRED_SOURCE_NAMES))
        self.assertIn('tools/qualify_hia_native_build.py',REQUIRED_SOURCE_NAMES)

    def test_missing_duplicate_reordered_extra_and_loader_failure_are_not_passes(self):
        from tools import qualify_hia_native_build as qualification
        ids=list(qualification.EXPECTED_IDS)
        cases=[(ids[:-1],[]),(ids[:-1]+ids[:1],[]),([ids[1],ids[0],*ids[2:]],[]),
               (ids+['unexpected.case'],[]),(ids,['original discovery failed'])]
        for loaded,errors in cases:
            with self.subTest(count=len(loaded),errors=errors),self.assertRaises(ValueError):
                qualification.admit_original_discovery(loaded,errors)
        with tempfile.TemporaryDirectory() as directory:
            output=Path(directory)/'no-authority'
            for options in ({},{'cold_report':'cold','development_manifest':'development'}):
                with self.assertRaises(ValueError):qualification.qualify(output,**options)
                self.assertFalse(output.exists())

    def test_original_caller_drift_is_retained_before_any_image_or_test_entry(self):
        from tools import qualify_hia_native_build as qualification
        changed=next(iter(qualification.MODULE_SOURCE_PINS))
        real=qualification._bytes_pin
        def changed_pin(path):
            return '0'*64 if Path(path)==ROOT/changed else real(path)
        with tempfile.TemporaryDirectory() as directory:
            output=Path(directory)/'evidence'
            with patch.object(qualification,'_bytes_pin',changed_pin), \
                 patch.object(qualification,'_bundle_observation',side_effect=AssertionError('mapped before source refusal')) as mapped, \
                 patch.object(unittest.TestLoader,'loadTestsFromNames',side_effect=AssertionError('tests before source refusal')) as loaded:
                with self.assertRaisesRegex(ValueError,'original 4b retained caller module bytes differ'):
                    qualification.qualify(output,development_manifest=Path(directory)/'never-present.json')
            mapped.assert_not_called();loaded.assert_not_called()
            report=json.loads((output/'report.json').read_text())
            self.assertEqual(report['status'],'HOLD')
            self.assertEqual(report['failure']['type'],'ValueError')
            self.assertEqual(report['actual_module_sources'][changed],'0'*64)
            self.assertNotIn('tests_run',report)


def _read_scope_observation(native,case,selected,outer):
    events=[]
    error=ValueError('read body')
    def mark(label,*values):
        current=sys.exception()
        events.append([label,*values,None if current is None else type(current).__name__])
    stamp=types.SimpleNamespace(st_dev=1,st_ino=2,st_size=3,st_mtime_ns=4,st_ctime_ns=5,
                                st_mode=stat.S_IFREG|0o600)
    class FakePath:
        calls=0
        def lstat(self):
            self.calls+=1;mark('lstat',self.calls)
            if case=='pathname-drift' and self.calls==2:
                return types.SimpleNamespace(**{**vars(stamp),'st_ino':9})
            return stamp
    class Stream:
        def fileno(self):mark('fileno');return 73
        def read(self,size):
            mark('read',size)
            if case in ('read-error','suppress-read','exit-error'):
                raise error
            return b'ab' if case=='short-read' else b'abc'
        def __del__(self):mark('stream-del')
    class Manager:
        def __enter__(self):
            mark('enter')
            if case=='enter-error':raise TypeError('enter failed')
            return Stream()
        def __exit__(self,kind,error,tb):
            mark('exit',None if kind is None else kind.__name__)
            if case=='exit-error':raise LookupError('exit failed')
            return case=='suppress-read'
        def __del__(self):mark('manager-del')
    calls=0
    def fstat(fd):
        nonlocal calls
        calls+=1;mark('fstat',fd,calls)
        if case=='before-drift' and calls==1 or case=='during-drift' and calls==2:
            return types.SimpleNamespace(**{**vars(stamp),'st_ino':9})
        return stamp
    def open_file(path,flags):mark('open',flags);return 73
    def fdopen(fd,mode):mark('fdopen',fd,mode);return Manager()
    fake_os=types.SimpleNamespace(open=open_file,fdopen=fdopen,fstat=fstat,
        **{key:getattr(os,key) for key in ('O_RDONLY','O_NONBLOCK','O_CLOEXEC','O_NOFOLLOW')})
    saved=None
    outcome=None
    def body():
        nonlocal saved,outcome
        with patch.object(backend,'os',fake_os):
            try:
                value=(native._helpers['_read_artifact'] if selected else backend._reference_read_artifact)(FakePath())
                outcome=['value',value.hex()]
            except BaseException as caught:
                saved=caught
                outcome=['error',type(caught).__name__,list(caught.args),caught is error,
                         None if caught.__context__ is None else type(caught.__context__).__name__]
        mark('after-call')
        if saved is not None:
            traceback.clear_frames(saved.__traceback__)
            saved.__traceback__=None
        saved=None
        error.__traceback__=None
        gc.collect()
        mark('after-clear')
    if outer:
        try:raise RuntimeError('outer')
        except RuntimeError:body()
    else:body()
    return {'outcome':outcome,'events':events}


class NativeBuildNativeTests(_Fixture,unittest.TestCase):
    def test_held_importerror_releases_original_module_before_error_traceback(self):
        from hepta.hia_native_build_native import NativeBuild
        from tests.hia_native_name_resolution import assert_import_error_retirement
        record = json.loads(self.manifest.read_bytes())
        def new_owner():
            return NativeBuild((self.manifest.parent / record['image_path']).read_bytes(),
                               record['image_sha256'], vars(backend))
        rows = assert_import_error_retirement(self, 'build', new_owner)
        (self.folder / 'import-error-retirement.json').write_text(json.dumps(rows, sort_keys=True, indent=2) + '\n')

    def test_deleted_or_replaced_public_global_keeps_original_lookup_error_and_effects(self):
        checked=program();saved=backend._inspect_object
        try:
            del backend._inspect_object
            rows=[]
            for call in (original('emit_program_machine'),self.native._helpers['emit_program_machine']):
                try:call(checked)
                except NameError as error:
                    rows.append((error.args,error.name,error.__context__,error.__cause__,error.__suppress_context__))
                else:self.fail('deleted original global was recreated')
            self.assertEqual(rows[0],rows[1]);self.assertEqual(rows[0][1],'_inspect_object')
        finally:backend._inspect_object=saved
        calls=[];error=LookupError('explicit replacement provider')
        def replacement(*args):calls.append(args);raise error
        for call in (original('emit_program_machine'),self.native._helpers['emit_program_machine']):
            with patch.object(backend,'_inspect_object',replacement):
                try:call(checked)
                except BaseException as observed:self.assertIs(observed,error)
                else:self.fail('original replacement was not used')
        self.assertEqual(len(calls),2);self.assertEqual(calls[0],calls[1])

    def test_original_post_publication_failure_withdraws_only_its_actual_link(self):
        checked=program();image=original('emit_program_machine')(checked)
        actual_publish=backend.publish_verified;actual_withdraw=backend.withdraw_own_link
        observations=[]
        for call in (original('compile_program_machine'),self.native._helpers['compile_program_machine']):
            with tempfile.TemporaryDirectory(dir=self.folder) as directory:
                destination=Path(directory)/'published.o';events=[]
                def publish(source,target,data):
                    result=actual_publish(source,target,data);events.append('published')
                    backend._implementation_hash=lambda:'changed after publication'
                    return result
                def withdraw(source,target):
                    events.append('withdraw');return actual_withdraw(source,target)
                with patch.object(backend,'_implementation_hash',backend._implementation_hash),\
                     patch.object(backend,'publish_verified',publish),patch.object(backend,'withdraw_own_link',withdraw):
                    result=outcome(call,image,program=checked,output=destination,kind='object')
                self.assertFalse(destination.exists());self.assertEqual(events,['published','withdraw'])
                observations.append(result)
        self.assertEqual(observations[0],observations[1])
        self.assertEqual(observations[0][0],'error')
        self.assertIn('E_HIA_PROGRAM_STALE',observations[0][2][0])

    def test_real_published_effect_with_lost_native_ack_is_retained_and_never_replayed(self):
        checked=program();image=original('emit_program_machine')(checked)
        with tempfile.TemporaryDirectory(dir=self.folder) as directory:
            destination=Path(directory)/'published.o';events=[];fired=[]
            actual_publish=backend.publish_verified;actual_invoke=NativeBuildFrame._invoke
            frame=self.native.prepare('compile_program_machine',
                (image,checked,destination,'object','cc',None,None,False,None))
            def publish(source,target,data):
                result=actual_publish(source,target,data);events.append('published');return result
            def interrupted(current,command,*args,**kwargs):
                result=actual_invoke(current,command,*args,**kwargs)
                if command==1 and current is frame._region_child and events and not fired:
                    fired.append(bytes(current.state))
                    raise KeyboardInterrupt('native publication acknowledgement was lost')
                return result
            with patch.object(backend,'publish_verified',publish),patch.object(NativeBuildFrame,'_invoke',interrupted):
                with self.assertRaises(NativeBuildUnknown):self.native.finish(frame)
            self.assertEqual(events,['published']);self.assertEqual(len(fired),1)
            self.assertEqual(destination.read_bytes(),image.object_bytes)
            self.assertIs(adapter._WITH_UNKNOWN[frame.nonce],frame)
            self.assertTrue(frame._uncertain);entries=self.native.entries
            with self.assertRaises(RuntimeError):frame.drive()
            self.assertEqual(events,['published']);self.assertEqual(self.native.entries,entries)

    def test_issued_object_nonce_and_terminal_cannot_authorize_replay(self):
        frame=self.native.prepare('_host',())
        self.assertEqual(frame.step(),1);issued=frame.pending;entries=self.native.entries
        with self.assertRaises(RuntimeError):frame.service(protocol.Issued(issued.raw))
        self.assertEqual(self.native.entries,entries)
        frame.service(issued);entries=self.native.entries
        with self.assertRaises(RuntimeError):frame.service(issued)
        self.assertEqual(self.native.entries,entries)
        status=frame.step()
        while status==1:frame.service(frame.pending);status=frame.step()
        self.assertEqual(status,0);self.assertEqual(frame.take(),original('_host')())
        with self.assertRaises(RuntimeError):frame.take()
        frame.close();self.assertTrue(frame._retired)

    def test_captured_scope_is_thread_local_and_normal_return_under_outer_error_retires(self):
        rows=[]
        with patch.dict(os.environ,{SELECTOR:str(self.manifest)}),selection.native_build_scope():
            held=selection.active_native_build()
            def work():
                rows.append(selection.captured_checker_owner()[0])
                with selection.native_build_scope():rows.append(selection.active_native_build().image_sha256)
                rows.append(selection.captured_checker_owner()[0])
            thread=threading.Thread(target=work);thread.start();thread.join(10)
            self.assertFalse(thread.is_alive());self.assertIs(selection.active_native_build(),held)
        self.assertEqual(rows,[False,self.native.image_sha256,False])
        try:raise LookupError('outer handled exception')
        except LookupError as outer:
            frame=self.native.prepare('_host',())
            self.assertEqual(self.native.finish(frame),original('_host')())
            self.assertTrue(frame._terminal_taken);self.assertTrue(frame._retired)
            self.assertIs(sys.exception(),outer)

    def test_original_with_exception_suppression_and_manager_stream_lifetimes(self):
        cases=('normal','enter-error','read-error','suppress-read','exit-error',
               'before-drift','during-drift','pathname-drift','short-read')
        for case in cases:
            for outer in (False,True):
                with self.subTest(case=case,outer=outer):
                    self.assertEqual(_read_scope_observation(self.native,case,False,outer),
                                     _read_scope_observation(self.native,case,True,outer))

    def test_suppressing_context_manager_cannot_confirm_or_replay_unknown_native_body(self):
        for after_read in (False,True):
            with self.subTest(after_read=after_read):
                events=[]
                stamp=types.SimpleNamespace(st_mode=stat.S_IFREG|0o600,st_dev=1,st_ino=2,
                    st_size=3,st_mtime_ns=4,st_ctime_ns=5)
                class FakePath:
                    def lstat(self):events.append('lstat');return stamp
                class Stream:
                    def fileno(self):return 73
                    def read(self,size):events.append('read');return b'abc'
                class Manager:
                    def __enter__(self):events.append('enter');return Stream()
                    def __exit__(self,*error):events.append('suppressed');return True
                fake_os=types.SimpleNamespace(open=lambda *args:73,fdopen=lambda *args:Manager(),
                    fstat=lambda fd:stamp,**{key:getattr(os,key) for key in
                    ('O_RDONLY','O_NONBLOCK','O_CLOEXEC','O_NOFOLLOW')})
                frame=self.native.prepare('_read_artifact',(FakePath(),));fired=[]
                actual_invoke=NativeBuildFrame._invoke
                class LostAcknowledgement(BaseException):pass
                def interrupted(current,command,*args,**kwargs):
                    value=actual_invoke(current,command,*args,**kwargs)
                    if (not fired and current is frame._region_child and
                            (command==1 and 'read' in events if after_read else command==2)):
                        fired.append((command,bytes(current.state)))
                        raise LostAcknowledgement('actual native transition returned before interruption')
                    return value
                with patch.object(backend,'os',fake_os),patch.object(NativeBuildFrame,'_invoke',interrupted):
                    with self.assertRaises(NativeBuildUnknown):self.native.finish(frame)
                self.assertEqual(len(fired),1);self.assertEqual(events.count('read'),int(after_read))
                self.assertEqual(events.count('suppressed'),1);self.assertEqual(events.count('lstat'),1)
                self.assertIs(adapter._WITH_UNKNOWN[frame.nonce],frame)
                self.assertTrue(frame._uncertain);self.assertTrue(frame._region_child._uncertain)
                entries=self.native.entries;before=events.copy();state=bytes(frame._region_child.state)
                with self.assertRaises(RuntimeError):frame.drive()
                self.assertEqual(self.native.entries,entries);self.assertEqual(events,before)
                self.assertEqual(bytes(frame._region_child.state),state)

    def test_complete_actual_object_and_shared_build_reports_equal_original(self):
        checked=program()
        expected=original('emit_program_machine')(checked)
        actual=self.native._helpers['emit_program_machine'](checked)
        self.assertEqual(actual,expected)
        for kind in ('object','shared'):
            with self.subTest(kind=kind),tempfile.TemporaryDirectory(dir=self.folder) as directory:
                root=Path(directory);rows=[]
                for label,call in (('reference',original('compile_program_machine')),
                                   ('native',self.native._helpers['compile_program_machine'])):
                    log=[];path=root/(label+('.o' if kind=='object' else '.so'))
                    row=call(actual,program=checked,output=path,kind=kind,linker='ld',command_log=log)
                    self.assertTrue(path.is_file());self.assertEqual(sha256(path.read_bytes()).hexdigest(),row['artifact_sha256'])
                    rows.append((row,path.read_bytes(),log))
                self.assertEqual(rows[0][1],rows[1][1])
                a,b=rows[0][0].copy(),rows[1][0].copy();a.pop('output');b.pop('output')
                self.assertEqual(a,b)
                self.assertTrue(all(row['status']=='completed' for result in rows for row in result[2]))

    def test_complete_public_build_uses_no_retained_coordinator_body(self):
        def forbidden(*args,**kwargs):raise AssertionError('old native-build policy was called')
        with patch.dict(os.environ,{SELECTOR:str(self.manifest)}),ExitStack() as stack:
            for name in ENTRIES:stack.enter_context(patch.object(backend,'_reference_'+name.lstrip('_'),forbidden))
            stack.enter_context(patch.object(backend,'_reference_reject',forbidden))
            checked=program()
            with tempfile.TemporaryDirectory(dir=self.folder) as directory:
                result=backend.build_program_machine(checked,Path(directory)/'program.o',kind='object')
                self.assertEqual(result['status'],'native_emitted_not_executed')
                self.assertEqual(result['exports'],['answer'])
                self.assertFalse(result['claims']['native_execution_qualified'])

    def test_original_first_errors_and_timeout_type_range_order(self):
        for kwargs in ({'command_log':()},*({'timeout_seconds':v} for v in (False,True,0,-1,3601,float('nan'),'1'))):
            with self.subTest(kwargs=kwargs):
                self.assertEqual(outcome(original('compile_program_machine'),None,program=None,output=None,**kwargs),
                                 outcome(self.native._helpers['compile_program_machine'],None,program=None,output=None,**kwargs))
        self.assertEqual(outcome(original('emit_program_machine'),None,target='other'),
                         outcome(self.native._helpers['emit_program_machine'],None,target='other'))
        self.assertEqual(outcome(original('_inspect_object'),b'invalid',()),
                         outcome(self.native._helpers['_inspect_object'],b'invalid',()))

    def test_original_logging_results_failure_capture_and_same_error(self):
        for fail in (False,True):
            with self.subTest(fail=fail):
                calls=[];logs=[];error=ValueError('original exact error')
                result=types.SimpleNamespace(returncode=3,raw_stdout=b'out',raw_stderr=b'err',stdout='out',stderr='err')
                error.capture=types.SimpleNamespace(returncode=-9,stdout=b'part',stderr=b'',stdout_total_bytes=19,stderr_total_bytes=0)
                def capture(argv,**kwargs):
                    calls.append((list(argv),kwargs))
                    if fail:raise error
                    return result
                for call in (original('_run_logged'),self.native._helpers['_run_logged']):
                    log=[]
                    with patch.object(backend,'run_bounded',capture):
                        if fail:
                            try:call(['tool'],command_log=log,timeout=1,stdout_limit=32)
                            except BaseException as observed:self.assertIs(observed,error)
                            else:self.fail('original failure was lost')
                        else:self.assertIs(call(['tool'],command_log=log,timeout=1,stdout_limit=32),result)
                    logs.append(log)
                self.assertEqual(calls[0],calls[1]);self.assertEqual(logs[0],logs[1])

    def test_single_import_name_complete_fromlist_and_ordered_import_from(self):
        import builtins
        actual_import=builtins.__import__
        rows=[]
        for call in (original('validate_block_layout_plan'),self.native._helpers['validate_block_layout_plan']):
            events=[]
            def observed(name,globals=None,locals=None,fromlist=(),level=0):
                if name in ('hia_program','hia_machine_plan'):
                    events.append((name,fromlist,level,globals is vars(backend),locals is None))
                return actual_import(name,globals,locals,fromlist,level)
            with patch.object(builtins,'__import__',observed):value=outcome(call,None,None)
            rows.append((value,events))
        self.assertEqual(rows[0],rows[1])
        self.assertEqual(rows[0][1][:2],[('hia_program',('verify_program',),1,True,True),
                                      ('hia_machine_plan',('MachinePlanRejected','validate_plan'),1,True,True)])

    def test_held_owner_absence_and_nested_environment_change_keep_actual_proof_identity(self):
        from hepta.hia_checker_identity import checker_digest
        with patch.dict(os.environ,{SELECTOR:str(self.manifest)}),selection.native_build_scope():
            held=selection.active_native_build();before=checker_digest()
            with patch.dict(os.environ,{SELECTOR:'/does/not/exist'}),selection.native_build_scope():
                self.assertIs(selection.active_native_build(),held)
                self.assertEqual(checker_digest(),before)
                self.assertEqual(backend._host(),original('_host')())
        with patch.dict(os.environ,{SELECTOR:''}),selection.native_build_scope():
            with patch.dict(os.environ,{SELECTOR:str(self.manifest)}),selection.native_build_scope():
                self.assertIsNone(selection.active_native_build())

    def test_warm_admission_rejects_changed_manifest_image_source_and_missing_source(self):
        record=json.loads(self.manifest.read_bytes())
        image=self.manifest.parent/record['image_path']
        selection.installed_native_build(self.manifest)
        for path in (self.manifest,image,SOURCE):
            with self.subTest(path=str(path)):
                raw=path.read_bytes()
                try:
                    changed=(json.dumps({**record,'source_sha256':'0'*64}).encode()
                             if path==self.manifest else raw+b'\n')
                    path.write_bytes(changed)
                    with self.assertRaises((ValueError,RuntimeError)):selection.installed_native_build(self.manifest)
                finally:path.write_bytes(raw)
        raw=SOURCE.read_bytes()
        try:
            SOURCE.unlink()
            with self.assertRaises((ValueError,FileNotFoundError)):selection.installed_native_build(self.manifest)
        finally:SOURCE.write_bytes(raw)
        self.assertIsInstance(selection.installed_native_build(self.manifest),NativeBuild)


class NativeBuildVMTests(_Fixture,unittest.TestCase):
    def test_actual_native_and_VM_match_complete_state_output_and_canaries(self):
        from hepta.hia_agent_assembly import assemble_program
        from hepta.hia_program_runtime import _Machine,_Owner,_View
        checked=assemble_program(SOURCE.read_bytes());function=checked.as_dict()['functions'][0]
        record=json.loads(self.manifest.read_bytes());raw=(self.manifest.parent/record['image_path']).read_bytes()
        owner=NativeBuild(raw,record['image_sha256']);real_entry=owner._entry;rows=[]
        def entry(source,size,output,outsize,workspace,worksize):
            original_bytes=tuple(ctypes.string_at(p,n) for p,n in
                ((source,size),(output,outsize),(workspace,worksize)))
            guards=[ctypes.create_string_buffer(b'Z'*16+raw+b'Y'*16,len(raw)+32) for raw in original_bytes]
            result=real_entry(ctypes.byref(guards[0],16),size,ctypes.byref(guards[1],16),outsize,
                              ctypes.byref(guards[2],16),worksize)
            owners=[_Owner(-1-i,bytearray(raw)) for i,raw in enumerate(original_bytes)]
            vm=_Machine(checked,20_000_000,4<<20,None,128)
            expected=vm.invoke(function,[_View(owners[0],False),_View(owners[1],True),_View(owners[2],True)])[0]
            self.assertEqual(result,expected)
            for guard,memory in zip(guards,owners):
                self.assertEqual(guard.raw[:16],b'Z'*16);self.assertEqual(guard.raw[-16:],b'Y'*16)
                self.assertEqual(guard.raw[16:-16],bytes(memory.data))
            self.assertEqual(guards[0].raw[16:-16],original_bytes[0])
            ctypes.memmove(output,guards[1].raw[16:-16],outsize)
            ctypes.memmove(workspace,guards[2].raw[16:-16],worksize)
            rows.append({'return':result,'command':struct.unpack_from('<Q',original_bytes[2])[0],
                'source_sha256':sha256(original_bytes[0]).hexdigest(),
                'output_sha256':sha256(guards[1].raw[16:-16]).hexdigest(),
                'workspace_sha256':sha256(guards[2].raw[16:-16]).hexdigest()})
            return result
        owner._entry=entry;owner._initialize_control();owner._bind_namespace()
        self.assertEqual(owner.run('_host'),original('_host')())
        self.assertEqual(outcome(owner._helpers['_reject'],'exact VM rejection'),
                         outcome(backend._reject,'exact VM rejection'))
        counts=Counter(row['command'] for row in rows)
        self.assertGreater(counts[2],0);self.assertGreater(counts[4],0)
        self.assertIn(3,[row['return'] for row in rows])
        (self.folder/'complete-native-VM-frames.json').write_text(json.dumps(rows,indent=2)+'\n')


class NativeBuildInstalledTests(_Fixture,unittest.TestCase):
    def test_real_wheel_pinned_bundle_and_warm_missing_or_changed_resource_refuse(self):
        from hepta.hia_agent_contract import (DISCOVERY_FILES,NATIVE_SOURCE_FILES,
            PUBLICATION_BUILD_FILES,SOURCE_BUILD_FILES,COMPILER_BUILD_FILES)
        source,wheels,installed=(self.folder/name for name in ('source','wheels','installed'))
        source.mkdir()
        shutil.copytree(ROOT/'hepta',source/'hepta',ignore=shutil.ignore_patterns('__pycache__'))
        resources=tuple('docs/'+name for name in DISCOVERY_FILES)+NATIVE_SOURCE_FILES+\
                  PUBLICATION_BUILD_FILES+SOURCE_BUILD_FILES+COMPILER_BUILD_FILES
        for name in (*dict.fromkeys(resources),'setup.py','pyproject.toml','MANIFEST.in'):
            target=source/name;target.parent.mkdir(parents=True,exist_ok=True)
            shutil.copyfile(ROOT/name,target)
        commands=[]
        def command(argv,label,*,env=None):
            result=subprocess.run(argv,cwd=self.folder,env=env,capture_output=True,timeout=120)
            (self.folder/(label+'.stdout')).write_bytes(result.stdout)
            (self.folder/(label+'.stderr')).write_bytes(result.stderr)
            commands.append({'argv':argv,'returncode':result.returncode,'timeout_seconds':120,
                'stdout_sha256':sha256(result.stdout).hexdigest(),'stderr_sha256':sha256(result.stderr).hexdigest()})
            (self.folder/'commands.json').write_text(json.dumps(commands,indent=2)+'\n')
            self.assertEqual(result.returncode,0,result.stdout+result.stderr)
            return result
        packaging=os.environ.get('HEPTA_HIA_TEST_PACKAGING_PYTHON',sys.executable)
        command([packaging,'-B','-m','pip','wheel','--no-cache-dir','--no-deps','--no-index',
                 '--no-build-isolation','--wheel-dir',str(wheels),str(source)],'wheel-build')
        wheel,=wheels.glob('*.whl')
        command([packaging,'-B','-m','pip','install','--no-cache-dir','--no-deps','--no-index',
                 '--target',str(installed),str(wheel)],'wheel-install')
        child=r'''import importlib.abc,json,os,sys
from hashlib import sha256
from pathlib import Path
sys.path.insert(0,sys.argv[1])
class NoAuthoring(importlib.abc.MetaPathFinder):
 def find_spec(self,fullname,path=None,target=None):
  if fullname in ('tools','tests') or fullname.startswith(('tools.','tests.')):
   raise AssertionError('installed native-build imported authoring or tests')
sys.meta_path.insert(0,NoAuthoring())
from hepta import hia_program_native as api
from hepta.hia_native_build_native import SOURCE,SELECTOR,ARITIES
from hepta.hia_native_build_selection import installed_native_build,native_build_scope,active_native_build
from hepta.hia_native_helpers import native_helpers_scope
from hepta.hia_agent_contract import installation_manifest
assert Path(sys.argv[1]) in SOURCE.parents and '_data' in SOURCE.parts
def forbidden(*args,**kwargs):raise AssertionError('retained native-build policy')
for name in tuple(ARITIES)[:-1]:setattr(api,'_reference_'+name.lstrip('_'),forbidden)
api._reference_reject=forbidden
manifest=Path(sys.argv[2]);bundle=Path(sys.argv[3])
record={'schema':'hepta.hia.native-helpers.v1','target':'linux-x86_64-lp64','abi':'hia-byte-six-argument-v1',
 'helpers':[{'selector':SELECTOR,'manifest_path':str(manifest),'manifest_sha256':sha256(manifest.read_bytes()).hexdigest()}]}
raw=(json.dumps(record,sort_keys=True)+'\n').encode();bundle.write_bytes(raw)
with native_helpers_scope(str(bundle),sha256(raw).hexdigest()):
 with native_build_scope():
  owner=active_native_build()
  assert api._host()['pointer_bits']==64
  assert api._read_artifact(Path(api.__file__))==Path(api.__file__).read_bytes()
  assert owner.entries>0
  assert isinstance(installation_manifest(),dict)
raw=SOURCE.read_bytes()
for missing in (False,True):
 try:
  if missing:SOURCE.unlink()
  else:SOURCE.write_bytes(raw+b'\n')
  try:installed_native_build(manifest)
  except (ValueError,FileNotFoundError):pass
  else:raise AssertionError('changed or missing installed HIA source accepted')
 finally:SOURCE.write_bytes(raw)
assert not any(k=='tools' or k.startswith('tools.') for k in sys.modules)
assert sys.flags.isolated and sys.flags.no_site
print(json.dumps({'status':'INSTALLED_NATIVE_BUILD_PASS','entries':owner.entries,'source':str(SOURCE)}))
'''
        script=self.folder/'installed-control.py';script.write_text(child)
        env={k:v for k,v in os.environ.items() if not k.startswith('HEPTA_HIA_')}
        env.update(PATH='',PYTHONPATH='')
        result=command([sys.executable,'-I','-S','-B',str(script),str(installed),str(self.manifest),
            str(self.folder/'bundle.json')],'installed-execution',env=env)
        self.assertEqual(json.loads(result.stdout)['status'],'INSTALLED_NATIVE_BUILD_PASS')


if __name__=='__main__':unittest.main()
