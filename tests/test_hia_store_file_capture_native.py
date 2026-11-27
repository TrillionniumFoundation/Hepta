"""Complete file-capture control qualification. No retained whole body on selected routes."""
from __future__ import annotations
import ast
import ctypes
from hashlib import sha256
import json
import os
from pathlib import Path
import struct
import tempfile
import threading
import unittest
from hepta import hia_agent_store as api
from hepta import hia_store_file_capture_native as native
from hepta.hia_agent_assembly import render_assembly
from tests import hia_store_file_capture_controls as controls
from tests import hia_store_file_capture_owned_fd_v2_oracle as oracle
from tools import generate_hia_store_file_capture as generator
from tools import qualify_hia_store_file_capture_owned_fd_v2 as qualification
ROOT=Path(__file__).resolve().parents[1]
COLD='HEPTA_HIA_STORE_FILE_CAPTURE_COLD_REPORT'
DEVELOPMENT='HEPTA_HIA_STORE_FILE_CAPTURE_DEVELOPMENT_COMPILER'
EVIDENCE='HEPTA_HIA_STORE_FILE_CAPTURE_EVIDENCE'
SOURCE_EVIDENCE='HEPTA_HIA_STORE_FILE_CAPTURE_SOURCE_EVIDENCE'

def directory(name):
    base=os.environ.get(name)
    if base=='':raise ValueError('empty explicit evidence path')
    if base is None:
        temporary=tempfile.TemporaryDirectory(prefix='hia-file-capture-')
        return Path(temporary.name),temporary
    path=Path(base).absolute();path.mkdir(mode=0o700,parents=True,exist_ok=False)
    return path,None

class StoreFileCaptureSourceTests(unittest.TestCase):
    def test_originals_source_binding_public_routes_and_complete_generated_graph(self):
        raw=(ROOT/'hepta/hia_agent_store.py').read_bytes();lines=raw.splitlines(keepends=True);tree=ast.parse(raw)
        for name in ('stable_read','capture_path'):
            definitions=[n for n in tree.body if isinstance(n,ast.FunctionDef) and n.name==name]
            self.assertEqual(len(definitions),2)
            original=b''.join(lines[definitions[0].lineno-1:definitions[0].end_lineno])
            self.assertEqual(sha256(original).hexdigest(),oracle.PINNED[name])
        self.assertEqual(native.SOURCE.read_bytes(),render_assembly(generator.document()).encode())
        self.assertEqual(len(native.PORTS),73)
        self.assertIsNot(api.stable_read,api._STABLE_READ_REFERENCE)
        self.assertIsNot(api.capture_path,api._CAPTURE_PATH_REFERENCE)
        from hepta.hia_native_helpers import HELPERS
        self.assertEqual(HELPERS[native.SELECTOR],('hia_store_file_capture_native','NativeStoreFileCapture'))
        flow=generator.FLOW
        self.assertEqual([x['name'] for x in flow],list(native.PORTS))
        self.assertEqual(len({x['name'] for x in flow}),73)

    def test_complete_original_first_frozen_domain_against_independent_VM(self):
        root,temporary=directory(SOURCE_EVIDENCE)
        try:
            qualification.originals(root/'original')
            qualification.compare(root/'VM',root/'original','vm')
            report=json.loads((root/'VM/comparison.json').read_bytes())
            self.assertEqual(report['differences'],0)
            authority=json.loads((root/'original/original-authority.json').read_bytes())
            self.assertEqual(report['count'],authority['count'])
            self.assertEqual((root/'original/complete-first/observations.jsonl').read_bytes(),
                             (root/'VM/candidate/observations.jsonl').read_bytes())
        finally:
            if temporary is not None:temporary.cleanup()

    def test_unselected_is_lazy_empty_selection_refuses_and_no_new_limit(self):
        saved=os.environ.pop(native.SELECTOR,None)
        try:
            def no_map(*args,**kwargs):raise AssertionError('unselected route mapped native')
            with controls.attributes(native.NativeStoreFileCapture,{'__init__':no_map}):
                with tempfile.TemporaryDirectory(prefix='hia-file-unselected-') as temporary:
                    path=Path(temporary)/'data';path.write_bytes(b'abc')
                    with self.assertRaises(OverflowError):api.stable_read(path,1<<80)
                    with self.assertRaises(OverflowError):api.capture_path(str(path),[Path(temporary)],1<<80)
                os.environ[native.SELECTOR]=''
                with self.assertRaises(ValueError):api.capture_path('/not-read',[],0)
        finally:
            if saved is None:os.environ.pop(native.SELECTOR,None)
            else:os.environ[native.SELECTOR]=saved

class StoreFileCaptureNativeTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        from tools.build_hia_store_file_capture import build
        from tools.build_hia_json_preflight import current_sources
        cold,development=os.environ.get(COLD),os.environ.get(DEVELOPMENT)
        if (cold is None)==(development is None) or cold=='' or development=='':
            raise ValueError('require exactly one current cold or explicit DEV compiler')
        cls.root,cls.temporary=directory(EVIDENCE);cls.cold=cold
        if cold is not None:
            from tools.hia_cold_compiler import compiler_from_cold_report
            cls.compiler=compiler_from_cold_report(Path(cold))
        else:cls.compiler=Path(development)
        cls.compiler_raw=cls.compiler.read_bytes();cls.sources=current_sources()
        cls.manifest=build(cls.root/'built',cls.compiler,cold,development=cold is None)

    @classmethod
    def tearDownClass(cls):
        from tools.build_hia_json_preflight import current_sources
        after=current_sources()
        stable=after==cls.sources and cls.compiler.read_bytes()==cls.compiler_raw
        controls.write(cls.root/'component-custody.json',{
            'schema':'hepta.hia.store-file-capture-component-custody.v1',
            'source_before':cls.sources,'source_after':after,'source_and_compiler_unchanged':stable,
            'manifest':str(cls.manifest),'matching_cold_report':cls.cold,
            'scope':'DEVELOPMENT_COMPONENT' if cls.cold is None else 'MATCHING_SOURCE_COLD_COMPONENT',
            'hosted_OS_stream_and_path_protocols':True,'all_input_equivalence_proved':False,
            'raw_syscall_candidate_not_silently_substituted':True,'whole_native_stack_qualified':False})
        if cls.temporary is not None:cls.temporary.cleanup()
        if not stable:raise AssertionError('component source or compiler changed')

    def setUp(self):
        self.output=self.root/self._testMethodName;self.output.mkdir()

    def test_01_complete_frozen_originals_and_every_derived_fault_against_native(self):
        qualification.originals(self.output/'original')
        qualification.compare(self.output/'native',self.output/'original','native',self.manifest)
        report=json.loads((self.output/'native/comparison.json').read_bytes())
        self.assertEqual(report['differences'],0)
        self.assertEqual((self.output/'original/complete-first/observations.jsonl').read_bytes(),
                         (self.output/'native/candidate/observations.jsonl').read_bytes())

    def test_02_complete_base_packets_match_independent_VM_all_bytes(self):
        report=controls.packet_cases(self.manifest,self.output)
        self.assertEqual(report['count'],124)
        self.assertGreater(report['entries'],124)
        self.assertTrue(report['complete_VM_and_native_raw_copies_saved'])

    def test_03_real_descriptor_authority_regular_extent_and_symlink_refusal(self):
        rows=controls.real_os_cases(self.manifest,self.output)
        self.assertEqual(len(rows),12)
        self.assertEqual(rows[0]['actual']['bytes'],b'bounded\x00binary\n'.hex())
        self.assertEqual(len(controls.real_os_races(self.manifest,self.output)),3)

    def test_04_actual_native_return_loss_never_replays_or_invents_close(self):
        script=ROOT/'tests/hia_store_file_capture_controls.py'
        rows=[]
        for case_id,mode,port in controls.ACK_CASES:
            for family in ('RuntimeError','KeyboardInterrupt','SystemExit','MemoryError'):
                label=case_id+'.'+family
                controls.run_process(self.output,label,[script,'--manifest',self.manifest,
                    '--output',self.output/label,'--ack-case',case_id,'--family',family],
                    env=controls.clean_environment(),timeout=60)
                row=json.loads((self.output/label/'control.json').read_bytes())
                self.assertTrue(row['same_exception']);self.assertTrue(row['loss_retained'])
                self.assertEqual(row['extra_replay_entries'],0)
                rows.append(row)
        self.assertEqual(len(rows),48)
        controls.write(self.output/'all-ACK-loss.json',rows)

    def test_05_same_frame_reentry_and_wrong_thread_refuse_before_cleanup(self):
        image=native.installed_store_file_capture(self.manifest)
        with tempfile.TemporaryDirectory(prefix='hia-capture-reentry-') as temporary:
            path=Path(temporary)/'data';path.write_bytes(b'abc')
            original_os=api.os;events=[]
            from hepta.hia_native_delivery import current_record
            class Proxy:
                def __getattr__(self,name):return getattr(original_os,name)
                def open(self,*args,**kwargs):
                    record=current_record();owner=record.owner
                    try:owner.finish()
                    except native.StoreFileCaptureUnknown:events.append('reentry-refused')
                    else:raise AssertionError('same frame reentered')
                    if record.retired or not record.current():raise AssertionError('reentry retired outer custody')
                    return original_os.open(*args,**kwargs)
            namespace=dict(vars(api));namespace['os']=Proxy()
            frame=native.StoreFileCaptureFrame(image,1,{'path':path,'limit':64,'dir_fd':None},namespace=namespace)
            self.assertEqual(frame.finish(),b'abc')
            self.assertEqual(events,['reentry-refused'])
            other=native.StoreFileCaptureFrame(image,1,{'path':path,'limit':64,'dir_fd':None})
            errors=[]
            def run():
                try:other.finish()
                except BaseException as error:errors.append(type(error).__name__)
            thread=threading.Thread(target=run);thread.start();thread.join(10)
            self.assertFalse(thread.is_alive());self.assertEqual(errors,['StoreFileCaptureUnknown'])
            self.assertFalse(other._entered);self.assertFalse(other._delivery.retired)
            self.assertEqual(other.finish(),b'abc')
            controls.write(self.output/'context.json',{'same_frame':events,'other_thread':errors,
                                                       'creator_completion_after_refusal':True})

    def test_06_explicit_manifest_drift_refuses_with_retained_bodies_poisoned(self):
        original=json.loads(self.manifest.read_bytes())
        wrong=self.output/'bad';wrong.mkdir()
        image=self.manifest.parent/original['image_path']
        (wrong/image.name).write_bytes(image.read_bytes())
        saved=os.environ.get(native.SELECTOR)
        try:
            with controls.attributes(api,{'_STABLE_READ_REFERENCE':controls.forbidden,
                                          '_CAPTURE_PATH_REFERENCE':controls.forbidden}):
                for label,changed in (('source',{**original,'source_sha256':'0'*64}),
                                      ('image',{**original,'image_sha256':'0'*64})):
                    manifest=wrong/(label+'.json');manifest.write_text(json.dumps(changed))
                    os.environ[native.SELECTOR]=str(manifest)
                    with self.subTest(label=label):
                        with self.assertRaises(ValueError):api.capture_path('/not-an-effect',[],1)
                os.environ[native.SELECTOR]=''
                with self.assertRaises(ValueError):api.stable_read('/not-an-effect',1)
        finally:
            if saved is None:os.environ.pop(native.SELECTOR,None)
            else:os.environ[native.SELECTOR]=saved

    def test_07_invalid_packets_have_no_foreign_effect_and_precise_state_refusal(self):
        image=native.installed_store_file_capture(self.manifest);rows=[]
        def call(raw,state):
            source=ctypes.create_string_buffer(raw+b'\xc9'*16,len(raw)+16)
            output=ctypes.create_string_buffer(b'\xa5'*112,112)
            workspace=ctypes.create_string_buffer(state+b'\xb7'*16,len(state)+16)
            code=image._entry(source,len(raw),output,96,workspace,128)
            self.assertEqual(source.raw,raw+b'\xc9'*16)
            self.assertEqual(output.raw[96:],b'\xa5'*16);self.assertEqual(workspace.raw[128:],b'\xb7'*16)
            return code,output.raw[:96],workspace.raw[:128]
        for mode in (1,2):
            initial=struct.pack('<10Q',native.REQUEST_MAGIC,0,0,0,0,mode,123,456,0,0)
            code,out,state=call(initial,bytes(128))
            self.assertEqual(code,96)
            words=struct.unpack('<12Q',out)
            wrong=struct.pack('<10Q',native.REQUEST_MAGIC,native.CLAIM,words[3]+1,words[2],0,mode,123,456,0,0)
            code,refusal,after=call(wrong,state)
            self.assertEqual(code,96);self.assertEqual(struct.unpack('<12Q',refusal)[1],1)
            old,new=struct.unpack('<16Q',state),struct.unpack('<16Q',after)
            self.assertEqual(new[3],0);self.assertEqual(new[5],8)
            for index in range(16):
                if index not in (3,5,10):self.assertEqual(old[index],new[index])
            corrupt=bytearray(state);corrupt[10*8]^=1
            code,bad,unchanged=call(wrong,bytes(corrupt))
            self.assertNotEqual(code,96);self.assertEqual(unchanged,bytes(corrupt))
            self.assertEqual(bad,b'\xa5'*96)
            rows.append({'mode':mode,'initial':initial.hex(),'state':state.hex(),
                         'wrong_request':wrong.hex(),'refusal':refusal.hex(),'refused_state':after.hex(),
                         'corrupt_code':code,'corrupt_state_unchanged':True})
        controls.write(self.output/'protocol.json',rows)

    def test_08_actual_installed_worker_capture_replay_and_identity_drift(self):
        from tests.hia_store_file_capture_installed import run
        report=run(self.manifest,self.output/'installed')
        self.assertGreater(len(report['wheel_files_checked_against_installed']),0)
        self.assertTrue(report['every_request_has_all_three_expected_identity_flags'])
        self.assertGreater(report['observations']['normal_counts']['request'],0)
        self.assertEqual(report['observations']['replay_counts']['request'],0)
